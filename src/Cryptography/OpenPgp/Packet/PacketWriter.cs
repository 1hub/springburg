using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    public class PacketWriter : IPacketWriter
    {
        private Stream stream;
        private bool preferOldFormat;
        private Stream? currentPacketStream;

        public PacketWriter(Stream stream, bool preferOldFormat = true)
        {
            this.stream = stream;
            this.preferOldFormat = preferOldFormat;
        }

        public void Dispose()
        {
            if (currentPacketStream != null)
                throw new InvalidOperationException("Streamable packet is currently being written");
            this.stream.Close();
        }

        private static void WriteNewPacketLength(
            Stream outputStream,
            long bodyLen)
        {
            if (bodyLen < 192)
            {
                outputStream.WriteByte((byte)bodyLen);
            }
            else if (bodyLen <= 8383)
            {
                bodyLen -= 192;

                outputStream.WriteByte((byte)(((bodyLen >> 8) & 0xff) + 192));
                outputStream.WriteByte((byte)bodyLen);
            }
            else
            {
                outputStream.WriteByte(0xff);
                outputStream.WriteByte((byte)(bodyLen >> 24));
                outputStream.WriteByte((byte)(bodyLen >> 16));
                outputStream.WriteByte((byte)(bodyLen >> 8));
                outputStream.WriteByte((byte)bodyLen);
            }
        }
        private static void WriteHeader(Stream outputStream, PacketTag tag, long bodyLen, bool partial = false, bool useOldPacket = false)
        {
            int hdr = 0x80;

            if (useOldPacket)
            {
                hdr |= ((int)tag) << 2;

                if (partial)
                {
                    outputStream.WriteByte((byte)(hdr | 0x03));
                }
                else if (bodyLen <= 0xff)
                {
                    outputStream.WriteByte((byte)hdr);
                    outputStream.WriteByte((byte)bodyLen);
                }
                else if (bodyLen <= 0xffff)
                {
                    outputStream.WriteByte((byte)(hdr | 0x01));
                    outputStream.WriteByte((byte)(bodyLen >> 8));
                    outputStream.WriteByte((byte)(bodyLen));
                }
                else
                {
                    outputStream.WriteByte((byte)(hdr | 0x02));
                    outputStream.WriteByte((byte)(bodyLen >> 24));
                    outputStream.WriteByte((byte)(bodyLen >> 16));
                    outputStream.WriteByte((byte)(bodyLen >> 8));
                    outputStream.WriteByte((byte)bodyLen);
                }
            }
            else
            {
                hdr |= 0x40 | (int)tag;
                outputStream.WriteByte((byte)hdr);
                if (!partial)
                {
                    WriteNewPacketLength(outputStream, bodyLen);
                }
            }
        }

        public void WritePacket(ContainedPacket packet)
        {
            if (currentPacketStream != null)
                throw new InvalidOperationException("Streamable packet is currently being written");

            using var packetStream = new PacketOutputStream(this, stream, packet.Tag, canBePartial: false, preferOldFormat: preferOldFormat);
            currentPacketStream = packetStream;
            packet.Encode(packetStream);
        }

        public Stream GetPacketStream(StreamablePacket packet)
        {
            if (currentPacketStream != null)
                throw new InvalidOperationException("Streamable packet is currently being written");

            var packetStream = new PacketOutputStream(this, stream, packet.Tag, canBePartial: true, preferOldFormat: preferOldFormat);
            packet.EncodeHeader(packetStream);
            currentPacketStream = packetStream;
            return packetStream;
        }

        public IPacketWriter CreateNestedWriter(Stream stream) => new PacketWriter(stream, preferOldFormat);

        /// <summary>
        /// Stream that pipes the output as OpenPGP packets, either partial ones
        /// or one with a preset length.
        /// </summary>
        class PacketOutputStream : Stream
        {
            private PacketWriter writer;
            private Stream outputStream;
            private List<byte[]>? bufferedPackets;
            private PacketTag packetTag;
            private bool delayedHeader;
            private bool canBePartial;
            private bool oldFormat;

            private byte[] partialBuffer;
            private int partialBufferLength;
            private int partialPower;
            private int partialOffset;
            private const int BufferSizePower = 16; // 2^16 size buffer on long files

            public override bool CanRead => false;

            public override bool CanSeek => false;

            public override bool CanWrite => true;

            public override long Length => throw new NotSupportedException();

            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

            public PacketOutputStream(
                PacketWriter writer,
                Stream outputStream,
                PacketTag tag,
                bool canBePartial = false,
                bool preferOldFormat = false)
            {
                if (outputStream == null)
                    throw new ArgumentNullException(nameof(outputStream));

                this.writer = writer;
                this.outputStream = outputStream;
                this.packetTag = tag;
                this.canBePartial = canBePartial;
                this.oldFormat = preferOldFormat && (int)tag < 16;
                this.delayedHeader = true;
                this.partialBufferLength = 1 << BufferSizePower;
                this.partialBuffer = ArrayPool<byte>.Shared.Rent(partialBufferLength);
                this.partialPower = BufferSizePower;
                this.partialOffset = 0;
            }

            private void PartialFlush(bool isLast)
            {
                if (delayedHeader)
                {
                    if (isLast)
                    {
                        if (bufferedPackets != null)
                        {
                            WriteHeader(outputStream, packetTag, partialOffset + bufferedPackets.Count * partialBufferLength, useOldPacket: oldFormat);
                            foreach (var buffer in bufferedPackets)
                            {
                                outputStream.Write(buffer);
                            }
                        }
                        else
                        {
                            WriteHeader(outputStream, packetTag, partialOffset, useOldPacket: oldFormat);
                        }
                        outputStream.Write(partialBuffer, 0, partialOffset);
                    }
                    else if (canBePartial)
                    {
                        delayedHeader = false;
                        WriteHeader(outputStream, packetTag, 0, partial: true, useOldPacket: oldFormat);
                        if (!oldFormat)
                        {
                            outputStream.WriteByte((byte)(0xE0 | partialPower));
                        }
                        outputStream.Write(partialBuffer, 0, partialBufferLength);
                    }
                    else
                    {
                        bufferedPackets = bufferedPackets ?? new List<byte[]>();
                        bufferedPackets.Add(partialBuffer);
                        // We never generate non-partial packets this long but they would be unrepresentable
                        Debug.Assert((bufferedPackets.Count + 1) * (long)partialBufferLength < 0xFFFFFFFFL);
                        partialBuffer = ArrayPool<byte>.Shared.Rent(partialBufferLength);
                    }
                }
                else
                {
                    if (!oldFormat)
                    {
                        if (isLast)
                        {
                            WriteNewPacketLength(outputStream, partialOffset);
                        }
                        else
                        {
                            outputStream.WriteByte((byte)(0xE0 | partialPower));
                        }
                    }
                    outputStream.Write(partialBuffer, 0, partialOffset);
                }

                partialOffset = 0;
            }

            public override void WriteByte(byte value)
            {
                if (partialOffset == partialBufferLength)
                {
                    PartialFlush(false);
                }

                partialBuffer[partialOffset++] = value;
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                Write(buffer.AsSpan(offset, count));
            }

            public override void Write(ReadOnlySpan<byte> buffer)
            {
                if (partialOffset == partialBufferLength)
                {
                    PartialFlush(false);
                }

                if (buffer.Length <= (partialBufferLength - partialOffset))
                {
                    buffer.CopyTo(partialBuffer.AsSpan(partialOffset));
                    partialOffset += buffer.Length;
                }
                else
                {
                    int diff = partialBufferLength - partialOffset;
                    buffer.Slice(0, diff).CopyTo(partialBuffer.AsSpan(partialOffset));
                    buffer = buffer.Slice(diff);
                    PartialFlush(false);
                    while (buffer.Length > partialBufferLength)
                    {
                        buffer.Slice(0, partialBufferLength).CopyTo(partialBuffer);
                        buffer = buffer.Slice(partialBufferLength);
                        PartialFlush(false);
                    }
                    buffer.CopyTo(partialBuffer);
                    partialOffset += buffer.Length;
                }
            }

            public override void Flush()
            {
                outputStream.Flush();
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    PartialFlush(true);

                    if (bufferedPackets != null)
                    {
                        foreach (var buffer in bufferedPackets)
                        {
                            ArrayPool<byte>.Shared.Return(buffer, true);
                        }
                        bufferedPackets = null;
                    }

                    if (partialBuffer != null)
                    {
                        ArrayPool<byte>.Shared.Return(partialBuffer, true);
                        partialBuffer = Array.Empty<byte>();
                    }

                    Debug.Assert(writer.currentPacketStream == this);
                    if (writer.currentPacketStream == this)
                    {
                        writer.currentPacketStream = null;
                    }
                }

                base.Dispose(disposing);
            }

            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

            public override void SetLength(long value) => throw new NotSupportedException();
        }
    }
}
