using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Stream that pipes the output as OpenPGP packets, either partial ones
    /// or one with a preset length.
    /// </summary>
    class BcpgOutputStream : Stream
    {
        private Stream outStr;
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

        /// <summary>Create a stream representing an old style partial object.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        /// <param name="tag">The packet tag for the object.</param>
        public BcpgOutputStream(
            Stream outStr,
            PacketTag tag)
        {
            if (outStr == null)
                throw new ArgumentNullException("outStr");

            this.outStr = outStr;
            this.WriteHeader(tag, true, true, 0);
        }

        /// <summary>Create a stream representing a general packet.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        /// <param name="tag">Packet tag.</param>
        /// <param name="length">Size of chunks making up the packet.</param>
        /// <param name="oldFormat">If true, the header is written out in old format.</param>
        public BcpgOutputStream(
            Stream outStr,
            PacketTag tag,
            long length,
            bool oldFormat)
        {
            if (outStr == null)
                throw new ArgumentNullException("outStr");

            this.outStr = outStr;

            if (length > 0xFFFFFFFFL)
            {
                this.WriteHeader(tag, false, true, 0);
                this.partialBufferLength = 1 << BufferSizePower;
                this.partialBuffer = new byte[partialBufferLength];
                this.partialPower = BufferSizePower;
                this.partialOffset = 0;
            }
            else
            {
                this.WriteHeader(tag, oldFormat, false, length);
            }
        }

        /// <summary>Create a new style partial input stream buffered into chunks.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        /// <param name="tag">Packet tag.</param>
        /// <param name="length">Size of chunks making up the packet.</param>
        public BcpgOutputStream(
            Stream outStr,
            PacketTag tag,
            long length)
        {
            if (outStr == null)
                throw new ArgumentNullException("outStr");

            this.outStr = outStr;
            this.WriteHeader(tag, false, false, length);
        }

        /// <summary>Create a new style partial input stream buffered into chunks.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        /// <param name="tag">Packet tag.</param>
        /// <param name="buffer">Buffer to use for collecting chunks.</param>
        public BcpgOutputStream(
            Stream outStr,
            PacketTag tag,
            byte[] buffer)
        {
            if (outStr == null)
                throw new ArgumentNullException("outStr");

            this.outStr = outStr;
            this.WriteHeader(tag, false, true, 0);

            this.partialBuffer = buffer;

            uint length = (uint)partialBuffer.Length;
            for (partialPower = 0; length != 1; partialPower++)
            {
                length >>= 1;
            }

            if (partialPower > 30)
            {
                throw new IOException("Buffer cannot be greater than 2^30 in length.");
            }
            this.partialBufferLength = 1 << partialPower;
            this.partialOffset = 0;
        }

        private void WriteNewPacketLength(
            long bodyLen)
        {
            if (bodyLen < 192)
            {
                outStr.WriteByte((byte)bodyLen);
            }
            else if (bodyLen <= 8383)
            {
                bodyLen -= 192;

                outStr.WriteByte((byte)(((bodyLen >> 8) & 0xff) + 192));
                outStr.WriteByte((byte)bodyLen);
            }
            else
            {
                outStr.WriteByte(0xff);
                outStr.WriteByte((byte)(bodyLen >> 24));
                outStr.WriteByte((byte)(bodyLen >> 16));
                outStr.WriteByte((byte)(bodyLen >> 8));
                outStr.WriteByte((byte)bodyLen);
            }
        }

        private void WriteHeader(
            PacketTag tag,
            bool oldPackets,
            bool partial,
            long bodyLen)
        {
            int hdr = 0x80;

            if (partialBuffer != null)
            {
                PartialFlush(true);
                partialBuffer = null;
            }

            if (oldPackets)
            {
                hdr |= ((int)tag) << 2;

                if (partial)
                {
                    this.WriteByte((byte)(hdr | 0x03));
                }
                else
                {
                    if (bodyLen <= 0xff)
                    {
                        this.WriteByte((byte)hdr);
                        this.WriteByte((byte)bodyLen);
                    }
                    else if (bodyLen <= 0xffff)
                    {
                        this.WriteByte((byte)(hdr | 0x01));
                        this.WriteByte((byte)(bodyLen >> 8));
                        this.WriteByte((byte)(bodyLen));
                    }
                    else
                    {
                        this.WriteByte((byte)(hdr | 0x02));
                        this.WriteByte((byte)(bodyLen >> 24));
                        this.WriteByte((byte)(bodyLen >> 16));
                        this.WriteByte((byte)(bodyLen >> 8));
                        this.WriteByte((byte)bodyLen);
                    }
                }
            }
            else
            {
                hdr |= 0x40 | (int)tag;
                this.WriteByte((byte)hdr);

                if (partial)
                {
                    partialOffset = 0;
                }
                else
                {
                    this.WriteNewPacketLength(bodyLen);
                }
            }
        }

        private void PartialFlush(
            bool isLast)
        {
            if (isLast)
            {
                WriteNewPacketLength(partialOffset);
                outStr.Write(partialBuffer, 0, partialOffset);
            }
            else
            {
                outStr.WriteByte((byte)(0xE0 | partialPower));
                outStr.Write(partialBuffer, 0, partialBufferLength);
            }

            partialOffset = 0;
        }

        private void WritePartial(
            byte b)
        {
            if (partialOffset == partialBufferLength)
            {
                PartialFlush(false);
            }

            partialBuffer[partialOffset++] = b;
        }

        private void WritePartial(ReadOnlySpan<byte> buffer)
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

        public override void WriteByte(
            byte value)
        {
            if (partialBuffer != null)
            {
                WritePartial(value);
            }
            else
            {
                outStr.WriteByte(value);
            }
        }

        public override void Write(
            byte[] buffer,
            int offset,
            int count)
        {
            if (partialBuffer != null)
            {
                WritePartial(buffer.AsSpan(offset, count));
            }
            else
            {
                outStr.Write(buffer, offset, count);
            }
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (partialBuffer != null)
            {
                WritePartial(buffer);
            }
            else
            {
                outStr.Write(buffer);
            }
        }

        public void Write(params byte[] buffer)
        {
            Write(buffer.AsSpan());
        }

        /// <summary>Flush the underlying stream.</summary>
        public override void Flush()
        {
            outStr.Flush();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (partialBuffer != null)
                {
                    PartialFlush(true);
                    Array.Clear(partialBuffer, 0, partialBuffer.Length);
                    partialBuffer = null;
                }
            }
            base.Dispose(disposing);
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
