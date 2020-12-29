using InflatablePalace.IO;
using InflatablePalace.IO.Checksum;
using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    public class ArmoredPacketReader : IPacketReader
    {
        private Stream stream;
        private ArmoredDataReader armoredDataReader;
        private Stream? armoredDataStream;
        private Crc24? crc24;
        private PacketReader? packetReader;
        private OnePassSignaturePacket? pendingOnePassPacket;

        public ArmoredPacketReader(Stream stream)
        {
            this.stream = stream;
            this.armoredDataReader = new ArmoredDataReader(stream);
        }

        public IPacketReader CreateNestedReader(Stream stream)
        {
            return new PacketReader(stream);
        }

        public bool VerifyCrc()
        {
            if (armoredDataReader.State == ReaderState.Headers)
            {
                // Skip past headers
                armoredDataReader.ReadHeaderLines();
            }

            if (armoredDataReader.State == ReaderState.ClearText)
            {
                // Skip past clear text
                using var literalDataStream = new LiteralDataStream(armoredDataReader);
                literalDataStream.CopyTo(Stream.Null);
                // Skip past headers
                armoredDataReader.ReadHeaderLines();
            }

            if (armoredDataReader.State == ReaderState.Base64)
            {
                if (armoredDataStream == null)
                {
                    this.crc24 = new Crc24();
                    this.armoredDataStream = new CryptoStream(new ArmoredDataStream(armoredDataReader), crc24, CryptoStreamMode.Read);
                }
                armoredDataStream?.CopyTo(Stream.Null);
                armoredDataStream?.Dispose();
            }

            Debug.Assert(this.armoredDataReader.State == ReaderState.CRC);
            var crcTail = this.armoredDataReader.ReadCrcAndFooter();
            Debug.Assert(this.crc24 != null);
            return crcTail.SequenceEqual(this.crc24.Hash!);
        }

        public void Dispose()
        {
            this.packetReader?.Dispose();

            if (this.armoredDataReader.State != ReaderState.EndOfArmor)
            {
                try
                {
                    // Read past everything
                    VerifyCrc();
                }
                catch (EndOfStreamException)
                {
                }
                catch (InvalidDataException)
                {
                }
            }
        }

        private void AdvanceState()
        {
            if (armoredDataReader.State == ReaderState.Headers)
            {
                var headerLines = armoredDataReader.ReadHeaderLines();
                if (armoredDataReader.State == ReaderState.ClearText)
                {
                    // Generate the pending one-pass packet
                    PgpHashAlgorithm hashAlgorithmTag = PgpHashAlgorithm.MD5;
                    foreach (var header in headerLines)
                    {
                        if (header.StartsWith("Hash: ", StringComparison.OrdinalIgnoreCase))
                        {
                            // FIXME: Multiple hashes
                            hashAlgorithmTag = PgpUtilities.GetHashAlgorithm(header.Substring(6).TrimEnd());
                        }
                    }
                    pendingOnePassPacket = new OnePassSignaturePacket(PgpSignature.CanonicalTextDocument, hashAlgorithmTag, 0, 0, false);
                }
                else if (armoredDataReader.State == ReaderState.Base64)
                {
                    Debug.Assert(this.packetReader == null);
                    this.crc24 = new Crc24();
                    this.armoredDataStream = new CryptoStream(new ArmoredDataStream(armoredDataReader), crc24, CryptoStreamMode.Read);
                    this.packetReader = new PacketReader(armoredDataStream);
                }
            }
        }

        public PacketTag NextPacketTag()
        {
            AdvanceState();

            if (armoredDataReader.State == ReaderState.ClearText)
            {
                if (pendingOnePassPacket != null)
                    return PacketTag.OnePassSignature;
                return PacketTag.LiteralData;
            }

            Debug.Assert(this.packetReader != null);
            return this.packetReader.NextPacketTag();
        }

        public ContainedPacket ReadContainedPacket()
        {
            AdvanceState();

            if (armoredDataReader.State == ReaderState.ClearText)
            {
                if (pendingOnePassPacket != null)
                {
                    var temp = pendingOnePassPacket;
                    pendingOnePassPacket = null;
                    return temp;
                }

                throw new InvalidDataException();
            }
            else if (armoredDataReader.State == ReaderState.Base64)
            {
                Debug.Assert(this.packetReader != null);
                return this.packetReader.ReadContainedPacket();
            }

            throw new InvalidDataException();
        }

        public (StreamablePacket Packet, Stream Stream) ReadStreamablePacket()
        {
            AdvanceState();

            if (armoredDataReader.State == ReaderState.ClearText)
            {
                if (pendingOnePassPacket != null)
                {
                    throw new InvalidDataException();
                }

                //var stream = new LiteralDataStream(armoredInputStream);
                return (new LiteralDataPacket(PgpDataFormat.Utf8, "", DateTime.MinValue), new LiteralDataStream(armoredDataReader));
            }
            else if (armoredDataReader.State == ReaderState.Base64)
            {
                Debug.Assert(this.packetReader != null);
                return this.packetReader.ReadStreamablePacket();
            }

            throw new InvalidDataException();
        }

        enum ReaderState
        {
            Headers,
            ClearText,
            Base64,
            CRC,
            EndOfArmor
        }

        class ArmoredDataReader
        {
            private Stream innerStream;
            private byte[]? pendingData;
            private bool ignoreNL;
            private ArrayBufferWriter<byte> pendingWhitespace;
            private bool endOfClearText;
            private int headerEndLineLength;

            public ReaderState State { get; set; } = ReaderState.Headers;

            public ArmoredDataReader(Stream innerStream)
            {
                this.innerStream = innerStream;
                this.pendingWhitespace = new ArrayBufferWriter<byte>();
            }

            public string[] ReadHeaderLines()
            {
                if (State != ReaderState.Headers)
                    throw new InvalidOperationException();

                List<string> lines = new List<string>();
                var outputBuffer = new ArrayBufferWriter<byte>();

                if (endOfClearText)
                {
                    // If we were reading clear text before then we consumed
                    // the first two dashes of the separator.
                    outputBuffer.Write(new[] { (byte)'-', (byte)'-' });
                }

                for (; ; )
                {
                    var b = innerStream.ReadByte();
                    switch (b)
                    {
                        case -1:
                            return Array.Empty<string>();

                        case '\n':
                            if (!ignoreNL)
                                goto case '\r';
                            ignoreNL = false;
                            break;

                        case '\r':
                            ignoreNL = b == '\r';

                            // Non-empty line
                            string? line = null;
                            if (outputBuffer.WrittenCount > 0)
                            {
                                line = Encoding.ASCII.GetString(outputBuffer.WrittenSpan);
                                outputBuffer.Clear();
                            }

                            if (!string.IsNullOrWhiteSpace(line))
                            {
                                lines.Add(line);
                            }
                            else if (lines.Count > 0)
                            {
                                // TODO: Verify the headers
                                headerEndLineLength = lines.First().Length - 2; // -2 for BEGIN -> END

                                State =
                                    !endOfClearText && Equals(lines.FirstOrDefault(), "-----BEGIN PGP SIGNED MESSAGE-----") ?
                                    ReaderState.ClearText : ReaderState.Base64;
                                return lines.ToArray();
                            }

                            break;

                        default:
                            outputBuffer.GetSpan(1)[0] = (byte)b;
                            outputBuffer.Advance(1);
                            break;
                    }
                }
            }

            public int ReadClearText(Span<byte> buffer)
            {
                if (State != ReaderState.ClearText)
                    throw new InvalidOperationException();

                // We usually try to output one character for one input character
                // but new line and dash sequences can produce up to 4 characters
                // at once, so size the buffer to accommodate that. We can also
                // overshoot the buffer with pending whitespace.
                var outputBuffer = new ArrayBufferWriter<byte>(buffer.Length + 3);

                if (pendingData != null)
                {
                    outputBuffer.Write(pendingData);
                }

                while (!endOfClearText && outputBuffer.WrittenCount < buffer.Length)
                {
                    var b = innerStream.ReadByte();

                    // End of stream
                    if (b == -1)
                    {
                        break;
                    }

                    switch (b)
                    {
                        case ' ':
                        case '\t':
                            // Collect pending whitespace because it could be trailing whitespace
                            // at end of line
                            pendingWhitespace.GetSpan(1)[0] = (byte)b;
                            pendingWhitespace.Advance(1);
                            break;

                        case '\r':
                        case '\n':
                            // Ignore \n that was still part of header
                            if (ignoreNL && b == '\n')
                            {
                                ignoreNL = false;
                                break;
                            }

                            // Discard any pending whitespace
                            pendingWhitespace.Clear();

                            // Read next character after the new line
                            var nextB = innerStream.ReadByte();
                            if (b == '\r' && nextB == '\n')
                                nextB = innerStream.ReadByte();

                            if (nextB == '-')
                            {
                                // New line followed byt dash. Now we are looking either at the end of
                                // clear text or a dash escape
                                nextB = innerStream.ReadByte();
                                if (nextB == ' ')
                                {
                                    // Dash escape, remove it and flush the new line
                                    outputBuffer.Write(new[] { (byte)'\r', (byte)'\n' });
                                }
                                else if (nextB == '-')
                                {
                                    // Possible end of clear text
                                    endOfClearText = true;
                                    break;
                                }
                                else
                                {
                                    // Invalid clear text, flush the new lind and output it
                                    var clearText = outputBuffer.GetSpan(4);
                                    clearText[0] = (byte)'\r';
                                    clearText[1] = (byte)'\n';
                                    clearText[2] = (byte)'-';
                                    clearText[3] = (byte)b;
                                    outputBuffer.Advance(4);
                                }
                            }
                            else
                            {
                                // Flush the new line
                                outputBuffer.Write(new[] { (byte)'\r', (byte)'\n' });

                                if (nextB == '\r' || nextB == '\n')
                                {
                                    b = nextB;
                                    goto case '\r';
                                }
                                else if (nextB == ' ' || nextB == '\t')
                                {
                                    pendingWhitespace.GetSpan(1)[0] = (byte)nextB;
                                    pendingWhitespace.Advance(1);
                                }
                                else
                                {
                                    outputBuffer.GetSpan(1)[0] = (byte)nextB;
                                    outputBuffer.Advance(1);
                                }
                            }
                            break;

                        default:
                            // Flush any pending whitespace
                            if (pendingWhitespace.WrittenCount > 0)
                            {
                                outputBuffer.Write(pendingWhitespace.WrittenSpan);
                                pendingWhitespace.Clear();
                            }

                            outputBuffer.GetSpan(1)[0] = (byte)b;
                            outputBuffer.Advance(1);
                            break;
                    }
                }

                if (outputBuffer.WrittenCount > buffer.Length)
                {
                    pendingData = outputBuffer.WrittenSpan.Slice(buffer.Length).ToArray();
                    outputBuffer.WrittenSpan.Slice(0, buffer.Length).CopyTo(buffer);
                    return buffer.Length;
                }
                else
                {
                    if (endOfClearText)
                    {
                        State = ReaderState.Headers;
                    }
                    pendingData = null;
                    outputBuffer.WrittenSpan.CopyTo(buffer);
                    return outputBuffer.WrittenCount;
                }
            }

            public int ReadArmoredData(Span<byte> buffer)
            {
                int totalWritten = 0;

                if (State != ReaderState.Base64)
                    throw new InvalidOperationException();

                if (pendingData != null)
                {
                    totalWritten = Math.Min(buffer.Length, pendingData.Length);
                    pendingData.AsSpan(0, totalWritten).CopyTo(buffer);
                    pendingData = totalWritten == pendingData.Length ? null : pendingData.AsSpan(totalWritten).ToArray();
                    buffer = buffer.Slice(totalWritten);
                }

                if (buffer.Length > 0)
                {
                    Span<byte> base64Data = new byte[((buffer.Length + 2) / 3) * 4];
                    int base64Pos = 0;

                    while (base64Pos < base64Data.Length)
                    {
                        var b = innerStream.ReadByte();

                        if (b == -1)
                        {
                            State = ReaderState.EndOfArmor; // Invalid
                            break;
                        }

                        if (b == '\r' || b == '\n')
                        {
                            var nextB = innerStream.ReadByte();
                            while (nextB == '\n' || nextB == '\r')
                            {
                                nextB = innerStream.ReadByte();
                            }

                            // We reached the CRC
                            if (nextB == '=')
                            {
                                State = ReaderState.CRC;
                                break;
                            }

                            b = nextB;
                        }

                        if ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') ||
                            b == '+' || b == '/' || b == '=')
                        {
                            base64Data[base64Pos++] = (byte)b;
                        }
                    }

                    // TODO: Should we pad the data if the padding is missing?

                    var status = Base64.DecodeFromUtf8InPlace(base64Data.Slice(0, base64Pos), out var bytesWritten);
                    Debug.Assert(status == OperationStatus.Done);
                    Debug.Assert(((bytesWritten + 2) / 3) * 4 == base64Pos);
                    if (bytesWritten > buffer.Length)
                    {
                        pendingData = base64Data.Slice(buffer.Length, bytesWritten - buffer.Length).ToArray();
                        base64Data.Slice(0, buffer.Length).CopyTo(buffer);
                        totalWritten += buffer.Length;
                    }
                    else
                    {
                        pendingData = null;
                        base64Data.Slice(0, bytesWritten).CopyTo(buffer);
                        totalWritten += bytesWritten;
                    }
                }

                return totalWritten;
            }

            public byte[] ReadCrcAndFooter()
            {
                if (State != ReaderState.CRC)
                    throw new InvalidOperationException();

                var crcBase64 = new byte[4];
                if (innerStream.ReadFully(crcBase64) != crcBase64.Length)
                    throw new EndOfStreamException();

                State = ReaderState.EndOfArmor;

                var status = Base64.DecodeFromUtf8InPlace(crcBase64, out var bytesWritten);
                Debug.Assert(status == OperationStatus.Done);

                // Skip over footer
                int b;
                var footer = new byte[headerEndLineLength];
                while ((b = innerStream.ReadByte()) >= 0 && char.IsWhiteSpace((char)b))
                {
                }
                // TODO: verify
                footer[0] = (byte)b;
                innerStream.ReadFully(footer.AsSpan(1));

                return crcBase64.AsSpan(0, bytesWritten).ToArray();
            }
        }

        class LiteralDataStream : Stream
        {
            private ArmoredDataReader armoredDataReader;

            public LiteralDataStream(ArmoredDataReader armoredDataReader)
            {
                this.armoredDataReader = armoredDataReader;
            }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (armoredDataReader.State == ReaderState.ClearText)
                    return armoredDataReader.ReadClearText(buffer.AsSpan(offset, count));
                return 0;
            }

            public override int Read(Span<byte> buffer)
            {
                if (armoredDataReader.State == ReaderState.ClearText)
                    return armoredDataReader.ReadClearText(buffer);
                return 0;
            }
        }

        class ArmoredDataStream : Stream
        {
            private ArmoredDataReader armoredDataReader;

            public ArmoredDataStream(ArmoredDataReader armoredDataReader)
            {
                this.armoredDataReader = armoredDataReader;
            }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (armoredDataReader.State == ReaderState.Base64)
                    return armoredDataReader.ReadArmoredData(buffer.AsSpan(offset, count));
                return 0;
            }

            public override int Read(Span<byte> buffer)
            {
                if (armoredDataReader.State == ReaderState.Base64)
                    return armoredDataReader.ReadArmoredData(buffer);
                return 0;
            }
        }
    }
}
