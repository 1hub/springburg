using Springburg.IO.Checksum;
using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    public class ArmoredPacketWriter : IPacketWriter
    {
        private Stream stream;
        private PacketWriter? writer;
        private Crc24? crc24;
        private Stream? base64OutputStream;
        private bool useClearText;
        private bool inClearText;
        private List<string>? hashHeaders;
        private string? type;

        public ArmoredPacketWriter(Stream stream, bool useClearText = true)
        {
            this.stream = stream;
            this.useClearText = useClearText;
        }

        public IPacketWriter CreateNestedWriter(Stream stream)
        {
            useClearText = false;
            return new PacketWriter(stream);
        }

        public void Dispose()
        {
            if (this.base64OutputStream != null)
            {
                this.base64OutputStream.Close();
                this.stream.Write(Encoding.ASCII.GetBytes("=" + Convert.ToBase64String(this.crc24!.Hash!) + "\r\n"));
                this.stream.Write(Encoding.ASCII.GetBytes("-----END PGP " + type + "-----\r\n"));
                this.base64OutputStream = null;
            }
            this.stream.Dispose();
        }

        public Stream GetPacketStream(StreamablePacket packet)
        {
            if (packet == null)
                throw new ArgumentNullException(nameof(packet));

            if (inClearText)
            {
                if (packet is LiteralDataPacket && hashHeaders != null)
                {
                    this.stream.Write(Encoding.ASCII.GetBytes("-----BEGIN PGP SIGNED MESSAGE-----\r\n"));
                    this.stream.Write(Encoding.ASCII.GetBytes("Hash: " + String.Join(", ", hashHeaders) + "\r\n\r\n"));
                    return new DashEscapeStream(this, this.stream);
                }
                else
                {
                    throw new InvalidOperationException();
                }
            }

            if (this.writer == null)
            {
                StartArmor(packet.Tag);
                Debug.Assert(this.writer != null);
            }
            return this.writer.GetPacketStream(packet);
        }

        public void WritePacket(ContainedPacket packet)
        {
            if (packet == null)
                throw new ArgumentNullException(nameof(packet));

            if (packet is OnePassSignaturePacket onePassSignaturePacket && useClearText && this.writer == null)
            {
                string hashName = PgpUtilities.GetDigestName(onePassSignaturePacket.HashAlgorithm);
                hashHeaders = hashHeaders ?? new List<string>();
                hashHeaders.Add(hashName);
                inClearText = true;
            }
            else if (inClearText)
            {
                throw new InvalidOperationException();
            }
            else
            {
                useClearText = false;
                if (this.writer == null)
                {
                    StartArmor(packet.Tag);
                    Debug.Assert(this.writer != null);
                }
                this.writer.WritePacket(packet);
            }
        }

        private void StartArmor(PacketTag tag)
        {
            switch (tag)
            {
                case PacketTag.PublicKey: type = "PUBLIC KEY BLOCK"; break;
                case PacketTag.SecretKey: type = "PRIVATE KEY BLOCK"; break;
                case PacketTag.Signature: type = "SIGNATURE"; break;
                default: type = "MESSAGE"; break;
            }

            stream.Write(Encoding.ASCII.GetBytes("-----BEGIN PGP " + type + "-----\r\n"));
            stream.Write(Encoding.ASCII.GetBytes("Version: " + ThisAssembly.AssemblyName + " " + ThisAssembly.AssemblyInformationalVersion + "\r\n\r\n"));

            this.crc24 = new Crc24();
            this.base64OutputStream = new CryptoStream(
                new Base64OutputStream(stream),
                this.crc24, CryptoStreamMode.Write);
            this.writer = new PacketWriter(base64OutputStream);
        }

        class DashEscapeStream : Stream
        {
            private readonly ArmoredPacketWriter writer;
            private readonly Stream outStream;
            private bool newLine = true;

            public override bool CanRead => false;

            public override bool CanSeek => false;

            public override bool CanWrite => true;

            public override long Length => throw new NotSupportedException();

            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

            public DashEscapeStream(ArmoredPacketWriter writer, Stream outStream)
            {
                this.writer = writer;
                this.outStream = outStream;
            }

            public override void WriteByte(byte b)
            {
                if (b == '-' && newLine)
                {
                    outStream.WriteByte((byte)'-');
                    outStream.WriteByte((byte)' ');
                }
                outStream.WriteByte(b);
                newLine = b == '\r' || b == '\n';
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                foreach (var b in buffer.AsSpan(offset, count))
                    WriteByte(b);
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    outStream.WriteByte((byte)'\r');
                    outStream.WriteByte((byte)'\n');
                    writer.inClearText = false;
                    writer.useClearText = false;
                }
                base.Dispose(disposing);
            }

            public override void Flush() => outStream.Flush();

            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

            public override void SetLength(long value) => throw new NotSupportedException();
        }

        class Base64OutputStream : Stream
        {
            private const int PlainTextLength = 54;

            private readonly Stream outStream;
            private byte[] encodingBuffer = new byte[(PlainTextLength * 4) / 3];
            private int encodingBufferPtr = 0;

            private byte[] nl = new[] { (byte)'\r', (byte)'\n' };

            public override bool CanRead => false;

            public override bool CanSeek => false;

            public override bool CanWrite => true;

            public override long Length => throw new NotSupportedException();

            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

            public Base64OutputStream(Stream outStream)
            {
                this.outStream = outStream;
            }

            public override void WriteByte(byte b)
            {
                encodingBuffer[encodingBufferPtr++] = b;

                if (encodingBufferPtr == PlainTextLength)
                {
                    var status = Base64.EncodeToUtf8InPlace(encodingBuffer, encodingBufferPtr, out var bytesWritten);
                    Debug.Assert(status == System.Buffers.OperationStatus.Done);
                    outStream.Write(encodingBuffer.AsSpan(0, bytesWritten));
                    outStream.Write(nl);
                    encodingBufferPtr = 0;
                }
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                foreach (var b in buffer.AsSpan(offset, count))
                {
                    encodingBuffer[encodingBufferPtr++] = b;
                    if (encodingBufferPtr == PlainTextLength)
                    {
                        var status = Base64.EncodeToUtf8InPlace(encodingBuffer, encodingBufferPtr, out var bytesWritten);
                        Debug.Assert(status == System.Buffers.OperationStatus.Done);
                        outStream.Write(encodingBuffer.AsSpan(0, bytesWritten));
                        outStream.Write(nl);
                        encodingBufferPtr = 0;
                    }
                }
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    if (encodingBufferPtr > 0)
                    {
                        var status = Base64.EncodeToUtf8InPlace(encodingBuffer, encodingBufferPtr, out var bytesWritten);
                        Debug.Assert(status == System.Buffers.OperationStatus.Done);
                        outStream.Write(encodingBuffer.AsSpan(0, bytesWritten));
                        outStream.Write(nl);
                        encodingBufferPtr = 0;
                    }
                }
                base.Dispose(disposing);
            }

            public override void Flush() => outStream.Flush();

            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

            public override void SetLength(long value) => throw new NotSupportedException();
        }
    }
}
