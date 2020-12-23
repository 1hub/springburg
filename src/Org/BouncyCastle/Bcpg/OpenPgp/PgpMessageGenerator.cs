using System;
using System.IO;
using System.IO.Compression;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpMessageGenerator : IDisposable
    {
        protected IPacketWriter packetWriter;
        private bool openCalled;

        public PgpMessageGenerator(Stream stream)
            : this(new PacketWriter(stream))
        {
        }

        public PgpMessageGenerator(IPacketWriter packetWriter)
        {
            this.packetWriter = packetWriter;
        }

        public void Dispose()
        {
            this.packetWriter.Dispose();
        }

        protected virtual IPacketWriter Open()
        {
            if (openCalled)
            {
                throw new InvalidOperationException("Writing multiple messages are not allowed");
            }

            openCalled = true;
            return new NonDisposablePacketWriter(packetWriter);
        }

        public Stream CreateLiteral(char format, string name, DateTime modificationTime)
        {
            return new PgpLiteralMessageGenerator(Open(), format, name, modificationTime).GetStream();
        }

        public Stream CreateLiteral(char format, FileInfo fileInfo)
        {
            return new PgpLiteralMessageGenerator(Open(), format, fileInfo).GetStream();
        }

        public PgpMessageGenerator CreateCompressed(CompressionAlgorithmTag algorithm, CompressionLevel compressionLevel = CompressionLevel.Optimal)
        {
            return new PgpCompressedMessageGenerator(Open(), algorithm, compressionLevel);
        }

        public PgpSignedMessageGenerator CreateSigned(int signatureType, PgpPrivateKey privateKey, HashAlgorithmTag hashAlgorithm, int version = 4)
        {
            return new PgpSignedMessageGenerator(Open(), signatureType, privateKey, hashAlgorithm, version);
        }

        public PgpEncryptedMessageGenerator CreateEncrypted(SymmetricKeyAlgorithmTag encAlgorithm, bool withIntegrityPacket = false)
        {
            return new PgpEncryptedMessageGenerator(Open(), encAlgorithm, withIntegrityPacket);
        }

        class NonDisposablePacketWriter : IPacketWriter
        {
            IPacketWriter packetWriter;

            public NonDisposablePacketWriter(IPacketWriter packetWriter)
            {
                this.packetWriter = packetWriter;
            }

            public IPacketWriter CreateNestedWriter(Stream stream) => packetWriter.CreateNestedWriter(stream);

            public void Dispose() { }

            public Stream GetPacketStream(StreamablePacket packet) => packetWriter.GetPacketStream(packet);

            public void WritePacket(ContainedPacket packet) => packetWriter.WritePacket(packet);
        }
    }
}
