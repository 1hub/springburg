using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpSignedMessageGenerator : PgpMessageGenerator
    {
        PgpSignatureGenerator signatureGenerator;

        /// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        internal PgpSignedMessageGenerator(IPacketWriter writer, int signatureType, PgpPrivateKey privateKey, HashAlgorithmTag hashAlgorithm, int version = 4)
            : base(writer)
        {
            signatureGenerator = new PgpSignatureGenerator(
                signatureType, privateKey, hashAlgorithm, version,
                ignoreTrailingWhitespace: writer is ArmoredPacketWriter);

            // FIXME: Nesting
            var onePassPacket = new OnePassSignaturePacket(
                signatureGenerator.SignatureType,
                signatureGenerator.HashAlgorithm,
                signatureGenerator.PrivateKey.PublicKeyPacket.Algorithm,
                signatureGenerator.PrivateKey.KeyId,
                /*isNested*/ false);
            writer.WritePacket(onePassPacket);
        }

        public void SetHashedSubpackets(PgpSignatureSubpacketVector hashedPackets) => signatureGenerator.SetHashedSubpackets(hashedPackets);

        public void SetUnhashedSubpackets(PgpSignatureSubpacketVector unhashedPackets) => signatureGenerator.SetHashedSubpackets(unhashedPackets);

        protected override IPacketWriter Open()
        {
            return new SigningPacketWriter(base.Open(), signatureGenerator.helper, this);
        }

        private PgpSignature Generate() => signatureGenerator.Generate();

        class SigningPacketWriter : IPacketWriter
        {
            IPacketWriter innerWriter;
            ICryptoTransform hashTransform;
            PgpSignedMessageGenerator generator;
            bool literalDataWritten;

            public SigningPacketWriter(IPacketWriter innerWriter, ICryptoTransform hashTransform, PgpSignedMessageGenerator generator)
            {
                this.innerWriter = innerWriter;
                this.hashTransform = hashTransform;
                this.generator = generator;
            }

            public IPacketWriter CreateNestedWriter(Stream stream)
            {
                return new SigningPacketWriter(innerWriter.CreateNestedWriter(stream), hashTransform, generator);
            }

            public void Dispose()
            {
                Debug.Assert(literalDataWritten);
                generator.Generate().Encode(innerWriter);
                // DO NOT DISPOSE THE INNER WRITER
            }

            public Stream GetPacketStream(StreamablePacket packet)
            {
                if (packet is LiteralDataPacket)
                {
                    // TODO: Version 5 signatures
                    var packetStream = innerWriter.GetPacketStream(packet);
                    literalDataWritten = true;
                    return new CryptoStream(packetStream, hashTransform, CryptoStreamMode.Write);
                }
                else
                {
                    return innerWriter.GetPacketStream(packet);
                }
            }

            public void WritePacket(ContainedPacket packet) => innerWriter.WritePacket(packet);
        }
    }
}
