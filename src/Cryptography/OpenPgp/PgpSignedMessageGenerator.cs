using InflatablePalace.Cryptography.OpenPgp.Packet;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace InflatablePalace.Cryptography.OpenPgp
{
    public class PgpSignedMessageGenerator : PgpMessageGenerator
    {
        private PgpSignatureGenerator signatureGenerator;
        private bool literalDataWritten;

        /// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        internal PgpSignedMessageGenerator(IPacketWriter writer, int signatureType, PgpPrivateKey privateKey, PgpHashAlgorithm hashAlgorithm, int version = 4)
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

        public PgpSignatureAttributes HashedAttributes => signatureGenerator.HashedAttributes;
        
        public PgpSignatureAttributes UnhashedAttributes => signatureGenerator.UnhashedAttributes;

        protected override IPacketWriter Open()
        {
            return new SigningPacketWriter(base.Open(), signatureGenerator.helper, this);
        }

        class SigningPacketWriter : IPacketWriter
        {
            IPacketWriter innerWriter;
            ICryptoTransform hashTransform;
            PgpSignedMessageGenerator generator;
            bool nested;

            public SigningPacketWriter(IPacketWriter innerWriter, ICryptoTransform hashTransform, PgpSignedMessageGenerator generator)
            {
                this.innerWriter = innerWriter;
                this.hashTransform = hashTransform;
                this.generator = generator;
            }

            public IPacketWriter CreateNestedWriter(Stream stream)
            {
                return new SigningPacketWriter(innerWriter.CreateNestedWriter(stream), hashTransform, generator) { nested = true };
            }

            public void Dispose()
            {
                if (nested)
                {
                    innerWriter.Dispose();
                }
                else
                {
                    Debug.Assert(generator.literalDataWritten);
                    innerWriter.WritePacket(generator.signatureGenerator.Generate());
                    // DO NOT DISPOSE THE INNER WRITER
                }
            }

            public Stream GetPacketStream(StreamablePacket packet)
            {
                if (packet is LiteralDataPacket)
                {
                    // TODO: Version 5 signatures
                    var packetStream = innerWriter.GetPacketStream(packet);
                    generator.literalDataWritten = true;
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
