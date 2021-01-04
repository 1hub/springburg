using Springburg.Cryptography.OpenPgp.Packet;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp
{
    public class PgpSignedMessageGenerator : PgpMessageGenerator
    {
        private PgpSignatureGenerator signatureGenerator;
        private bool onePassWritten;
        private bool literalDataWritten;

        /// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        internal PgpSignedMessageGenerator(IPacketWriter writer, PgpSignatureType signatureType, PgpPrivateKey privateKey, PgpHashAlgorithm hashAlgorithm, int version = 4)
            : base(writer)
        {
            signatureGenerator = new PgpSignatureGenerator(
                signatureType, privateKey, hashAlgorithm, version,
                ignoreTrailingWhitespace: writer is ArmoredPacketWriter);
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
                if (!generator.onePassWritten)
                {
                    WriteOnePassSignature(false);
                }
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

            public void WritePacket(ContainedPacket packet)
            {
                // The only packets that should be writtern here are the streamable ones
                // or nested signature.
                if (packet is OnePassSignaturePacket && !generator.onePassWritten)
                {
                    // Nested signature, write our one-pass packet first
                    WriteOnePassSignature(true);
                    innerWriter.WritePacket(packet);
                }
                else if (packet is SignaturePacket)
                {
                    Debug.Assert(generator.onePassWritten);
                    Debug.Assert(generator.literalDataWritten);
                    innerWriter.WritePacket(packet);
                }
                else
                {
                    throw new InvalidOperationException();
                }
            }

            private void WriteOnePassSignature(bool isNested)
            {
                Debug.Assert(!generator.onePassWritten);
                var onePassPacket = new OnePassSignaturePacket(
                    generator.signatureGenerator.SignatureType,
                    generator.signatureGenerator.HashAlgorithm,
                    generator.signatureGenerator.PrivateKey.Algorithm,
                    generator.signatureGenerator.PrivateKey.KeyId,
                    isNested);
                innerWriter.WritePacket(onePassPacket);
                generator.onePassWritten = true;
            }
        }
    }
}
