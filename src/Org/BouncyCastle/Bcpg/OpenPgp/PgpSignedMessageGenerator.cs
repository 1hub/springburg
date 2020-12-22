using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Bcpg.Sig;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpSignedMessageGenerator : PgpSignatureGenerator
    {
        /// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        public PgpSignedMessageGenerator(int signatureType, PgpPrivateKey privateKey, HashAlgorithmTag hashAlgorithm, int version = 4)
            : base(signatureType, privateKey, hashAlgorithm, version)
        {
        }

        public IPacketWriter Open(IPacketWriter writer)
        {
            // FIXME: Nesting
            var onePassPacket = new OnePassSignaturePacket(helper.SignatureType, hashAlgorithm, privateKey.PublicKeyPacket.Algorithm, privateKey.KeyId, /*isNested*/ false);
            writer.WritePacket(onePassPacket);
            if (writer is ArmoredPacketWriter)
            {
                helper.IgnoreTrailingWhitespace = true;
            }
            return new SigningPacketWriter(writer, helper, this);
        }

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
