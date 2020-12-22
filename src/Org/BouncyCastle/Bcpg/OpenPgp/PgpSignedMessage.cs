using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpSignedMessage : PgpMessage
    {
        private OnePassSignaturePacket onePassSignaturePacket;
        private SignaturePacket signaturePacket;
        private IPacketReader packetReader;
        private PgpSignatureHelper signatureHelper;

        internal PgpSignedMessage(IPacketReader packetReader)
        {
            var packet = packetReader.ReadPacket();
            onePassSignaturePacket = packet as OnePassSignaturePacket;
            signaturePacket = packet as SignaturePacket;
            Debug.Assert(onePassSignaturePacket != null || signaturePacket != null);
            this.packetReader = packetReader;
        }

        public long KeyId => onePassSignaturePacket != null ? onePassSignaturePacket.KeyId : signaturePacket.KeyId;

        public PublicKeyAlgorithmTag KeyAlgorithm => onePassSignaturePacket != null ? onePassSignaturePacket.KeyAlgorithm : signaturePacket.KeyAlgorithm;

        public HashAlgorithmTag HashAlgorithm => onePassSignaturePacket != null ? onePassSignaturePacket.HashAlgorithm : signaturePacket.HashAlgorithm;

        public PgpMessage ReadMessage()
        {
            signatureHelper = new PgpSignatureHelper(
                onePassSignaturePacket != null ? onePassSignaturePacket.SignatureType : signaturePacket.SignatureType,
                onePassSignaturePacket != null ? onePassSignaturePacket.HashAlgorithm : signaturePacket.HashAlgorithm);

            var signingReader = new SigningPacketReader(packetReader, signatureHelper);

            return ReadMessage(signingReader);
        }

        // TODO: Verify with key ring

        public bool Verify(PgpPublicKey publicKey) => Verify(publicKey, out var _);

        public bool Verify(PgpPublicKey publicKey, out DateTime creationTime)
        {
            if (signaturePacket == null)
            {
                signaturePacket = (SignaturePacket)packetReader.ReadPacket();
            }

            creationTime = signaturePacket.CreationTime;

            return signatureHelper.Verify(signaturePacket.GetSignature(), signaturePacket.GetSignatureTrailer(), publicKey.GetKey());
        }

        class SigningPacketReader : IPacketReader
        {
            IPacketReader innerReader;
            ICryptoTransform hashTransform;
            bool literalDataRead;

            public SigningPacketReader(IPacketReader innerReader, ICryptoTransform hashTransform)
            {
                this.innerReader = innerReader;
                this.hashTransform = hashTransform;
            }

            public IPacketReader CreateNestedReader(Stream stream)
            {
                // FIXME: Better exception
                throw new NotSupportedException();
            }

            public void Dispose()
            {
                Debug.Assert(literalDataRead);
                // DO NOT DISPOSE THE INNER READER
            }

            public PacketTag NextPacketTag()
            {
                return innerReader.NextPacketTag();
            }

            public Packet ReadPacket()
            {
                if (innerReader.NextPacketTag() == PacketTag.LiteralData)
                {
                    // TODO: Version 5 signatures
                    var literalDataPacket = (LiteralDataPacket)innerReader.ReadPacket();
                    literalDataRead = true;
                    // FIXME: Improve interface
                    literalDataPacket.inputStream = new CryptoStream(literalDataPacket.GetInputStream(), hashTransform, CryptoStreamMode.Read);
                    return literalDataPacket;
                }
                return innerReader.ReadPacket();
            }
        }
    }
}
