using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg
{
    public class ECDHPublicBcpgKey : ECPublicBcpgKey
    {
        private byte reserved;
        private HashAlgorithmTag hashFunctionId;
        private SymmetricKeyAlgorithmTag symAlgorithmId;

        /// <param name="bcpgIn">The stream to read the packet from.</param>
        public ECDHPublicBcpgKey(Stream bcpgIn)
            : base(bcpgIn)
        {
            int length = bcpgIn.ReadByte();
            byte[] kdfParameters = new byte[length];
            if (kdfParameters.Length != 3)
                throw new InvalidOperationException("kdf parameters size of 3 expected.");

            Streams.ReadFully(bcpgIn, kdfParameters);

            reserved = kdfParameters[0];
            hashFunctionId = (HashAlgorithmTag)kdfParameters[1];
            symAlgorithmId = (SymmetricKeyAlgorithmTag)kdfParameters[2];

            VerifyHashAlgorithm();
            VerifySymmetricKeyAlgorithm();
        }

        public ECDHPublicBcpgKey(
            Oid oid,
            MPInteger encodedPoint,
            HashAlgorithmTag hashAlgorithm,
            SymmetricKeyAlgorithmTag symmetricKeyAlgorithm)
            : base(oid, encodedPoint)
        {
            reserved = 1;
            hashFunctionId = hashAlgorithm;
            symAlgorithmId = symmetricKeyAlgorithm;

            VerifyHashAlgorithm();
            VerifySymmetricKeyAlgorithm();
        }

        public byte Reserved => reserved;

        public HashAlgorithmTag HashAlgorithm => hashFunctionId;

        public SymmetricKeyAlgorithmTag SymmetricKeyAlgorithm => symAlgorithmId;

        public override void Encode(Stream bcpgOut)
        {
            base.Encode(bcpgOut);
            bcpgOut.WriteByte(0x3);
            bcpgOut.WriteByte(reserved);
            bcpgOut.WriteByte((byte)hashFunctionId);
            bcpgOut.WriteByte((byte)symAlgorithmId);
        }

        private void VerifyHashAlgorithm()
        {
            switch (hashFunctionId)
            {
                case HashAlgorithmTag.Sha256:
                case HashAlgorithmTag.Sha384:
                case HashAlgorithmTag.Sha512:
                    break;
                default:
                    throw new InvalidOperationException("Hash algorithm must be SHA-256 or stronger.");
            }
        }

        private void VerifySymmetricKeyAlgorithm()
        {
            switch (symAlgorithmId)
            {
                case SymmetricKeyAlgorithmTag.Aes128:
                case SymmetricKeyAlgorithmTag.Aes192:
                case SymmetricKeyAlgorithmTag.Aes256:
                    break;
                default:
                    throw new InvalidOperationException("Symmetric key algorithm must be AES-128 or stronger.");
            }
        }
    }
}
