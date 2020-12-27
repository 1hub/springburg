using InflatablePalace.IO;
using System;
using System.IO;
using System.Security.Cryptography;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    class ECDHPublicBcpgKey : ECPublicBcpgKey
    {
        private byte reserved;
        private PgpHashAlgorithm hashFunctionId;
        private PgpSymmetricKeyAlgorithm symAlgorithmId;

        /// <param name="bcpgIn">The stream to read the packet from.</param>
        public ECDHPublicBcpgKey(Stream bcpgIn)
            : base(bcpgIn)
        {
            int length = bcpgIn.ReadByte();
            byte[] kdfParameters = new byte[length];
            if (kdfParameters.Length != 3)
                throw new InvalidOperationException("kdf parameters size of 3 expected.");

            if (bcpgIn.ReadFully(kdfParameters) < kdfParameters.Length)
                throw new EndOfStreamException();

            reserved = kdfParameters[0];
            hashFunctionId = (PgpHashAlgorithm)kdfParameters[1];
            symAlgorithmId = (PgpSymmetricKeyAlgorithm)kdfParameters[2];

            VerifyHashAlgorithm();
            VerifySymmetricKeyAlgorithm();
        }

        public ECDHPublicBcpgKey(
            Oid oid,
            MPInteger encodedPoint,
            PgpHashAlgorithm hashAlgorithm,
            PgpSymmetricKeyAlgorithm symmetricKeyAlgorithm)
            : base(oid, encodedPoint)
        {
            reserved = 1;
            hashFunctionId = hashAlgorithm;
            symAlgorithmId = symmetricKeyAlgorithm;

            VerifyHashAlgorithm();
            VerifySymmetricKeyAlgorithm();
        }

        public byte Reserved => reserved;

        public PgpHashAlgorithm HashAlgorithm => hashFunctionId;

        public PgpSymmetricKeyAlgorithm SymmetricKeyAlgorithm => symAlgorithmId;

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
                case PgpHashAlgorithm.Sha256:
                case PgpHashAlgorithm.Sha384:
                case PgpHashAlgorithm.Sha512:
                    break;
                default:
                    throw new InvalidOperationException("Hash algorithm must be SHA-256 or stronger.");
            }
        }

        private void VerifySymmetricKeyAlgorithm()
        {
            switch (symAlgorithmId)
            {
                case PgpSymmetricKeyAlgorithm.Aes128:
                case PgpSymmetricKeyAlgorithm.Aes192:
                case PgpSymmetricKeyAlgorithm.Aes256:
                    break;
                default:
                    throw new InvalidOperationException("Symmetric key algorithm must be AES-128 or stronger.");
            }
        }
    }
}
