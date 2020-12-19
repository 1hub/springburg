using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class OnePassSignaturePacket : ContainedPacket
    {
        private int version;
        private int sigType;
        private HashAlgorithmTag hashAlgorithm;
        private PublicKeyAlgorithmTag keyAlgorithm;
        private long keyId;
        private int nested;

        internal OnePassSignaturePacket(Stream bcpgIn)
        {
            version = bcpgIn.ReadByte();
            sigType = bcpgIn.ReadByte();
            hashAlgorithm = (HashAlgorithmTag)bcpgIn.ReadByte();
            keyAlgorithm = (PublicKeyAlgorithmTag)bcpgIn.ReadByte();

            keyId |= (long)bcpgIn.ReadByte() << 56;
            keyId |= (long)bcpgIn.ReadByte() << 48;
            keyId |= (long)bcpgIn.ReadByte() << 40;
            keyId |= (long)bcpgIn.ReadByte() << 32;
            keyId |= (long)bcpgIn.ReadByte() << 24;
            keyId |= (long)bcpgIn.ReadByte() << 16;
            keyId |= (long)bcpgIn.ReadByte() << 8;
            keyId |= (uint)bcpgIn.ReadByte();

            nested = bcpgIn.ReadByte();
        }

        public OnePassSignaturePacket(
            int sigType,
            HashAlgorithmTag hashAlgorithm,
            PublicKeyAlgorithmTag keyAlgorithm,
            long keyId,
            bool isNested)
        {
            this.version = 3;
            this.sigType = sigType;
            this.hashAlgorithm = hashAlgorithm;
            this.keyAlgorithm = keyAlgorithm;
            this.keyId = keyId;
            this.nested = (isNested) ? 0 : 1;
        }

        public int SignatureType => sigType;

        public PublicKeyAlgorithmTag KeyAlgorithm => keyAlgorithm;

        public HashAlgorithmTag HashAlgorithm => hashAlgorithm;

        public long KeyId => keyId;

        public override PacketTag Tag => PacketTag.OnePassSignature;

        public override void Encode(Stream bcpgOut)
        {
            bcpgOut.Write(new[] {
                (byte)version,
                (byte)sigType,
                (byte)hashAlgorithm,
                (byte)keyAlgorithm });
            bcpgOut.Write(OpenPgp.PgpUtilities.KeyIdToBytes(keyId));
            bcpgOut.WriteByte((byte)nested);
        }
    }
}
