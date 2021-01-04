using Springburg.IO;
using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    /// <summary>Basic packet for a PGP public key.</summary>
    class PublicKeyEncSessionPacket : ContainedPacket
    {
        private int version;
        private long keyId;
        private PgpPublicKeyAlgorithm algorithm;
        private byte[] sessionKey;

        internal PublicKeyEncSessionPacket(Stream bcpgIn)
        {
            version = bcpgIn.ReadByte();

            keyId |= (long)bcpgIn.ReadByte() << 56;
            keyId |= (long)bcpgIn.ReadByte() << 48;
            keyId |= (long)bcpgIn.ReadByte() << 40;
            keyId |= (long)bcpgIn.ReadByte() << 32;
            keyId |= (long)bcpgIn.ReadByte() << 24;
            keyId |= (long)bcpgIn.ReadByte() << 16;
            keyId |= (long)bcpgIn.ReadByte() << 8;
            keyId |= (uint)bcpgIn.ReadByte();

            algorithm = (PgpPublicKeyAlgorithm)bcpgIn.ReadByte();

            sessionKey = bcpgIn.ReadAll();
        }

        public PublicKeyEncSessionPacket(
            long keyId,
            PgpPublicKeyAlgorithm algorithm,
            ReadOnlySpan<byte> sessionKey)
        {
            this.version = 3;
            this.keyId = keyId;
            this.algorithm = algorithm;
            this.sessionKey = sessionKey.ToArray();
        }

        public int Version => version;

        public long KeyId => keyId;

        public PgpPublicKeyAlgorithm Algorithm => algorithm;

        public byte[] SessionKey => sessionKey;

        public override PacketTag Tag => PacketTag.PublicKeyEncryptedSession;

        public override void Encode(Stream bcpgOut)
        {
            bcpgOut.WriteByte((byte)version);
            bcpgOut.Write(PgpUtilities.KeyIdToBytes(keyId));
            bcpgOut.WriteByte((byte)algorithm);
            bcpgOut.Write(sessionKey);
        }
    }
}
