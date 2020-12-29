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

            switch (algorithm)
            {
                case PgpPublicKeyAlgorithm.RsaEncrypt:
                case PgpPublicKeyAlgorithm.RsaGeneral:
                    sessionKey = new MPInteger(bcpgIn).Value;
                    break;
                case PgpPublicKeyAlgorithm.ElGamalEncrypt:
                case PgpPublicKeyAlgorithm.ElGamalGeneral:
                    MPInteger p = new MPInteger(bcpgIn);
                    MPInteger g = new MPInteger(bcpgIn);
                    int halfLength = Math.Max(p.Value.Length, g.Value.Length);
                    sessionKey = new byte[halfLength * 2];
                    p.Value.CopyTo(sessionKey.AsSpan(halfLength - p.Value.Length));
                    g.Value.CopyTo(sessionKey.AsSpan(sessionKey.Length - g.Value.Length));
                    break;
                case PgpPublicKeyAlgorithm.ECDH:
                    sessionKey = bcpgIn.ReadAll();
                    break;
                default:
                    throw new IOException("unknown PGP public key algorithm encountered");
            }
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

            switch (algorithm)
            {
                case PgpPublicKeyAlgorithm.RsaEncrypt:
                case PgpPublicKeyAlgorithm.RsaGeneral:
                    new MPInteger(sessionKey).Encode(bcpgOut);
                    break;
                case PgpPublicKeyAlgorithm.ElGamalEncrypt:
                case PgpPublicKeyAlgorithm.ElGamalGeneral:
                    int halfLength = sessionKey.Length / 2;
                    new MPInteger(sessionKey.AsSpan(0, halfLength)).Encode(bcpgOut);
                    new MPInteger(sessionKey.AsSpan(halfLength)).Encode(bcpgOut);
                    break;
                case PgpPublicKeyAlgorithm.ECDH:
                    bcpgOut.Write(sessionKey);
                    break;
                default:
                    throw new IOException("unknown PGP public key algorithm encountered");
            }
        }
    }
}
