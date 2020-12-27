using InflatablePalace.IO;
using System;
using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    /// <summary>Basic packet for a PGP public key.</summary>
    class PublicKeyEncSessionPacket : ContainedPacket
    {
        private int version;
        private long keyId;
        private PublicKeyAlgorithmTag algorithm;
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

            algorithm = (PublicKeyAlgorithmTag)bcpgIn.ReadByte();

            switch (algorithm)
            {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    sessionKey = new MPInteger(bcpgIn).Value;
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    MPInteger p = new MPInteger(bcpgIn);
                    MPInteger g = new MPInteger(bcpgIn);
                    int halfLength = Math.Max(p.Value.Length, g.Value.Length);
                    sessionKey = new byte[halfLength * 2];
                    p.Value.CopyTo(sessionKey.AsSpan(halfLength - p.Value.Length));
                    g.Value.CopyTo(sessionKey.AsSpan(sessionKey.Length - g.Value.Length));
                    break;
                case PublicKeyAlgorithmTag.ECDH:
                    sessionKey = bcpgIn.ReadAll();
                    break;
                default:
                    throw new IOException("unknown PGP public key algorithm encountered");
            }
        }

        public PublicKeyEncSessionPacket(
            long keyId,
            PublicKeyAlgorithmTag algorithm,
            ReadOnlySpan<byte> sessionKey)
        {
            this.version = 3;
            this.keyId = keyId;
            this.algorithm = algorithm;
            this.sessionKey = sessionKey.ToArray();
        }

        public int Version => version;

        public long KeyId => keyId;

        public PublicKeyAlgorithmTag Algorithm => algorithm;

        public byte[] SessionKey => sessionKey;

        public override PacketTag Tag => PacketTag.PublicKeyEncryptedSession;

        public override void Encode(Stream bcpgOut)
        {
            bcpgOut.WriteByte((byte)version);
            bcpgOut.Write(PgpUtilities.KeyIdToBytes(keyId));
            bcpgOut.WriteByte((byte)algorithm);

            switch (algorithm)
            {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    new MPInteger(sessionKey).Encode(bcpgOut);
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    int halfLength = sessionKey.Length / 2;
                    new MPInteger(sessionKey.AsSpan(0, halfLength)).Encode(bcpgOut);
                    new MPInteger(sessionKey.AsSpan(halfLength)).Encode(bcpgOut);
                    break;
                case PublicKeyAlgorithmTag.ECDH:
                    bcpgOut.Write(sessionKey);
                    break;
                default:
                    throw new IOException("unknown PGP public key algorithm encountered");
            }
        }
    }
}
