using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic packet for a PGP public key.</summary>
    public class PublicKeyEncSessionPacket : ContainedPacket
    {
        private int version;
        private long keyId;
        private PublicKeyAlgorithmTag algorithm;
        private byte[] sessionKey;

        internal PublicKeyEncSessionPacket(
            BcpgInputStream bcpgIn)
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
                    sessionKey = Streams.ReadAll(bcpgIn);
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

        public override void Encode(
            BcpgOutputStream bcpgOut)
        {
            using MemoryStream bOut = new MemoryStream();
            using BcpgOutputStream pOut = new BcpgOutputStream(bOut);

            pOut.WriteByte((byte)version);

            pOut.WriteLong(keyId);

            pOut.WriteByte((byte)algorithm);

            switch (algorithm)
            {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    new MPInteger(sessionKey).Encode(pOut);
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    int halfLength = sessionKey.Length / 2;
                    new MPInteger(sessionKey.AsSpan(0, halfLength)).Encode(pOut);
                    new MPInteger(sessionKey.AsSpan(halfLength)).Encode(pOut);
                    break;
                case PublicKeyAlgorithmTag.ECDH:
                    pOut.Write(sessionKey);
                    break;
                default:
                    throw new IOException("unknown PGP public key algorithm encountered");
            }

            bcpgOut.WritePacket(PacketTag.PublicKeyEncryptedSession, bOut.ToArray(), true);
        }
    }
}
