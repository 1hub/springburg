using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class PublicKeyPacket : ContainedPacket
    {
        private int version;
        private long time;
        private int validDays;
        private PublicKeyAlgorithmTag algorithm;
        private BcpgKey key;

        internal PublicKeyPacket(Stream bcpgIn)
        {
            version = bcpgIn.ReadByte();

            time = ((uint)bcpgIn.ReadByte() << 24) | ((uint)bcpgIn.ReadByte() << 16)
                | ((uint)bcpgIn.ReadByte() << 8) | (uint)bcpgIn.ReadByte();

            if (version <= 3)
            {
                validDays = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
            }

            algorithm = (PublicKeyAlgorithmTag)bcpgIn.ReadByte();

            switch (algorithm)
            {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.RsaSign:
                    key = new RsaPublicBcpgKey(bcpgIn);
                    break;
                case PublicKeyAlgorithmTag.Dsa:
                    key = new DsaPublicBcpgKey(bcpgIn);
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    key = new ElGamalPublicBcpgKey(bcpgIn);
                    break;
                case PublicKeyAlgorithmTag.ECDH:
                    key = new ECDHPublicBcpgKey(bcpgIn);
                    break;
                case PublicKeyAlgorithmTag.ECDsa:
                case PublicKeyAlgorithmTag.EdDsa:
                    key = new ECDsaPublicBcpgKey(bcpgIn);
                    break;
                default:
                    throw new IOException("unknown PGP public key algorithm encountered");
            }
        }

        /// <summary>Construct a version 4 public key packet.</summary>
        public PublicKeyPacket(
            PublicKeyAlgorithmTag algorithm,
            DateTime time,
            BcpgKey key)
        {
            this.version = 4;
            this.time = new DateTimeOffset(time, TimeSpan.Zero).ToUnixTimeSeconds();
            this.algorithm = algorithm;
            this.key = key;
        }

        public int Version => version;

        public PublicKeyAlgorithmTag Algorithm => algorithm;

        public int ValidDays => validDays;

        public virtual DateTime GetTime() => DateTimeOffset.FromUnixTimeSeconds(time).DateTime;

        public virtual BcpgKey Key => key;

        public byte[] GetEncodedContents()
        {
            using MemoryStream bOut = new MemoryStream();
            Encode(bOut);
            return bOut.ToArray();
        }

        public override PacketTag Tag => PacketTag.PublicKey;

        public override void Encode(Stream bcpgOut)
        {
            bcpgOut.WriteByte((byte)version);
            bcpgOut.Write(new byte[] { (byte)(time >> 24), (byte)(time >> 16), (byte)(time >> 8), (byte)time });

            if (version <= 3)
            {
                bcpgOut.WriteByte((byte)(validDays >> 8));
                bcpgOut.WriteByte((byte)validDays);
            }

            bcpgOut.WriteByte((byte)algorithm);
            key.Encode(bcpgOut);
        }
    }
}
