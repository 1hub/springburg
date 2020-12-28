using System;
using System.IO;
using System.Security.Cryptography;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    class PublicKeyPacket : ContainedPacket
    {
        private int version;
        private long time;
        private int validDays;
        private PgpPublicKeyAlgorithm algorithm;
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

            algorithm = (PgpPublicKeyAlgorithm)bcpgIn.ReadByte();

            switch (algorithm)
            {
                case PgpPublicKeyAlgorithm.RsaEncrypt:
                case PgpPublicKeyAlgorithm.RsaGeneral:
                case PgpPublicKeyAlgorithm.RsaSign:
                    key = new RsaPublicBcpgKey(bcpgIn);
                    break;
                case PgpPublicKeyAlgorithm.Dsa:
                    key = new DsaPublicBcpgKey(bcpgIn);
                    break;
                case PgpPublicKeyAlgorithm.ElGamalEncrypt:
                case PgpPublicKeyAlgorithm.ElGamalGeneral:
                    key = new ElGamalPublicBcpgKey(bcpgIn);
                    break;
                case PgpPublicKeyAlgorithm.ECDH:
                    key = new ECDHPublicBcpgKey(bcpgIn);
                    break;
                case PgpPublicKeyAlgorithm.ECDsa:
                case PgpPublicKeyAlgorithm.EdDsa:
                    key = new ECDsaPublicBcpgKey(bcpgIn);
                    break;
                default:
                    throw new IOException("unknown PGP public key algorithm encountered");
            }
        }

        /// <summary>Construct a version 4 public key packet.</summary>
        public PublicKeyPacket(
            PgpPublicKeyAlgorithm algorithm,
            DateTime time,
            BcpgKey key)
        {
            this.version = 4;
            this.time = new DateTimeOffset(time, TimeSpan.Zero).ToUnixTimeSeconds();
            this.algorithm = algorithm;
            this.key = key;
        }

        public int Version => version;

        public PgpPublicKeyAlgorithm Algorithm => algorithm;

        public int ValidDays => validDays;

        public virtual DateTime GetTime() => DateTimeOffset.FromUnixTimeSeconds(time).DateTime;

        public virtual BcpgKey Key => key;

        public byte[] GetEncodedContents()
        {
            using MemoryStream bOut = new MemoryStream();
            Encode(bOut);
            return bOut.ToArray();
        }

        public byte[] CalculateFingerprint()
        {
            BcpgKey key = Key;
            HashAlgorithm digest;

            if (Version <= 3)
            {
                RsaPublicBcpgKey rK = (RsaPublicBcpgKey)key;
                digest = MD5.Create();
                digest.TransformBlock(rK.Modulus.Value, 0, rK.Modulus.Value.Length, null, 0);
                digest.TransformBlock(rK.PublicExponent.Value, 0, rK.PublicExponent.Value.Length, null, 0);
            }
            else
            {
                try
                {
                    byte[] kBytes = GetEncodedContents();
                    digest = SHA1.Create();
                    digest.TransformBlock(new byte[] { 0x99, (byte)(kBytes.Length >> 8), (byte)kBytes.Length }, 0, 3, null, 0);
                    digest.TransformBlock(kBytes, 0, kBytes.Length, null, 0);
                }
                catch (Exception e)
                {
                    throw new PgpException("can't encode key components: " + e.Message, e);
                }
            }

            digest.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

            return digest.Hash!;
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
