using Springburg.IO;
using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    abstract class KeyPacket : ContainedPacket
    {
        private int version;
        private long time;
        private int validDays;
        private PgpPublicKeyAlgorithm algorithm;
        private int publicKeyLength;
        private byte[] keyBytes;

        internal KeyPacket(Stream bcpgIn)
        {
            this.version = bcpgIn.ReadByte();
            this.time = ((uint)bcpgIn.ReadByte() << 24) | ((uint)bcpgIn.ReadByte() << 16) | ((uint)bcpgIn.ReadByte() << 8) | (uint)bcpgIn.ReadByte();

            if (version <= 3)
            {
                this.validDays = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
            }

            this.algorithm = (PgpPublicKeyAlgorithm)bcpgIn.ReadByte();
            this.keyBytes = bcpgIn.ReadAll();

            UpdatePublicKeyLength();
        }

        /// <summary>Construct a version 4 public key packet.</summary>
        public KeyPacket(
            PgpPublicKeyAlgorithm algorithm,
            DateTime time,
            byte[] keyBytes)
        {
            this.version = 4;
            this.time = new DateTimeOffset(time, TimeSpan.Zero).ToUnixTimeSeconds();
            this.algorithm = algorithm;
            this.keyBytes = keyBytes;
            UpdatePublicKeyLength();
        }

        public KeyPacket(KeyPacket keyPacket)
        {
            this.version = keyPacket.Version;
            this.time = keyPacket.time;
            this.algorithm = keyPacket.Algorithm;
            this.keyBytes = keyPacket.keyBytes.AsSpan(0, keyPacket.PublicKeyLength).ToArray();
            this.publicKeyLength = keyPacket.publicKeyLength;
        }

        public int Version => version;

        public PgpPublicKeyAlgorithm Algorithm => algorithm;

        public int ValidDays => validDays;

        public DateTime CreationTime => DateTimeOffset.FromUnixTimeSeconds(time).DateTime;

        public byte[] KeyBytes => keyBytes;

        public int PublicKeyLength => publicKeyLength;

        private void UpdatePublicKeyLength()
        {
            // Version 4
            publicKeyLength = 0;
            switch (this.algorithm)
            {
                case PgpPublicKeyAlgorithm.RsaGeneral:
                case PgpPublicKeyAlgorithm.RsaEncrypt:
                case PgpPublicKeyAlgorithm.RsaSign:
                    publicKeyLength = GetMPIntegerLength(this.keyBytes, 2);
                    break;
                case PgpPublicKeyAlgorithm.Dsa:
                    publicKeyLength = GetMPIntegerLength(this.keyBytes, 4);
                    break;
                case PgpPublicKeyAlgorithm.ElGamalGeneral:
                case PgpPublicKeyAlgorithm.ElGamalEncrypt:
                    publicKeyLength = GetMPIntegerLength(this.keyBytes, 3);
                    break;
                case PgpPublicKeyAlgorithm.EdDsa:
                case PgpPublicKeyAlgorithm.ECDsa:
                    int oidLength = this.keyBytes[0];
                    publicKeyLength = oidLength + 1 + GetMPIntegerLength(this.keyBytes.AsSpan(oidLength + 1), 1);
                    break;
                case PgpPublicKeyAlgorithm.ECDH:
                    oidLength = this.keyBytes[0];
                    publicKeyLength = oidLength + 1 + GetMPIntegerLength(this.keyBytes.AsSpan(oidLength + 1), 1);
                    publicKeyLength += this.keyBytes[publicKeyLength] + 1; // KDF
                    break;
                default:
                    throw new NotImplementedException();
            }
        }

        private int GetMPIntegerLength(ReadOnlySpan<byte> input, int mpIntegerCount)
        {
            int totalBytesRead = 0;
            while (mpIntegerCount > 0)
            {
                Keys.MPInteger.ReadInteger(input.Slice(totalBytesRead), out int bytesRead);
                totalBytesRead += bytesRead;
                mpIntegerCount--;
            }
            return totalBytesRead;
        }

        public byte[] GetEncodedContents()
        {
            using MemoryStream bOut = new MemoryStream();
            Encode(bOut);
            return bOut.GetBuffer().AsSpan(0, (int)bOut.Length - this.keyBytes.Length + publicKeyLength).ToArray();
        }

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
            bcpgOut.Write(keyBytes);
        }
    }
}
