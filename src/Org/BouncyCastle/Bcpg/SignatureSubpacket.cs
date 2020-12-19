using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic type for a PGP Signature sub-packet.</summary>
    public class SignatureSubpacket
    {
        private readonly SignatureSubpacketTag type;
        private readonly bool critical;
        private readonly bool isLongLength;
        internal byte[] data;

        protected internal SignatureSubpacket(
            SignatureSubpacketTag type,
            bool critical,
            bool isLongLength,
            byte[] data)
        {
            this.type = type;
            this.critical = critical;
            this.isLongLength = isLongLength;
            this.data = data;
        }

        public SignatureSubpacketTag SubpacketType
        {
            get { return type; }
        }

        public bool IsCritical()
        {
            return critical;
        }

        public bool IsLongLength()
        {
            return isLongLength;
        }

        /// <summary>Return the generic data making up the packet.</summary>
        public byte[] GetData()
        {
            return (byte[])data.Clone();
        }

        public void Encode(
            Stream os)
        {
            int bodyLen = data.Length + 1;

            if (isLongLength)
            {
                os.WriteByte(0xff);
                os.WriteByte((byte)(bodyLen >> 24));
                os.WriteByte((byte)(bodyLen >> 16));
                os.WriteByte((byte)(bodyLen >> 8));
                os.WriteByte((byte)bodyLen);
            }
            else
            {
                if (bodyLen < 192)
                {
                    os.WriteByte((byte)bodyLen);
                }
                else if (bodyLen <= 8383)
                {
                    bodyLen -= 192;

                    os.WriteByte((byte)(((bodyLen >> 8) & 0xff) + 192));
                    os.WriteByte((byte)bodyLen);
                }
                else
                {
                    os.WriteByte(0xff);
                    os.WriteByte((byte)(bodyLen >> 24));
                    os.WriteByte((byte)(bodyLen >> 16));
                    os.WriteByte((byte)(bodyLen >> 8));
                    os.WriteByte((byte)bodyLen);
                }
            }

            if (critical)
            {
                os.WriteByte((byte)(0x80 | (int)type));
            }
            else
            {
                os.WriteByte((byte)type);
            }

            os.Write(data, 0, data.Length);
        }

        protected static byte[] SecondsToBytes(long seconds)
        {
            byte[] data = new byte[4];
            data[0] = (byte)(seconds >> 24);
            data[1] = (byte)(seconds >> 16);
            data[2] = (byte)(seconds >> 8);
            data[3] = (byte)seconds;
            return data;
        }

        protected static long BytesToSeconds(byte[] data)
        {
            return ((uint)data[0] << 24) | ((uint)data[1] << 16) | ((uint)data[2] << 8) | data[3];
        }


        protected static byte[] TimeToBytes(DateTime time)
        {
            return SecondsToBytes(new DateTimeOffset(time, TimeSpan.Zero).ToUnixTimeSeconds());
        }

        protected static DateTime BytesToTime(byte[] data)
        {
            return DateTimeOffset.FromUnixTimeSeconds(BytesToSeconds(data)).UtcDateTime;
        }
    }
}
