using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * packet giving signature creation time.
    */
    public class SignatureCreationTime
        : SignatureSubpacket
    {
        protected static byte[] TimeToBytes(
            DateTime time)
        {
            long t = new DateTimeOffset(time, TimeSpan.Zero).ToUnixTimeSeconds();
            byte[] data = new byte[4];
            data[0] = (byte)(t >> 24);
            data[1] = (byte)(t >> 16);
            data[2] = (byte)(t >> 8);
            data[3] = (byte)t;
            return data;
        }

        public SignatureCreationTime(
            bool critical,
            bool isLongLength,
            byte[] data)
            : base(SignatureSubpacketTag.CreationTime, critical, isLongLength, data)
        {
        }

        public SignatureCreationTime(
            bool critical,
            DateTime date)
            : base(SignatureSubpacketTag.CreationTime, critical, false, TimeToBytes(date))
        {
        }

        public DateTime GetTime()
        {
            long time = (long)(
                    ((uint)data[0] << 24)
                | ((uint)data[1] << 16)
                | ((uint)data[2] << 8)
                | ((uint)data[3])
                );
            return DateTimeOffset.FromUnixTimeSeconds(time).DateTime;
        }
    }
}
