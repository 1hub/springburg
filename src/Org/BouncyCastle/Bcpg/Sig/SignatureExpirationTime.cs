using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
    public class SignatureExpirationTime : SignatureSubpacket
    {
        public SignatureExpirationTime(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.ExpireTime, critical, isLongLength, data)
        {
        }

        public SignatureExpirationTime(bool critical, TimeSpan time)
            : base(SignatureSubpacketTag.ExpireTime, critical, false, SecondsToBytes((long)time.TotalSeconds))
        {
        }

        public TimeSpan Time => TimeSpan.FromSeconds(BytesToSeconds(data));
    }
}
