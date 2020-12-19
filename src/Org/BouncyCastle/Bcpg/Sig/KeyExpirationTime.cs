using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
    public class KeyExpirationTime : SignatureSubpacket
    {
        public KeyExpirationTime(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.KeyExpireTime, critical, isLongLength, data)
        {
        }

        public KeyExpirationTime(bool critical, TimeSpan time)
            : base(SignatureSubpacketTag.KeyExpireTime, critical, false, SecondsToBytes((long)time.TotalSeconds))
        {
        }

        public TimeSpan Time => TimeSpan.FromSeconds(BytesToSeconds(data));
    }
}
