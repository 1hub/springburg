using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
    public class SignatureExpirationTime : SignatureSubpacket
    {
        public SignatureExpirationTime(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.ExpireTime, critical, isLongLength, data)
        {
        }

        public SignatureExpirationTime(bool critical, long time)
            : base(SignatureSubpacketTag.ExpireTime, critical, false, SecondsToBytes(time))
        {
        }

        public long Time => BytesToSeconds(data);
    }
}
