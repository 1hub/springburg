using System;

namespace Springburg.Cryptography.OpenPgp.Packet.Signature
{
    class SignatureExpirationTime : SignatureSubpacket
    {
        public SignatureExpirationTime(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.SignatureExpirationTime, critical, isLongLength, data)
        {
        }

        public SignatureExpirationTime(bool critical, TimeSpan time)
            : base(SignatureSubpacketTag.SignatureExpirationTime, critical, false, SecondsToBytes((long)time.TotalSeconds))
        {
        }

        public TimeSpan Time => TimeSpan.FromSeconds(BytesToSeconds(data));
    }
}
