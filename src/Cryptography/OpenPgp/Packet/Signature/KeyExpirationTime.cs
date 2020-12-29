using System;

namespace Springburg.Cryptography.OpenPgp.Packet.Signature
{
    class KeyExpirationTime : SignatureSubpacket
    {
        public KeyExpirationTime(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.KeyExpirationTime, critical, isLongLength, data)
        {
        }

        public KeyExpirationTime(bool critical, TimeSpan time)
            : base(SignatureSubpacketTag.KeyExpirationTime, critical, false, SecondsToBytes((long)time.TotalSeconds))
        {
        }

        public TimeSpan Time => TimeSpan.FromSeconds(BytesToSeconds(data));
    }
}
