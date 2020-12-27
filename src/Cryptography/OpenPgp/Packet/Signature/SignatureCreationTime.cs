using System;

namespace InflatablePalace.Cryptography.OpenPgp.Packet.Signature
{
    class SignatureCreationTime : SignatureSubpacket
    {
        public SignatureCreationTime(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.SignatureCreationTime, critical, isLongLength, data)
        {
        }

        public SignatureCreationTime(bool critical, DateTime date)
            : base(SignatureSubpacketTag.SignatureCreationTime, critical, false, TimeToBytes(date))
        {
        }

        public DateTime Time => BytesToTime(data);
    }
}
