using System;

namespace InflatablePalace.Cryptography.OpenPgp.Packet.Sig
{
    class SignatureCreationTime : SignatureSubpacket
    {
        public SignatureCreationTime(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.CreationTime, critical, isLongLength, data)
        {
        }

        public SignatureCreationTime(bool critical, DateTime date)
            : base(SignatureSubpacketTag.CreationTime, critical, false, TimeToBytes(date))
        {
        }

        public DateTime Time => BytesToTime(data);
    }
}
