namespace InflatablePalace.Cryptography.OpenPgp.Packet.Sig
{
    class Revocable : SignatureSubpacket
    {
        public Revocable(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.Revocable, critical, isLongLength, data)
        {
        }

        public Revocable(bool critical, bool isRevocable)
            : base(SignatureSubpacketTag.Revocable, critical, false, new byte[] { isRevocable ? 1 : 0 })
        {
        }

        public bool IsRevocable => data[0] > 0;
    }
}
