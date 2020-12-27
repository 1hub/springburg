namespace InflatablePalace.Cryptography.OpenPgp.Packet.Signature
{
    class Features : SignatureSubpacket
    {
        public Features(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.Features, critical, isLongLength, data)
        {
        }

        public Features(bool critical, PgpFeatureFlags features)
            : base(SignatureSubpacketTag.Features, critical, false, new byte[] { (byte)features })
        {
        }

        public PgpFeatureFlags Flags => (PgpFeatureFlags)data[0];
    }
}
