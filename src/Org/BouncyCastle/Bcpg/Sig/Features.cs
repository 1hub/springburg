namespace Org.BouncyCastle.Bcpg.Sig
{
    public class Features : SignatureSubpacket
    {
        public Features(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.Features, critical, isLongLength, data)
        {
        }

        public Features(bool critical, FeatureFlags features)
            : base(SignatureSubpacketTag.Features, critical, false, new byte[] { (byte)features })
        {
        }

        public FeatureFlags Flags => (FeatureFlags)data[0];
    }
}
