using System;

namespace Org.BouncyCastle.Bcpg
{
    [Flags]
    public enum FeatureFlags : byte
    {
        ModificationDetection = 1,
        AeadEncryptedData = 2,
        Version5PublicKey = 4
    }
}
