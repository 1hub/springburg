using System;

namespace InflatablePalace.Cryptography.OpenPgp
{
    [Flags]
    public enum PgpFeatureFlags : byte
    {
        ModificationDetection = 1,
        AeadEncryptedData = 2,
        Version5PublicKey = 4
    }
}
