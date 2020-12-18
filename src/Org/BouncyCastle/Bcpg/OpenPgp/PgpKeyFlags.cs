using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Key flag values for the KeyFlags subpacket.</summary>
    [Flags]
    public enum PgpKeyFlags
    {
        CanCertify = 0x01, // This key may be used to certify other keys.
        CanSign = 0x02, // This key may be used to sign data.
        CanEncryptCommunications = 0x04, // This key may be used to encrypt communications.
        CanEncryptStorage = 0x08, // This key may be used to encrypt storage.
        MaybeSplit = 0x10, // The private component of this key may have been split by a secret-sharing mechanism.
        CanAuthenticate = 0x20, // This key may be used for authentication.
        MaybeShared = 0x80, // The private component of this key may be in the possession of more than one person.
        CanUseAsADSK = 0x400, // This key may be used as an additional decryption subkey (ADSK).
        CanTimestamp = 0x800, // This key may be used for timestamping.
    }
}
