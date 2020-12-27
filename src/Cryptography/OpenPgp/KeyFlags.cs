using System;

namespace InflatablePalace.Cryptography.OpenPgp
{
    /// <summary>Key flag values for the KeyFlags subpacket.</summary>
    [Flags]
    public enum KeyFlags
    {
        CertifyOther = 0x01, // This key may be used to certify other keys.
        SignData = 0x02, // This key may be used to sign data.
        EncryptCommunications = 0x04, // This key may be used to encrypt communications.
        EncryptStorage = 0x08, // This key may be used to encrypt storage.
        Split = 0x10, // The private component of this key may have been split by a secret-sharing mechanism.
        Authentication = 0x20, // This key may be used for authentication.
        Shared = 0x80, // The private component of this key may be in the possession of more than one person.
        UseAsADSK = 0x400, // This key may be used as an additional decryption subkey (ADSK).
        Timestamp = 0x800, // This key may be used for timestamping.
    }
}
