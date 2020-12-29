namespace Springburg.Cryptography.OpenPgp
{
    public enum PgpSignatureType : byte
    {
        BinaryDocument = 0x00,
        CanonicalTextDocument = 0x01,
        StandAlone = 0x02,

        DefaultCertification = 0x10,
        NoCertification = 0x11,
        CasualCertification = 0x12,
        PositiveCertification = 0x13,

        SubkeyBinding = 0x18,
        PrimaryKeyBinding = 0x19,
        DirectKey = 0x1f,
        KeyRevocation = 0x20,
        SubkeyRevocation = 0x28,
        CertificationRevocation = 0x30,
        Timestamp = 0x40,
    }
}
