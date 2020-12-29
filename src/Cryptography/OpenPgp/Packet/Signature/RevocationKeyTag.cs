namespace Springburg.Cryptography.OpenPgp.Packet.Signature
{
    enum RevocationKeyTag : byte
    {
        ClassDefault = 0x80,
        ClassSensitive = 0x40
    }
}
