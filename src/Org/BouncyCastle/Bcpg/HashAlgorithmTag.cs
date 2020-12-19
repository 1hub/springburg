namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic tags for hash algorithms.</summary>
    public enum HashAlgorithmTag : byte
    {
        MD5 = 1,
        Sha1 = 2,
        RipeMD160 = 3,
        DoubleSha = 4, // Reserved for double-width SHA (experimental)
        MD2 = 5,
        Tiger192 = 6, // Reserved for TIGER/192
        Haval5pass160 = 7, // Reserved for HAVAL (5 pass, 160-bit)

        Sha256 = 8, // SHA-256
        Sha384 = 9, // SHA-384
        Sha512 = 10, // SHA-512
        Sha224 = 11, // SHA-224
    }
}
