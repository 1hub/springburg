namespace Springburg.Cryptography.OpenPgp
{
    /// <summary>Basic tags for compression algorithms.</summary>
    public enum PgpCompressionAlgorithm : byte
    {
        Uncompressed = 0, // Uncompressed
        Zip = 1, // RFC 1951
        ZLib = 2, // RFC 1950
        BZip2 = 3,
    }
}
