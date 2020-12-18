namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    interface IPgpKey
    {
        long KeyId { get; }
        bool IsMasterKey { get; }
    }
}
