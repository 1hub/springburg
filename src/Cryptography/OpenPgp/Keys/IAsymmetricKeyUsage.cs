namespace Springburg.Cryptography.OpenPgp.Keys
{
    public interface IAsymmetricKeyUsage
    {
        PgpPublicKeyAlgorithm Algorithm { get; }
        bool CanSign { get; }
        bool CanEncrypt { get; }
    }
}
