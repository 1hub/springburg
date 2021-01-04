namespace Springburg.Cryptography.OpenPgp.Keys
{
    interface IAsymmetricKeyUsage
    {
        PgpPublicKeyAlgorithm Algorithm { get; }
        bool CanSign { get; }
        bool CanEncrypt { get; }
    }
}
