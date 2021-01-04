using Springburg.Cryptography.OpenPgp.Packet;


namespace Springburg.Cryptography.OpenPgp.Keys
{
    class S2kParameters
    {
        public S2kUsageTag UsageTag { get; set; } = S2kUsageTag.Sha1;
        public PgpSymmetricKeyAlgorithm EncryptionAlgorithm { get; set; } = PgpSymmetricKeyAlgorithm.Aes128;
        public PgpHashAlgorithm HashAlgorithm { get; set; } = PgpHashAlgorithm.Sha256;
        // Salt, iteration count, AEAD
    }
}
