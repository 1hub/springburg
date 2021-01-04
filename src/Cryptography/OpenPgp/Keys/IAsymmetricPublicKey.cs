using System;

namespace Springburg.Cryptography.OpenPgp.Keys
{
    public interface IAsymmetricPublicKey : IAsymmetricKeyUsage
    {
        byte[] ExportPublicKey();

        bool VerifySignature(
            ReadOnlySpan<byte> rgbHash,
            ReadOnlySpan<byte> rgbSignature,
            PgpHashAlgorithm hashAlgorithm);

        byte[] EncryptSessionInfo(ReadOnlySpan<byte> sessionInfo);
    }
}
