using System;

namespace Springburg.Cryptography.OpenPgp.Keys
{
    public interface IAsymmetricPrivateKey : IAsymmetricKeyUsage
    {
       byte[] ExportPrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            S2kParameters s2kParameters);

        byte[] CreateSignature(ReadOnlySpan<byte> rgbHash, PgpHashAlgorithm hashAlgorithm);

        bool TryDecryptSessionInfo(ReadOnlySpan<byte> encryptedSessionData, Span<byte> sessionData, out int bytesWritten);
    }
}
