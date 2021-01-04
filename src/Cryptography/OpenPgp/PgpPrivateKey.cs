using Springburg.Cryptography.Algorithms;
using Springburg.Cryptography.OpenPgp.Keys;
using System;

namespace Springburg.Cryptography.OpenPgp
{
    /// <summary>General class to contain a private key for use with other OpenPGP objects.</summary>
    public class PgpPrivateKey
    {
        private readonly long keyId;
        internal readonly IAsymmetricPrivateKey privateKey;

        public PgpPrivateKey(long keyId, IAsymmetricPrivateKey privateKey)
        {
            this.keyId = keyId;
            this.privateKey = privateKey;
        }

        /// <summary>The keyId associated with the contained private key.</summary>
        public long KeyId => keyId;

        public PgpPublicKeyAlgorithm Algorithm => this.privateKey.Algorithm;

        /// <summary>Return the decrypted session data for the packet.</summary>
        public bool TryDecryptSessionInfo(ReadOnlySpan<byte> encryptedSessionData, Span<byte> sessionData, out int bytesWritten)
        {
            return this.privateKey.TryDecryptSessionInfo(encryptedSessionData, sessionData, out bytesWritten);
        }

        public byte[] Sign(byte[] hash, PgpHashAlgorithm hashAlgorithm)
        {
            return this.privateKey.CreateSignature(hash, hashAlgorithm);
        }
    }
}
