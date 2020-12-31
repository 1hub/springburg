using Springburg.Cryptography.Algorithms;
using Springburg.Cryptography.OpenPgp.Packet;
using Internal.Cryptography;
using System;
using System.Security.Cryptography;
using Springburg.Cryptography.OpenPgp.Keys;

namespace Springburg.Cryptography.OpenPgp
{
    /// <summary>General class to contain a private key for use with other OpenPGP objects.</summary>
    public class PgpPrivateKey
    {
        private readonly long keyId;
        internal readonly IAsymmetricPrivateKey privateKey;

        /// <summary>
        /// Create a PgpPrivateKey from a keyID, the associated public data packet, and a regular private key.
        /// </summary>
        /// <param name="keyId">ID of the corresponding public key.</param>
        /// <param name="publicKeyPacket">the public key data packet to be associated with this private key.</param>
        /// <param name="privateKey">the private key data packet to be associated with this private key.</param>
        internal PgpPrivateKey(
            long keyId,
            AsymmetricAlgorithm privateKey,
            ReadOnlySpan<byte> fingerprint)
        {
            //if (!privateKey.IsPrivate)
            //    throw new ArgumentException("Expected a private key", "privateKey");

            this.keyId = keyId;
            //this.privateKey = privateKey;

            if (privateKey is RSA rsa)
                this.privateKey = new RsaKey(rsa);
            else if (privateKey is DSA dsa)
                this.privateKey = new DsaKey(dsa);
            else if (privateKey is ElGamal elGamal)
                this.privateKey = new ElGamalKey(elGamal);
            // FIXME: KDF from public key packet, fingerprint
            else if (privateKey is ECDiffieHellman ecdh)
                this.privateKey = new ECDiffieHellmanKey(ecdh, new byte[] { 0, (byte)PgpHashAlgorithm.Sha256, (byte)PgpSymmetricKeyAlgorithm.Aes128 }, fingerprint.ToArray());
            else if (privateKey is ECDsa ecdsa)
                this.privateKey = new ECDsaKey(ecdsa);
            else
                throw new NotSupportedException();
        }

        internal PgpPrivateKey(
            long keyId,
            IAsymmetricPrivateKey privateKey)
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
