using Springburg.Cryptography.Algorithms;
using Springburg.Cryptography.OpenPgp.Keys;
using Springburg.Cryptography.OpenPgp.Packet;
using System;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp
{
    /// <summary>
    /// General class to handle .NET key pairs and convert them into OpenPGP ones.
    /// </summary>
    /// <remarks>
    /// A word for the unwary, the KeyId for an OpenPGP public key is calculated from
    /// a hash that includes the time of creation, if you pass a different date to the
    /// constructor below with the same public private key pair the KeyId will not be the
    /// same as for previous generations of the key, so ideally you only want to do
    /// this once.
    /// </remarks>
    public class PgpKeyPair
    {
        public PgpKeyPair(
            AsymmetricAlgorithm asymmetricAlgorithm,
            DateTime creationTime,
            bool isMasterKey = true)
        {
            IAsymmetricPrivateKey privateKey;
            IAsymmetricPublicKey publicKey;
            byte[]? ecdhFingerprint = null;

            if (asymmetricAlgorithm is RSA rsa)
                privateKey = new RsaKey(rsa);
            else if (asymmetricAlgorithm is DSA dsa)
                privateKey = new DsaKey(dsa);
            else if (asymmetricAlgorithm is ElGamal elGamal)
                privateKey = new ElGamalKey(elGamal);
            else if (asymmetricAlgorithm is ECDiffieHellman ecdh)
                privateKey = new ECDiffieHellmanKey(ecdh, new byte[] { 0, (byte)PgpHashAlgorithm.Sha256, (byte)PgpSymmetricKeyAlgorithm.Aes128 }, ecdhFingerprint = new byte[20]);
            else if (asymmetricAlgorithm is Ed25519 eddsa)
                privateKey = new EdDsaKey(eddsa);
            else if (asymmetricAlgorithm is ECDsa ecdsa)
                privateKey = new ECDsaKey(ecdsa);
            else
                throw new NotSupportedException();
            publicKey = (IAsymmetricPublicKey)privateKey;

            var keyBytes = publicKey.ExportPublicKey();
            var keyPacket = isMasterKey ?
                new PublicKeyPacket(publicKey.Algorithm, creationTime, keyBytes) :
                new PublicSubkeyPacket(publicKey.Algorithm, creationTime, keyBytes);

            this.PublicKey = new PgpPublicKey(keyPacket) { key = publicKey };

            if (ecdhFingerprint != null)
                this.PublicKey.Fingerprint.Slice(0, 20).CopyTo(ecdhFingerprint);

            this.PrivateKey = new PgpPrivateKey(this.PublicKey.KeyId, privateKey);
        }

        /// <summary>The keyId associated with this key pair.</summary>
        public long KeyId => PublicKey.KeyId;

        public PgpPublicKey PublicKey { get; private set; }

        public PgpPrivateKey PrivateKey { get; private set; }
    }
}
