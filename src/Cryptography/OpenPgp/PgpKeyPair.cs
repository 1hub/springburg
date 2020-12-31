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
            AsymmetricAlgorithm keyPair,
            DateTime time)
        {
            this.PublicKey = new PgpPublicKey(keyPair, time, isMasterKey: true);
            this.PrivateKey = new PgpPrivateKey(this.PublicKey.KeyId, keyPair, PublicKey.Fingerprint);
        }

        /// <summary>Create a key pair from a PgpPrivateKey and a PgpPublicKey.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="privateKey">The private key.</param>
        public PgpKeyPair(PgpPublicKey publicKey, PgpPrivateKey privateKey)
        {
            this.PublicKey = publicKey;
            this.PrivateKey = privateKey;
        }

        /// <summary>The keyId associated with this key pair.</summary>
        public long KeyId => PublicKey.KeyId;

        public PgpPublicKey PublicKey { get; private set; }

        public PgpPrivateKey PrivateKey { get; private set; }
    }
}
