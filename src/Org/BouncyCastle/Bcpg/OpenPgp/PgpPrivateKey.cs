using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>General class to contain a private key for use with other OpenPGP objects.</summary>
    public class PgpPrivateKey
    {
        private readonly long keyId;
        private readonly PublicKeyPacket publicKeyPacket;
        private readonly AsymmetricAlgorithm privateKey;

        /// <summary>
        /// Create a PgpPrivateKey from a keyID, the associated public data packet, and a regular private key.
        /// </summary>
        /// <param name="keyId">ID of the corresponding public key.</param>
        /// <param name="publicKeyPacket">the public key data packet to be associated with this private key.</param>
        /// <param name="privateKey">the private key data packet to be associated with this private key.</param>
        public PgpPrivateKey(
            long keyId,
            PublicKeyPacket publicKeyPacket,
            AsymmetricAlgorithm privateKey)
        {
            //if (!privateKey.IsPrivate)
            //    throw new ArgumentException("Expected a private key", "privateKey");

            this.keyId = keyId;
            this.publicKeyPacket = publicKeyPacket;
            this.privateKey = privateKey;
        }

        /// <summary>The keyId associated with the contained private key.</summary>
        public long KeyId => keyId;

        /// <summary>The public key packet associated with this private key, if available.</summary>
        public PublicKeyPacket PublicKeyPacket => publicKeyPacket;

        /// <summary>The contained private key.</summary>
        internal AsymmetricAlgorithm Key => privateKey;
    }
}
