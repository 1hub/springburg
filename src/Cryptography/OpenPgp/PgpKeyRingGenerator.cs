using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Springburg.Cryptography.OpenPgp
{
    /// <summary>
    /// Generator for a PGP master and subkey ring.
    /// This class will generate both the secret and public key rings
    /// </summary>
    public class PgpKeyRingGenerator
    {
        private IList<PgpSecretKey> keys = new List<PgpSecretKey>();
        //private int certificationLevel;
        private byte[] rawPassPhrase;
        private PgpKeyPair masterKey;

        /// <summary>
        /// Create a new key ring generator.
        /// </summary>
        /// <param name="masterKey">The master key pair.</param>
        /// <param name="id">User id associated with the keys in the ring.</param>
        /// <param name="creationTime">The creation time for the master key pair.</param>
        /// <param name="passPhrase">The passPhrase to be used to protect secret keys.</param>
        /// <param name="useSha1">Checksum the secret keys with SHA1 rather than the older 16 bit checksum.</param>
        /// <param name="certificationLevel">The certification level for keys on this ring.</param>
        /// <param name="encAlgorithm">The algorithm to be used to protect secret keys.</param>
        /// <param name="hashAlgorithm">The hash algorithm for key signatures and certifications.</param>
        /// <param name="hashedAttributes">Packets to be included in the certification hash.</param>
        /// <param name="unhashedAttributes">Packets to be attached unhashed to the certification.</param>
        public PgpKeyRingGenerator(
            AsymmetricAlgorithm masterKey,
            string id,
            string passPhrase,
            DateTime creationTime = default(DateTime),
            PgpSignatureType certificationLevel = PgpSignatureType.DefaultCertification,
            PgpSignatureAttributes? hashedAttributes = null,
            PgpSignatureAttributes? unhashedAttributes = null)
            : this(masterKey, id, Encoding.UTF8.GetBytes(passPhrase), creationTime, certificationLevel, hashedAttributes, unhashedAttributes)
        {
        }

        /// <summary>
        /// Create a new key ring generator.
        /// </summary>
        /// <param name="asymmetricAlgorithm">The master key pair.</param>
        /// <param name="id">User id associated with the keys in the ring.</param>
        /// <param name="creationTime">The creation time for the master key pair.</param>
        /// <param name="rawPassPhrase">The passPhrase to be used to protect secret keys.</param>
        /// <param name="certificationLevel">The certification level for keys on this ring.</param>
        /// <param name="hashedAttributes">Packets to be included in the certification hash.</param>
        /// <param name="unhashedAttributes">Packets to be attached unhashed to the certification.</param>
        public PgpKeyRingGenerator(
            AsymmetricAlgorithm asymmetricAlgorithm,
            string id,
            byte[]? rawPassPhrase = null,
            DateTime creationTime = default(DateTime),
            PgpSignatureType certificationLevel = PgpSignatureType.DefaultCertification,
            PgpSignatureAttributes? hashedAttributes = null,
            PgpSignatureAttributes? unhashedAttributes = null)
        {
            this.masterKey = new PgpKeyPair(
                asymmetricAlgorithm,
                creationTime == default(DateTime) ? DateTime.UtcNow : creationTime);

            this.rawPassPhrase = rawPassPhrase ?? Array.Empty<byte>();

            // Certify the ID/public key
            var selfCertification = PgpCertification.GenerateUserCertification(
                certificationLevel,
                this.masterKey,
                id,
                this.masterKey.PublicKey,
                hashedAttributes,
                unhashedAttributes,
                PgpHashAlgorithm.Sha1);
            var certifiedPublicKey = (PgpPublicKey)PgpPublicKey.AddCertification(this.masterKey.PublicKey, id, selfCertification);

            keys.Add(new PgpSecretKey(certifiedPublicKey, this.masterKey.PrivateKey, this.rawPassPhrase));
        }

        /// <summary>
        /// Add a subkey with specific hashed and unhashed packets associated with it and
        /// default certification.
        /// </summary>
        /// <param name="hashedAttributes">Hashed packet values to be included in certification.</param>
        /// <param name="unhashedAttributes">Unhashed packets values to be included in certification.</param>
        public void AddSubKey(
            AsymmetricAlgorithm asymmetricAlgorithm,
            DateTime creationTime = default(DateTime),
            PgpSignatureAttributes? hashedAttributes = null,
            PgpSignatureAttributes? unhashedAttributes = null)
        {
            var subKey = new PgpKeyPair(
                asymmetricAlgorithm,
                creationTime == default(DateTime) ? DateTime.UtcNow : creationTime,
                isMasterKey: false);

            var subkeyBinding = PgpCertification.GenerateSubkeyBinding(
                masterKey,
                subKey.PublicKey,
                hashedAttributes,
                unhashedAttributes,
                PgpHashAlgorithm.Sha1);

            var certifiedSubKey = (PgpPublicKey)PgpPublicKey.AddCertification(subKey.PublicKey, subkeyBinding);

            keys.Add(new PgpSecretKey(certifiedSubKey, subKey.PrivateKey, rawPassPhrase));
        }


        /// <summary>Return the secret key ring.</summary>
        public PgpSecretKeyRing GenerateSecretKeyRing()
        {
            return new PgpSecretKeyRing(keys);
        }

        /// <summary>Return the public key ring that corresponds to the secret key ring.</summary>
        public PgpPublicKeyRing GeneratePublicKeyRing()
        {
            var pubKeys = new List<PgpPublicKey>();
            foreach (var secretKey in keys)
                pubKeys.Add(new PgpPublicKey(secretKey));
            return new PgpPublicKeyRing(pubKeys);
        }
    }
}
