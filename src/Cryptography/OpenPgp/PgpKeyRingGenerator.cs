using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace InflatablePalace.Cryptography.OpenPgp
{
    /// <summary>
    /// Generator for a PGP master and subkey ring.
    /// This class will generate both the secret and public key rings
    /// </summary>
    public class PgpKeyRingGenerator
    {
        private IList<PgpSecretKey> keys = new List<PgpSecretKey>();
        private string id;
        private PgpSymmetricKeyAlgorithm encAlgorithm;
        private PgpHashAlgorithm hashAlgorithm;
        //private int certificationLevel;
        private byte[] rawPassPhrase;
        private bool useSha1;
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
            bool useSha1 = true,
            PgpSignatureType certificationLevel = PgpSignatureType.DefaultCertification,
            PgpSymmetricKeyAlgorithm encAlgorithm = PgpSymmetricKeyAlgorithm.Aes128,
            PgpHashAlgorithm hashAlgorithm = PgpHashAlgorithm.Sha1,
            PgpSignatureAttributes? hashedAttributes = null,
            PgpSignatureAttributes? unhashedAttributes = null)
            : this(masterKey, id, Encoding.UTF8.GetBytes(passPhrase), creationTime, useSha1, certificationLevel, encAlgorithm, hashAlgorithm, hashedAttributes, unhashedAttributes)
        {
        }

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
            byte[]? rawPassPhrase = null,
            DateTime creationTime = default(DateTime),
            bool useSha1 = true,
            PgpSignatureType certificationLevel = PgpSignatureType.DefaultCertification,
            PgpSymmetricKeyAlgorithm encAlgorithm = PgpSymmetricKeyAlgorithm.Aes128,
            PgpHashAlgorithm hashAlgorithm = PgpHashAlgorithm.Sha1,
            PgpSignatureAttributes? hashedAttributes = null,
            PgpSignatureAttributes? unhashedAttributes = null)
        {
            this.masterKey = new PgpKeyPair(masterKey, creationTime == default(DateTime) ? DateTime.UtcNow : creationTime);

            //this.certificationLevel = certificationLevel;
            this.id = id;
            this.encAlgorithm = encAlgorithm;
            this.rawPassPhrase = rawPassPhrase ?? Array.Empty<byte>();
            this.useSha1 = useSha1;
            //this.hashedAttributes = hashedAttributes;
            //this.unhashedAttributes = unhashedAttributes;
            this.hashAlgorithm = hashAlgorithm;

            // Certify the ID/public key
            var selfCertification = PgpCertification.GenerateUserCertification(
                certificationLevel,
                this.masterKey,
                id,
                this.masterKey.PublicKey,
                hashedAttributes,
                unhashedAttributes,
                hashAlgorithm);
            var certifiedPublicKey = PgpPublicKey.AddCertification(this.masterKey.PublicKey, id, selfCertification);

            keys.Add(new PgpSecretKey(this.masterKey.PrivateKey, certifiedPublicKey, encAlgorithm, this.rawPassPhrase, useSha1, true));
        }

        /// <summary>
        /// Add a subkey with specific hashed and unhashed packets associated with it and
        /// default certification.
        /// </summary>
        /// <param name="hashedAttributes">Hashed packet values to be included in certification.</param>
        /// <param name="unhashedAttributes">Unhashed packets values to be included in certification.</param>
        public void AddSubKey(
            AsymmetricAlgorithm subKey,
            DateTime creationTime = default(DateTime),
            PgpSignatureAttributes? hashedAttributes = null,
            PgpSignatureAttributes? unhashedAttributes = null)
        {
            var publicSubKey = new PgpPublicKey(
                subKey,
                creationTime == default(DateTime) ? DateTime.UtcNow : creationTime,
                isMasterKey: false);

            var subkeyBinding = PgpCertification.GenerateSubkeyBinding(
                masterKey,
                publicSubKey,
                hashedAttributes,
                unhashedAttributes,
                hashAlgorithm);

            var certifiedSubKey = PgpPublicKey.AddCertification(publicSubKey, subkeyBinding);

            keys.Add(new PgpSecretKey(new PgpPrivateKey(certifiedSubKey.KeyId, certifiedSubKey.PublicKeyPacket, subKey), certifiedSubKey, encAlgorithm, rawPassPhrase, useSha1, false));
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
                pubKeys.Add(secretKey.PublicKey);
            return new PgpPublicKeyRing(pubKeys);
        }
    }
}
