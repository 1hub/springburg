using System;
using System.IO;
using System.Text;
using InflatablePalace.Cryptography.OpenPgp.Packet;

namespace InflatablePalace.Cryptography.OpenPgp
{
    /// <summary>Generator for PGP signatures.</summary>
    public class PgpSignatureGenerator
    {
        private PgpHashAlgorithm hashAlgorithm;

        private PgpSignatureAttributes hashedAttributes;
        private PgpSignatureAttributes unhashedAttributes;

        internal PgpSignatureTransformation helper;
        private PgpPrivateKey privateKey;

        private int version;

        /// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        public PgpSignatureGenerator(int signatureType, PgpPrivateKey privateKey, PgpHashAlgorithm hashAlgorithm, int version = 4, bool ignoreTrailingWhitespace = false)
        {
            // TODO: Add version 5 support
            if (version < 3 || version > 4)
                throw new ArgumentOutOfRangeException(nameof(version));

            this.version = version;
            this.hashAlgorithm = hashAlgorithm;
            this.helper = new PgpSignatureTransformation(signatureType, hashAlgorithm, ignoreTrailingWhitespace);
            this.privateKey = privateKey;
        }

        public PgpHashAlgorithm HashAlgorithm => helper.HashAlgorithm;

        public int SignatureType => helper.SignatureType;

        public PgpPrivateKey PrivateKey => privateKey;

        public PgpSignatureAttributes HashedAttributes
        {
            get
            {
                if (version == 3)
                    throw new PgpException("Version 3 signatures don't support attributes");

                return hashedAttributes ?? (hashedAttributes = new PgpSignatureAttributes());
            }
            set
            {
                if (version == 3)
                    throw new PgpException("Version 3 signatures don't support attributes");

                hashedAttributes = value;
            }
        }

        public PgpSignatureAttributes UnhashedAttributes
        {
            get
            {
                if (version == 3)
                    throw new PgpException("Version 3 signatures don't support attributes");

                return unhashedAttributes ?? (unhashedAttributes = new PgpSignatureAttributes());
            }
            set
            {
                if (version == 3)
                    throw new PgpException("Version 3 signatures don't support attributes");

                unhashedAttributes = value;
            }
        }

        /// <summary>Return a signature object containing the current signature state.</summary>
        internal SignaturePacket Generate()
        {
            DateTime creationTime = DateTime.UtcNow;

            if (version >= 4)
            {
                if (!HashedAttributes.SignatureCreationTime.HasValue)
                {
                    HashedAttributes.SetSignatureCreationTime(false, creationTime);
                }
                else
                {
                    creationTime = hashedAttributes.SignatureCreationTime.Value;
                }

                if (!HashedAttributes.IssuerKeyId.HasValue &&
                    !UnhashedAttributes.IssuerKeyId.HasValue)
                { 
                    UnhashedAttributes.SetIssuerKeyId(false, privateKey.KeyId);
                }
            }

            var hashedPackets = hashedAttributes == null ? Array.Empty<SignatureSubpacket>() : hashedAttributes.ToSubpacketArray();

            helper.Finish(
                version,
                privateKey.PublicKeyPacket.Algorithm,
                creationTime,
                hashedPackets);

            var signature = privateKey.Sign(helper.Hash, helper.HashAlgorithm);
            return new SignaturePacket(
                version, helper.SignatureType, privateKey.KeyId, privateKey.PublicKeyPacket.Algorithm,
                hashAlgorithm, creationTime,
                hashedPackets,
                unhashedAttributes == null ? Array.Empty<SignatureSubpacket>() : unhashedAttributes.ToSubpacketArray(),
                helper.Hash.AsSpan(0, 2).ToArray(), signature);
        }

        /// <summary>Generate a certification for the passed in ID and key.</summary>
        /// <param name="id">The ID we are certifying against the public key.</param>
        /// <param name="pubKey">The key we are certifying against the ID.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(string id, PgpPublicKey pubKey)
        {
            this.helper.UpdateWithPublicKey(pubKey);
            this.helper.UpdateWithIdData(0xb4, Encoding.UTF8.GetBytes(id));
            return new PgpSignature(Generate());
        }

        /// <summary>Generate a certification for the passed in userAttributes.</summary>
        /// <param name="userAttributes">The ID we are certifying against the public key.</param>
        /// <param name="pubKey">The key we are certifying against the ID.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(
            PgpUserAttributes userAttributes,
            PgpPublicKey pubKey)
        {
            this.helper.UpdateWithPublicKey(pubKey);

            //
            // hash in the attributes
            //
            try
            {
                MemoryStream bOut = new MemoryStream();
                foreach (UserAttributeSubpacket packet in userAttributes.ToSubpacketArray())
                {
                    packet.Encode(bOut);
                }
                this.helper.UpdateWithIdData(0xd1, bOut.ToArray());
            }
            catch (IOException e)
            {
                throw new PgpException("cannot encode subpacket array", e);
            }

            return new PgpSignature(Generate());
        }

        /// <summary>Generate a certification for the passed in key against the passed in master key.</summary>
        /// <param name="masterKey">The key we are certifying against.</param>
        /// <param name="pubKey">The key we are certifying.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(
            PgpPublicKey masterKey,
            PgpPublicKey pubKey)
        {
            this.helper.UpdateWithPublicKey(masterKey);
            this.helper.UpdateWithPublicKey(pubKey);
            return new PgpSignature(Generate());
        }

        /// <summary>Generate a certification, such as a revocation, for the passed in key.</summary>
        /// <param name="pubKey">The key we are certifying.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateRevokation(PgpPublicKey pubKey)
        {
            this.helper.UpdateWithPublicKey(pubKey);
            return new PgpSignature(Generate());
        }
    }
}
