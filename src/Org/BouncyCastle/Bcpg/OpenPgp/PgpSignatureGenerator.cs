using System;
using System.IO;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Bcpg.Sig;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Generator for PGP signatures.</summary>
    public class PgpSignatureGenerator
    {
        protected HashAlgorithmTag hashAlgorithm;

        protected SignatureSubpacket[] unhashed = Array.Empty<SignatureSubpacket>();
        protected SignatureSubpacket[] hashed = Array.Empty<SignatureSubpacket>();

        internal PgpSignatureTransformation helper;
        protected PgpPrivateKey privateKey;

        protected int version;

        /// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        public PgpSignatureGenerator(int signatureType, PgpPrivateKey privateKey, HashAlgorithmTag hashAlgorithm, int version = 4, bool ignoreTrailingWhitespace = false)
        {
            // TODO: Add version 5 support
            if (version < 3 || version > 4)
                throw new ArgumentOutOfRangeException(nameof(version));

            this.version = version;
            this.hashAlgorithm = hashAlgorithm;
            this.helper = new PgpSignatureTransformation(signatureType, hashAlgorithm);
            this.helper.IgnoreTrailingWhitespace = ignoreTrailingWhitespace;
            this.privateKey = privateKey;
        }

        public HashAlgorithmTag HashAlgorithm => helper.HashAlgorithm;

        public int SignatureType => helper.SignatureType;

        public PgpPrivateKey PrivateKey => privateKey;

        public void SetHashedSubpackets(PgpSignatureSubpacketVector hashedPackets)
        {
            if (version == 3)
                throw new PgpException("Version 3 signatures don't support subpackets");

            hashed = hashedPackets == null ? Array.Empty<SignatureSubpacket>() : hashedPackets.ToSubpacketArray();
        }

        public void SetUnhashedSubpackets(PgpSignatureSubpacketVector unhashedPackets)
        {
            if (version == 3)
                throw new PgpException("Version 3 signatures don't support subpackets");

            unhashed = unhashedPackets == null ? Array.Empty<SignatureSubpacket>() : unhashedPackets.ToSubpacketArray();
        }

        /// <summary>Return a signature object containing the current signature state.</summary>
        internal PgpSignature Generate()
        {
            DateTime creationTime = DateTime.UtcNow;
            SignatureSubpacket[] hPkts = hashed, unhPkts = unhashed;

            if (version >= 4)
            {
                var creationTimePacket = hashed.OfType<SignatureCreationTime>().FirstOrDefault();
                if (creationTimePacket == null)
                {
                    hPkts = hPkts.Append(new SignatureCreationTime(false, creationTime)).ToArray();
                }
                else
                {
                    creationTime = creationTimePacket.Time;
                }

                if (!hashed.Any(sp => sp.SubpacketType == SignatureSubpacketTag.IssuerKeyId) &&
                    !unhashed.Any(sp => sp.SubpacketType == SignatureSubpacketTag.IssuerKeyId))
                {
                    unhPkts = unhPkts.Append(new IssuerKeyId(false, privateKey.KeyId)).ToArray();
                }
            }

            helper.Finish(version, privateKey.PublicKeyPacket.Algorithm, creationTime, hPkts);

            var signature = helper.Sign(privateKey);
            return new PgpSignature(new SignaturePacket(
                version, helper.SignatureType, privateKey.KeyId, privateKey.PublicKeyPacket.Algorithm,
                hashAlgorithm, creationTime, hPkts, unhPkts,
                helper.Hash.AsSpan(0, 2).ToArray(), signature));
        }

        /// <summary>Generate a certification for the passed in ID and key.</summary>
        /// <param name="id">The ID we are certifying against the public key.</param>
        /// <param name="pubKey">The key we are certifying against the ID.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(string id, PgpPublicKey pubKey)
        {
            this.helper.UpdateWithPublicKey(pubKey);
            this.helper.UpdateWithIdData(0xb4, Encoding.UTF8.GetBytes(id));
            return Generate();
        }

        /// <summary>Generate a certification for the passed in userAttributes.</summary>
        /// <param name="userAttributes">The ID we are certifying against the public key.</param>
        /// <param name="pubKey">The key we are certifying against the ID.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(
            PgpUserAttributeSubpacketVector userAttributes,
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

            return Generate();
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
            return Generate();
        }

        /// <summary>Generate a certification, such as a revocation, for the passed in key.</summary>
        /// <param name="pubKey">The key we are certifying.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(PgpPublicKey pubKey)
        {
            this.helper.UpdateWithPublicKey(pubKey);
            return Generate();
        }
    }
}
