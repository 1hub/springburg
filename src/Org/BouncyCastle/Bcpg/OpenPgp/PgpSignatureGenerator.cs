using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
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
            if (version >= 4)
            {
                SignatureSubpacket[] hPkts = hashed, unhPkts = unhashed;

                if (!hashed.Any(sp => sp.SubpacketType == SignatureSubpacketTag.CreationTime))
                {
                    hPkts = hPkts.Append(new SignatureCreationTime(false, DateTime.UtcNow)).ToArray();
                }

                if (!hashed.Any(sp => sp.SubpacketType == SignatureSubpacketTag.IssuerKeyId) &&
                    !unhashed.Any(sp => sp.SubpacketType == SignatureSubpacketTag.IssuerKeyId))
                {
                    unhPkts = unhPkts.Append(new IssuerKeyId(false, privateKey.KeyId)).ToArray();
                }

                int version = 4;
                byte[] hData;

                try
                {
                    MemoryStream hOut = new MemoryStream();

                    for (int i = 0; i != hPkts.Length; i++)
                    {
                        hPkts[i].Encode(hOut);
                    }

                    byte[] data = hOut.ToArray();

                    MemoryStream sOut = new MemoryStream(data.Length + 6);
                    sOut.WriteByte((byte)version);
                    sOut.WriteByte((byte)helper.SignatureType);
                    sOut.WriteByte((byte)privateKey.PublicKeyPacket.Algorithm);
                    sOut.WriteByte((byte)hashAlgorithm);
                    sOut.WriteByte((byte)(data.Length >> 8));
                    sOut.WriteByte((byte)data.Length);
                    sOut.Write(data, 0, data.Length);

                    int hDataLength = (int)sOut.Length;
                    sOut.WriteByte((byte)version);
                    sOut.WriteByte(0xff);
                    sOut.WriteByte((byte)(hDataLength >> 24));
                    sOut.WriteByte((byte)(hDataLength >> 16));
                    sOut.WriteByte((byte)(hDataLength >> 8));
                    sOut.WriteByte((byte)hDataLength);

                    hData = sOut.ToArray();
                }
                catch (IOException e)
                {
                    throw new PgpException("exception encoding hashed data.", e);
                }

                var signature = helper.Sign(hData, privateKey);

                return new PgpSignature(
                    new SignaturePacket(helper.SignatureType, privateKey.KeyId, privateKey.PublicKeyPacket.Algorithm,
                        hashAlgorithm, hPkts, unhPkts, signature.Hash.AsSpan(0, 2).ToArray(), signature.SigValues));
            }
            else
            {
                var creationTime = DateTimeOffset.UtcNow;
                long seconds = creationTime.ToUnixTimeSeconds();

                byte[] hData = new byte[]
                {
                    (byte)helper.SignatureType,
                    (byte)(seconds >> 24),
                    (byte)(seconds >> 16),
                    (byte)(seconds >> 8),
                    (byte)seconds
                };

                var signature = helper.Sign(hData, privateKey);
                return new PgpSignature(new SignaturePacket(3, helper.SignatureType, privateKey.KeyId, privateKey.PublicKeyPacket.Algorithm, hashAlgorithm, creationTime.UtcDateTime, signature.Hash.AsSpan(0, 2).ToArray(), signature.SigValues));
            }
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
