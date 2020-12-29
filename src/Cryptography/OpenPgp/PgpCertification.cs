using InflatablePalace.Cryptography.OpenPgp.Packet;
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace InflatablePalace.Cryptography.OpenPgp
{
    /// <summary>
    /// Class that represent OpenPGP certification signature and methods for verifying
    /// it against provided public keys.
    /// </summary>
    public class PgpCertification
    {
        PgpSignature signature;
        ContainedPacket? userPacket;
        PgpPublicKey publicKey;

        internal PgpCertification(
            PgpSignature signature,
            ContainedPacket? userPacket,
            PgpPublicKey publicKey)
        {
            this.signature = signature;
            this.userPacket = userPacket;
            this.publicKey = publicKey;
        }

        internal PgpPublicKey PublicKey => publicKey;

        public long KeyId => signature.KeyId;

        public PgpSignatureType SignatureType => signature.SignatureType;

        public PgpSignatureAttributes HashedAttributes => signature.HashedAttributes;

        public PgpSignatureAttributes UnhashedAttributes => signature.UnhashedAttributes;

        public PgpSignature Signature => signature;

        private static MemoryStream GenerateCertificationData(
            PgpPublicKey signingKey,
            ContainedPacket? userPacket,
            PgpPublicKey publicKey)
        {
            var data = new MemoryStream();

            if (!signingKey.Fingerprint.SequenceEqual(publicKey.Fingerprint) && userPacket == null)
            {
                byte[] signingKeyBytes = signingKey.PublicKeyPacket.GetEncodedContents();
                data.Write(new[] {
                (byte)0x99,
                (byte)(signingKeyBytes.Length >> 8),
                (byte)(signingKeyBytes.Length) });
                data.Write(signingKeyBytes);
            }

            byte[] keyBytes = publicKey.PublicKeyPacket.GetEncodedContents();
            data.Write(new[] {
                (byte)0x99,
                (byte)(keyBytes.Length >> 8),
                (byte)(keyBytes.Length) });
            data.Write(keyBytes);

            byte idType = 0;
            byte[]? idBytes = null;

            if (userPacket is UserAttributePacket userAttributePacket)
            {
                using var bOut = new MemoryStream();
                foreach (UserAttributeSubpacket packet in userAttributePacket.GetSubpackets())
                {
                    packet.Encode(bOut);
                }
                idType = 0xd1;
                idBytes = bOut.ToArray();
            }
            else if (userPacket is UserIdPacket userIdPacket)
            {
                idType = 0xb4;
                idBytes = Encoding.UTF8.GetBytes(userIdPacket.GetId());
            }

            if (idBytes != null)
            {
                data.Write(new[] {
                    (byte)idType,
                    (byte)(idBytes.Length >> 24),
                    (byte)(idBytes.Length >> 16),
                    (byte)(idBytes.Length >> 8),
                    (byte)(idBytes.Length) });
                data.Write(idBytes);
            }

            data.Position = 0;

            return data;
        }

        /// <summary>
        /// Verify the signature as certifying by the passed in public key.
        /// </summary>
        /// <returns>True, if the signature matches, false otherwise.</returns>
        public bool Verify(PgpPublicKey signingKey)
        {
            if (signingKey == null)
                throw new ArgumentNullException(nameof(signingKey));

            Debug.Assert(signingKey.KeyId == KeyId);
            return signature.Verify(signingKey, GenerateCertificationData(signingKey, userPacket, publicKey));
        }

        /// <summary>Verify a self-certifcation or self-revocation.</summary>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        public bool Verify()
        {
            return Verify(publicKey);
        }

        /// <summary>Generate a certification for the passed in key against the passed in master key.</summary>
        /// <param name="masterKey">The key we are certifying against.</param>
        /// <param name="subKey">The key we are certifying.</param>
        /// <returns>The certification.</returns>
        public static PgpCertification GenerateSubkeyBinding(
            PgpKeyPair masterKey,
            PgpPublicKey subKey,
            PgpSignatureAttributes? hashedAttributes = null,
            PgpSignatureAttributes? unhashedAttributes = null,
            PgpHashAlgorithm hashAlgorithm = PgpHashAlgorithm.Sha1)
        {
            if (masterKey == null)
                throw new ArgumentNullException(nameof(masterKey));
            if (subKey == null)
                throw new ArgumentNullException(nameof(subKey));

            var signatureGenerator = new PgpSignatureGenerator(PgpSignatureType.SubkeyBinding, masterKey.PrivateKey, hashAlgorithm);
            if (hashedAttributes != null)
                signatureGenerator.HashedAttributes = hashedAttributes;
            if (unhashedAttributes != null)
                signatureGenerator.UnhashedAttributes = unhashedAttributes;
            var signature = signatureGenerator.Generate(GenerateCertificationData(masterKey.PublicKey, null, subKey));
            return new PgpCertification(signature, null, subKey);
        }

        // FIXME: This method is too advanced
        public static PgpCertification GenerateUserCertification(
            PgpSignatureType signatureType,
            PgpKeyPair signingKey,
            string userId,
            PgpPublicKey userPublicKey,
            PgpSignatureAttributes? hashedAttributes = null,
            PgpSignatureAttributes? unhashedAttributes = null,
            PgpHashAlgorithm hashAlgorithm = PgpHashAlgorithm.Sha1)
        {
            if (signingKey == null)
                throw new ArgumentNullException(nameof(signingKey));
            if (userId == null)
                throw new ArgumentNullException(nameof(userId));
            if (userPublicKey == null)
                throw new ArgumentNullException(nameof(userPublicKey));

            var userPacket = new UserIdPacket(userId);
            var signatureGenerator = new PgpSignatureGenerator(signatureType, signingKey.PrivateKey, hashAlgorithm);
            if (hashedAttributes != null)
                signatureGenerator.HashedAttributes = hashedAttributes;
            if (unhashedAttributes != null)
                signatureGenerator.UnhashedAttributes = unhashedAttributes;
            var signature = signatureGenerator.Generate(GenerateCertificationData(signingKey.PublicKey, userPacket, userPublicKey));
            return new PgpCertification(signature, userPacket, userPublicKey);
        }

        // FIXME: This method is too advanced
        public static PgpCertification GenerateUserCertification(
            PgpSignatureType signatureType,
            PgpKeyPair signingKey,
            PgpUserAttributes userAttributes,
            PgpPublicKey userPublicKey,
            PgpSignatureAttributes? hashedAttributes = null,
            PgpSignatureAttributes? unhashedAttributes = null,
            PgpHashAlgorithm hashAlgorithm = PgpHashAlgorithm.Sha1)
        {
            if (signingKey == null)
                throw new ArgumentNullException(nameof(signingKey));
            if (userAttributes == null)
                throw new ArgumentNullException(nameof(userAttributes));
            if (userPublicKey == null)
                throw new ArgumentNullException(nameof(userPublicKey));

            var userPacket = new UserAttributePacket(userAttributes.ToSubpacketArray());
            var signatureGenerator = new PgpSignatureGenerator(signatureType, signingKey.PrivateKey, hashAlgorithm);
            if (hashedAttributes != null)
                signatureGenerator.HashedAttributes = hashedAttributes;
            if (unhashedAttributes != null)
                signatureGenerator.UnhashedAttributes = unhashedAttributes;
            var signature = signatureGenerator.Generate(GenerateCertificationData(signingKey.PublicKey, userPacket, userPublicKey));
            return new PgpCertification(signature, userPacket, userPublicKey);
        }

        public static PgpCertification GenerateKeyRevocation(
            PgpKeyPair signingKey,
            PgpPublicKey revokedKey,
            PgpSignatureAttributes? hashedAttributes = null,
            PgpSignatureAttributes? unhashedAttributes = null,
            PgpHashAlgorithm hashAlgorithm = PgpHashAlgorithm.Sha1)
        {
            if (signingKey == null)
                throw new ArgumentNullException(nameof(signingKey));
            if (revokedKey == null)
                throw new ArgumentNullException(nameof(revokedKey));

            var signatureGenerator = new PgpSignatureGenerator(revokedKey.IsMasterKey ? PgpSignatureType.KeyRevocation : PgpSignatureType.SubkeyRevocation, signingKey.PrivateKey, hashAlgorithm);
            if (hashedAttributes != null)
                signatureGenerator.HashedAttributes = hashedAttributes;
            if (unhashedAttributes != null)
                signatureGenerator.UnhashedAttributes = unhashedAttributes;
            var signature = signatureGenerator.Generate(GenerateCertificationData(signingKey.PublicKey, null, revokedKey));
            return new PgpCertification(signature, null, revokedKey);
        }
    }
}
