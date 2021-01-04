using Springburg.Cryptography.OpenPgp.Keys;
using Springburg.Cryptography.OpenPgp.Packet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp
{
    public abstract class PgpKey
    {
        private protected KeyPacket keyPacket;
        private protected TrustPacket? trustPacket;
        protected List<PgpCertification> keyCertifications;
        protected List<PgpUser> ids;
        protected long keyId;
        protected byte[] fingerprint;

        protected internal IAsymmetricPublicKey? key;

        internal KeyPacket KeyPacket => keyPacket;

        /// <summary>The version of this key.</summary>
        public int Version => keyPacket.Version;

        /// <summary>The creation time of this key.</summary>
        public DateTime CreationTime => keyPacket.CreationTime;

        /// <summary>The keyId associated with the public key.</summary>
        public long KeyId => keyId;

        /// <summary>The fingerprint of the key</summary>
        public ReadOnlySpan<byte> Fingerprint => fingerprint;

        /// <summary>
        /// Check if this key has an algorithm type that makes it suitable to use for encryption.
        /// </summary>
        /// <remarks>
        /// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
        /// determining the preferred use of the key.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if this key algorithm is suitable for encryption.
        /// </returns>
        public bool IsEncryptionKey => GetKey().CanEncrypt;

        /// <summary>
        /// Check if this key has an algorithm type that makes it suitable to use for signing.
        /// </summary>
        /// <remarks>
        /// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
        /// determining the preferred use of the key.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if this key algorithm is suitable for signing.
        /// </returns>
        public bool IsSigningKey => GetKey().CanSign;

        /// <summary>True, if this could be a master key.</summary>
        public bool IsMasterKey => keyPacket is not PublicSubkeyPacket && keyPacket is not SecretSubkeyPacket;

        /// <summary>The algorithm code associated with the public key.</summary>
        public PgpPublicKeyAlgorithm Algorithm => keyPacket.Algorithm;

        /// <summary>
        /// Return all signatures/certifications directly associated with this key (ie, not to a user id).
        /// </summary>
        public IList<PgpCertification> KeyCertifications => this.keyCertifications.AsReadOnly();

        private protected PgpKey(KeyPacket keyPacket)
        {
            this.keyPacket = keyPacket;
            this.keyCertifications = new List<PgpCertification>();
            this.ids = new List<PgpUser>();

            this.fingerprint = CalculateFingerprint();

            if (keyPacket.Version <= 3)
            {
                var rsaParameters = RsaKey.ReadOpenPgpPublicKey(keyPacket.KeyBytes, out var _);
                var modulus = rsaParameters.Modulus!;

                this.keyId = (long)(((ulong)modulus[modulus.Length - 8] << 56)
                    | ((ulong)modulus[modulus.Length - 7] << 48)
                    | ((ulong)modulus[modulus.Length - 6] << 40)
                    | ((ulong)modulus[modulus.Length - 5] << 32)
                    | ((ulong)modulus[modulus.Length - 4] << 24)
                    | ((ulong)modulus[modulus.Length - 3] << 16)
                    | ((ulong)modulus[modulus.Length - 2] << 8)
                    | (ulong)modulus[modulus.Length - 1]);
            }
            else
            {
                this.keyId = (long)(((ulong)fingerprint[fingerprint.Length - 8] << 56)
                    | ((ulong)fingerprint[fingerprint.Length - 7] << 48)
                    | ((ulong)fingerprint[fingerprint.Length - 6] << 40)
                    | ((ulong)fingerprint[fingerprint.Length - 5] << 32)
                    | ((ulong)fingerprint[fingerprint.Length - 4] << 24)
                    | ((ulong)fingerprint[fingerprint.Length - 3] << 16)
                    | ((ulong)fingerprint[fingerprint.Length - 2] << 8)
                    | (ulong)fingerprint[fingerprint.Length - 1]);
            }
        }

        private protected PgpKey(IPacketReader packetReader, KeyPacket keyPacket, bool subKey)
            : this(keyPacket)
        {
            // Ignore GPG comment packets if found.
            while (packetReader.NextPacketTag() == PacketTag.Experimental2)
            {
                packetReader.ReadContainedPacket();
            }

            this.trustPacket = packetReader.NextPacketTag() == PacketTag.Trust ? (TrustPacket)packetReader.ReadContainedPacket() : null;

            while (packetReader.NextPacketTag() == PacketTag.Signature)
            {
                SignaturePacket signaturePacket = (SignaturePacket)packetReader.ReadContainedPacket();
                TrustPacket? signatureTrustPacket = packetReader.NextPacketTag() == PacketTag.Trust ? (TrustPacket)packetReader.ReadContainedPacket() : null;
                var signature = new PgpSignature(signaturePacket, signatureTrustPacket);
                this.keyCertifications.Add(new PgpCertification(signature, null, this));
            }

            if (!subKey)
            {
                while (packetReader.NextPacketTag() == PacketTag.UserId
                    || packetReader.NextPacketTag() == PacketTag.UserAttribute)
                {
                    ids.Add(new PgpUser(packetReader, this));
                }
            }
        }

        /// <summary>Copy constructor.</summary>
        /// <param name="pubKey">The public key to copy.</param>
        protected PgpKey(PgpKey pubKey)
        {
            this.keyPacket = pubKey.keyPacket;

            this.keyCertifications = new List<PgpCertification>(pubKey.keyCertifications.Count);
            foreach (var keySig in pubKey.keyCertifications)
            {
                this.keyCertifications.Add(new PgpCertification(keySig.Signature, null, this));
            }

            this.ids = new List<PgpUser>(pubKey.ids.Count);
            foreach (var id in pubKey.ids)
            {
                this.ids.Add(new PgpUser(id, this));
            }

            this.fingerprint = pubKey.fingerprint;
            this.keyId = pubKey.keyId;
        }


        protected internal void Encode(IPacketWriter outStr)
        {
            outStr.WritePacket(keyPacket);
            if (trustPacket != null)
                outStr.WritePacket(trustPacket);
            foreach (PgpCertification keySig in keyCertifications)
                keySig.Signature.Encode(outStr);
            foreach (PgpUser user in ids)
                user.Encode(outStr);
        }

        public byte[] EncryptSessionInfo(byte[] sessionInfo)
        {
            var key = GetKey();

            if (!key.CanEncrypt)
                throw new PgpException("Key is not usable for encryption");

            return key.EncryptSessionInfo(sessionInfo);
        }

        /// <summary>Return the trust data associated with the public key, if present.</summary>
        /// <returns>A byte array with trust data, null otherwise.</returns>
        public ReadOnlySpan<byte> GetTrustData() => trustPacket == null ? Array.Empty<byte>() : trustPacket.GetLevelAndTrustAmount();

        /// <summary>Allows enumeration of any user attribute vectors associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpUserAttributeSubpacketVector</c> objects.</returns>
        public IEnumerable<PgpUser> GetUserAttributes()
        {
            return ids.Where(u => u.UserId == null);
        }

        /// <summary>Allows enumeration of any user IDs associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        public IEnumerable<PgpUser> GetUserIds()
        {
            return ids.Where(u => u.UserId != null);
        }

        /// <summary>
        /// Get validity of the public key from the time of creation.
        /// </summary>
        /// <retuns>The number of valid seconds from creation time or TimeSpan.MaxValue if it never expires.</returns>
        /// <remarks>Depending on the version of the key format the precision is either to days or seconds.</remarks>
        public TimeSpan GetValidity()
        {
            if (keyPacket.Version <= 3)
            {
                return TimeSpan.FromDays(keyPacket.ValidDays);
            }

            if (IsMasterKey)
            {
                foreach (var user in ids)
                {
                    if (GetExpirationTimeFromSig(user.SelfCertifications, out var expiryTime))
                    {
                        return expiryTime;
                    }
                }

                if (GetExpirationTimeFromSig(this.keyCertifications.Where(s => s.SignatureType == PgpSignatureType.DirectKey), out var expiryTime2))
                {
                    return expiryTime2;
                }
            }
            else
            {
                if (GetExpirationTimeFromSig(this.keyCertifications.Where(s => s.SignatureType == PgpSignatureType.SubkeyBinding || s.SignatureType == PgpSignatureType.DirectKey), out var expiryTime))
                {
                    return expiryTime;
                }
            }

            return TimeSpan.MaxValue;
        }

        /// <summary>Check whether this (sub)key has a revocation signature on it.</summary>
        /// <returns>True, if this (sub)key has been revoked.</returns>
        public bool IsRevoked()
        {
            PgpSignatureType signatureType = IsMasterKey ? PgpSignatureType.KeyRevocation : PgpSignatureType.SubkeyRevocation;

            foreach (var keyCertification in KeyCertifications)
            {
                if (keyCertification.Signature.SignatureType == signatureType)
                {
                    return true;
                }
            }

            return false;
        }

        public bool Verify(byte[] hash, byte[] signature, PgpHashAlgorithm hashAlgorithm)
        {
            var key = GetKey();

            if (!key.CanSign)
                throw new PgpException("Key is not usable for singing");

            return key.VerifySignature(hash, signature, hashAlgorithm);
        }

        private byte[] CalculateFingerprint()
        {
            HashAlgorithm digest;

            if (Version <= 3)
            {
                var rsaParameters = RsaKey.ReadOpenPgpPublicKey(keyPacket.KeyBytes, out var _);
                digest = MD5.Create();
                digest.TransformBlock(rsaParameters.Modulus!, 0, rsaParameters.Modulus!.Length, null, 0);
                digest.TransformBlock(rsaParameters.Exponent!, 0, rsaParameters.Exponent!.Length, null, 0);
            }
            else
            {
                byte[] kBytes = keyPacket.GetEncodedContents();
                digest = SHA1.Create();
                digest.TransformBlock(new byte[] { 0x99, (byte)(kBytes.Length >> 8), (byte)kBytes.Length }, 0, 3, null, 0);
                digest.TransformBlock(kBytes, 0, kBytes.Length, null, 0);
            }

            digest.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

            return digest.Hash!;
        }

        private bool GetExpirationTimeFromSig(IEnumerable<PgpCertification> certifications, out TimeSpan expiryTime)
        {
            DateTime lastDate = DateTime.MinValue;

            expiryTime = TimeSpan.MinValue;
            foreach (PgpCertification certification in certifications)
            {
                TimeSpan? current = certification.HashedAttributes.KeyExpirationTime;
                if (current == null)
                    continue;

                if (certification.KeyId == this.KeyId)
                {
                    if (certification.Signature.CreationTime > lastDate)
                    {
                        lastDate = certification.Signature.CreationTime;
                        expiryTime = current.Value;
                    }
                }
                else if (current != TimeSpan.MaxValue && current > expiryTime)
                {
                    expiryTime = current.Value;
                }
            }

            return expiryTime != TimeSpan.MinValue;
        }

        /// <summary>The public key contained in the object.</summary>
        /// <returns>A lightweight public key.</returns>
        /// <exception cref="PgpException">If the key algorithm is not recognised.</exception>
        private IAsymmetricPublicKey GetKey()
        {
            if (key != null)
            {
                return key;
            }

            switch (keyPacket.Algorithm)
            {
                case PgpPublicKeyAlgorithm.RsaEncrypt:
                case PgpPublicKeyAlgorithm.RsaGeneral:
                case PgpPublicKeyAlgorithm.RsaSign:
                    return key = RsaKey.CreatePublic(keyPacket.KeyBytes, out var _);
                case PgpPublicKeyAlgorithm.Dsa:
                    return key = DsaKey.CreatePublic(keyPacket.KeyBytes, out var _);
                case PgpPublicKeyAlgorithm.ElGamalEncrypt:
                case PgpPublicKeyAlgorithm.ElGamalGeneral:
                    return key = ElGamalKey.CreatePublic(keyPacket.KeyBytes, out var _);
                case PgpPublicKeyAlgorithm.ECDsa:
                    return key = ECDsaKey.CreatePublic(keyPacket.KeyBytes, out var _);
                case PgpPublicKeyAlgorithm.ECDH:
                    return key = ECDiffieHellmanKey.CreatePublic(fingerprint, keyPacket.KeyBytes, out var _);
                case PgpPublicKeyAlgorithm.EdDsa:
                    return key = EdDsaKey.CreatePublic(keyPacket.KeyBytes, out var _);
                default:
                    throw new PgpException("unknown public key algorithm encountered");
            }
        }

        protected abstract PgpKey CreateMutableCopy();

        public PgpPublicKey GetPublicKey() => this is PgpPublicKey ? (PgpPublicKey)this : new PgpPublicKey((PgpSecretKey)this);

        /// <summary>Add a certification for an id to the given public key.</summary>
        /// <param name="key">The key the certification is to be added to.</param>
        /// <param name="id">The ID the certification is associated with.</param>
        /// <param name="certification">The new certification.</param>
        /// <returns>The re-certified key.</returns>
        public static TKey AddCertification<TKey>(
            TKey key,
            string id,
            PgpCertification certification)
            where TKey : PgpKey
        {
            var returnKey = (TKey)key.CreateMutableCopy();

            Debug.Assert(certification.PublicKey.KeyId == key.KeyId);

            for (int i = 0; i < returnKey.ids.Count; i++)
            {
                if (returnKey.ids[i].UserId?.Equals(id) == true)
                {
                    returnKey.ids[i] = PgpUser.AddCertification(returnKey.ids[i], returnKey, certification.Signature);
                    return returnKey;
                }
            }

            returnKey.ids.Add(new PgpUser(new UserIdPacket(id), returnKey, certification.Signature));
            return returnKey;
        }

        /// <summary>Add a certification for the given UserAttributeSubpackets to the given public key.</summary>
        /// <param name="key">The key the certification is to be added to.</param>
        /// <param name="userAttributes">The attributes the certification is associated with.</param>
        /// <param name="certification">The new certification.</param>
        /// <returns>The re-certified key.</returns>
        public static TKey AddCertification<TKey>(
            TKey key,
            PgpUserAttributes userAttributes,
            PgpCertification certification)
            where TKey : PgpKey
        {
            var returnKey = (TKey)key.CreateMutableCopy();

            Debug.Assert(certification.PublicKey.KeyId == key.KeyId);

            for (int i = 0; i < returnKey.ids.Count; i++)
            {
                if (returnKey.ids[i].UserAttributes?.Equals(userAttributes) == true)
                {
                    returnKey.ids[i] = PgpUser.AddCertification(returnKey.ids[i], returnKey, certification.Signature);
                    return returnKey;
                }
            }

            returnKey.ids.Add(new PgpUser(new UserAttributePacket(userAttributes.ToSubpacketArray()), returnKey, certification.Signature));
            return returnKey;
        }

        /// <summary>
        /// Remove any certifications associated with a user attribute subpacket on a key.
        /// </summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="userAttributes">The attributes to be removed.</param>
        /// <returns>
        /// The re-certified key, or null if the user attribute subpacket was not found on the key.
        /// </returns>
        public static TKey? RemoveCertification<TKey>(TKey key, PgpUserAttributes userAttributes)
            where TKey : PgpKey
        {
            for (int i = 0; i < key.ids.Count; i++)
            {
                if (key.ids[i].UserAttributes?.Equals(userAttributes) == true)
                {
                    var returnKey = (TKey)key.CreateMutableCopy();
                    returnKey.ids.RemoveAt(i);
                    return returnKey;
                }
            }

            return null;
        }

        /// <summary>Remove any certifications associated with a given ID on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="id">The ID that is to be removed.</param>
        /// <returns>The re-certified key, or null if the ID was not found on the key.</returns>
        public static TKey? RemoveCertification<TKey>(TKey key, string id)
            where TKey : PgpKey
        {
            for (int i = 0; i < key.ids.Count; i++)
            {
                if (key.ids[i].UserId?.Equals(id) == true)
                {
                    var returnKey = (TKey)key.CreateMutableCopy();
                    returnKey.ids.RemoveAt(i);
                    return returnKey;
                }
            }

            return null;
        }

        /// <summary>Remove a certification associated with a given ID on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="id">The ID that the certfication is to be removed from.</param>
        /// <param name="certification">The certfication to be removed.</param>
        /// <returns>The re-certified key, or null if the certification was not found.</returns>
        public static TKey? RemoveCertification<TKey>(
            TKey key,
            PgpUser user,
            PgpCertification certification)
            where TKey : PgpKey
        {
            Debug.Assert(certification.PublicKey.KeyId == key.KeyId);

            for (int i = 0; i < key.ids.Count; i++)
            {
                if (key.ids[i].UserIdOrAttributes.Equals(user.UserIdOrAttributes))
                {
                    var returnKey = (TKey)key.CreateMutableCopy();
                    returnKey.ids[i] = PgpUser.RemoveCertification(returnKey.ids[i], returnKey, certification);
                    return returnKey;
                }
            }

            return null;
        }

        /// <summary>Remove a certification associated with a given user attributes on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="userAttributes">The user attributes that the certfication is to be removed from.</param>
        /// <param name="certification">The certification to be removed.</param>
        /// <returns>The re-certified key, or null if the certification was not found.</returns>
        public static TKey? RemoveCertification<TKey>(
            TKey key,
            PgpUserAttributes userAttributes,
            PgpCertification certification)
            where TKey : PgpKey
        {
            Debug.Assert(certification.PublicKey.KeyId == key.KeyId);

            for (int i = 0; i < key.ids.Count; i++)
            {
                if (key.ids[i].UserAttributes?.Equals(userAttributes) == true)
                {
                    var returnKey = (TKey)key.CreateMutableCopy();
                    returnKey.ids[i] = PgpUser.RemoveCertification(returnKey.ids[i], returnKey, certification);
                    return returnKey;
                }
            }

            return null;
        }

        /// <summary>Add a revocation or some other key certification to a key.</summary>
        /// <param name="key">The key the revocation is to be added to.</param>
        /// <param name="certification">The key signature to be added.</param>
        /// <returns>The new changed public key object.</returns>
        public static TKey AddCertification<TKey>(
            TKey key,
            PgpCertification certification)
            where TKey : PgpKey
        {
            Debug.Assert(certification.PublicKey.KeyId == key.KeyId);

            if (key.IsMasterKey)
            {
                if (certification.SignatureType == PgpSignatureType.SubkeyRevocation)
                {
                    throw new ArgumentException("signature type incorrect for master key revocation.");
                }
            }
            else
            {
                if (certification.SignatureType == PgpSignatureType.KeyRevocation)
                {
                    throw new ArgumentException("signature type incorrect for sub-key revocation.");
                }
            }

            var returnKey = (TKey)key.CreateMutableCopy();
            returnKey.keyCertifications.Add(new PgpCertification(certification.Signature, null, returnKey));
            return returnKey;
        }

        /// <summary>Remove a certification from the key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="certification">The certfication to be removed.</param>
        /// <returns>The modified key, null if the certification was not found.</returns>
        public static TKey? RemoveCertification<TKey>(
            TKey key,
            PgpCertification certification)
            where TKey : PgpKey
        {
            int index = key.keyCertifications.IndexOf(certification);
            if (index >= 0)
            {
                var returnKey = (TKey)key.CreateMutableCopy();
                returnKey.keyCertifications.RemoveAt(index);
                return returnKey;
            }

            return null;
        }
    }
}