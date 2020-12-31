using Springburg.Cryptography.Algorithms;
using Springburg.Cryptography.OpenPgp.Packet;
using Springburg.Cryptography.OpenPgp.Keys;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp
{
    /// <summary>General class to handle a PGP public key object.</summary>
    public class PgpPublicKey : PgpEncodable, IPgpKey
    {
        private long keyId;
        private byte[] fingerprint;

        private IAsymmetricPublicKey? key;
        internal PublicKeyPacket publicPk;
        internal TrustPacket? trustPk;
        internal List<PgpCertification> keyCertifications;
        internal List<PgpUser> ids;

        private byte[] CalculateFingerprint()
        {
            //BcpgKey key = Key;
            HashAlgorithm digest;

            if (Version <= 3)
            {
                var rsaParameters = RsaKey.ReadOpenPgpPublicKey(publicPk.KeyBytes, out var _);
                digest = MD5.Create();
                digest.TransformBlock(rsaParameters.Modulus!, 0, rsaParameters.Modulus!.Length, null, 0);
                digest.TransformBlock(rsaParameters.Exponent!, 0, rsaParameters.Exponent!.Length, null, 0);
            }
            else
            {
                byte[] kBytes = publicPk.GetEncodedContents();
                digest = SHA1.Create();
                digest.TransformBlock(new byte[] { 0x99, (byte)(kBytes.Length >> 8), (byte)kBytes.Length }, 0, 3, null, 0);
                digest.TransformBlock(kBytes, 0, kBytes.Length, null, 0);
            }

            digest.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

            return digest.Hash!;
        }

        private void Init()
        {
            this.fingerprint = CalculateFingerprint();

            if (publicPk.Version <= 3)
            {
                var rsaParameters = RsaKey.ReadOpenPgpPublicKey(publicPk.KeyBytes, out var _);
                //RsaPublicBcpgKey rK = (RsaPublicBcpgKey)publicPk.Key;
                var modulus = rsaParameters.Modulus;

                this.keyId = (long)(((ulong)modulus[modulus.Length - 8] << 56)
                    | ((ulong)modulus[modulus.Length - 7] << 48)
                    | ((ulong)modulus[modulus.Length - 6] << 40)
                    | ((ulong)modulus[modulus.Length - 5] << 32)
                    | ((ulong)modulus[modulus.Length - 4] << 24)
                    | ((ulong)modulus[modulus.Length - 3] << 16)
                    | ((ulong)modulus[modulus.Length - 2] << 8)
                    | (ulong)modulus[modulus.Length - 1]);
                //this.keyId = (long)(ulong)(rK.Modulus & 0xffff_ffff_ffff_ffff);
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

        /// <summary>
        /// Create a PgpPublicKey from the passed in lightweight one.
        /// </summary>
        /// <remarks>
        /// Note: the time passed in affects the value of the key's keyId, so you probably only want
        /// to do this once for a lightweight key, or make sure you keep track of the time you used.
        /// </remarks>
        /// <param name="pubKey">Actual public key to associate.</param>
        /// <param name="time">Date of creation.</param>
        /// <exception cref="ArgumentException">If <c>pubKey</c> is not public.</exception>
        /// <exception cref="PgpException">On key creation problem.</exception>
        internal PgpPublicKey(
            AsymmetricAlgorithm pubKey,
            DateTime time,
            bool isMasterKey = true)
        {
            byte[]? ecdhFingerprint = null;

            if (pubKey is RSA rsa)
                this.key = new RsaKey(rsa);
            else if (pubKey is DSA dsa)
                this.key = new DsaKey(dsa);
            else if (pubKey is ElGamal elGamal)
                this.key = new ElGamalKey(elGamal);
            else if (pubKey is ECDiffieHellman ecdh)
                this.key = new ECDiffieHellmanKey(ecdh, new byte[] { 0, (byte)PgpHashAlgorithm.Sha256, (byte)PgpSymmetricKeyAlgorithm.Aes128 }, ecdhFingerprint = new byte[20]);
            else if (pubKey is ECDsa ecdsa)
                this.key = new ECDsaKey(ecdsa);
            else
                throw new NotSupportedException();

            var keyBytes = this.key.ExportPublicKey();

            this.publicPk = isMasterKey ?
                new PublicKeyPacket(this.key.Algorithm, time, keyBytes) :
                new PublicSubkeyPacket(this.key.Algorithm, time, keyBytes);
            this.keyCertifications = new List<PgpCertification>();
            this.ids = new List<PgpUser>();

            Init();
            Debug.Assert(this.fingerprint != null);

            if (ecdhFingerprint != null)
                this.fingerprint.AsSpan(0, 20).CopyTo(ecdhFingerprint);
        }

        internal PgpPublicKey(PublicKeyPacket publicPk)
        {
            this.publicPk = publicPk;
            this.keyCertifications = new List<PgpCertification>();
            this.ids = new List<PgpUser>();

            Init();
            Debug.Assert(this.fingerprint != null);
        }

        internal PgpPublicKey(IPacketReader packetReader, PublicKeyPacket publicKeyPacket, bool subKey)
        {
            // Ignore GPG comment packets if found.
            while (packetReader.NextPacketTag() == PacketTag.Experimental2)
            {
                packetReader.ReadContainedPacket();
            }

            this.publicPk = publicKeyPacket;
            this.trustPk = packetReader.NextPacketTag() == PacketTag.Trust ? (TrustPacket)packetReader.ReadContainedPacket() : null;

            this.keyCertifications = new List<PgpCertification>();
            this.ids = new List<PgpUser>();

            while (packetReader.NextPacketTag() == PacketTag.Signature)
            {
                SignaturePacket signaturePacket = (SignaturePacket)packetReader.ReadContainedPacket();
                TrustPacket? signatureTrustPacket = packetReader.NextPacketTag() == PacketTag.Trust ? (TrustPacket)packetReader.ReadContainedPacket() : null;
                var signature = new PgpSignature(signaturePacket, signatureTrustPacket);
                this.keyCertifications.Add(new PgpCertification(signature, null, this));
            }

            Init();
            Debug.Assert(this.fingerprint != null);

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
        internal PgpPublicKey(
            PgpPublicKey pubKey)
        {
            this.publicPk = pubKey.publicPk;

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

        /// <summary>The version of this key.</summary>
        public int Version => publicPk.Version;

        /// <summary>The creation time of this key.</summary>
        public DateTime CreationTime => publicPk.CreationTime;

        /// <summary>Return the trust data associated with the public key, if present.</summary>
        /// <returns>A byte array with trust data, null otherwise.</returns>
        public ReadOnlySpan<byte> GetTrustData() => trustPk == null ? Array.Empty<byte>() : trustPk.GetLevelAndTrustAmount();

        internal PublicKeyPacket PublicKeyPacket => publicPk;

        /// <summary>
        /// Get validity of the public key from the time of creation.
        /// </summary>
        /// <retuns>The number of valid seconds from creation time or TimeSpan.MaxValue if it never expires.</returns>
        /// <remarks>Depending on the version of the key format the precision is either to days or seconds.</remarks>
        public TimeSpan GetValidity()
        {
            if (publicPk.Version <= 3)
            {
                return TimeSpan.FromDays(publicPk.ValidDays);
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
        public bool IsEncryptionKey
        {
            get
            {
                switch (publicPk.Algorithm)
                {
                    case PgpPublicKeyAlgorithm.ECDH:
                    case PgpPublicKeyAlgorithm.ElGamalEncrypt:
                    case PgpPublicKeyAlgorithm.ElGamalGeneral:
                    case PgpPublicKeyAlgorithm.RsaEncrypt:
                    case PgpPublicKeyAlgorithm.RsaGeneral:
                        return true;
                    default:
                        return false;
                }
            }
        }

        /// <summary>True, if this could be a master key.</summary>
        public bool IsMasterKey
        {
            get { return !(publicPk is PublicSubkeyPacket); }
        }

        /// <summary>The algorithm code associated with the public key.</summary>
        public PgpPublicKeyAlgorithm Algorithm
        {
            get { return publicPk.Algorithm; }
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

            switch (publicPk.Algorithm)
            {
                case PgpPublicKeyAlgorithm.RsaEncrypt:
                case PgpPublicKeyAlgorithm.RsaGeneral:
                case PgpPublicKeyAlgorithm.RsaSign:
                    return key = RsaKey.CreatePublic(publicPk.KeyBytes, out var _);
                case PgpPublicKeyAlgorithm.Dsa:
                    return key = DsaKey.CreatePublic(publicPk.KeyBytes, out var _);
                case PgpPublicKeyAlgorithm.ElGamalEncrypt:
                case PgpPublicKeyAlgorithm.ElGamalGeneral:
                    return key = ElGamalKey.CreatePublic(publicPk.KeyBytes, out var _);
                case PgpPublicKeyAlgorithm.ECDsa:
                    return key = ECDsaKey.CreatePublic(publicPk.KeyBytes, out var _);
                case PgpPublicKeyAlgorithm.ECDH:
                    return key = ECDiffieHellmanKey.CreatePublic(fingerprint, publicPk.KeyBytes, out var _);
                case PgpPublicKeyAlgorithm.EdDsa:
                    return key = ECDsaKey.CreatePublic(publicPk.KeyBytes, out var _);
                default:
                    throw new PgpException("unknown public key algorithm encountered");
            }
        }

        public byte[] EncryptSessionInfo(byte[] sessionInfo)
        {
            var key = GetKey();

            if (!key.CanEncrypt)
                throw new PgpException("Key is not usable for encryption");

            return key.EncryptSessionInfo(sessionInfo);
        }

        public bool Verify(byte[] hash, byte[] signature, PgpHashAlgorithm hashAlgorithm)
        {
            var key = GetKey();

            if (!key.CanSign)
                throw new PgpException("Key is not usable for singing");

            return key.VerifySignature(hash, signature, hashAlgorithm);
        }

        /// <summary>Allows enumeration of any user IDs associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        public IEnumerable<PgpUser> GetUserIds()
        {
            return ids.Where(u => u.UserId != null);
        }

        /// <summary>Allows enumeration of any user attribute vectors associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpUserAttributeSubpacketVector</c> objects.</returns>
        public IEnumerable<PgpUser> GetUserAttributes()
        {
            return ids.Where(u => u.UserId == null);
        }

        /// <summary>
        /// Return all signatures/certifications directly associated with this key (ie, not to a user id).
        /// </summary>
        public IList<PgpCertification> KeyCertifications => this.keyCertifications.AsReadOnly();

        public override void Encode(IPacketWriter outStr)
        {
            outStr.WritePacket(publicPk);

            if (trustPk != null)
            {
                outStr.WritePacket(trustPk);
            }

            foreach (PgpCertification keySig in keyCertifications)
                keySig.Signature.Encode(outStr);
            foreach (PgpUser user in ids)
                user.Encode(outStr);
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

        /// <summary>Add a certification for an id to the given public key.</summary>
        /// <param name="key">The key the certification is to be added to.</param>
        /// <param name="id">The ID the certification is associated with.</param>
        /// <param name="certification">The new certification.</param>
        /// <returns>The re-certified key.</returns>
        public static PgpPublicKey AddCertification(
            PgpPublicKey key,
            string id,
            PgpCertification certification)
        {
            PgpPublicKey returnKey = new PgpPublicKey(key);

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
        public static PgpPublicKey AddCertification(
            PgpPublicKey key,
            PgpUserAttributes userAttributes,
            PgpCertification certification)
        {
            PgpPublicKey returnKey = new PgpPublicKey(key);

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
        public static PgpPublicKey? RemoveCertification(PgpPublicKey key, PgpUserAttributes userAttributes)
        {
            for (int i = 0; i < key.ids.Count; i++)
            {
                if (key.ids[i].UserAttributes?.Equals(userAttributes) == true)
                {
                    PgpPublicKey returnKey = new PgpPublicKey(key);
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
        public static PgpPublicKey? RemoveCertification(PgpPublicKey key, string id)
        {
            for (int i = 0; i < key.ids.Count; i++)
            {
                if (key.ids[i].UserId?.Equals(id) == true)
                {
                    PgpPublicKey returnKey = new PgpPublicKey(key);
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
        public static PgpPublicKey? RemoveCertification(
            PgpPublicKey key,
            PgpUser user,
            PgpCertification certification)
        {
            Debug.Assert(certification.PublicKey.KeyId == key.KeyId);

            for (int i = 0; i < key.ids.Count; i++)
            {
                if (key.ids[i].UserIdOrAttributes.Equals(user.UserIdOrAttributes))
                {
                    PgpPublicKey returnKey = new PgpPublicKey(key);
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
        public static PgpPublicKey? RemoveCertification(
            PgpPublicKey key,
            PgpUserAttributes userAttributes,
            PgpCertification certification)
        {
            Debug.Assert(certification.PublicKey.KeyId == key.KeyId);

            for (int i = 0; i < key.ids.Count; i++)
            {
                if (key.ids[i].UserAttributes?.Equals(userAttributes) == true)
                {
                    PgpPublicKey returnKey = new PgpPublicKey(key);
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
        public static PgpPublicKey AddCertification(
            PgpPublicKey key,
            PgpCertification certification)
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

            PgpPublicKey returnKey = new PgpPublicKey(key);
            returnKey.keyCertifications.Add(new PgpCertification(certification.Signature, null, returnKey));
            return returnKey;
        }

        /// <summary>Remove a certification from the key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="certification">The certfication to be removed.</param>
        /// <returns>The modified key, null if the certification was not found.</returns>
        public static PgpPublicKey? RemoveCertification(
            PgpPublicKey key,
            PgpCertification certification)
        {
            int index = key.keyCertifications.IndexOf(certification);
            if (index >= 0)
            {
                var returnKey = new PgpPublicKey(key);
                returnKey.keyCertifications.RemoveAt(index);
                return returnKey;
            }

            return null;
        }
    }
}
