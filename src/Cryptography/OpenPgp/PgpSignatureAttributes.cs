using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Springburg.Cryptography.OpenPgp.Packet;
using Springburg.Cryptography.OpenPgp.Packet.Signature;

namespace Springburg.Cryptography.OpenPgp
{
    public class PgpSignatureAttributes
    {
        private SignatureSubpacket[]? orginalSubpackets;
        private IDictionary<SignatureSubpacketTag, SignatureSubpacket> subpackets;
        private IList<NotationData> notations;

        public PgpSignatureAttributes()
        {
            subpackets = new Dictionary<SignatureSubpacketTag, SignatureSubpacket>();
            notations = new List<NotationData>();
        }

        internal PgpSignatureAttributes(SignatureSubpacket[] subpackets)
        {
            this.orginalSubpackets = subpackets;
            // FIXME: How to handle duplicate attributes?
            this.subpackets = new ReadOnlyDictionary<SignatureSubpacketTag, SignatureSubpacket>(subpackets.Where(s => s.SubpacketType != SignatureSubpacketTag.NotationData).ToDictionary(s => s.SubpacketType));
            this.notations = subpackets.OfType<NotationData>().ToList().AsReadOnly() ;
        }

        public bool IsRevocable
        {
            get
            {
                if (subpackets.TryGetValue(SignatureSubpacketTag.Revocable, out var p))
                    return ((Revocable)p).IsRevocable;
                return true;
            }
        }

        public void SetRevocable(bool isCritical, bool isRevocable)
        {
            subpackets[SignatureSubpacketTag.Revocable] = new Revocable(isCritical, isRevocable);
        }

        public bool IsExportable
        {
            get
            {
                if (subpackets.TryGetValue(SignatureSubpacketTag.Exportable, out var p))
                    return ((Exportable)p).IsExportable;
                return true;
            }
        }

        public void SetExportable(bool isCritical, bool isExportable)
        {
            subpackets[SignatureSubpacketTag.Exportable] = new Exportable(isCritical, isExportable);
        }

        public PgpFeatureFlags? Features
        {
            get
            {
                if (subpackets.TryGetValue(SignatureSubpacketTag.Features, out var p))
                    return ((Features)p).Flags;
                return null;
            }
        }

        public void SetFeatures(bool isCritical, PgpFeatureFlags features)
        {
            subpackets[SignatureSubpacketTag.Features] = new Features(isCritical, features);
        }

        /// <summary>
		/// Add a TrustSignature packet to the signature. The values for depth and trust are largely
		/// installation dependent but there are some guidelines in RFC 4880 - 5.2.3.13.
		/// </summary>
		/// <param name="isCritical">true if the packet is critical.</param>
		/// <param name="depth">depth level.</param>
		/// <param name="trustAmount">trust amount.</param>
		public void SetTrust(bool isCritical, byte depth, byte trustAmount)
        {
            subpackets[SignatureSubpacketTag.TrustSignature] = new TrustSignature(isCritical, depth, trustAmount);
        }

        public TimeSpan? KeyExpirationTime
        {
            get
            {
                if (subpackets.TryGetValue(SignatureSubpacketTag.KeyExpirationTime, out var p))
                    return ((KeyExpirationTime)p).Time;
                return null;
            }
        }

        /// <summary>
        /// Set the number of seconds a key is valid for after the time of its creation.
        /// A value of zero means the key never expires.
        /// </summary>
        /// <param name="isCritical">True, if should be treated as critical, false otherwise.</param>
        /// <param name="seconds">The number of seconds the key is valid, or zero if no expiry.</param>
        public void SetKeyExpirationTime(bool isCritical, TimeSpan seconds)
        {
            subpackets[SignatureSubpacketTag.KeyExpirationTime] = new KeyExpirationTime(isCritical, seconds);
        }

        public TimeSpan? SignatureExpirationTime
        {
            get
            {
                if (subpackets.TryGetValue(SignatureSubpacketTag.SignatureExpirationTime, out var p))
                    return ((SignatureExpirationTime)p).Time;
                return null;
            }
        }

        /// <summary>
        /// Set the number of seconds a signature is valid for after the time of its creation.
        /// A value of zero means the signature never expires.
        /// </summary>
        /// <param name="isCritical">True, if should be treated as critical, false otherwise.</param>
        /// <param name="seconds">The number of seconds the signature is valid, or zero if no expiry.</param>
        public void SetSignatureExpirationTime(bool isCritical, TimeSpan seconds)
        {
            subpackets[SignatureSubpacketTag.SignatureExpirationTime] = new SignatureExpirationTime(isCritical, seconds);
        }

        public DateTime? SignatureCreationTime
        {
            get
            {
                if (subpackets.TryGetValue(SignatureSubpacketTag.SignatureCreationTime, out var p))
                    return ((SignatureCreationTime)p).Time;
                return null;
            }
        }

        /// <summary>
        /// Set the creation time for the signature.
        /// </summary>
        /// <remarks>
        /// This overrides the generation of a creation time when the signature is generated.
        /// </remarks>
        public void SetSignatureCreationTime(bool isCritical, DateTime time)
        {
            subpackets[SignatureSubpacketTag.SignatureCreationTime] = new SignatureCreationTime(isCritical, time);
        }

        public PgpHashAlgorithm[]? PreferredHashAlgorithms
        {
            get
            {
                if (subpackets.TryGetValue(SignatureSubpacketTag.PreferredHashAlgorithms, out var p))
                    return ((PreferredAlgorithms)p).GetPreferences<PgpHashAlgorithm>();
                return null;
            }
        }

        public void SetPreferredHashAlgorithms(bool isCritical, PgpHashAlgorithm[] algorithms)
        {
            subpackets[SignatureSubpacketTag.PreferredHashAlgorithms] = new PreferredAlgorithms(SignatureSubpacketTag.PreferredHashAlgorithms, isCritical, algorithms.Cast<byte>().ToArray());
        }

        public PgpSymmetricKeyAlgorithm[]? PreferredSymmetricAlgorithms
        {
            get
            {
                if (subpackets.TryGetValue(SignatureSubpacketTag.PreferredSymmetricAlgorithms, out var p))
                    return ((PreferredAlgorithms)p).GetPreferences<PgpSymmetricKeyAlgorithm>();
                return null;
            }
        }

        public void SetPreferredSymmetricAlgorithms(bool isCritical, PgpSymmetricKeyAlgorithm[] algorithms)
        {
            subpackets[SignatureSubpacketTag.PreferredSymmetricAlgorithms] = new PreferredAlgorithms(SignatureSubpacketTag.PreferredSymmetricAlgorithms, isCritical, algorithms.Cast<byte>().ToArray());
        }

        public PgpCompressionAlgorithm[]? PreferredCompressionAlgorithms
        {
            get
            {
                if (subpackets.TryGetValue(SignatureSubpacketTag.PreferredCompressionAlgorithms, out var p))
                    return ((PreferredAlgorithms)p).GetPreferences<PgpCompressionAlgorithm>();
                return null;
            }
        }

        public void SetPreferredCompressionAlgorithms(bool isCritical, PgpCompressionAlgorithm[] algorithms)
        {
            subpackets[SignatureSubpacketTag.PreferredCompressionAlgorithms] = new PreferredAlgorithms(SignatureSubpacketTag.PreferredCompressionAlgorithms, isCritical, algorithms.Cast<byte>().ToArray());
        }

        public PgpKeyFlags? KeyFlags
        {
            get
            {
                if (subpackets.TryGetValue(SignatureSubpacketTag.KeyFlags, out var p))
                    return ((KeyFlags)p).Flags;
                return null;
            }
        }

        public void SetKeyFlags(bool isCritical, PgpKeyFlags flags)
        {
            subpackets[SignatureSubpacketTag.KeyFlags] = new KeyFlags(isCritical, flags);
        }

        public string? SignerUserId
        {
            get
            {
                if (subpackets.TryGetValue(SignatureSubpacketTag.SignerUserId, out var p))
                    return ((SignerUserId)p).GetId();
                return null;
            }
        }

        public void SetSignerUserId(bool isCritical, string userId)
        {
            if (userId == null)
                throw new ArgumentNullException(nameof(userId));

            subpackets[SignatureSubpacketTag.SignerUserId] = new SignerUserId(isCritical, userId);
        }

        public void SetSignerUserId(bool isCritical, byte[] rawUserId)
        {
            if (rawUserId == null)
                throw new ArgumentNullException(nameof(rawUserId));

            subpackets[SignatureSubpacketTag.SignerUserId] = new SignerUserId(isCritical, false, rawUserId);
        }

        public void SetEmbeddedSignature(
            bool isCritical,
            PgpSignature pgpSignature)
        {
            if (pgpSignature == null)
                throw new ArgumentNullException(nameof(pgpSignature));

            byte[] sig = pgpSignature.GetEncoded();
            byte[] data;

            // TODO Should be >= ?
            if (sig.Length - 1 > 256)
            {
                data = new byte[sig.Length - 3];
            }
            else
            {
                data = new byte[sig.Length - 2];
            }

            Array.Copy(sig, sig.Length - data.Length, data, 0, data.Length);

            subpackets[SignatureSubpacketTag.EmbeddedSignature] = new EmbeddedSignature(isCritical, false, data);
        }

        public bool IsPrimaryUserId
        {
            get
            {
                if (subpackets.TryGetValue(SignatureSubpacketTag.PrimaryUserId, out var p))
                    return ((PrimaryUserId)p).IsPrimaryUserId;
                return false;
            }
        }

        public void SetPrimaryUserId(bool isCritical, bool isPrimaryUserId)
        {
            subpackets[SignatureSubpacketTag.PrimaryUserId] = new PrimaryUserId(isCritical, isPrimaryUserId);
        }

        public IEnumerable<PgpNotation> GetNotationData()
        {
            foreach (var notationData in this.notations)
            {
                // FIXME: Binary
                yield return new PgpNotation(notationData.GetNotationName(), notationData.GetNotationValue(), notationData.IsHumanReadable);
            }
        }

        public void SetNotationData(
            bool isCritical,
            bool isHumanReadable,
            string notationName,
            string notationValue)
        {
            notations.Add(new NotationData(isCritical, isHumanReadable, notationName, notationValue));
        }

        /// <summary>
        /// Sets revocation reason sub packet
        /// </summary>	    
        public void SetRevocationReason(bool isCritical, PgpRevocationReason reason, string description)
        {
            subpackets[SignatureSubpacketTag.RevocationReason] = new RevocationReason(isCritical, reason, description);
        }

        /// <summary>
        /// Sets revocation key sub packet
        /// </summary>	
        public void SetRevocationKey(bool isCritical, PgpPublicKeyAlgorithm keyAlgorithm, byte[] fingerprint)
        {
            subpackets[SignatureSubpacketTag.RevocationKey] = new RevocationKey(isCritical, RevocationKeyTag.ClassDefault, keyAlgorithm, fingerprint);
        }

        public long? IssuerKeyId
        {
            get
            {
                if (subpackets.TryGetValue(SignatureSubpacketTag.IssuerKeyId, out var p))
                    return ((IssuerKeyId)p).KeyId;
                return null;
            }
        }

        /// <summary>
        /// Sets issuer key sub packet
        /// </summary>	
        public void SetIssuerKeyId(bool isCritical, long keyId)
        {
            subpackets[SignatureSubpacketTag.IssuerKeyId] = new IssuerKeyId(isCritical, keyId);
        }

        internal SignatureSubpacket[] ToSubpacketArray()
        {
            if (orginalSubpackets != null)
                return orginalSubpackets;
            return subpackets.Values.Concat(notations).ToArray();
        }
    }
}
