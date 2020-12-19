using System;
using Org.BouncyCastle.Bcpg.Sig;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Container for a list of signature subpackets.</summary>
    public class PgpSignatureSubpacketVector
    {
        private readonly SignatureSubpacket[] packets;

        internal PgpSignatureSubpacketVector(
            SignatureSubpacket[] packets)
        {
            this.packets = packets;
        }

        public SignatureSubpacket GetSubpacket(
            SignatureSubpacketTag type)
        {
            for (int i = 0; i != packets.Length; i++)
            {
                if (packets[i].SubpacketType == type)
                {
                    return packets[i];
                }
            }

            return null;
        }

        /**
		 * Return true if a particular subpacket type exists.
		 *
		 * @param type type to look for.
		 * @return true if present, false otherwise.
		 */
        public bool HasSubpacket(
            SignatureSubpacketTag type)
        {
            return GetSubpacket(type) != null;
        }

        /**
		 * Return all signature subpackets of the passed in type.
		 * @param type subpacket type code
		 * @return an array of zero or more matching subpackets.
		 */
        public SignatureSubpacket[] GetSubpackets(
            SignatureSubpacketTag type)
        {
            int count = 0;
            for (int i = 0; i < packets.Length; ++i)
            {
                if (packets[i].SubpacketType == type)
                {
                    ++count;
                }
            }

            SignatureSubpacket[] result = new SignatureSubpacket[count];

            int pos = 0;
            for (int i = 0; i < packets.Length; ++i)
            {
                if (packets[i].SubpacketType == type)
                {
                    result[pos++] = packets[i];
                }
            }

            return result;
        }

        public NotationData[] GetNotationDataOccurrences()
        {
            SignatureSubpacket[] notations = GetSubpackets(SignatureSubpacketTag.NotationData);
            NotationData[] vals = new NotationData[notations.Length];

            for (int i = 0; i < notations.Length; i++)
            {
                vals[i] = (NotationData)notations[i];
            }

            return vals;
        }

        public long GetIssuerKeyId()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.IssuerKeyId);

            return p == null ? 0 : ((IssuerKeyId)p).KeyId;
        }

        public bool HasSignatureCreationTime()
        {
            return GetSubpacket(SignatureSubpacketTag.CreationTime) != null;
        }

        public DateTime GetSignatureCreationTime()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.CreationTime);
            if (p == null)
                throw new PgpException("SignatureCreationTime not available");

            return ((SignatureCreationTime)p).Time;
        }

        /// <summary>
        /// Return the number of seconds a signature is valid for after its creation date.
        /// </summary>
        /// <returns>Seconds a signature is valid for or TimeSpan.MaxValue if signature never expires.</returns>
        public TimeSpan GetSignatureExpirationTime()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.ExpireTime);
            return p == null ? TimeSpan.MaxValue : ((SignatureExpirationTime)p).Time;
        }

        /// <summary>
        /// Return the number of seconds a key is valid for after its creation date.
        /// </summary>
        /// <returns>Seconds a key is valid for or TimeSpan.MaxValue if signature never expires.</returns>
        public TimeSpan GetKeyExpirationTime()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.KeyExpireTime);
            return p == null ? TimeSpan.MaxValue : ((KeyExpirationTime)p).Time;
        }

        public HashAlgorithmTag[] GetPreferredHashAlgorithms()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.PreferredHashAlgorithms);

            return p == null ? null : ((PreferredAlgorithms)p).GetPreferences<HashAlgorithmTag>();
        }

        public SymmetricKeyAlgorithmTag[] GetPreferredSymmetricAlgorithms()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.PreferredSymmetricAlgorithms);

            return p == null ? null : ((PreferredAlgorithms)p).GetPreferences<SymmetricKeyAlgorithmTag>();
        }

        public CompressionAlgorithmTag[] GetPreferredCompressionAlgorithms()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.PreferredCompressionAlgorithms);

            return p == null ? null : ((PreferredAlgorithms)p).GetPreferences<CompressionAlgorithmTag>();
        }

        public KeyFlags GetKeyFlags()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.KeyFlags);

            return p == null ? 0 : ((Sig.KeyFlags)p).Flags;
        }

        public string GetSignerUserId()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.SignerUserId);

            return p == null ? null : ((SignerUserId)p).GetId();
        }

        public bool IsPrimaryUserId()
        {
            PrimaryUserId primaryId = (PrimaryUserId)
                this.GetSubpacket(SignatureSubpacketTag.PrimaryUserId);

            if (primaryId != null)
            {
                return primaryId.IsPrimaryUserId;
            }

            return false;
        }

        public SignatureSubpacketTag[] GetCriticalTags()
        {
            int count = 0;
            for (int i = 0; i != packets.Length; i++)
            {
                if (packets[i].IsCritical())
                {
                    count++;
                }
            }

            SignatureSubpacketTag[] list = new SignatureSubpacketTag[count];

            count = 0;

            for (int i = 0; i != packets.Length; i++)
            {
                if (packets[i].IsCritical())
                {
                    list[count++] = packets[i].SubpacketType;
                }
            }

            return list;
        }

        public Features GetFeatures()
        {
            SignatureSubpacket p = this.GetSubpacket(SignatureSubpacketTag.Features);

            if (p == null)
                return null;

            return new Features(p.IsCritical(), p.IsLongLength(), p.GetData());
        }

        /// <summary>Return the number of packets this vector contains.</summary>
        public int Count
        {
            get { return packets.Length; }
        }

        internal SignatureSubpacket[] ToSubpacketArray()
        {
            return packets;
        }
    }
}
