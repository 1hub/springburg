using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// Often a PGP key ring file is made up of a succession of master/sub-key key rings.
    /// If you want to read an entire secret key file in one hit this is the class for you.
    /// </summary>
    public class PgpSecretKeyRingBundle : PgpEncodable
    {
        private readonly IDictionary<long, PgpSecretKeyRing> secretRings;
        private readonly IList<long> order;

        private PgpSecretKeyRingBundle(
            IDictionary<long, PgpSecretKeyRing> secretRings,
            IList<long> order)
        {
            this.secretRings = secretRings;
            this.order = order;
        }

        public PgpSecretKeyRingBundle(byte[] encoding)
            : this(new MemoryStream(encoding, false))
        {
        }

        /// <summary>Build a PgpSecretKeyRingBundle from the passed in input stream.</summary>
        /// <param name="inputStream">Input stream containing data.</param>
        /// <exception cref="IOException">If a problem parsing the stream occurs.</exception>
        /// <exception cref="PgpException">If an object is encountered which isn't a PgpSecretKeyRing.</exception>
        public PgpSecretKeyRingBundle(Stream inputStream)
        {
            this.secretRings = new Dictionary<long, PgpSecretKeyRing>();
            this.order = new List<long>();

            var packetReader = new PacketReader(inputStream);
            while (packetReader.NextPacketTag() == PacketTag.SecretKey)
            {
                var keyRing = new PgpSecretKeyRing(packetReader);
                long key = keyRing.GetPublicKey().KeyId;
                secretRings.Add(key, keyRing);
                order.Add(key);
            }
        }

        public PgpSecretKeyRingBundle(IEnumerable<PgpSecretKeyRing> e)
        {
            this.secretRings = new Dictionary<long, PgpSecretKeyRing>();
            this.order = new List<long>();

            foreach (PgpSecretKeyRing pgpSecret in e)
            {
                long key = pgpSecret.GetPublicKey().KeyId;
                secretRings.Add(key, pgpSecret);
                order.Add(key);
            }
        }

        /// <summary>Return the number of rings in this collection.</summary>
        public int Count => order.Count;

        /// <summary>Allow enumeration of the secret key rings making up this collection.</summary>
        public IEnumerable<PgpSecretKeyRing> GetKeyRings() => secretRings.Values;

        /// <summary>Allow enumeration of the key rings associated with the passed in userId.</summary>
        /// <param name="userId">The user ID to be matched.</param>
        /// <param name="matchPartial">If true, userId need only be a substring of an actual ID string to match.</param>
        /// <param name="ignoreCase">If true, case is ignored in user ID comparisons.</param>
        /// <returns>An <c>IEnumerable</c> of key rings which matched (possibly none).</returns>
        public IEnumerable<PgpSecretKeyRing> GetKeyRings(
            string userId,
            bool matchPartial = false,
            bool ignoreCase = false)
        {
            IList<PgpSecretKeyRing> rings = new List<PgpSecretKeyRing>();
            StringComparison comparison = ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

            foreach (PgpSecretKeyRing pubRing in GetKeyRings())
            {
                foreach (string nextUserID in pubRing.GetSecretKey().UserIds)
                {
                    if ((matchPartial && nextUserID.IndexOf(userId, comparison) >= 0) ||
                        (!matchPartial && nextUserID.Equals(userId, comparison)))
                    {
                        rings.Add(pubRing);
                    }
                }
            }

            return rings;
        }

        /// <summary>Return the PGP secret key associated with the given key id.</summary>
        /// <param name="keyId">The ID of the secret key to return.</param>
        public PgpSecretKey GetSecretKey(long keyId)
        {
            foreach (PgpSecretKeyRing secRing in GetKeyRings())
            {
                PgpSecretKey sec = secRing.GetSecretKey(keyId);
                if (sec != null)
                {
                    return sec;
                }
            }
            return null;
        }

        /// <summary>Return the secret key ring which contains the key referred to by keyId</summary>
        /// <param name="keyId">The ID of the secret key</param>
        public PgpSecretKeyRing GetSecretKeyRing(long keyId)
        {
            long id = keyId;

            if (secretRings.TryGetValue(id, out var secretKeyRing))
            {
                return secretKeyRing;
            }

            foreach (PgpSecretKeyRing secretRing in GetKeyRings())
            {
                PgpSecretKey secret = secretRing.GetSecretKey(keyId);
                if (secret != null)
                {
                    return secretRing;
                }
            }

            return null;
        }

        /// <summary>
        /// Return true if a key matching the passed in key ID is present, false otherwise.
        /// </summary>
        /// <param name="keyID">key ID to look for.</param>
        public bool Contains(long keyID)
        {
            return GetSecretKey(keyID) != null;
        }

        public override void Encode(IPacketWriter outStr)
        {
            foreach (long key in order)
            {
                secretRings[key].Encode(outStr);
            }
        }

        /// <summary>
        /// Return a new bundle containing the contents of the passed in bundle and
        /// the passed in secret key ring.
        /// </summary>
        /// <param name="bundle">The <c>PgpSecretKeyRingBundle</c> the key ring is to be added to.</param>
        /// <param name="secretKeyRing">The key ring to be added.</param>
        /// <returns>A new <c>PgpSecretKeyRingBundle</c> merging the current one with the passed in key ring.</returns>
        /// <exception cref="ArgumentException">If the keyId for the passed in key ring is already present.</exception>
        public static PgpSecretKeyRingBundle AddSecretKeyRing(
            PgpSecretKeyRingBundle bundle,
            PgpSecretKeyRing secretKeyRing)
        {
            long key = secretKeyRing.GetPublicKey().KeyId;

            if (bundle.secretRings.ContainsKey(key))
            {
                throw new ArgumentException("Collection already contains a key with a keyId for the passed in ring.");
            }

            IDictionary<long, PgpSecretKeyRing> newSecretRings = new Dictionary<long, PgpSecretKeyRing>(bundle.secretRings);
            IList<long> newOrder = new List<long>(bundle.order);

            newSecretRings[key] = secretKeyRing;
            newOrder.Add(key);

            return new PgpSecretKeyRingBundle(newSecretRings, newOrder);
        }

        /// <summary>
        /// Return a new bundle containing the contents of the passed in bundle with
        /// the passed in secret key ring removed.
        /// </summary>
        /// <param name="bundle">The <c>PgpSecretKeyRingBundle</c> the key ring is to be removed from.</param>
        /// <param name="secretKeyRing">The key ring to be removed.</param>
        /// <returns>A new <c>PgpSecretKeyRingBundle</c> not containing the passed in key ring.</returns>
        /// <exception cref="ArgumentException">If the keyId for the passed in key ring is not present.</exception>
        public static PgpSecretKeyRingBundle RemoveSecretKeyRing(
            PgpSecretKeyRingBundle bundle,
            PgpSecretKeyRing secretKeyRing)
        {
            long key = secretKeyRing.GetPublicKey().KeyId;

            if (!bundle.secretRings.ContainsKey(key))
            {
                throw new ArgumentException("Collection does not contain a key with a keyId for the passed in ring.");
            }

            IDictionary<long, PgpSecretKeyRing> newSecretRings = new Dictionary<long, PgpSecretKeyRing>(bundle.secretRings);
            IList<long> newOrder = new List<long>(bundle.order);

            newSecretRings.Remove(key);
            newOrder.Remove(key);

            return new PgpSecretKeyRingBundle(newSecretRings, newOrder);
        }
    }
}
