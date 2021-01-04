using Springburg.Cryptography.OpenPgp.Packet;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Springburg.Cryptography.OpenPgp
{
    /// <summary>
    /// Often a PGP key ring file is made up of a succession of master/sub-key key rings.
    /// If you want to read an entire public key file in one hit this is the class for you.
    /// </summary>
    public class PgpPublicKeyRingBundle : PgpEncodable
    {
        private readonly IDictionary<long, PgpPublicKeyRing> pubRings;
        private readonly IList<long> order;

        private PgpPublicKeyRingBundle(
            IDictionary<long, PgpPublicKeyRing> pubRings,
            IList<long> order)
        {
            this.pubRings = pubRings;
            this.order = order;
        }

        public PgpPublicKeyRingBundle(byte[] encoding)
            : this(new MemoryStream(encoding, false))
        {
        }

        /// <summary>Build a PgpPublicKeyRingBundle from the passed in input stream.</summary>
        /// <param name="inputStream">Input stream containing data.</param>
        /// <exception cref="IOException">If a problem parsing the stream occurs.</exception>
        /// <exception cref="PgpException">If an object is encountered which isn't a PgpPublicKeyRing.</exception>
        public PgpPublicKeyRingBundle(Stream inputStream)
            : this(new PacketReader(inputStream))
        {
        }

        public PgpPublicKeyRingBundle(IPacketReader packetReader)
        {
            this.pubRings = new Dictionary<long, PgpPublicKeyRing>();
            this.order = new List<long>(); 

            while (packetReader.NextPacketTag() == PacketTag.PublicKey)
            {
                var keyRing = new PgpPublicKeyRing(packetReader);
                long key = keyRing.GetPublicKey().KeyId;
                pubRings.Add(key, keyRing);
                order.Add(key);
            }
        }

        public PgpPublicKeyRingBundle(IEnumerable<PgpPublicKeyRing> e)
        {
            this.pubRings = new Dictionary<long, PgpPublicKeyRing>();
            this.order = new List<long>();

            foreach (PgpPublicKeyRing pgpPub in e)
            {
                long key = pgpPub.GetPublicKey().KeyId;
                pubRings.Add(key, pgpPub);
                order.Add(key);
            }
        }

        /// <summary>Return the number of key rings in this collection.</summary>
        public int Count => order.Count;

        /// <summary>Allow enumeration of the public key rings making up this collection.</summary>
        public IEnumerable<PgpPublicKeyRing> GetKeyRings() => pubRings.Values;

        /// <summary>Allow enumeration of the key rings associated with the passed in userId.</summary>
        /// <param name="userId">The user ID to be matched.</param>
        /// <param name="matchPartial">If true, userId need only be a substring of an actual ID string to match.</param>
        /// <param name="ignoreCase">If true, case is ignored in user ID comparisons.</param>
        /// <returns>An <c>IEnumerable</c> of key rings which matched (possibly none).</returns>
        public IEnumerable<PgpPublicKeyRing> GetKeyRings(
            string userId,
            bool matchPartial = false,
            bool ignoreCase = false)
        {
            IList<PgpPublicKeyRing> rings = new List<PgpPublicKeyRing>();
            StringComparison comparison = ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

            foreach (PgpPublicKeyRing pubRing in GetKeyRings())
            {
                foreach (string nextUserID in pubRing.GetPublicKey().GetUserIds().Select(u => u.UserId!))
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

        /// <summary>Return the PGP public key associated with the given key id.</summary>
        /// <param name="keyId">The ID of the public key to return.</param>
        public PgpKey? GetPublicKey(long keyId)
        {
            foreach (PgpPublicKeyRing pubRing in GetKeyRings())
            {
                PgpKey? pub = pubRing.GetPublicKey(keyId);
                if (pub != null)
                {
                    return pub;
                }
            }

            return null;
        }

        /// <summary>Return the public key ring which contains the key referred to by keyId</summary>
        /// <param name="keyId">key ID to match against</param>
        public PgpPublicKeyRing? GetPublicKeyRing(long keyId)
        {
            if (pubRings.TryGetValue(keyId, out var keyRing))
            {
                return keyRing;
            }

            foreach (PgpPublicKeyRing pubRing in GetKeyRings())
            {
                PgpKey? pub = pubRing.GetPublicKey(keyId);

                if (pub != null)
                {
                    return pubRing;
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
            return GetPublicKey(keyID) != null;
        }

        public override void Encode(IPacketWriter outStr)
        {
            foreach (long key in order)
            {
                PgpPublicKeyRing sec = pubRings[key];
                sec.Encode(outStr);
            }
        }

        /// <summary>
        /// Return a new bundle containing the contents of the passed in bundle and
        /// the passed in public key ring.
        /// </summary>
        /// <param name="bundle">The <c>PgpPublicKeyRingBundle</c> the key ring is to be added to.</param>
        /// <param name="publicKeyRing">The key ring to be added.</param>
        /// <returns>A new <c>PgpPublicKeyRingBundle</c> merging the current one with the passed in key ring.</returns>
        /// <exception cref="ArgumentException">If the keyId for the passed in key ring is already present.</exception>
        public static PgpPublicKeyRingBundle AddPublicKeyRing(
            PgpPublicKeyRingBundle bundle,
            PgpPublicKeyRing publicKeyRing)
        {
            long key = publicKeyRing.GetPublicKey().KeyId;

            if (bundle.pubRings.ContainsKey(key))
            {
                throw new ArgumentException("Bundle already contains a key with a keyId for the passed in ring.");
            }

            IDictionary<long, PgpPublicKeyRing> newPubRings = new Dictionary<long, PgpPublicKeyRing>(bundle.pubRings);
            IList<long> newOrder = new List<long>(bundle.order);

            newPubRings[key] = publicKeyRing;

            newOrder.Add(key);

            return new PgpPublicKeyRingBundle(newPubRings, newOrder);
        }

        /// <summary>
        /// Return a new bundle containing the contents of the passed in bundle with
        /// the passed in public key ring removed.
        /// </summary>
        /// <param name="bundle">The <c>PgpPublicKeyRingBundle</c> the key ring is to be removed from.</param>
        /// <param name="publicKeyRing">The key ring to be removed.</param>
        /// <returns>A new <c>PgpPublicKeyRingBundle</c> not containing the passed in key ring.</returns>
        /// <exception cref="ArgumentException">If the keyId for the passed in key ring is not present.</exception>
        public static PgpPublicKeyRingBundle RemovePublicKeyRing(
            PgpPublicKeyRingBundle bundle,
            PgpPublicKeyRing publicKeyRing)
        {
            long key = publicKeyRing.GetPublicKey().KeyId;

            if (!bundle.pubRings.ContainsKey(key))
            {
                throw new ArgumentException("Bundle does not contain a key with a keyId for the passed in ring.");
            }

            IDictionary<long, PgpPublicKeyRing> newPubRings = new Dictionary<long, PgpPublicKeyRing>(bundle.pubRings);
            IList<long> newOrder = new List<long>(bundle.order);

            newPubRings.Remove(key);
            newOrder.Remove(key);

            return new PgpPublicKeyRingBundle(newPubRings, newOrder);
        }
    }
}
