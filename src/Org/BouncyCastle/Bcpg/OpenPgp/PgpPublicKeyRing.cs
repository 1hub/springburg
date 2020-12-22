using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// Class to hold a single master public key and its subkeys.
    /// </summary>
    /// <remarks>
    /// Often PGP keyring files consist of multiple master keys, if you are trying to process
    /// or construct one of these you should use the PgpPublicKeyRingBundle class.
    /// </remarks>
    public class PgpPublicKeyRing : PgpKeyRing
    {
        private IList<PgpPublicKey> keys;

        public PgpPublicKeyRing(IList<PgpPublicKey> pubKeys)
        {
            this.keys = new List<PgpPublicKey>(pubKeys);
        }

        public PgpPublicKeyRing(byte[] encoding)
            : this(new MemoryStream(encoding, false))
        {
        }

        public PgpPublicKeyRing(Stream inputStream)
            : this(new PacketReader(inputStream))
        {
        }

        internal PgpPublicKeyRing(PacketReader packetReader)
        {
            this.keys = new List<PgpPublicKey>();

            PacketTag initialTag = packetReader.NextPacketTag();
            if (initialTag != PacketTag.PublicKey && initialTag != PacketTag.PublicSubkey)
            {
                throw new PgpUnexpectedPacketException();
            }

            PublicKeyPacket pubPk = (PublicKeyPacket)packetReader.ReadContainedPacket();
            keys.Add(ReadPublicKey(packetReader, pubPk));

            // Read subkeys
            while (packetReader.NextPacketTag() == PacketTag.PublicSubkey)
            {
                pubPk = (PublicSubkeyPacket)packetReader.ReadContainedPacket();
                keys.Add(ReadPublicKey(packetReader, pubPk, subKey: true));
            }
        }

        /// <summary>Return the first public key in the ring.</summary>
        public PgpPublicKey GetPublicKey() => keys[0];

        /// <summary>Return the public key referred to by the passed in key ID if it is present.</summary>
        public PgpPublicKey GetPublicKey(long keyId) => keys.Where(k => k.KeyId == keyId).FirstOrDefault();

        /// <summary>Allows enumeration of all the public keys.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpPublicKey</c> objects.</returns>
        public IEnumerable<PgpPublicKey> GetPublicKeys() => keys;

        public override void Encode(IPacketWriter outputStream)
        {
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            foreach (PgpPublicKey k in keys)
                k.Encode(outputStream);
        }

        /// <summary>
        /// Returns a new key ring with the public key passed in either added or
        /// replacing an existing one.
        /// </summary>
        /// <param name="pubRing">The public key ring to be modified.</param>
        /// <param name="pubKey">The public key to be inserted.</param>
        /// <returns>A new <c>PgpPublicKeyRing</c></returns>
        public static PgpPublicKeyRing InsertPublicKey(
            PgpPublicKeyRing pubRing,
            PgpPublicKey pubKey)
        {
            IList<PgpPublicKey> keys = new List<PgpPublicKey>(pubRing.keys);
            InsertKey(keys, pubKey);
            return new PgpPublicKeyRing(keys);
        }

        /// <summary>Returns a new key ring with the public key passed in removed from the key ring.</summary>
        /// <param name="pubRing">The public key ring to be modified.</param>
        /// <param name="pubKey">The public key to be removed.</param>
        /// <returns>A new <c>PgpPublicKeyRing</c>, or null if pubKey is not found.</returns>
        public static PgpPublicKeyRing RemovePublicKey(
            PgpPublicKeyRing pubRing,
            PgpPublicKey pubKey)
        {
            IList<PgpPublicKey> keys = new List<PgpPublicKey>(pubRing.keys);
            return RemoveKey(keys, pubKey) ? new PgpPublicKeyRing(keys) : null;
        }
    }
}
