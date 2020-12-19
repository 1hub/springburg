using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// Class to hold a single master secret key and its subkeys.
    /// </summary>
    /// <remarks>
    /// Often PGP keyring files consist of multiple master keys, if you are trying to process
    /// or construct one of these you should use the PgpSecretKeyRingBundle class.
    /// </remarks>
    public class PgpSecretKeyRing : PgpKeyRing
    {
        private readonly IList<PgpSecretKey> keys;
        private readonly IList<PgpPublicKey> extraPubKeys;

        public PgpSecretKeyRing(IList<PgpSecretKey> keys)
            : this(keys, Array.Empty<PgpPublicKey>())
        {
        }

        public PgpSecretKeyRing(
            IList<PgpSecretKey> keys,
            IList<PgpPublicKey> extraPubKeys)
        {
            this.keys = new List<PgpSecretKey>(keys);
            this.extraPubKeys = new List<PgpPublicKey>(extraPubKeys);
        }

        public PgpSecretKeyRing(byte[] encoding)
            : this(new MemoryStream(encoding))
        {
        }

        public PgpSecretKeyRing(Stream inputStream)
            : this(new PacketReader(inputStream))
        {
        }

        internal PgpSecretKeyRing(PacketReader packetReader)
        {
            this.keys = new List<PgpSecretKey>();
            this.extraPubKeys = new List<PgpPublicKey>();

            PacketTag initialTag = packetReader.NextPacketTag();
            if (initialTag != PacketTag.SecretKey && initialTag != PacketTag.SecretSubkey)
            {
                throw new IOException("secret key ring doesn't start with secret key tag: "
                    + "tag 0x" + ((int)initialTag).ToString("X"));
            }

            SecretKeyPacket secret = (SecretKeyPacket)packetReader.ReadPacket();
            keys.Add(new PgpSecretKey(secret, ReadPublicKey(packetReader, secret.PublicKeyPacket)));

            // Read subkeys
            while (packetReader.NextPacketTag() == PacketTag.SecretSubkey || packetReader.NextPacketTag() == PacketTag.PublicSubkey)
            {
                if (packetReader.NextPacketTag() == PacketTag.SecretSubkey)
                {
                    SecretSubkeyPacket sub = (SecretSubkeyPacket)packetReader.ReadPacket();
                    keys.Add(new PgpSecretKey(sub, ReadPublicKey(packetReader, sub.PublicKeyPacket, subKey: true)));
                }
                else
                {
                    PublicSubkeyPacket sub = (PublicSubkeyPacket)packetReader.ReadPacket();
                    extraPubKeys.Add(ReadPublicKey(packetReader, sub, subKey: true));
                }
            }
        }

        /// <summary>Return the public key for the master key.</summary>
        public PgpPublicKey GetPublicKey() => keys[0].PublicKey;

        /// <summary>Return the master private key.</summary>
        public PgpSecretKey GetSecretKey() => keys[0];

        /// <summary>Allows enumeration of the secret keys.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSecretKey</c> objects.</returns>
        public IEnumerable<PgpSecretKey> GetSecretKeys() => keys;

        public PgpSecretKey GetSecretKey(long keyId) => keys.Where(k => k.KeyId == keyId).FirstOrDefault();

        /// <summary>
        /// Return an iterator of the public keys in the secret key ring that
        /// have no matching private key. At the moment only personal certificate data
        /// appears in this fashion.
        /// </summary>
        /// <returns>An <c>IEnumerable</c> of unattached, or extra, public keys.</returns>
        public IEnumerable<PgpPublicKey> GetExtraPublicKeys() => extraPubKeys;

        public override void Encode(PacketWriter outputStream)
        {
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            foreach (PgpSecretKey key in keys)
                key.Encode(outputStream);
            foreach (PgpPublicKey extraPubKey in extraPubKeys)
                extraPubKey.Encode(outputStream);
        }

        /// <summary>
        /// Replace the public key set on the secret ring with the corresponding key off the public ring.
        /// </summary>
        /// <param name="secretRing">Secret ring to be changed.</param>
        /// <param name="publicRing">Public ring containing the new public key set.</param>
        public static PgpSecretKeyRing ReplacePublicKeys(
            PgpSecretKeyRing secretRing,
            PgpPublicKeyRing publicRing)
        {
            IList<PgpSecretKey> newList = new List<PgpSecretKey>(secretRing.keys.Count);

            foreach (PgpSecretKey sk in secretRing.keys)
            {
                PgpPublicKey pk = publicRing.GetPublicKey(sk.KeyId);

                newList.Add(PgpSecretKey.ReplacePublicKey(sk, pk));
            }

            return new PgpSecretKeyRing(newList);
        }

        /// <summary>
        /// Return a copy of the passed in secret key ring, with the master key and sub keys encrypted
        /// using a new password and the passed in algorithm.
        /// </summary>
        /// <param name="ring">The <c>PgpSecretKeyRing</c> to be copied.</param>
        /// <param name="oldPassPhrase">The current password for key.</param>
        /// <param name="newPassPhrase">The new password for the key.</param>
        /// <param name="newEncAlgorithm">The algorithm to be used for the encryption.</param>
        /// <param name="rand">Source of randomness.</param>
        public static PgpSecretKeyRing CopyWithNewPassword(
            PgpSecretKeyRing ring,
            char[] oldPassPhrase,
            char[] newPassPhrase,
            SymmetricKeyAlgorithmTag newEncAlgorithm)
        {
            IList<PgpSecretKey> newKeys = new List<PgpSecretKey>(ring.keys.Count);
            foreach (PgpSecretKey secretKey in ring.GetSecretKeys())
            {
                if (secretKey.IsPrivateKeyEmpty)
                {
                    newKeys.Add(secretKey);
                }
                else
                {
                    newKeys.Add(PgpSecretKey.CopyWithNewPassword(secretKey, oldPassPhrase, newPassPhrase, newEncAlgorithm));
                }
            }

            return new PgpSecretKeyRing(newKeys, ring.extraPubKeys);
        }

        /// <summary>
        /// Returns a new key ring with the secret key passed in either added or
        /// replacing an existing one with the same key ID.
        /// </summary>
        /// <param name="secRing">The secret key ring to be modified.</param>
        /// <param name="secKey">The secret key to be inserted.</param>
        /// <returns>A new <c>PgpSecretKeyRing</c></returns>
        public static PgpSecretKeyRing InsertSecretKey(
            PgpSecretKeyRing secRing,
            PgpSecretKey secKey)
        {
            IList<PgpSecretKey> keys = new List<PgpSecretKey>(secRing.keys);
            InsertKey(keys, secKey);
            return new PgpSecretKeyRing(keys, secRing.extraPubKeys);
        }

        /// <summary>Returns a new key ring with the secret key passed in removed from the key ring.</summary>
        /// <param name="secRing">The secret key ring to be modified.</param>
        /// <param name="secKey">The secret key to be removed.</param>
        /// <returns>A new <c>PgpSecretKeyRing</c>, or null if secKey is not found.</returns>
        public static PgpSecretKeyRing RemoveSecretKey(
            PgpSecretKeyRing secRing,
            PgpSecretKey secKey)
        {
            IList<PgpSecretKey> keys = new List<PgpSecretKey>(secRing.keys);
            return RemoveKey(keys, secKey) ? new PgpSecretKeyRing(keys, secRing.extraPubKeys) : null;
        }
    }
}
