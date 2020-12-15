using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Bcpg.Sig;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Generator for PGP signatures.</summary>
    public class PgpSignatureGenerator : PgpSignatureBase
    {
        private static readonly SignatureSubpacket[] EmptySignatureSubpackets = new SignatureSubpacket[0];

        private PublicKeyAlgorithmTag keyAlgorithm;
        private HashAlgorithmTag hashAlgorithm;

        private SignatureSubpacket[] unhashed = EmptySignatureSubpackets;
        private SignatureSubpacket[] hashed = EmptySignatureSubpackets;

        private PgpPrivateKey privateKey;

        public override HashAlgorithmTag HashAlgorithm => hashAlgorithm;

        /// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        public PgpSignatureGenerator(
            PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.hashAlgorithm = hashAlgorithm;
        }

        /// <summary>Initialise the generator for signing.</summary>
        public void InitSign(int signatureType, PgpPrivateKey privateKey)
        {
            this.privateKey = privateKey;
            Init(signatureType);
        }

        public void SetHashedSubpackets(
            PgpSignatureSubpacketVector hashedPackets)
        {
            hashed = hashedPackets == null
                ? EmptySignatureSubpackets
                : hashedPackets.ToSubpacketArray();
        }

        public void SetUnhashedSubpackets(
            PgpSignatureSubpacketVector unhashedPackets)
        {
            unhashed = unhashedPackets == null
                ? EmptySignatureSubpackets
                : unhashedPackets.ToSubpacketArray();
        }

        /// <summary>Return the one pass header associated with the current signature.</summary>
        public PgpOnePassSignature GenerateOnePassVersion(bool isNested)
        {
            return new PgpOnePassSignature(new OnePassSignaturePacket(signatureType, hashAlgorithm, keyAlgorithm, privateKey.KeyId, isNested));
        }

        /// <summary>Return a signature object containing the current signature state.</summary>
        public PgpSignature Generate()
        {
            SignatureSubpacket[] hPkts = hashed, unhPkts = unhashed;

            if (!packetPresent(hashed, SignatureSubpacketTag.CreationTime))
            {
                hPkts = insertSubpacket(hPkts, new SignatureCreationTime(false, DateTime.UtcNow));
            }

            if (!packetPresent(hashed, SignatureSubpacketTag.IssuerKeyId)
                && !packetPresent(unhashed, SignatureSubpacketTag.IssuerKeyId))
            {
                unhPkts = insertSubpacket(unhPkts, new IssuerKeyId(false, privateKey.KeyId));
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
                sOut.WriteByte((byte)signatureType);
                sOut.WriteByte((byte)keyAlgorithm);
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

            bool isRsa = keyAlgorithm == PublicKeyAlgorithmTag.RsaSign || keyAlgorithm == PublicKeyAlgorithmTag.RsaGeneral;
            if (isRsa != privateKey.Key is RSA)
                throw new PgpException("invalid combination of algorithms");

            var signature = Sign(hData, privateKey.Key);

            return new PgpSignature(
                new SignaturePacket(signatureType, privateKey.KeyId, keyAlgorithm,
                    hashAlgorithm, hPkts, unhPkts, signature.Hash.AsSpan(0, 2).ToArray(), signature.SigValues));
        }

        /// <summary>Generate a certification for the passed in ID and key.</summary>
        /// <param name="id">The ID we are certifying against the public key.</param>
        /// <param name="pubKey">The key we are certifying against the ID.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(
            string id,
            PgpPublicKey pubKey)
        {
            UpdateWithPublicKey(pubKey);

            //
            // hash in the id
            //
            UpdateWithIdData(0xb4, Encoding.UTF8.GetBytes(id));

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
            UpdateWithPublicKey(pubKey);

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
                UpdateWithIdData(0xd1, bOut.ToArray());
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
            UpdateWithPublicKey(masterKey);
            UpdateWithPublicKey(pubKey);

            return Generate();
        }

        /// <summary>Generate a certification, such as a revocation, for the passed in key.</summary>
        /// <param name="pubKey">The key we are certifying.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(PgpPublicKey pubKey)
        {
            UpdateWithPublicKey(pubKey);

            return Generate();
        }

        private byte[] GetEncodedPublicKey(PgpPublicKey pubKey)
        {
            try
            {
                return pubKey.publicPk.GetEncodedContents();
            }
            catch (IOException e)
            {
                throw new PgpException("exception preparing key.", e);
            }
        }

        private bool packetPresent(
            SignatureSubpacket[] packets,
            SignatureSubpacketTag type)
        {
            for (int i = 0; i != packets.Length; i++)
            {
                if (packets[i].SubpacketType == type)
                {
                    return true;
                }
            }

            return false;
        }

        private SignatureSubpacket[] insertSubpacket(
            SignatureSubpacket[] packets,
            SignatureSubpacket subpacket)
        {
            SignatureSubpacket[] tmp = new SignatureSubpacket[packets.Length + 1];
            tmp[0] = subpacket;
            packets.CopyTo(tmp, 1);
            return tmp;
        }

        private void UpdateWithIdData(
            int header,
            byte[] idBytes)
        {
            this.Update(
                (byte)header,
                (byte)(idBytes.Length >> 24),
                (byte)(idBytes.Length >> 16),
                (byte)(idBytes.Length >> 8),
                (byte)(idBytes.Length));
            this.Update(idBytes);
        }

        private void UpdateWithPublicKey(
            PgpPublicKey key)
        {
            byte[] keyBytes = GetEncodedPublicKey(key);

            this.Update(
                (byte)0x99,
                (byte)(keyBytes.Length >> 8),
                (byte)(keyBytes.Length));
            this.Update(keyBytes);
        }
    }
}
