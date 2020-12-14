using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Bcpg.Sig;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>Generator for PGP signatures.</remarks>
    // TODO Should be able to implement ISigner?
    public class PgpSignatureGenerator
    {
        private static readonly SignatureSubpacket[] EmptySignatureSubpackets = new SignatureSubpacket[0];

        private PublicKeyAlgorithmTag keyAlgorithm;
        private HashAlgorithmTag hashAlgorithm;
        private PgpPrivateKey privKey;
        private HashAlgorithm dig;
        private int signatureType;
        private byte lastb;

        private SignatureSubpacket[] unhashed = EmptySignatureSubpackets;
        private SignatureSubpacket[] hashed = EmptySignatureSubpackets;

        /// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        public PgpSignatureGenerator(
            PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.hashAlgorithm = hashAlgorithm;
        }

        /// <summary>Initialise the generator for signing.</summary>
        public void InitSign(
            int sigType,
            PgpPrivateKey key)
        {
            InitSign(sigType, key, null);
        }

        /// <summary>Initialise the generator for signing.</summary>
        public void InitSign(
            int sigType,
            PgpPrivateKey key,
            RandomNumberGenerator random)
        {
            this.privKey = key;
            this.signatureType = sigType;

            dig = PgpUtilities.GetHashAlgorithm(hashAlgorithm);
            lastb = 0;
        }

        public void Update(
            byte b)
        {
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                doCanonicalUpdateByte(b);
            }
            else
            {
                doUpdateByte(b);
            }
        }

        private void doCanonicalUpdateByte(
            byte b)
        {
            if (b == '\r')
            {
                doUpdateCRLF();
            }
            else if (b == '\n')
            {
                if (lastb != '\r')
                {
                    doUpdateCRLF();
                }
            }
            else
            {
                doUpdateByte(b);
            }

            lastb = b;
        }

        private void doUpdateCRLF()
        {
            doUpdateByte((byte)'\r');
            doUpdateByte((byte)'\n');
        }

        private void doUpdateByte(
            byte b)
        {
            dig.TransformBlock(new byte[] { b }, 0, 1, null, 0);
        }

        public void Update(
            params byte[] b)
        {
            Update(b, 0, b.Length);
        }

        public void Update(
            byte[] b,
            int off,
            int len)
        {
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                int finish = off + len;

                for (int i = off; i != finish; i++)
                {
                    doCanonicalUpdateByte(b[i]);
                }
            }
            else
            {
                dig.TransformBlock(b, off, len, null, 0);
            }
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
        public PgpOnePassSignature GenerateOnePassVersion(
            bool isNested)
        {
            return new PgpOnePassSignature(
                new OnePassSignaturePacket(
                    signatureType, hashAlgorithm, keyAlgorithm, privKey.KeyId, isNested));
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
                unhPkts = insertSubpacket(unhPkts, new IssuerKeyId(false, privKey.KeyId));
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

                hData = sOut.ToArray();
            }
            catch (IOException e)
            {
                throw new PgpException("exception encoding hashed data.", e);
            }

            dig.TransformBlock(hData, 0, hData.Length, null, 0);

            hData = new byte[]
            {
                (byte) version,
                0xff,
                (byte)(hData.Length >> 24),
                (byte)(hData.Length >> 16),
                (byte)(hData.Length >> 8),
                (byte) hData.Length
            };

            byte[] sigBytes;

            dig.TransformFinalBlock(hData, 0, hData.Length);

            // an RSA signature
            bool isRsa = keyAlgorithm == PublicKeyAlgorithmTag.RsaSign
                || keyAlgorithm == PublicKeyAlgorithmTag.RsaGeneral;

            if (isRsa && privKey.Key is not RSA)
                throw new PgpException("invalid combination of algorithms");

            if (privKey.Key is RSA rsa)
                sigBytes = rsa.SignHash(dig.Hash, PgpUtilities.GetHashAlgorithmName(hashAlgorithm), RSASignaturePadding.Pkcs1);
            else if (privKey.Key is DSA dsa)
                sigBytes = dsa.CreateSignature(dig.Hash, DSASignatureFormat.Rfc3279DerSequence);
            else if (privKey.Key is ECDsa ecdsa)
                sigBytes = ecdsa.SignHash(dig.Hash, DSASignatureFormat.Rfc3279DerSequence);
            else
                throw new NotImplementedException();

            byte[] digest = dig.Hash;
            byte[] fingerPrint = new byte[] { digest[0], digest[1] };

            MPInteger[] sigValues = isRsa
                ? PgpUtilities.RsaSigToMpi(sigBytes)
                : PgpUtilities.DsaSigToMpi(sigBytes);

            return new PgpSignature(
                new SignaturePacket(signatureType, privKey.KeyId, keyAlgorithm,
                    hashAlgorithm, hPkts, unhPkts, fingerPrint, sigValues));
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

            return this.Generate();
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
        public PgpSignature GenerateCertification(
            PgpPublicKey pubKey)
        {
            UpdateWithPublicKey(pubKey);

            return Generate();
        }

        private byte[] GetEncodedPublicKey(
            PgpPublicKey pubKey)
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
