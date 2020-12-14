using System;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>Generator for old style PGP V3 Signatures.</remarks>
    // TODO Should be able to implement ISigner?
    public class PgpV3SignatureGenerator
    {
        private PublicKeyAlgorithmTag keyAlgorithm;
        private HashAlgorithmTag hashAlgorithm;
        private PgpPrivateKey privKey;
        private HashAlgorithm dig;
        private int signatureType;
        private byte lastb;

        /// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        public PgpV3SignatureGenerator(
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
            byte[] b)
        {
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                for (int i = 0; i != b.Length; i++)
                {
                    doCanonicalUpdateByte(b[i]);
                }
            }
            else
            {
                dig.TransformBlock(b, 0, b.Length, null, 0);
            }
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

        /// <summary>Return the one pass header associated with the current signature.</summary>
        public PgpOnePassSignature GenerateOnePassVersion(
            bool isNested)
        {
            return new PgpOnePassSignature(
                new OnePassSignaturePacket(signatureType, hashAlgorithm, keyAlgorithm, privKey.KeyId, isNested));
        }

        /// <summary>Return a V3 signature object containing the current signature state.</summary>
        public PgpSignature Generate()
        {
            long creationTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            byte[] hData = new byte[]
            {
                (byte) signatureType,
                (byte)(creationTime >> 24),
                (byte)(creationTime >> 16),
                (byte)(creationTime >> 8),
                (byte) creationTime
            };

            dig.TransformFinalBlock(hData, 0, hData.Length);

            // an RSA signature
            bool isRsa = keyAlgorithm == PublicKeyAlgorithmTag.RsaSign
                || keyAlgorithm == PublicKeyAlgorithmTag.RsaGeneral;

            if (isRsa && privKey.Key is not RSA)
                throw new PgpException("invalid combination of algorithms");

            byte[] sigBytes;
            if (privKey.Key is RSA rsa)
                sigBytes = rsa.SignHash(dig.Hash, PgpUtilities.GetHashAlgorithmName(hashAlgorithm), RSASignaturePadding.Pkcs1);
            else if (privKey.Key is DSA dsa)
                sigBytes = dsa.CreateSignature(dig.Hash, DSASignatureFormat.Rfc3279DerSequence);
            else if (privKey.Key is ECDsa ecdsa)
                sigBytes = ecdsa.SignHash(dig.Hash, DSASignatureFormat.Rfc3279DerSequence);
            else
                throw new NotImplementedException();

            //byte[] sigBytes = sig.GenerateSignature();
            byte[] digest = dig.Hash;
            byte[] fingerPrint = new byte[] { digest[0], digest[1] };

            MPInteger[] sigValues = isRsa
                ? PgpUtilities.RsaSigToMpi(sigBytes)
                : PgpUtilities.DsaSigToMpi(sigBytes);

            return new PgpSignature(
                new SignaturePacket(3, signatureType, privKey.KeyId, keyAlgorithm,
                    hashAlgorithm, creationTime, fingerPrint, sigValues));
        }
    }
}
