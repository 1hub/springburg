using System;
using System.Diagnostics;
using System.Reflection.Metadata;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    class PgpSignatureHelper
    {
        private HashAlgorithm sig;
        private byte lastb; // Initial value anything but '\r'
        private int signatureType;
        private HashAlgorithmTag hashAlgorithm;

        public PgpSignatureHelper(int signatureType, HashAlgorithmTag hashAlgorithm)
        {
            this.signatureType = signatureType;
            this.hashAlgorithm = hashAlgorithm;
            this.lastb = 0;
            this.sig = PgpUtilities.GetHashAlgorithm(hashAlgorithm);
        }

        public int SignatureType => signatureType;

        public void Update(byte b)
        {
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                doCanonicalUpdateByte(b);
            }
            else
            {
                sig.TransformBlock(new byte[] { b }, 0, 1, null, 0);
            }
        }

        private void doCanonicalUpdateByte(byte b)
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
                sig.TransformBlock(new byte[] { b }, 0, 1, null, 0);
            }

            lastb = b;
        }

        private void doUpdateCRLF()
        {
            sig.TransformBlock(new byte[] { (byte)'\r', (byte)'\n' }, 0, 2, null, 0);
        }

        public void Update(params byte[] bytes)
        {
            Update(bytes, 0, bytes.Length);
        }

        public void Update(
            byte[] bytes,
            int off,
            int length)
        {
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                int finish = off + length;

                for (int i = off; i != finish; i++)
                {
                    doCanonicalUpdateByte(bytes[i]);
                }
            }
            else
            {
                sig.TransformBlock(bytes, off, length, null, 0);
            }
        }

        public bool Verify(MPInteger[] signature, byte[] trailer, AsymmetricAlgorithm key)
        {
            sig.TransformFinalBlock(trailer, 0, trailer.Length);
            var hash = sig.Hash;
            if (key is RSA rsa)
                return rsa.VerifyHash(hash, signature[0].Value, PgpUtilities.GetHashAlgorithmName(hashAlgorithm), RSASignaturePadding.Pkcs1);

            Debug.Assert(signature.Length == 2);
            int rsLength = Math.Max(signature[0].Value.Length, signature[1].Value.Length);
            byte[] sigBytes = new byte[rsLength * 2];
            signature[0].Value.CopyTo(sigBytes, rsLength - signature[0].Value.Length);
            signature[1].Value.CopyTo(sigBytes, sigBytes.Length - signature[1].Value.Length);

            if (key is DSA dsa)
                return dsa.VerifySignature(hash, sigBytes, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            if (key is ECDsa ecdsa)
                return ecdsa.VerifyHash(hash, sigBytes, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

            throw new NotImplementedException();
        }

        public (MPInteger[] SigValues, byte[] Hash) Sign(byte[] trailer, AsymmetricAlgorithm privateKey)
        {
            sig.TransformFinalBlock(trailer, 0, trailer.Length);

            byte[] sigBytes;
            if (privateKey is RSA rsa)
                sigBytes = rsa.SignHash(sig.Hash, PgpUtilities.GetHashAlgorithmName(hashAlgorithm), RSASignaturePadding.Pkcs1);
            else if (privateKey is DSA dsa)
                sigBytes = dsa.CreateSignature(sig.Hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            else if (privateKey is ECDsa ecdsa)
                sigBytes = ecdsa.SignHash(sig.Hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            else
                throw new NotImplementedException();

            MPInteger[] sigValues;
            if (privateKey is RSA)
            {
                sigValues = new MPInteger[] { new MPInteger(sigBytes) };
            }
            else
            {
                sigValues = new MPInteger[] {
                    new MPInteger(sigBytes.AsSpan(0, sigBytes.Length / 2).ToArray()),
                    new MPInteger(sigBytes.AsSpan(sigBytes.Length / 2).ToArray())
                };
            }

            return (sigValues, sig.Hash);
        }
    }
}
