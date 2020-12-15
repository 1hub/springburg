using System;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public abstract class PgpSignatureBase
    {
        protected HashAlgorithm sig;
        private byte lastb; // Initial value anything but '\r'
        protected int signatureType;

        protected void Init(int signatureType)
        {
            this.signatureType = signatureType;
            this.lastb = 0;
            this.sig = PgpUtilities.GetHashAlgorithm(HashAlgorithm);
        }

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

        protected bool Verify(byte[] signature, byte[] trailer, AsymmetricAlgorithm key)
        {
            sig.TransformFinalBlock(trailer, 0, trailer.Length);
            var hash = sig.Hash;
            if (key is RSA rsa)
                return rsa.VerifyHash(hash, signature, PgpUtilities.GetHashAlgorithmName(HashAlgorithm), RSASignaturePadding.Pkcs1);
            if (key is DSA dsa)
                return dsa.VerifySignature(hash, signature, DSASignatureFormat.Rfc3279DerSequence);
            if (key is ECDsa ecdsa)
                return ecdsa.VerifyHash(hash, signature, DSASignatureFormat.Rfc3279DerSequence);
            throw new NotImplementedException();
        }

        protected (MPInteger[] SigValues, byte[] Hash) Sign(byte[] trailer, AsymmetricAlgorithm privateKey)
        {
            sig.TransformFinalBlock(trailer, 0, trailer.Length);

            byte[] sigBytes;
            if (privateKey is RSA rsa)
                sigBytes = rsa.SignHash(sig.Hash, PgpUtilities.GetHashAlgorithmName(HashAlgorithm), RSASignaturePadding.Pkcs1);
            else if (privateKey is DSA dsa)
                sigBytes = dsa.CreateSignature(sig.Hash, DSASignatureFormat.Rfc3279DerSequence);
            else if (privateKey is ECDsa ecdsa)
                sigBytes = ecdsa.SignHash(sig.Hash, DSASignatureFormat.Rfc3279DerSequence);
            else
                throw new NotImplementedException();

            byte[] digest = sig.Hash;
            byte[] fingerPrint = new byte[] { digest[0], digest[1] };

            MPInteger[] sigValues = privateKey is RSA ? PgpUtilities.RsaSigToMpi(sigBytes) : PgpUtilities.DsaSigToMpi(sigBytes);

            return (sigValues, sig.Hash);
        }

        public abstract HashAlgorithmTag HashAlgorithm { get; }
    }
}
