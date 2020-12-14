using System;
using System.IO;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A one pass signature object.</remarks>
    public class PgpOnePassSignature
    {
        private static OnePassSignaturePacket Cast(Packet packet)
        {
            if (!(packet is OnePassSignaturePacket))
                throw new IOException("unexpected packet in stream: " + packet);

            return (OnePassSignaturePacket)packet;
        }

        private readonly OnePassSignaturePacket sigPack;
        private readonly int signatureType;
        private HashAlgorithm sig;
        private PgpPublicKey pubKey;
        private byte lastb;

        internal PgpOnePassSignature(
            BcpgInputStream bcpgInput)
            : this(Cast(bcpgInput.ReadPacket()))
        {
        }

        internal PgpOnePassSignature(
            OnePassSignaturePacket sigPack)
        {
            this.sigPack = sigPack;
            this.signatureType = sigPack.SignatureType;
        }

        /// <summary>Initialise the signature object for verification.</summary>
        public void InitVerify(
            PgpPublicKey pubKey)
        {
            lastb = 0;
            this.sig = PgpUtilities.GetHashAlgorithm(sigPack.HashAlgorithm);
            this.pubKey = pubKey;
            /*
            try
            {
                sig = SignerUtilities.GetSigner(
                    PgpUtilities.GetSignatureName(sigPack.KeyAlgorithm, sigPack.HashAlgorithm));
            }
            catch (Exception e)
            {
                throw new PgpException("can't set up signature object.", e);
            }

            try
            {
                sig.Init(false, pubKey.GetKey());
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }*/
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
                sig.TransformBlock(new byte[] { b }, 0, 1, null, 0);
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
                sig.TransformBlock(new byte[] { b }, 0, 1, null, 0);
            }

            lastb = b;
        }

        private void doUpdateCRLF()
        {
            sig.TransformBlock(new byte[] { (byte)'\r', (byte)'\n' }, 0, 2, null, 0);
        }

        public void Update(
            byte[] bytes)
        {
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                for (int i = 0; i != bytes.Length; i++)
                {
                    doCanonicalUpdateByte(bytes[i]);
                }
            }
            else
            {
                sig.TransformBlock(bytes, 0, bytes.Length, null, 0);
            }
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

        /// <summary>Verify the calculated signature against the passed in PgpSignature.</summary>
        public bool Verify(
            PgpSignature pgpSig)
        {
            byte[] trailer = pgpSig.GetSignatureTrailer();

            sig.TransformFinalBlock(trailer, 0, trailer.Length);

            var key = pubKey.GetKey();
            if (key is RSA rsa)
                return rsa.VerifyHash(sig.Hash, pgpSig.GetSignature(), PgpUtilities.GetHashAlgorithmName(sigPack.HashAlgorithm), RSASignaturePadding.Pkcs1);
            if (key is DSA dsa)
                return dsa.VerifySignature(sig.Hash, pgpSig.GetSignature(), DSASignatureFormat.Rfc3279DerSequence);
            if (key is ECDsa ecdsa)
                return ecdsa.VerifyHash(sig.Hash, pgpSig.GetSignature(), DSASignatureFormat.Rfc3279DerSequence);
            throw new NotImplementedException();
            //return sig.VerifySignature(pgpSig.GetSignature());
        }

        public long KeyId
        {
            get { return sigPack.KeyId; }
        }

        public int SignatureType
        {
            get { return sigPack.SignatureType; }
        }

        public HashAlgorithmTag HashAlgorithm
        {
            get { return sigPack.HashAlgorithm; }
        }

        public PublicKeyAlgorithmTag KeyAlgorithm
        {
            get { return sigPack.KeyAlgorithm; }
        }

        public byte[] GetEncoded()
        {
            MemoryStream bOut = new MemoryStream();

            Encode(bOut);

            return bOut.ToArray();
        }

        public void Encode(
            Stream outStr)
        {
            BcpgOutputStream.Wrap(outStr).WritePacket(sigPack);
        }
    }
}
