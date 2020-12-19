using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Generator for old style PGP V3 Signatures.</summary>
    public class PgpV3SignatureGenerator
    {
        private HashAlgorithmTag hashAlgorithm;

        private PgpSignatureHelper helper;
        private PgpPrivateKey privateKey;

        /// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        public PgpV3SignatureGenerator(HashAlgorithmTag hashAlgorithm)
        {
            this.hashAlgorithm = hashAlgorithm;
        }

        /// <summary>Initialise the generator for signing.</summary>
        public void InitSign(int signatureType, PgpPrivateKey privateKey)
        {
            this.helper = new PgpSignatureHelper(signatureType, hashAlgorithm);
            this.privateKey = privateKey;
        }

        public void Update(byte b) => this.helper.Update(b);

        public void Update(params byte[] bytes) => this.helper.Update(bytes);

        public void Update(byte[] bytes, int off, int length) => this.helper.Update(bytes, off, length);

        /// <summary>Return the one pass header associated with the current signature.</summary>
        public PgpOnePassSignature GenerateOnePassVersion(bool isNested)
        {
            return new PgpOnePassSignature(new OnePassSignaturePacket(helper.SignatureType, hashAlgorithm, privateKey.PublicKeyPacket.Algorithm, privateKey.KeyId, isNested));
        }

        /// <summary>Return a V3 signature object containing the current signature state.</summary>
        public PgpSignature Generate()
        {
            var creationTime = DateTimeOffset.UtcNow;
            long seconds = creationTime.ToUnixTimeSeconds();

            byte[] hData = new byte[]
            {
                (byte)helper.SignatureType,
                (byte)(seconds >> 24),
                (byte)(seconds >> 16),
                (byte)(seconds >> 8),
                (byte)seconds
            };

            var signature = helper.Sign(hData, privateKey.Key);
            return new PgpSignature(new SignaturePacket(3, helper.SignatureType, privateKey.KeyId, privateKey.PublicKeyPacket.Algorithm, hashAlgorithm, creationTime.UtcDateTime, signature.Hash.AsSpan(0, 2).ToArray(), signature.SigValues));
        }
    }
}
