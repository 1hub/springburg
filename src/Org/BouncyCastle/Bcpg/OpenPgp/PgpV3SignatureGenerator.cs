using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Generator for old style PGP V3 Signatures.</summary>
    public class PgpV3SignatureGenerator : PgpSignatureBase
    {
        private HashAlgorithmTag hashAlgorithm;

        private PgpPrivateKey privateKey;

        public override HashAlgorithmTag HashAlgorithm => hashAlgorithm;

        /// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        public PgpV3SignatureGenerator(
            HashAlgorithmTag hashAlgorithm)
        {
            this.hashAlgorithm = hashAlgorithm;
        }

        /// <summary>Initialise the generator for signing.</summary>
        public void InitSign(int signatureType, PgpPrivateKey privateKey)
        {
            this.privateKey = privateKey;
            Init(signatureType);
        }

        /// <summary>Return the one pass header associated with the current signature.</summary>
        public PgpOnePassSignature GenerateOnePassVersion(bool isNested)
        {
            return new PgpOnePassSignature(new OnePassSignaturePacket(signatureType, hashAlgorithm, privateKey.PublicKeyPacket.Algorithm, privateKey.KeyId, isNested));
        }

        /// <summary>Return a V3 signature object containing the current signature state.</summary>
        public PgpSignature Generate()
        {
            var creationTime = DateTimeOffset.UtcNow;
            long seconds = creationTime.ToUnixTimeSeconds();

            byte[] hData = new byte[]
            {
                (byte) signatureType,
                (byte)(seconds >> 24),
                (byte)(seconds >> 16),
                (byte)(seconds >> 8),
                (byte)seconds
            };

            var signature = Sign(hData, privateKey.Key);
            return new PgpSignature(new SignaturePacket(3, signatureType, privateKey.KeyId, privateKey.PublicKeyPacket.Algorithm, hashAlgorithm, creationTime.UtcDateTime, sig.Hash.AsSpan(0, 2).ToArray(), signature.SigValues));
        }
    }
}
