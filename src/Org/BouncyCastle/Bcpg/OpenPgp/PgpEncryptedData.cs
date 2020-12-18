using InflatablePalace.Cryptography.Algorithms;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public abstract class PgpEncryptedData
    {
        protected InputStreamPacket encData;
        private CryptoStream encStream;
        private HashAlgorithm hashAlgorithm;
        private TailEndCryptoTransform tailEndCryptoTransform;

        internal PgpEncryptedData(InputStreamPacket encData)
        {
            this.encData = encData;
        }

        /// <summary>Return the raw input stream for the data stream.</summary>
        public virtual Stream GetInputStream()
        {
            return encData.GetInputStream();
        }

        /// <summary>Return the decrypted data stream for the packet.</summary>
        protected Stream GetDataStream(SymmetricKeyAlgorithmTag keyAlgorithm, ReadOnlySpan<byte> key, bool verifyIntegrity)
        {
            SymmetricAlgorithm encryptionAlgorithm = PgpUtilities.GetSymmetricAlgorithm(keyAlgorithm);
            var iv = new byte[(encryptionAlgorithm.BlockSize + 7) / 8];
            byte[] keyArray = Array.Empty<byte>();
            ICryptoTransform decryptor;

            try
            {
                keyArray = key.ToArray();
                if (encData is SymmetricEncIntegrityPacket)
                {
                    decryptor = encryptionAlgorithm.CreateDecryptor(keyArray, iv);
                }
                else
                {
                    encryptionAlgorithm.Mode = CipherMode.ECB;
                    decryptor = new OpenPGPCFBTransformWrapper(encryptionAlgorithm.CreateEncryptor(keyArray, null), iv, false);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyArray.AsSpan());
            }

            encStream = new CryptoStream(
                encData.GetInputStream(),
                new ZeroPaddedCryptoTransformWrapper(decryptor),
                CryptoStreamMode.Read);
            if (encData is SymmetricEncIntegrityPacket)
            {
                hashAlgorithm = SHA1.Create();
                tailEndCryptoTransform = new TailEndCryptoTransform(hashAlgorithm, hashAlgorithm.HashSize / 8);
                encStream = new CryptoStream(encStream, tailEndCryptoTransform, CryptoStreamMode.Read);
            }

            if (Streams.ReadFully(encStream, iv, 0, iv.Length) < iv.Length)
                throw new EndOfStreamException("unexpected end of stream.");

            int v1 = encStream.ReadByte();
            int v2 = encStream.ReadByte();

            if (v1 < 0 || v2 < 0)
                throw new EndOfStreamException("unexpected end of stream.");

            if (verifyIntegrity)
            {
                bool repeatCheckPassed = iv[iv.Length - 2] == (byte)v1 && iv[iv.Length - 1] == (byte)v2;

                // Note: some versions of PGP appear to produce 0 for the extra
                // bytes rather than repeating the two previous bytes
                bool zeroesCheckPassed = v1 == 0 && v2 == 0;

                if (!repeatCheckPassed && !zeroesCheckPassed)
                {
                    throw new PgpDataValidationException("quick check failed.");
                }

            }

            return encStream;
        }


        /// <summary>Return true if the message is integrity protected.</summary>
        /// <returns>True, if there is a modification detection code namespace associated
        /// with this stream.</returns>
        public bool IsIntegrityProtected()
        {
            return encData is SymmetricEncIntegrityPacket;
        }

        /// <summary>Verify the MDC packet, if present</summary>
        /// <remarks>Note: This can only be called after the message has been read.</remarks>
        /// <returns>True, if the message verifies, false otherwise</returns>
        public bool Verify()
        {
            if (!IsIntegrityProtected())
                throw new PgpException("data not integrity protected.");

            // make sure we are at the end.
            encStream.CopyTo(Stream.Null);

            // process the MDC packet
            var digest = hashAlgorithm.Hash;
            var streamDigest = tailEndCryptoTransform.TailEnd;

            return CryptographicOperations.FixedTimeEquals(digest, streamDigest);
        }
    }
}
