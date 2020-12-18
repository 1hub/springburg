using System;
using System.IO;
using System.Security.Cryptography;
using InflatablePalace.Cryptography.Algorithms;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>A password based encryption object.</summary>
    public class PgpPbeEncryptedData : PgpEncryptedData
    {
        private readonly SymmetricKeyEncSessionPacket keyData;

        internal PgpPbeEncryptedData(
            SymmetricKeyEncSessionPacket keyData,
            InputStreamPacket encData)
            : base(encData)
        {
            this.keyData = keyData;
        }

        /// <summary>Return the raw input stream for the data stream.</summary>
        public override Stream GetInputStream()
        {
            return encData.GetInputStream();
        }

        /// <summary>Return the decrypted input stream, using the passed in passphrase.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public Stream GetDataStream(char[] passPhrase)
        {
            return DoGetDataStream(PgpUtilities.EncodePassPhrase(passPhrase, false), true);
        }

        /// <summary>Return the decrypted input stream, using the passed in passphrase.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8 (Encoding.UTF8.GetBytes).
        /// </remarks>
        public Stream GetDataStreamUtf8(char[] passPhrase)
        {
            return DoGetDataStream(PgpUtilities.EncodePassPhrase(passPhrase, true), true);
        }

        /// <summary>Return the decrypted input stream, using the passed in passphrase.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public Stream GetDataStreamRaw(byte[] rawPassPhrase)
        {
            return DoGetDataStream(rawPassPhrase, false);
        }

        internal Stream DoGetDataStream(byte[] rawPassPhrase, bool clearPassPhrase)
        {
            byte[] key = Array.Empty<byte>();

            try
            {
                SymmetricKeyAlgorithmTag keyAlgorithm = keyData.EncAlgorithm;

                key = PgpUtilities.DoMakeKeyFromPassPhrase(keyAlgorithm, keyData.S2k, rawPassPhrase, clearPassPhrase);
                byte[] secKeyData = keyData.GetSecKeyData();
                if (secKeyData != null && secKeyData.Length > 0)
                {
                    byte[] secureKey = Array.Empty<byte>();
                    try
                    {
                        using var keyCipher = PgpUtilities.GetSymmetricAlgorithm(keyAlgorithm);
                        using var keyDecryptor = new ZeroPaddedCryptoTransformWrapper(keyCipher.CreateDecryptor(key, new byte[(keyCipher.BlockSize + 7) / 8]));
                        secureKey = keyDecryptor.TransformFinalBlock(secKeyData, 0, secKeyData.Length);
                        keyAlgorithm = (SymmetricKeyAlgorithmTag)secureKey[0];
                        return GetDataStream(keyAlgorithm, secureKey.AsSpan(1), verifyIntegrity: true);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(secureKey);
                    }
                }
                else
                {
                    return GetDataStream(keyAlgorithm, key, verifyIntegrity: true);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }
}
