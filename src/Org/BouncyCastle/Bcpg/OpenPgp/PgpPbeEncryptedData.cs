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
            try
            {
                SymmetricKeyAlgorithmTag keyAlgorithm = keyData.EncAlgorithm;

                byte[] key = PgpUtilities.DoMakeKeyFromPassPhrase(keyAlgorithm, keyData.S2k, rawPassPhrase, clearPassPhrase);

                byte[] secKeyData = keyData.GetSecKeyData();
                if (secKeyData != null && secKeyData.Length > 0)
                {
                    using var keyCipher = PgpUtilities.GetSymmetricAlgorithm(keyAlgorithm);
                    keyCipher.Padding = PaddingMode.None;
                    using var keyDecryptor = new ZeroPaddedCryptoTransformWrapper(keyCipher.CreateDecryptor(key, new byte[keyCipher.BlockSize / 8]));
                    byte[] keyBytes = keyDecryptor.TransformFinalBlock(secKeyData, 0, secKeyData.Length);

                    keyAlgorithm = (SymmetricKeyAlgorithmTag)keyBytes[0];

                    key = keyBytes.AsSpan(1).ToArray();
                }


                var c = PgpUtilities.GetSymmetricAlgorithm(keyAlgorithm);
                var iv = new byte[c.BlockSize / 8];

                ICryptoTransform decryptor;
                if (encData is SymmetricEncIntegrityPacket)
                {
                    decryptor = c.CreateDecryptor(key, iv);
                }
                else
                {
                    c.Mode = CipherMode.ECB;
                    decryptor = new OpenPGPCFBTransformWrapper(c.CreateEncryptor(key, null), iv, false);
                }

                encStream = new CryptoStream(encData.GetInputStream(), new ZeroPaddedCryptoTransformWrapper(decryptor), CryptoStreamMode.Read);

                if (encData is SymmetricEncIntegrityPacket)
                {
                    truncStream = new TruncatedStream(encStream);

                    hashAlgorithm = SHA1.Create();
                    encStream = new CryptoStream(truncStream, hashAlgorithm, CryptoStreamMode.Read);
                }

                if (Streams.ReadFully(encStream, iv, 0, iv.Length) < iv.Length)
                    throw new EndOfStreamException("unexpected end of stream.");

                int v1 = encStream.ReadByte();
                int v2 = encStream.ReadByte();

                if (v1 < 0 || v2 < 0)
                    throw new EndOfStreamException("unexpected end of stream.");

                // Note: the oracle attack on the "quick check" bytes is not deemed
                // a security risk for PBE (see PgpPublicKeyEncryptedData)

                bool repeatCheckPassed = iv[iv.Length - 2] == (byte)v1 && iv[iv.Length - 1] == (byte)v2;

                // Note: some versions of PGP appear to produce 0 for the extra
                // bytes rather than repeating the two previous bytes
                bool zeroesCheckPassed = v1 == 0 && v2 == 0;

                if (!repeatCheckPassed && !zeroesCheckPassed)
                {
                    throw new PgpDataValidationException("quick check failed.");
                }

                return encStream;
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }
        }
    }
}
