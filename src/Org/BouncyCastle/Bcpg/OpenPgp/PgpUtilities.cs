using InflatablePalace.Cryptography.Algorithms;
using InflatablePalace.OpenPGP;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Basic utility class.</summary>
    public static class PgpUtilities
    {
        public static string GetDigestName(HashAlgorithmTag hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithmTag.Sha1: return "SHA1";
                case HashAlgorithmTag.MD2: return "MD2";
                case HashAlgorithmTag.MD5: return "MD5";
                case HashAlgorithmTag.RipeMD160: return "RIPEMD160";
                case HashAlgorithmTag.Sha224: return "SHA224";
                case HashAlgorithmTag.Sha256: return "SHA256";
                case HashAlgorithmTag.Sha384: return "SHA384";
                case HashAlgorithmTag.Sha512: return "SHA512";
                default:
                    throw new PgpException("unknown hash algorithm tag in GetDigestName: " + hashAlgorithm);
            }
        }

        public static string GetSymmetricCipherName(
                SymmetricKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
                case SymmetricKeyAlgorithmTag.Null: return null;
                case SymmetricKeyAlgorithmTag.TripleDes: return "DESEDE";
                case SymmetricKeyAlgorithmTag.Idea: return "IDEA";
                case SymmetricKeyAlgorithmTag.Cast5: return "CAST5";
                case SymmetricKeyAlgorithmTag.Blowfish: return "Blowfish";
                case SymmetricKeyAlgorithmTag.Safer: return "SAFER";
                case SymmetricKeyAlgorithmTag.Des: return "DES";
                case SymmetricKeyAlgorithmTag.Aes128: return "AES";
                case SymmetricKeyAlgorithmTag.Aes192: return "AES";
                case SymmetricKeyAlgorithmTag.Aes256: return "AES";
                case SymmetricKeyAlgorithmTag.Twofish: return "Twofish";
                case SymmetricKeyAlgorithmTag.Camellia128: return "Camellia";
                case SymmetricKeyAlgorithmTag.Camellia192: return "Camellia";
                case SymmetricKeyAlgorithmTag.Camellia256: return "Camellia";
                default:
                    throw new PgpException("unknown symmetric algorithm: " + algorithm);
            }
        }

        public static int GetKeySize(SymmetricKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
                case SymmetricKeyAlgorithmTag.Des:
                    return 64;
                case SymmetricKeyAlgorithmTag.Idea:
                case SymmetricKeyAlgorithmTag.Cast5:
                case SymmetricKeyAlgorithmTag.Blowfish:
                case SymmetricKeyAlgorithmTag.Safer:
                case SymmetricKeyAlgorithmTag.Aes128:
                case SymmetricKeyAlgorithmTag.Camellia128:
                    return 128;
                case SymmetricKeyAlgorithmTag.TripleDes:
                case SymmetricKeyAlgorithmTag.Aes192:
                case SymmetricKeyAlgorithmTag.Camellia192:
                    return 192;
                case SymmetricKeyAlgorithmTag.Aes256:
                case SymmetricKeyAlgorithmTag.Twofish:
                case SymmetricKeyAlgorithmTag.Camellia256:
                    return 256;
                default:
                    throw new PgpException("unknown symmetric algorithm: " + algorithm);
            }
        }

        internal static byte[] EncodePassPhrase(char[] passPhrase, bool utf8)
        {
            return passPhrase == null
                ? null
                : utf8
                ? Encoding.UTF8.GetBytes(passPhrase)
                : Encoding.ASCII.GetBytes(passPhrase);
        }

        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public static byte[] MakeKeyFromPassPhrase(SymmetricKeyAlgorithmTag algorithm, S2k s2k, char[] passPhrase)
        {
            return DoMakeKeyFromPassPhrase(algorithm, s2k, EncodePassPhrase(passPhrase, false), true);
        }

        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8 (Encoding.UTF8.GetBytes).
        /// </remarks>
        public static byte[] MakeKeyFromPassPhraseUtf8(SymmetricKeyAlgorithmTag algorithm, S2k s2k, char[] passPhrase)
        {
            return DoMakeKeyFromPassPhrase(algorithm, s2k, EncodePassPhrase(passPhrase, true), true);
        }

        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public static byte[] MakeKeyFromPassPhraseRaw(SymmetricKeyAlgorithmTag algorithm, S2k s2k, byte[] rawPassPhrase)
        {
            return DoMakeKeyFromPassPhrase(algorithm, s2k, rawPassPhrase, false);
        }

        internal static byte[] DoMakeKeyFromPassPhrase(SymmetricKeyAlgorithmTag algorithm, S2k s2k, byte[] rawPassPhrase, bool clearPassPhrase)
        {
            int keySize = GetKeySize(algorithm);
            byte[] pBytes = rawPassPhrase;
            byte[] keyBytes = new byte[(keySize + 7) / 8];

            int generatedBytes = 0;
            int loopCount = 0;

            while (generatedBytes < keyBytes.Length)
            {
                HashAlgorithm digest;
                if (s2k != null)
                {
                    try
                    {
                        digest = GetHashAlgorithm(s2k.HashAlgorithm);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("can't find S2k digest", e);
                    }

                    for (int i = 0; i != loopCount; i++)
                    {
                        digest.TransformBlock(new byte[] { 0 }, 0, 1, null, 0);
                    }

                    byte[] iv = s2k.GetIV();

                    switch (s2k.Type)
                    {
                        case S2k.Simple:
                            digest.TransformBlock(pBytes, 0, pBytes.Length, null, 0);
                            break;
                        case S2k.Salted:
                            digest.TransformBlock(iv, 0, iv.Length, null, 0);
                            digest.TransformBlock(pBytes, 0, pBytes.Length, null, 0);
                            break;
                        case S2k.SaltedAndIterated:
                            long count = s2k.IterationCount;
                            digest.TransformBlock(iv, 0, iv.Length, null, 0);
                            digest.TransformBlock(pBytes, 0, pBytes.Length, null, 0);

                            count -= iv.Length + pBytes.Length;

                            while (count > 0)
                            {
                                if (count < iv.Length)
                                {
                                    digest.TransformBlock(iv, 0, (int)count, null, 0);
                                    break;
                                }
                                else
                                {
                                    digest.TransformBlock(iv, 0, iv.Length, null, 0);
                                    count -= iv.Length;
                                }

                                if (count < pBytes.Length)
                                {
                                    digest.TransformBlock(pBytes, 0, (int)count, null, 0);
                                    count = 0;
                                }
                                else
                                {
                                    digest.TransformBlock(pBytes, 0, pBytes.Length, null, 0);
                                    count -= pBytes.Length;
                                }
                            }
                            break;
                        default:
                            throw new PgpException("unknown S2k type: " + s2k.Type);
                    }
                }
                else
                {
                    try
                    {
                        digest = MD5.Create();

                        for (int i = 0; i != loopCount; i++)
                        {
                            digest.TransformBlock(new byte[] { 0 }, 0, 1, null, 0);
                        }

                        digest.TransformBlock(pBytes, 0, pBytes.Length, null, 0);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("can't find MD5 digest", e);
                    }
                }

                digest.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                byte[] dig = digest.Hash;

                if (dig.Length > (keyBytes.Length - generatedBytes))
                {
                    Array.Copy(dig, 0, keyBytes, generatedBytes, keyBytes.Length - generatedBytes);
                }
                else
                {
                    Array.Copy(dig, 0, keyBytes, generatedBytes, dig.Length);
                }

                generatedBytes += dig.Length;

                loopCount++;
            }

            if (clearPassPhrase && rawPassPhrase != null)
            {
                Array.Clear(rawPassPhrase, 0, rawPassPhrase.Length);
            }

            return keyBytes;// MakeKey(algorithm, keyBytes);
        }

        private const int ReadAhead = 60;

        private static bool IsPossiblyBase64(
            int ch)
        {
            return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9') || (ch == '+') || (ch == '/')
                    || (ch == '\r') || (ch == '\n');
        }

        /// <summary>
        /// Return either an ArmoredInputStream or a BcpgInputStream based on whether
        /// the initial characters of the stream are binary PGP encodings or not.
        /// </summary>
        /*public static Stream GetDecoderStream(
            Stream inputStream)
        {
            // TODO Remove this restriction?
            if (!inputStream.CanSeek)
                throw new ArgumentException("inputStream must be seek-able", "inputStream");

            long markedPos = inputStream.Position;

            int ch = inputStream.ReadByte();
            if ((ch & 0x80) != 0)
            {
                inputStream.Position = markedPos;

                return inputStream;
            }

            if (!IsPossiblyBase64(ch))
            {
                inputStream.Position = markedPos;

                return new ArmoredInputStream(inputStream);
            }

            byte[] buf = new byte[ReadAhead];
            int count = 1;
            int index = 1;

            buf[0] = (byte)ch;
            while (count != ReadAhead && (ch = inputStream.ReadByte()) >= 0)
            {
                if (!IsPossiblyBase64(ch))
                {
                    inputStream.Position = markedPos;

                    return new ArmoredInputStream(inputStream);
                }

                if (ch != '\n' && ch != '\r')
                {
                    buf[index++] = (byte)ch;
                }

                count++;
            }

            inputStream.Position = markedPos;

            //
            // nothing but new lines, little else, assume regular armoring
            //
            if (count < 4)
            {
                return new ArmoredInputStream(inputStream);
            }

            //
            // test our non-blank data
            //
            byte[] firstBlock = new byte[8];

            Array.Copy(buf, 0, firstBlock, 0, firstBlock.Length);

            try
            {
                byte[] decoded = Base64.Decode(firstBlock);

                //
                // it's a base64 PGP block.
                //
                bool hasHeaders = (decoded[0] & 0x80) == 0;

                return new ArmoredInputStream(inputStream, hasHeaders);
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new IOException(e.Message);
            }
        }*/

        internal static byte[] GenerateIV(int length)
        {
            byte[] iv = new byte[length];
            RandomNumberGenerator.Fill(iv);
            return iv;
        }

        internal static S2k GenerateS2k(HashAlgorithmTag hashAlgorithm, int s2kCount)
        {
            byte[] iv = GenerateIV(8);
            return new S2k(hashAlgorithm, iv, s2kCount);
        }

        internal static ECPoint DecodePoint(MPInteger point)
        {
            var pointBytes = point.Value;
            if (pointBytes[0] == 4) // Uncompressed point
            {
                var expectedLength = (pointBytes.Length - 1) / 2;
                return new ECPoint { X = pointBytes.AsSpan(1, expectedLength).ToArray(), Y = pointBytes.AsSpan(expectedLength + 1, expectedLength).ToArray() };
            }
            else if (pointBytes[0] == 0x40) // Compressed point
            {
                return new ECPoint { X = pointBytes.AsSpan(1).ToArray(), Y = new byte[pointBytes.Length - 1] };
            }
            else
            {
                throw new PgpException("unsupported point format");
            }
        }

        internal static MPInteger EncodePoint(ECPoint point)
        {
            var pointBytes = new byte[1 + point.X.Length + point.Y.Length];
            pointBytes[0] = 4;
            Array.Copy(point.X, 0, pointBytes, 1, point.X.Length);
            Array.Copy(point.Y, 0, pointBytes, 1 + point.X.Length, point.Y.Length);
            return new MPInteger(pointBytes);
        }

        internal static HashAlgorithm GetHashAlgorithm(HashAlgorithmTag hashAlgorithmTag)
        {
            switch (hashAlgorithmTag)
            {
                case HashAlgorithmTag.Sha1: return SHA1.Create();
                //case HashAlgorithmTag.Sha224: return HashAlgorithm.Create("2.16.840.1.101.3.4.2.4");
                case HashAlgorithmTag.Sha256: return SHA256.Create();
                case HashAlgorithmTag.Sha384: return SHA384.Create();
                case HashAlgorithmTag.Sha512: return SHA512.Create();
                case HashAlgorithmTag.MD5: return MD5.Create();
                default: throw new NotImplementedException("unknown hash algorithm");
            }
        }

        internal static HashAlgorithmName GetHashAlgorithmName(HashAlgorithmTag hashAlgorithmTag)
        {
            switch (hashAlgorithmTag)
            {
                case HashAlgorithmTag.Sha1: return HashAlgorithmName.SHA1;
                //case HashAlgorithmTag.Sha224: return HashAlgorithmName.FromOid("2.16.840.1.101.3.4.2.4");
                case HashAlgorithmTag.Sha256: return HashAlgorithmName.SHA256;
                case HashAlgorithmTag.Sha384: return HashAlgorithmName.SHA384;
                case HashAlgorithmTag.Sha512: return HashAlgorithmName.SHA512;
                case HashAlgorithmTag.MD5: return HashAlgorithmName.MD5;
                default: throw new NotImplementedException("unknown hash algorithm");
            }
        }

        internal static SymmetricAlgorithm GetSymmetricAlgorithm(SymmetricKeyAlgorithmTag symmetricKeyAlgorithmTag)
        {
            SymmetricAlgorithm symmetricAlgorithm;

            switch (symmetricKeyAlgorithmTag)
            {
                case SymmetricKeyAlgorithmTag.Aes128:
                case SymmetricKeyAlgorithmTag.Aes192:
                case SymmetricKeyAlgorithmTag.Aes256:
                    symmetricAlgorithm = Aes.Create();
                    symmetricAlgorithm.BlockSize = 128;
                    switch (symmetricKeyAlgorithmTag)
                    {
                        case SymmetricKeyAlgorithmTag.Aes128:
                            symmetricAlgorithm.KeySize = 128;
                            break;
                        case SymmetricKeyAlgorithmTag.Aes192:
                            symmetricAlgorithm.KeySize = 192;
                            break;
                        case SymmetricKeyAlgorithmTag.Aes256:
                            symmetricAlgorithm.KeySize = 256;
                            break;
                    }
                    break;

                case SymmetricKeyAlgorithmTag.TripleDes:
                    symmetricAlgorithm = TripleDES.Create();
                    break;

                case SymmetricKeyAlgorithmTag.Idea:
                    symmetricAlgorithm = new IDEA();
                    break;

                case SymmetricKeyAlgorithmTag.Cast5:
                    symmetricAlgorithm = new CAST5();
                    break;

                case SymmetricKeyAlgorithmTag.Twofish:
                    symmetricAlgorithm = new Twofish();
                    break;

                default:
                    throw new PgpException("unknown cipher");
            }

            symmetricAlgorithm.Mode = CipherMode.CFB;
            symmetricAlgorithm.FeedbackSize = symmetricAlgorithm.BlockSize;
            return symmetricAlgorithm;
        }

        internal static ECDiffieHellman GetECDiffieHellman(ECParameters parameters)
        {
            if (parameters.Curve.Oid.Value == "1.3.6.1.4.1.3029.1.5.1")
                return new X25519(parameters);
            return ECDiffieHellman.Create(parameters);
        }

        internal static ECDiffieHellman GetECDiffieHellman(ECCurve curve)
        {
            if (curve.Oid.Value == "1.3.6.1.4.1.3029.1.5.1")
                return new X25519();
            return ECDiffieHellman.Create(curve);
        }
    }
}
