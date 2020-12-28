using InflatablePalace.Cryptography.Algorithms;
using InflatablePalace.Cryptography.OpenPgp.Packet;
using InflatablePalace.OpenPGP;
using System;
using System.Security.Cryptography;
using System.Text;

namespace InflatablePalace.Cryptography.OpenPgp
{
    /// <summary>Basic utility class.</summary>
    public static class PgpUtilities
    {
        internal static byte[] KeyIdToBytes(long keyId)
        {
            return new[]
            {
                (byte)(keyId >> 56),
                (byte)(keyId >> 48),
                (byte)(keyId >> 40),
                (byte)(keyId >> 32),
                (byte)(keyId >> 24),
                (byte)(keyId >> 16),
                (byte)(keyId >> 8),
                (byte)keyId
            };
        }

        public static string GetDigestName(PgpHashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case PgpHashAlgorithm.Sha1: return "SHA1";
                case PgpHashAlgorithm.MD2: return "MD2";
                case PgpHashAlgorithm.MD5: return "MD5";
                case PgpHashAlgorithm.RipeMD160: return "RIPEMD160";
                case PgpHashAlgorithm.Sha224: return "SHA224";
                case PgpHashAlgorithm.Sha256: return "SHA256";
                case PgpHashAlgorithm.Sha384: return "SHA384";
                case PgpHashAlgorithm.Sha512: return "SHA512";
                default:
                    throw new PgpException("unknown hash algorithm tag in GetDigestName: " + hashAlgorithm);
            }
        }

        public static string GetSymmetricCipherName(PgpSymmetricKeyAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case PgpSymmetricKeyAlgorithm.Null: return "Null";
                case PgpSymmetricKeyAlgorithm.TripleDes: return "DESEDE";
                case PgpSymmetricKeyAlgorithm.Idea: return "IDEA";
                case PgpSymmetricKeyAlgorithm.Cast5: return "CAST5";
                case PgpSymmetricKeyAlgorithm.Blowfish: return "Blowfish";
                case PgpSymmetricKeyAlgorithm.Safer: return "SAFER";
                case PgpSymmetricKeyAlgorithm.Des: return "DES";
                case PgpSymmetricKeyAlgorithm.Aes128: return "AES";
                case PgpSymmetricKeyAlgorithm.Aes192: return "AES";
                case PgpSymmetricKeyAlgorithm.Aes256: return "AES";
                case PgpSymmetricKeyAlgorithm.Twofish: return "Twofish";
                case PgpSymmetricKeyAlgorithm.Camellia128: return "Camellia";
                case PgpSymmetricKeyAlgorithm.Camellia192: return "Camellia";
                case PgpSymmetricKeyAlgorithm.Camellia256: return "Camellia";
                default:
                    throw new PgpException("unknown symmetric algorithm: " + algorithm);
            }
        }

        public static int GetKeySize(PgpSymmetricKeyAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case PgpSymmetricKeyAlgorithm.Des:
                    return 64;
                case PgpSymmetricKeyAlgorithm.Idea:
                case PgpSymmetricKeyAlgorithm.Cast5:
                case PgpSymmetricKeyAlgorithm.Blowfish:
                case PgpSymmetricKeyAlgorithm.Safer:
                case PgpSymmetricKeyAlgorithm.Aes128:
                case PgpSymmetricKeyAlgorithm.Camellia128:
                    return 128;
                case PgpSymmetricKeyAlgorithm.TripleDes:
                case PgpSymmetricKeyAlgorithm.Aes192:
                case PgpSymmetricKeyAlgorithm.Camellia192:
                    return 192;
                case PgpSymmetricKeyAlgorithm.Aes256:
                case PgpSymmetricKeyAlgorithm.Twofish:
                case PgpSymmetricKeyAlgorithm.Camellia256:
                    return 256;
                default:
                    throw new PgpException("unknown symmetric algorithm: " + algorithm);
            }
        }

        internal static byte[] DoMakeKeyFromPassPhrase(PgpSymmetricKeyAlgorithm algorithm, S2k? s2k, byte[] rawPassPhrase)
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

                    byte[] iv = s2k.GetIV().ToArray();

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

                byte[] dig = digest.Hash!;

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

        internal static S2k GenerateS2k(PgpHashAlgorithm hashAlgorithm, int s2kCount)
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
            var pointBytes = new byte[1 + point.X!.Length + point.Y!.Length];
            pointBytes[0] = 4;
            Array.Copy(point.X, 0, pointBytes, 1, point.X.Length);
            Array.Copy(point.Y, 0, pointBytes, 1 + point.X.Length, point.Y.Length);
            return new MPInteger(pointBytes);
        }

        public static PgpHashAlgorithm GetHashAlgorithm(string name)
        {
            return name switch
            {
                "SHA1" => PgpHashAlgorithm.Sha1,
                "MD2" => PgpHashAlgorithm.MD2,
                "MD5" => PgpHashAlgorithm.MD5,
                "RIPEMD160" => PgpHashAlgorithm.RipeMD160,
                "SHA224" => PgpHashAlgorithm.Sha224,
                "SHA256" => PgpHashAlgorithm.Sha256,
                "SHA384" => PgpHashAlgorithm.Sha384,
                "SHA512" => PgpHashAlgorithm.Sha512,
                _ => throw new PgpException("unknown hash algorithm name in GetHashAlgorithm: " + name)
            };
        }

        internal static HashAlgorithm GetHashAlgorithm(PgpHashAlgorithm hashAlgorithmTag)
        {
            switch (hashAlgorithmTag)
            {
                case PgpHashAlgorithm.Sha1: return SHA1.Create();
                //case HashAlgorithmTag.Sha224: return HashAlgorithm.Create("2.16.840.1.101.3.4.2.4");
                case PgpHashAlgorithm.Sha256: return SHA256.Create();
                case PgpHashAlgorithm.Sha384: return SHA384.Create();
                case PgpHashAlgorithm.Sha512: return SHA512.Create();
                case PgpHashAlgorithm.MD5: return MD5.Create();
                default: throw new NotImplementedException("unknown hash algorithm");
            }
        }

        internal static HashAlgorithmName GetHashAlgorithmName(PgpHashAlgorithm hashAlgorithmTag)
        {
            switch (hashAlgorithmTag)
            {
                case PgpHashAlgorithm.Sha1: return HashAlgorithmName.SHA1;
                //case HashAlgorithmTag.Sha224: return HashAlgorithmName.FromOid("2.16.840.1.101.3.4.2.4");
                case PgpHashAlgorithm.Sha256: return HashAlgorithmName.SHA256;
                case PgpHashAlgorithm.Sha384: return HashAlgorithmName.SHA384;
                case PgpHashAlgorithm.Sha512: return HashAlgorithmName.SHA512;
                case PgpHashAlgorithm.MD5: return HashAlgorithmName.MD5;
                default: throw new NotImplementedException("unknown hash algorithm");
            }
        }

        /// <summary>
        /// Get symmetric algorithm implementation in CFB mode with feedback size equal to block size
        /// and no padding
        /// </summary>
        /// <param name="symmetricKeyAlgorithmTag">Algorithm identifier</param>
        /// <returns>Symmetric algorithm implementation</returns>
        internal static SymmetricAlgorithm GetSymmetricAlgorithm(PgpSymmetricKeyAlgorithm symmetricKeyAlgorithmTag)
        {
            SymmetricAlgorithm symmetricAlgorithm;

            switch (symmetricKeyAlgorithmTag)
            {
                case PgpSymmetricKeyAlgorithm.Aes128:
                case PgpSymmetricKeyAlgorithm.Aes192:
                case PgpSymmetricKeyAlgorithm.Aes256:
                    symmetricAlgorithm = Aes.Create();
                    symmetricAlgorithm.BlockSize = 128;
                    switch (symmetricKeyAlgorithmTag)
                    {
                        case PgpSymmetricKeyAlgorithm.Aes128:
                            symmetricAlgorithm.KeySize = 128;
                            break;
                        case PgpSymmetricKeyAlgorithm.Aes192:
                            symmetricAlgorithm.KeySize = 192;
                            break;
                        case PgpSymmetricKeyAlgorithm.Aes256:
                            symmetricAlgorithm.KeySize = 256;
                            break;
                    }
                    break;

                case PgpSymmetricKeyAlgorithm.TripleDes:
                    symmetricAlgorithm = TripleDES.Create();
                    break;

                case PgpSymmetricKeyAlgorithm.Idea:
                    symmetricAlgorithm = new IDEA();
                    break;

                case PgpSymmetricKeyAlgorithm.Cast5:
                    symmetricAlgorithm = new CAST5();
                    break;

                case PgpSymmetricKeyAlgorithm.Twofish:
                    symmetricAlgorithm = new Twofish();
                    break;

                default:
                    throw new PgpException("unknown cipher");
            }

            symmetricAlgorithm.Mode = CipherMode.CFB;
            symmetricAlgorithm.FeedbackSize = symmetricAlgorithm.BlockSize;
            symmetricAlgorithm.Padding = PaddingMode.None;
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
