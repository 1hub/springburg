using Springburg.Cryptography.Algorithms;
using Springburg.Cryptography.OpenPgp.Packet;
using System;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp
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

        internal static S2k GenerateS2k(PgpHashAlgorithm hashAlgorithm, int s2kCount)
        {
            byte[] iv = new byte[8];
            RandomNumberGenerator.Fill(iv);
            return new S2k(hashAlgorithm, iv, s2kCount);
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
    }
}
