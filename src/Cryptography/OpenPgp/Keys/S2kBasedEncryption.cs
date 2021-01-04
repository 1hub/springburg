using Springburg.Cryptography.Helpers;
using System;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp.Keys
{
    class S2kBasedEncryption
    {
        public static void MakeKey(
            ReadOnlySpan<byte> password,
            PgpHashAlgorithm hashAlgorithm,
            ReadOnlySpan<byte> salt,
            long iterationCount,
            Span<byte> key)
        {
            using var incrementalHash = IncrementalHash.CreateHash(PgpUtilities.GetHashAlgorithmName(hashAlgorithm));
            // Produce the key
            int keySizeInBytes = key.Length;
            // Align the size of key array to size of hash
            int loopsNeeded = (keySizeInBytes + incrementalHash.HashLengthInBytes - 1) / incrementalHash.HashLengthInBytes;
            Span<byte> keyBytes = stackalloc byte[loopsNeeded * incrementalHash.HashLengthInBytes];
            var zeros = new byte[loopsNeeded];
            try
            {
                for (int loopCount = 0; loopCount < loopsNeeded; loopCount++)
                {
                    incrementalHash.AppendData(zeros, 0, loopCount);
                    incrementalHash.AppendData(salt);
                    incrementalHash.AppendData(password);

                    long count = iterationCount;
                    if (count > 0)
                    {
                        count -= salt.Length + password.Length;
                        while (count > 0)
                        {
                            if (count < salt.Length)
                            {
                                incrementalHash.AppendData(salt.Slice(0, (int)count));
                                break;
                            }
                            else
                            {
                                incrementalHash.AppendData(salt);
                                count -= salt.Length;
                            }

                            if (count < password.Length)
                            {
                                incrementalHash.AppendData(password.Slice(0, (int)count));
                                break;
                            }
                            else
                            {
                                incrementalHash.AppendData(password);
                                count -= password.Length;
                            }
                        }
                    }

                    incrementalHash.GetHashAndReset(keyBytes.Slice(loopCount * incrementalHash.HashLengthInBytes));
                }

                keyBytes.Slice(0, key.Length).CopyTo(key);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyBytes);
            }
        }

        public static void DecryptSecretKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten, int version = 4)
        {
            S2kUsageTag usageTag = (S2kUsageTag)source[0];
            PgpSymmetricKeyAlgorithm encryptionAlgorithm;
            var salt = new ReadOnlySpan<byte>();
            long iterationCount = 0;
            PgpHashAlgorithm hashAlgorithm;

            if (usageTag == S2kUsageTag.Checksum || usageTag == S2kUsageTag.Sha1 /* || usageTag == S2kUsageTag.Aead */)
            {
                encryptionAlgorithm = (PgpSymmetricKeyAlgorithm)source[1];
                byte s2kType = source[2];
                hashAlgorithm = (PgpHashAlgorithm)source[3];
                source = source.Slice(4);
                if (s2kType > 0 && s2kType <= 3)
                {
                    salt = source.Slice(0, 8);
                    source = source.Slice(8);
                    if (s2kType == 3)
                    {
                        iterationCount = (16 + (source[0] & 15)) << ((source[0] >> 4) + 6);
                        source = source.Slice(1);
                    }
                }
                else if (s2kType == 101) // GNU private
                {
                    throw new NotImplementedException();
                }
                else
                {
                    throw new CryptographicException(); // Unknown S2K type
                }
            }
            else if (usageTag == S2kUsageTag.None)
            {
                // No encryption
                bytesWritten = source.Slice(1).TryCopyTo(destination) ? source.Length : 0;
                return;
            }
            else
            {
                // No salt, no iterations, MD5 hash
                encryptionAlgorithm = (PgpSymmetricKeyAlgorithm)usageTag;
                hashAlgorithm = PgpHashAlgorithm.MD5;
                usageTag = S2kUsageTag.Checksum;
                source = source.Slice(1);
            }

            int keySizeInBytes = (PgpUtilities.GetKeySize(encryptionAlgorithm) + 7) / 8;
            Span<byte> keyBytes = stackalloc byte[keySizeInBytes];
            try
            {
                MakeKey(password, hashAlgorithm, salt, iterationCount, keyBytes);

                using var c = PgpUtilities.GetSymmetricAlgorithm(encryptionAlgorithm);

                // Read the IV
                c.IV = source.Slice(0, c.BlockSize / 8).ToArray();
                c.Key = keyBytes.ToArray();

                source = source.Slice(c.BlockSize / 8);

                if (destination.Length < source.Length)
                {
                    bytesWritten = 0;
                    return;
                }

                // Do the actual decryption
                bytesWritten = source.Length;
                if (version == 4)
                {
                    using var decryptor = new ZeroPaddedCryptoTransform(c.CreateDecryptor());
                    var data = decryptor.TransformFinalBlock(source.ToArray(), 0, source.Length);
                    data.AsSpan().CopyTo(destination);
                    CryptographicOperations.ZeroMemory(data);
                }
                else if (version == 3)
                {
                    // Version 3 is four RSA parameters encoded as MPIntegers separately
                    var sourceArray = source.ToArray();
                    int pos = 0;
                    for (int i = 0; i != 4; i++)
                    {
                        int encLen = ((source[pos] << 8) + source[pos + 1] + 7) / 8;
                        destination[pos] = source[pos];
                        destination[pos + 1] = source[pos + 1];
                        pos += 2;

                        if (encLen > source.Length - pos)
                            throw new PgpException("out of range encLen found in encData");

                        using var decryptor = new ZeroPaddedCryptoTransform(c.CreateDecryptor());
                        var data = decryptor.TransformFinalBlock(sourceArray, pos, encLen);
                        data.CopyTo(destination.Slice(pos));
                        CryptographicOperations.ZeroMemory(data);
                        pos += encLen;

                        if (i != 3)
                        {
                            c.IV = source.Slice(pos - (c.BlockSize / 8), c.BlockSize / 8).ToArray();
                        }
                    }

                    destination[pos] = source[pos];
                    destination[pos + 1] = source[pos + 1];
                }

                if (!VerifyChecksum(usageTag, destination.Slice(0, bytesWritten), out int checksumLength))
                    throw new CryptographicException();

                bytesWritten -= checksumLength;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyBytes);
            }
        }

        private static bool VerifyChecksum(
            S2kUsageTag usageTag,
            ReadOnlySpan<byte> data,
            out int checksumLength)
        {
            if (usageTag == S2kUsageTag.Sha1)
            {
                using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
                sha1.AppendData(data.Slice(0, data.Length - sha1.HashLengthInBytes));
                checksumLength = sha1.HashLengthInBytes;
                return sha1.GetHashAndReset().AsSpan().SequenceEqual(data.Slice(data.Length - sha1.HashLengthInBytes));
            }
            else if (usageTag == S2kUsageTag.Checksum)
            {
                int checksum = 0;
                for (int i = 0; i < data.Length - 2; i++)
                {
                    checksum += data[i];
                }
                checksumLength = 2;
                return data[data.Length - 2] == (byte)(checksum >> 8) && data[data.Length - 1] == (byte)checksum;
            }
            else // None
            {
                checksumLength = 0;
                return true;
            }
        }

        public static int GetEncryptedLength(
            S2kParameters s2kParameters,
            int sourceLength,
            int version = 4)
        {
            if (version >= 4)
            {
                // 4 bytes for usage tag, encryption algorithm, s2k type, hash algorithm
                // 8 bytes for salt
                // 1 byte for iteration count
                // IV of cipher's block size in bytes
                // 20 for SHA-1 checksum
                using var symmetricAlgorithm = PgpUtilities.GetSymmetricAlgorithm(s2kParameters.EncryptionAlgorithm);
                return
                    4 + 8 + 1 +
                    ((symmetricAlgorithm.BlockSize + 7) / 8) +
                    sourceLength +
                    (s2kParameters.UsageTag == S2kUsageTag.Checksum ? 2 : 20);
            }
            else
            {
                using var symmetricAlgorithm = PgpUtilities.GetSymmetricAlgorithm(s2kParameters.EncryptionAlgorithm);
                // 1 for encryption algorithm, hash is fixed at MD5, no salt and no iterations, 2 bytes for checksum
                return 1 + ((symmetricAlgorithm.BlockSize + 7) / 8) + sourceLength + 2;
            }
        }

        public static void EncryptSecretKey(
            ReadOnlySpan<byte> password,
            S2kParameters s2kParameters,
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            int version = 4)
        {
            if (password.Length == 0)
            {
                destination[0] = (byte)S2kUsageTag.None;
                source.CopyTo(destination.Slice(1));
                return;
            }

            using var c = PgpUtilities.GetSymmetricAlgorithm(s2kParameters.EncryptionAlgorithm);

            int keySizeInBytes = (c.KeySize + 7) / 8;
            Span<byte> keyBytes = stackalloc byte[keySizeInBytes];

            if (version <= 3)
            {
                MakeKey(password, PgpHashAlgorithm.MD5, Array.Empty<byte>(), 0, keyBytes);

                destination[0] = (byte)s2kParameters.EncryptionAlgorithm;

                c.GenerateIV();
                c.IV.CopyTo(destination.Slice(1));
                int bytesWritten = 13 + ((c.BlockSize + 7) / 8);
                destination = destination.Slice(bytesWritten);

                c.Key = keyBytes.ToArray();

                int checksum = 0;
                foreach (var b in source)
                    checksum += b;

                for (int i = 0; i < 4; i++)
                {
                    using var encryptor = new ZeroPaddedCryptoTransform(c.CreateEncryptor());

                    destination[0] = source[0];
                    destination[1] = source[1];

                    var mpInteger = MPInteger.ReadInteger(source, out int bytesConsumed).ToArray();
                    source = source.Slice(bytesConsumed);

                    var data = encryptor.TransformFinalBlock(mpInteger, 0, mpInteger.Length);
                    data.AsSpan().CopyTo(destination.Slice(2));
                    destination = destination.Slice(2 + data.Length);
                    CryptographicOperations.ZeroMemory(mpInteger);

                    if (i != 4)
                    {
                        c.IV = data.AsSpan(data.Length - (c.BlockSize / 8)).ToArray();
                    }
                }

                destination[0] = (byte)(checksum >> 8);
                destination[1] = (byte)(checksum);
            }
            else
            {
                var salt = new byte[8];
                RandomNumberGenerator.Fill(salt);
                byte rawIterationCount = 0x60;
                int iterationCount = (16 + (rawIterationCount & 15)) << ((rawIterationCount >> 4) + 6);

                MakeKey(password, s2kParameters.HashAlgorithm, salt, iterationCount, keyBytes);

                destination[0] = (byte)s2kParameters.UsageTag;
                destination[1] = (byte)s2kParameters.EncryptionAlgorithm;
                destination[2] = 3; // Salted & iterated
                destination[3] = (byte)s2kParameters.HashAlgorithm;

                salt.CopyTo(destination.Slice(4));
                destination[12] = rawIterationCount;

                c.GenerateIV();
                c.IV.CopyTo(destination.Slice(13));
                int bytesWritten = 13 + ((c.BlockSize + 7) / 8);
                destination = destination.Slice(bytesWritten);

                c.Key = keyBytes.ToArray();

                using var encryptor = new ZeroPaddedCryptoTransform(c.CreateEncryptor());
                byte[] checksumBytes;

                if (s2kParameters.UsageTag == S2kUsageTag.Sha1)
                {
                    using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
                    sha1.AppendData(source);
                    checksumBytes = sha1.GetHashAndReset();
                }
                else
                {
                    int checksum = 0;
                    foreach (var b in source)
                        checksum += b;
                    checksumBytes = new byte[] { (byte)(checksum >> 8), (byte)checksum };
                }

                var decSource = new byte[source.Length + checksumBytes.Length];
                source.CopyTo(decSource);
                checksumBytes.CopyTo(decSource, source.Length);

                var data = encryptor.TransformFinalBlock(decSource, 0, decSource.Length);
                data.AsSpan().CopyTo(destination);

                CryptographicOperations.ZeroMemory(data);
                CryptographicOperations.ZeroMemory(decSource);
            }
        }
    }
}