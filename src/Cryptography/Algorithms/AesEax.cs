using System;
using System.Security.Cryptography;
using Internal.Cryptography;
using Springburg.Cryptography.Primitives;

namespace Springburg.Cryptography.Algorithms
{
    public sealed class AesEax : IDisposable
    {
        private readonly Aes aes;
        private readonly CMAC cmac;

        public static KeySizes TagByteSizes { get; } = new KeySizes(0, 16, 1);

        public AesEax(byte[] key)
            : this(new ReadOnlySpan<byte>(key))
        {
        }

        public AesEax(ReadOnlySpan<byte> key)
        {
            this.aes = Aes.Create();
            this.aes.Key = key.ToArray();
            this.aes.Mode = CipherMode.ECB;
            this.aes.Padding = PaddingMode.None;
            this.cmac = new CMAC(Aes.Create(), key.ToArray());
        }

        public void Dispose()
        {
            this.aes.Dispose();
            this.cmac.Dispose();
        }

        private static void CheckParameters(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag)
        {
            if (plaintext.Length != ciphertext.Length)
                throw new ArgumentException(SR.Cryptography_PlaintextCiphertextLengthMismatch);
            if (tag.Length > 16)
                throw new ArgumentException(SR.Cryptography_InvalidTagLength, nameof(tag));
        }

        public void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[]? associatedData = null)
        {
            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));
            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));
            if (tag == null)
                throw new ArgumentNullException(nameof(tag));

            Encrypt((ReadOnlySpan<byte>)nonce, plaintext, ciphertext, tag, associatedData);
        }

        public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
        {
            CheckParameters(plaintext, ciphertext, tag);
            Process(nonce, plaintext, ciphertext, tag, associatedData, outputIsCiphertext: true);
        }

        public void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[]? associatedData = null)
        {
            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));
            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));
            if (tag == null)
                throw new ArgumentNullException(nameof(tag));

            Decrypt((ReadOnlySpan<byte>)nonce, ciphertext, tag, plaintext, associatedData);
        }

        public void Decrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext,
            ReadOnlySpan<byte> associatedData = default)
        {
            CheckParameters(plaintext, ciphertext, tag);

            var computedTag = CryptoPool.Rent(tag.Length);
            try
            {
                Process(nonce, ciphertext, plaintext, computedTag.AsSpan(0, tag.Length), associatedData, outputIsCiphertext: false);

                if (!CryptographicOperations.FixedTimeEquals(computedTag.AsSpan(0, tag.Length), tag))
                {
                    throw new CryptographicException(SR.Cryptography_AuthTagMismatch);
                }
            }
            finally
            {
                CryptoPool.Return(computedTag, tag.Length);
            }
        }

        private void Process(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output, Span<byte> tag, ReadOnlySpan<byte> associatedData, bool outputIsCiphertext)
        {
            using var encryptor = aes.CreateEncryptor();
            var tmp = CryptoPool.Rent(16);
            var counter = CryptoPool.Rent(16);
            var counterEnc = CryptoPool.Rent(16);
            var nonceMac = CryptoPool.Rent(16);
            var associatedDataMac = CryptoPool.Rent(16);
            var ciphertextMac = CryptoPool.Rent(16);

            try
            {
                CryptographicOperations.ZeroMemory(tmp.AsSpan(0, 15));
                tmp[15] = 0; // N tag
                cmac.TransformBlock(tmp, 0, 16, null, 0);
                cmac.TryComputeHash(nonce, nonceMac, out var _);

                tmp[15] = 1; // H tag
                cmac.TransformBlock(tmp, 0, 16, null, 0);
                cmac.TryComputeHash(associatedData, associatedDataMac, out var _);

                cmac.Initialize();
                tmp[15] = 2; // C tag
                cmac.TransformBlock(tmp, 0, 16, null, 0);

                nonceMac.AsSpan().CopyTo(counter);
                while (input.Length >= 16)
                {
                    encryptor.TransformBlock(counter, 0, 16, counterEnc, 0);
                    if (outputIsCiphertext)
                    {
                        for (int i = 0; i < 16; i++)
                            tmp[i] = (byte)(input[i] ^ counterEnc[i]);
                        cmac.TransformBlock(tmp, 0, 16, null, 0);
                        tmp.AsSpan(0, 16).CopyTo(output);
                    }
                    else
                    {
                        input.Slice(0, 16).CopyTo(tmp);
                        cmac.TransformBlock(tmp, 0, 16, null, 0);
                        for (int i = 0; i < 16; i++)
                            output[i] = (byte)(input[i] ^ counterEnc[i]);
                    }                    
                    byte add = 1;
                    for (int i = 15; i >= 0; i--)
                    {
                        counter[i] += add;
                        add = counter[i] == 0 ? 1 : 0;
                    }
                    input = input.Slice(16);
                    output = output.Slice(16);
                }

                if (input.Length > 0)
                {
                    encryptor.TransformBlock(counter, 0, 16, counterEnc, 0);
                    if (outputIsCiphertext)
                    {
                        for (int i = 0; i < input.Length; i++)
                            tmp[i] = (byte)(input[i] ^ counterEnc[i]);
                        cmac.TransformBlock(tmp, 0, input.Length, null, 0);
                        tmp.AsSpan(0, input.Length).CopyTo(output);
                    }
                    else
                    {
                        input.CopyTo(tmp);
                        cmac.TransformBlock(tmp, 0, input.Length, null, 0);
                        for (int i = 0; i < input.Length; i++)
                            output[i] = (byte)(input[i] ^ counterEnc[i]);
                    }
                }

                cmac.TryComputeHash(Array.Empty<byte>(), ciphertextMac, out var _);

                for (int i = 0; i < tag.Length; i++)
                    tag[i] = (byte)(nonceMac[i] ^ associatedDataMac[i] ^ ciphertextMac[i]);
            }
            finally
            {
                cmac.Initialize();
                CryptoPool.Return(tmp, 16);
                CryptoPool.Return(counter, 16);
                CryptoPool.Return(counterEnc, 16);
                CryptoPool.Return(nonceMac, 16);
                CryptoPool.Return(associatedDataMac, 16);
                CryptoPool.Return(ciphertextMac, 16);
            }
        }
    }
}