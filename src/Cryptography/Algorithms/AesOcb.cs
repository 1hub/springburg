using System;
using System.Security.Cryptography;
using System.Text;
using Internal.Cryptography;

namespace Springburg.Cryptography.Algorithms
{
    public sealed class AesOcb : IDisposable
    {
        private readonly Aes aes;
        private readonly ICryptoTransform encryptor;
        private readonly byte[] l_dollar;
        private readonly byte[] l_star;

        private const int NonceSize = 12;
        public static KeySizes NonceByteSizes { get; } = new KeySizes(NonceSize, NonceSize, 1);
        public static KeySizes TagByteSizes { get; } = new KeySizes(8, 16, 4);

        public AesOcb(byte[] key)
            : this(new ReadOnlySpan<byte>(key))
        {
        }

        public AesOcb(ReadOnlySpan<byte> key)
        {
            this.aes = Aes.Create();
            this.aes.Key = key.ToArray();
            this.aes.Mode = CipherMode.ECB;
            this.aes.Padding = PaddingMode.None;

            l_star = CryptoPool.Rent(16);
            l_dollar = CryptoPool.Rent(16);            
            
            encryptor = aes.CreateEncryptor();
            CryptographicOperations.ZeroMemory(l_star.AsSpan(0, 16));
            encryptor.TransformBlock(l_star, 0, 16, l_star, 0);
            Double(l_star, l_dollar);
        }

        public void Dispose()
        {
            encryptor.Dispose();
            aes.Clear();
            CryptoPool.Return(l_dollar);
            CryptoPool.Return(l_star);
        }

        private static void CheckParameters(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> tag)
        {
            if (plaintext.Length != ciphertext.Length)
                throw new ArgumentException(SR.Cryptography_PlaintextCiphertextLengthMismatch);
            if (nonce.Length != NonceSize)
                throw new ArgumentException(SR.Cryptography_InvalidNonceLength, nameof(nonce));
            if (tag.Length != 8 && tag.Length != 12 && tag.Length != 16)
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
            CheckParameters(plaintext, ciphertext, nonce, tag);

            var realNonce = CryptoPool.Rent(16);
            var stretch = CryptoPool.Rent(24);
            var offset = CryptoPool.Rent(16);
            var checksum = CryptoPool.Rent(16);
            var tmp = CryptoPool.Rent(16);
            CryptographicOperations.ZeroMemory(checksum.AsSpan(0, 16));

            try
            {
                int bottom = nonce[^1] & 0x3f;

                realNonce[0] = (byte)(tag.Length << 7);
                nonce.CopyTo(realNonce.AsSpan(16 - nonce.Length));
                realNonce[15 - nonce.Length] |= 1;
                realNonce[15] &= 0xc0;

                encryptor.TransformBlock(realNonce, 0, 16, stretch, 0);
                for (int i = 0; i < 8; ++i)
                    stretch[16 + i] = (byte)(stretch[i] ^ stretch[i + 1]);

                int bits = bottom % 8, bytes = bottom / 8;
                if (bits == 0)
                {
                    stretch.AsSpan(bytes, 16).CopyTo(offset);
                }
                else
                {
                    for (int i = 0; i < 16; ++i)
                    {
                        uint b1 = stretch[bytes];
                        uint b2 = stretch[++bytes];
                        offset[i] = (byte) ((b1 << bits) | (b2 >> (8 - bits)));
                    }
                }

                for (int i = 1; plaintext.Length >= 16; i++)
                {
                    Calc_L_i(i, tmp);
                    Xor(offset, tmp, offset);
                    Xor(offset, plaintext.Slice(0, 16), tmp);
                    encryptor.TransformBlock(tmp, 0, 16, tmp, 0);
                    Xor(tmp, offset, ciphertext);
                    Xor(checksum, plaintext, checksum);
                    plaintext = plaintext.Slice(16);
                    ciphertext = ciphertext.Slice(16);
                }

                if (plaintext.Length > 0)
                {
                    Xor(offset, l_star, offset);
                    encryptor.TransformBlock(offset, 0, 16, tmp, 0);
                    for (int i = 0; i < plaintext.Length; i++)
                        ciphertext[i] = (byte)(plaintext[i] ^ tmp[i]);
                    Extend(plaintext, tmp);
                    Xor(checksum, tmp, checksum);
                }

                Xor(checksum, l_dollar, checksum);
                Xor(checksum, offset, checksum);
                encryptor.TransformBlock(checksum, 0, 16, checksum, 0);
                Hash(associatedData, tmp);
                Xor(tmp, checksum, checksum);
                checksum.AsSpan(0, tag.Length).CopyTo(tag);
            }
            finally
            {
                CryptoPool.Return(realNonce, 16);
                CryptoPool.Return(stretch, 24);
                CryptoPool.Return(offset, 16);
                CryptoPool.Return(checksum, 16);                
                CryptoPool.Return(tmp, 16);                
            }
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
            CheckParameters(plaintext, ciphertext, nonce, tag);

            using var decryptor = aes.CreateDecryptor();
            var realNonce = CryptoPool.Rent(16);
            var stretch = CryptoPool.Rent(24);
            var offset = CryptoPool.Rent(16);
            var checksum = CryptoPool.Rent(16);
            var tmp = CryptoPool.Rent(16);
            CryptographicOperations.ZeroMemory(checksum.AsSpan(0, 16));

            try
            {
                int bottom = nonce[^1] & 0x3f;

                realNonce[0] = (byte)(tag.Length << 7);
                nonce.CopyTo(realNonce.AsSpan(16 - nonce.Length));
                realNonce[15 - nonce.Length] |= 1;
                realNonce[15] &= 0xc0;

                encryptor.TransformBlock(realNonce, 0, 16, stretch, 0);
                for (int i = 0; i < 8; ++i)
                    stretch[16 + i] = (byte)(stretch[i] ^ stretch[i + 1]);

                int bits = bottom % 8, bytes = bottom / 8;
                if (bits == 0)
                {
                    stretch.AsSpan(bytes, 16).CopyTo(offset);
                }
                else
                {
                    for (int i = 0; i < 16; ++i)
                    {
                        uint b1 = stretch[bytes];
                        uint b2 = stretch[++bytes];
                        offset[i] = (byte) ((b1 << bits) | (b2 >> (8 - bits)));
                    }
                }

                for (int i = 1; ciphertext.Length >= 16; i++)
                {
                    Calc_L_i(i, tmp);
                    Xor(offset, tmp, offset);
                    Xor(offset, ciphertext.Slice(0, 16), tmp);
                    decryptor.TransformBlock(tmp, 0, 16, tmp, 0);
                    Xor(tmp, offset, plaintext);
                    Xor(checksum, plaintext, checksum);
                    plaintext = plaintext.Slice(16);
                    ciphertext = ciphertext.Slice(16);
                }

                if (ciphertext.Length > 0)
                {
                    Xor(offset, l_star, offset);
                    encryptor.TransformBlock(offset, 0, 16, tmp, 0);
                    for (int i = 0; i < ciphertext.Length; i++)
                        plaintext[i] = (byte)(ciphertext[i] ^ tmp[i]);
                    Extend(plaintext, tmp);
                    Xor(checksum, tmp, checksum);
                }

                Xor(checksum, l_dollar, checksum);
                Xor(checksum, offset, checksum);
                encryptor.TransformBlock(checksum, 0, 16, checksum, 0);
                Hash(associatedData, tmp);
                Xor(tmp, checksum, checksum);
                if (!CryptographicOperations.FixedTimeEquals(checksum.AsSpan(0, tag.Length), tag))
                {
                    throw new CryptographicException(SR.Cryptography_AuthTagMismatch);
                }
            }
            finally
            {
                CryptoPool.Return(realNonce, 16);
                CryptoPool.Return(stretch, 24);
                CryptoPool.Return(offset, 16);
                CryptoPool.Return(checksum, 16);
                CryptoPool.Return(tmp, 16);
            }
        }

        private void Hash(ReadOnlySpan<byte> associatedData, Span<byte> sum)
        {
            var offset = CryptoPool.Rent(16);
            var tmp = CryptoPool.Rent(16);

            CryptographicOperations.ZeroMemory(offset.AsSpan(0, 16));
            CryptographicOperations.ZeroMemory(sum.Slice(0, 16));

            try
            {
                for (int i = 1; associatedData.Length >= 16; i++)
                {
                    Calc_L_i(i, tmp);
                    Xor(offset, tmp, offset);
                    Xor(offset, associatedData.Slice(0, 16), tmp);
                    encryptor.TransformBlock(tmp, 0, 16, tmp, 0);
                    Xor(sum, tmp, sum);
                    associatedData = associatedData.Slice(16);
                }

                if (associatedData.Length > 0)
                {
                    Xor(offset, l_star, offset);
                    Extend(associatedData, tmp);
                    Xor(offset, tmp, tmp);
                    encryptor.TransformBlock(tmp, 0, 16, tmp, 0);
                    Xor(sum, tmp, sum);
                }
            }
            finally
            {
                CryptoPool.Return(offset, 16);
                CryptoPool.Return(tmp, 16);
            }
        }

        private void Calc_L_i(int i, Span<byte> L_i)
        {
            Double(l_dollar, L_i);
            for (; (i & 1) == 0; i >>= 1)
                Double(L_i, L_i);
        }

        private static void Xor(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> destination)
        {
            for (int i = 15; i >= 0; --i)
                destination[i] = (byte)(a[i] ^ b[i]);
        }

        private static int ShiftLeft(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            int i = 16;
            uint bit = 0;
            while (--i >= 0)
            {
                uint b = source[i];
                destination[i] = (byte) ((b << 1) | bit);
                bit = (b >> 7) & 1;
            }
            return (int)bit;
        }

        private static void Double(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            int carry = ShiftLeft(source, destination);
            destination[15] ^= (byte)(0x87 >> ((1 - carry) << 3));
        }

        private static void Extend(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            CryptographicOperations.ZeroMemory(destination.Slice(0, 16));
            source.CopyTo(destination);
            destination[source.Length] = 0x80;
        }
    }
}