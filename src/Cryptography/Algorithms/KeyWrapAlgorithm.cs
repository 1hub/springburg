// RFC3394 Key Wrapping Algorithm
// Written by Jay Miller
// This code is hereby released into the public domain, This applies worldwide.

using System;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;

namespace InflatablePalace.Cryptography.Algorithms
{
    /// <summary>
    /// An implementation of the RFC3394 key-wrapping algorithm.
    /// </summary>
    public class KeyWrapAlgorithm
    {
        byte[] DefaultIV = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
        byte[] _kek;

        /// <summary>
        /// Constructs a <b>KeyWrapAlgorithm</b> object with the specified key-encryption key.
        /// </summary>
        /// <param name="kek">The key-encryption key to use for subsequent wrapping and unwrapping operations.  This must be a valid AES key.</param>
        /// <exception cref="ArgumentNullException"><c>kek</c> was a null reference.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><c>kek</c> must be a valid AES key, either 128, 192 or 256 bits long.</exception>
        public KeyWrapAlgorithm(byte[] kek)
        {
            ValidateKEK(kek);
            _kek = kek;
        }

        /// <summary>
        /// Wrap key data.
        /// </summary>
        /// <param name="plaintext">The key data, two or more 8-byte blocks.</param>
        /// <returns>The encrypted, wrapped data.</returns>
        /// <exception cref="ArgumentNullException"><c>plaintext</c> was <b>null</b>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The plaintext contained fewer than 16 bytes.</exception>
        /// <exception cref="ArgumentException"><c>plaintext</c> was not made up of 64-bit blocks.</exception>
        public byte[] WrapKey(byte[] plaintext)
        {
            ValidateInput(plaintext, "plaintext");

            // 1) Initialize variables

            Block A = new Block(DefaultIV);
            Block[] R = Block.BytesToBlocks(plaintext);
            long n = R.Length;

            // 2) Calculate intermediate values

            for (long j = 0; j < 6; j++)
            {
                for (long i = 0; i < n; i++)
                {
                    long t = n * j + i + 1;  // add 1 because i is zero-based
                    Block[] B = Encrypt(A.Concat(R[i]));
                    A = MSB(B);
                    R[i] = LSB(B);
                    A ^= t;
                }
            }

            // 3) Output the results

            Block[] C = new Block[n + 1];
            C[0] = A;
            for (long i = 1; i <= n; i++)
                C[i] = R[i - 1];

            return Block.BlocksToBytes(C);
        }

        /// <summary>
        /// Unwrap encrypted key data.
        /// </summary>
        /// <param name="ciphertext">The encrypted key data, two or more 8-byte blocks.</param>
        /// <returns>The original key data.</returns>
        /// <exception cref="ArgumentNullException"><c>ciphertext</c> was <b>null</b>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The ciphertext contained fewer than 16 bytes.</exception>
        /// <exception cref="ArgumentException"><c>ciphertext</c> was not made up of 64-bit blocks.</exception>
        /// <exception cref="CryptographicException">The decryption process failed an integrity check.</exception>
        public byte[] UnwrapKey(byte[] ciphertext)
        {
            ValidateInput(ciphertext, "ciphertext");
            Block[] C = Block.BytesToBlocks(ciphertext);

            // 1) Initialize variables

            Block A = C[0];
            Block[] R = new Block[C.Length - 1];
            for (int i = 1; i < C.Length; i++)
                R[i - 1] = C[i];
            long n = R.Length;

            // 2) Calculate intermediate values

            for (long j = 5; j >= 0; j--)
            {
                for (long i = n - 1; i >= 0; i--)
                {
                    long t = n * j + i + 1;  // add 1 because i is zero-based
                    A ^= t;
                    Block[] B = Decrypt(A.Concat(R[i]));
                    A = MSB(B);
                    R[i] = LSB(B);
                }
            }

            // 3) Output the results

            if (!CryptographicOperations.FixedTimeEquals(DefaultIV, A.Bytes))
                throw new CryptographicException("Integrity check failed.");

            return Block.BlocksToBytes(R);
        }

        /// <summary>
        /// Wrap key data with a key-encryption key.
        /// </summary>
        /// <param name="kek">The key encryption key.  This must be a valid AES key.</param>
        /// <param name="plaintext">The key data, two or more 8-byte blocks.</param>
        /// <returns>The encrypted, wrapped data.</returns>
        /// <exception cref="ArgumentNullException">One or more arguments was <b>null</b>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Either <c>kek</c> was an invalid AES key, or the plaintext contained fewer than 16 bytes.</exception>
        /// <exception cref="ArgumentException"><c>plaintext</c> was not made up of 64-bit blocks.</exception>
        public static byte[] WrapKey(byte[] kek, byte[] plaintext)
        {
            KeyWrapAlgorithm kwa = new KeyWrapAlgorithm(kek);
            return kwa.WrapKey(plaintext);
        }

        /// <summary>
        /// Unwrap key data with a key-decryption key.
        /// </summary>
        /// <param name="kek">The key-decryption key.  This must be a valid AES key.</param>
        /// <param name="ciphertext">The encrypted key data, two or more 8-byte blocks.</param>
        /// <returns>The original key data.</returns>
        /// <exception cref="ArgumentNullException">One or more arguments was <b>null</b>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Either <c>kek</c> was an invalid AES key, or the ciphertext contained fewer than 16 bytes.</exception>
        /// <exception cref="ArgumentException"><c>ciphertext</c> was not made up of 64-bit blocks.</exception>
        /// <exception cref="CryptographicException">The decryption process failed an integrity check.</exception>
        public static byte[] UnwrapKey(byte[] kek, byte[] ciphertext)
        {
            KeyWrapAlgorithm kwa = new KeyWrapAlgorithm(kek);
            return kwa.UnwrapKey(ciphertext);
        }

        /// <summary>
        /// Validates a key encryption key.
        /// </summary>
        /// <param name="kek">The key encryption key (KEK) to validate.</param>
        private static void ValidateKEK(byte[] kek)
        {
            if (kek == null)
                throw new ArgumentNullException("kek");
            if (kek.Length != 16 && kek.Length != 24 && kek.Length != 32)
                throw new ArgumentOutOfRangeException("kek");
        }

        /// <summary>
        /// Validates the input to the (un)wrapping methods.
        /// </summary>
        /// <param name="input">Input to validate.</param>
        /// <param name="paramName">Name to use for exception messages.</param>
        /// <remarks>n must be at least 2, see §2.</remarks>
        private static void ValidateInput(byte[] input, string paramName)
        {
            if (input == null)
                throw new ArgumentNullException(paramName);
            if (input.Length < 16)
                throw new ArgumentOutOfRangeException(paramName);
            if (input.Length % 8 != 0)
                throw new ArgumentException("Length of bytes must be a multiple of 8.", paramName);
        }

        /// <summary>
        /// Encrypts a block of plaintext with AES.
        /// </summary>
        /// <param name="plaintext">Plaintext to encrypt.</param>
        /// <returns><see cref="Block"/> containing the ciphertext bytes.</returns>
        private Block[] Encrypt(byte[] plaintext)
        {
            Aes alg = Aes.Create();
            alg.Padding = PaddingMode.None;
            alg.Mode = CipherMode.ECB;
            alg.Key = _kek;

            if (plaintext == null)
                throw new ArgumentNullException("plaintext");
            if (plaintext.Length != alg.BlockSize / 8)
                throw new ArgumentOutOfRangeException("plaintext");

            byte[] ciphertext = new byte[alg.BlockSize / 8];

            using (MemoryStream ms = new MemoryStream(plaintext))
            using (ICryptoTransform xf = alg.CreateEncryptor())
            using (CryptoStream cs = new CryptoStream(ms, xf, CryptoStreamMode.Read))
                cs.Read(ciphertext, 0, alg.BlockSize / 8);

            return Block.BytesToBlocks(ciphertext);
        }

        /// <summary>
        /// Decrypts a block of ciphertext with AES.
        /// </summary>
        /// <param name="ciphertext">Ciphertext to decrypt.</param>
        /// <returns><see cref="Block"/> containing the plaintext bytes.</returns>
        private Block[] Decrypt(byte[] ciphertext)
        {
            Aes alg = Aes.Create();
            alg.Padding = PaddingMode.None;
            alg.Mode = CipherMode.ECB;
            alg.Key = _kek;

            if (ciphertext == null)
                throw new ArgumentNullException("ciphertext");
            if (ciphertext.Length != alg.BlockSize / 8)
                throw new ArgumentOutOfRangeException("ciphertext");

            byte[] plaintext;

            using (MemoryStream ms = new MemoryStream())
            using (ICryptoTransform xf = alg.CreateDecryptor())
            using (CryptoStream cs = new CryptoStream(ms, xf, CryptoStreamMode.Write))
            {
                cs.Write(ciphertext, 0, alg.BlockSize / 8);
                plaintext = ms.ToArray();
            }

            return Block.BytesToBlocks(plaintext);
        }

        /// <summary>
        /// Retrieves the 64 most significant bits of a 128-bit <see cref="Block"/>[].
        /// </summary>
        /// <param name="B">An array of two blocks (128 bits).</param>
        /// <returns>The 64 most significant bits of <paramref name="B"/>.</returns>
        private static Block MSB(Block[] B)
        {
            Debug.Assert(B.Length == 2);
            return B[0];
        }

        /// <summary>
        /// Retrieves the 64 least significant bits of a 128-bit <see cref="Block"/>[].
        /// </summary>
        /// <param name="B">An array of two blocks (128 bits).</param>
        /// <returns>The 64 most significant bits of <paramref name="B"/>.</returns>
        private static Block LSB(Block[] B)
        {
            Debug.Assert(B.Length == 2);
            return B[1];
        }

        /// <summary>
        /// A <b>Block</b> contains exactly 64 bits of data.  This class
        /// provides several handy block-level operations.
        /// </summary>
        internal class Block
        {
            byte[] _b = new byte[8];

            public Block(Block b) : this(b.Bytes) { }
            public Block(byte[] bytes) : this(bytes, 0) { }
            public Block(byte[] bytes, int index)
            {
                if (bytes == null)
                    throw new ArgumentNullException(nameof(bytes));
                if (index + 8 > bytes.Length)
                    throw new ArgumentException("Insufficient buffer size", nameof(bytes));
                if (index < 0)
                    throw new ArgumentOutOfRangeException(nameof(index));

                Array.Copy(bytes, index, _b, 0, 8);
            }

            // Gets the contents of the current Block.
            public byte[] Bytes
            {
                get { return _b; }
            }

            // Concatenates the current Block with the specified Block.
            public byte[] Concat(Block right)
            {
                if (right == null)
                    throw new ArgumentNullException("right");

                byte[] output = new byte[16];

                _b.CopyTo(output, 0);
                right.Bytes.CopyTo(output, 8);

                return output;
            }

            // Converts an array of bytes to an array of Blocks.
            public static Block[] BytesToBlocks(byte[] bytes)
            {
                if (bytes == null)
                    throw new ArgumentNullException(nameof(bytes));
                if (bytes.Length % 8 != 0)
                    throw new ArgumentException("Length of bytes must be a multiple of 8", nameof(bytes));

                Block[] blocks = new Block[bytes.Length / 8];

                for (int i = 0; i < bytes.Length; i += 8)
                    blocks[i / 8] = new Block(bytes, i);

                return blocks;
            }

            // Converts an array of Blocks to an arry of bytes.
            public static byte[] BlocksToBytes(Block[] blocks)
            {
                if (blocks == null)
                    throw new ArgumentNullException(nameof(blocks));

                byte[] bytes = new byte[blocks.Length * 8];

                for (int i = 0; i < blocks.Length; i++)
                    blocks[i].Bytes.CopyTo(bytes, i * 8);

                return bytes;
            }

            // XOR operator against a 64-bit value.
            public static Block operator ^(Block left, long right)
            {
                return Xor(left, right);
            }

            // XORs a block with a 64-bit value.
            public static Block Xor(Block left, long right)
            {
                if (left == null)
                    throw new ArgumentNullException(nameof(left));

                Block result = new Block(left);
                ReverseBytes(result.Bytes);
                long temp = BitConverter.ToInt64(result.Bytes, 0);

                result = new Block(BitConverter.GetBytes(temp ^ right));
                ReverseBytes(result.Bytes);
                return result;
            }

            // Swaps the byte positions in the specified array.
            internal static void ReverseBytes(byte[] bytes)
            {
                Debug.Assert(bytes != null);
                for (int i = 0; i < bytes.Length / 2; i++)
                {
                    byte temp = bytes[i];
                    bytes[i] = bytes[(bytes.Length - 1) - i];
                    bytes[(bytes.Length - 1) - i] = temp;
                }
            }
        }
    }
}
