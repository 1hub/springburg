using InflatablePalace.Cryptography.Algorithms.Modes;
using System;
using System.Security.Cryptography;

namespace InflatablePalace.Cryptography.Algorithms
{
    class IDEA : SymmetricAlgorithm
    {
        public IDEA()
        {
            this.LegalKeySizesValue = new KeySizes[] { new KeySizes(128, 128, 0) };
            this.LegalBlockSizesValue = new KeySizes[] { new KeySizes(64, 64, 0) };
            this.KeySize = 128;
            this.BlockSize = 64;
            this.Padding = PaddingMode.Zeros;
            this.Mode = CipherMode.ECB;
        }

        public override ICryptoTransform CreateEncryptor(byte[] key, byte[] iv) =>
            ModeHelper.CreateEncryptor(ModeValue, PaddingValue, key, iv, (key, encryption) => new IDEATransform(key, encryption));

        public override ICryptoTransform CreateDecryptor(byte[] key, byte[] iv) =>
            ModeHelper.CreateDecryptor(ModeValue, PaddingValue, key, iv, (key, encryption) => new IDEATransform(key, encryption));

        public override void GenerateIV()
        {
            throw new NotImplementedException();
        }

        public override void GenerateKey()
        {
            throw new NotImplementedException();
        }

        public override CipherMode Mode
        {
            set
            {
                ModeHelper.ThrowOnUnsupportedMode(value);
                this.ModeValue = value;
            }
        }

        sealed class IDEATransform : IBlockTransform
        {
            private int[] workingKey;

            public IDEATransform(byte[] key, bool encryption)
            {
                this.workingKey = encryption ? ExpandKey(key) : InvertKey(ExpandKey(key));
            }

            public int BlockSizeInBytes => 8;

            public int Transform(ReadOnlySpan<byte> input, Span<byte> output)
            {
                int x0, x1, x2, x3, t0, t1;
                int o0, o1, o2, o3;
                int keyOff = 0;
                x0 = (input[0] << 8) + input[1];
                x1 = (input[2] << 8) + input[3];
                x2 = (input[4] << 8) + input[5];
                x3 = (input[6] << 8) + input[7];
                for (int round = 0; round < 8; round++)
                {
                    x0 = Mul(x0, workingKey[keyOff++]);
                    x1 += workingKey[keyOff++];
                    x1 &= 0xffff;
                    x2 += workingKey[keyOff++];
                    x2 &= 0xffff;
                    x3 = Mul(x3, workingKey[keyOff++]);
                    t0 = x1;
                    t1 = x2;
                    x2 ^= x0;
                    x1 ^= x3;
                    x2 = Mul(x2, workingKey[keyOff++]);
                    x1 += x2;
                    x1 &= 0xffff;
                    x1 = Mul(x1, workingKey[keyOff++]);
                    x2 += x1;
                    x2 &= 0xffff;
                    x0 ^= x1;
                    x3 ^= x2;
                    x1 ^= t1;
                    x2 ^= t0;
                }
                o0 = Mul(x0, workingKey[keyOff++]);
                o1 = x2 + workingKey[keyOff++];
                o2 = x1 + workingKey[keyOff++];
                o3 = Mul(x3, workingKey[keyOff]);
                output[0] = (byte)(o0 >> 8);
                output[1] = (byte)o0;
                output[2] = (byte)(o1 >> 8);
                output[3] = (byte)o1;
                output[4] = (byte)(o2 >> 8);
                output[5] = (byte)o2;
                output[6] = (byte)(o3 >> 8);
                output[7] = (byte)o3;
                return BlockSizeInBytes;
            }

            /// <summary>
            /// This function computes multiplicative inverse using Euclid's Greatest
            /// Common Divisor algorithm. Zero and one are self inverse.
            ///
            /// i.e. x* MulInv(x) == 1 (modulo BASE)
            /// </summary>
            private static int MulInv(int x)
            {
                int t0, t1, q, y;

                if (x < 2)
                    return x;

                t0 = 1;
                t1 = 0x10001 / x;
                y = 0x10001 % x;
                while (y != 1)
                {
                    q = x / y;
                    x = x % y;
                    t0 = (t0 + (t1 * q)) & 0xffff;
                    if (x == 1)
                        return t0;
                    q = y / x;
                    y = y % x;
                    t1 = (t1 + (t0 * q)) & 0xffff;
                }

                return (1 - t1) & 0xffff;
            }

            /// <summary>Return the additive inverse of x, i.e. x + AddInv(x) == 0</summary>
            private static int AddInv(int x) => (0 - x) & 0xffff;

            /// <summary>
            /// return x = x * y where the multiplication is done modulo
            /// 65537 (0x10001) (as defined in the IDEA specification) and
            /// a zero input is taken to be 65536 (0x10000).
            /// </summary>
            private static int Mul(int x, int y)
            {
                if (x == 0)
                    return (0x10001 - y) & 0xffff;
                if (y == 0)
                    return (0x10001 - x) & 0xffff;

                int p = x * y;
                y = p & 0xffff;
                x = (int)((uint)p >> 16);
                x = y - x + ((y < x) ? 1 : 0);
                return x & 0xffff;
            }

            /// <summary>
            /// The following function is used to expand the user key to the encryption
            /// subkey. The first 16 bytes are the user key, and the rest of the subkey
            /// is calculated by rotating the previous 16 bytes by 25 bits to the left,
            /// and so on until the subkey is completed.
            /// </summary>
            private static int[] ExpandKey(byte[] uKey)
            {
                int[] key = new int[52];
                if (uKey.Length < 16)
                {
                    byte[] tmp = new byte[16];
                    Array.Copy(uKey, 0, tmp, tmp.Length - uKey.Length, uKey.Length);
                    uKey = tmp;
                }
                for (int i = 0; i < 8; i++)
                {
                    key[i] = (uKey[i * 2] << 8) + uKey[i * 2 + 1];
                }
                for (int i = 8; i < 52; i++)
                {
                    if ((i & 7) < 6)
                        key[i] = ((key[i - 7] & 127) << 9 | key[i - 6] >> 7) & 0xffff;
                    else if ((i & 7) == 6)
                        key[i] = ((key[i - 7] & 127) << 9 | key[i - 14] >> 7) & 0xffff;
                    else
                        key[i] = ((key[i - 15] & 127) << 9 | key[i - 14] >> 7) & 0xffff;
                }
                return key;
            }

            /// <summary>The function to invert the encryption subkey to the decryption subkey</summary>
            private int[] InvertKey(int[] inKey)
            {
                int t1, t2, t3, t4;
                int p = 52; // We work backwards
                int[] key = new int[52];
                int inOff = 0;

                t1 = MulInv(inKey[inOff++]);
                t2 = AddInv(inKey[inOff++]);
                t3 = AddInv(inKey[inOff++]);
                t4 = MulInv(inKey[inOff++]);
                key[--p] = t4;
                key[--p] = t3;
                key[--p] = t2;
                key[--p] = t1;

                for (int round = 1; round < 8; round++)
                {
                    t1 = inKey[inOff++];
                    t2 = inKey[inOff++];
                    key[--p] = t2;
                    key[--p] = t1;

                    t1 = MulInv(inKey[inOff++]);
                    t2 = AddInv(inKey[inOff++]);
                    t3 = AddInv(inKey[inOff++]);
                    t4 = MulInv(inKey[inOff++]);
                    key[--p] = t4;
                    key[--p] = t2; // NB: Order
                    key[--p] = t3;
                    key[--p] = t1;
                }
                t1 = inKey[inOff++];
                t2 = inKey[inOff++];
                key[--p] = t2;
                key[--p] = t1;

                t1 = MulInv(inKey[inOff++]);
                t2 = AddInv(inKey[inOff++]);
                t3 = AddInv(inKey[inOff++]);
                t4 = MulInv(inKey[inOff]);
                key[--p] = t4;
                key[--p] = t3;
                key[--p] = t2;
                key[--p] = t1;
                return key;
            }
        }
    }
}
