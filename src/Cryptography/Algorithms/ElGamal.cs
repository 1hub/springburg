using Internal.Cryptography;
using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Springburg.Cryptography.Algorithms
{
    public class ElGamal : AsymmetricAlgorithm
    {
        private readonly BigInteger P;
        private readonly BigInteger G;
        private readonly BigInteger Y;
        private readonly BigInteger X;

        private ElGamal()
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };
        }

        private ElGamal(BigInteger P, BigInteger G, BigInteger Y, BigInteger X)
            : this()
        {
            this.P = P;
            this.G = G;
            this.Y = Y;
            this.X = X;
            KeySizeValue = P.GetByteCount() * 8;
        }

        public static ElGamal Create(ElGamalParameters parameters)
        {
            return new ElGamal(
                P: new BigInteger(parameters.P, isUnsigned: true, isBigEndian: true),
                G: new BigInteger(parameters.G, isUnsigned: true, isBigEndian: true),
                Y: new BigInteger(parameters.Y, isUnsigned: true, isBigEndian: true),
                X: parameters.X != null ? new BigInteger(parameters.X, isUnsigned: true, isBigEndian: true) : BigInteger.Zero);
        }

        public ElGamalParameters ExportParameters(bool includePrivateParams)
        {
            return new ElGamalParameters
            {
                P = P.ToByteArray(isBigEndian: true, isUnsigned: true),
                G = G.ToByteArray(isBigEndian: true, isUnsigned: true),
                Y = Y.ToByteArray(isBigEndian: true, isUnsigned: true),
                X = includePrivateParams ? X.ToByteArray(isBigEndian: true, isUnsigned: true) : Array.Empty<byte>()
            };
        }

        public ReadOnlySpan<byte> Decrypt(ReadOnlySpan<byte> data, RSAEncryptionPadding padding)
        {
            if (padding != RSAEncryptionPadding.Pkcs1)
                throw new ArgumentOutOfRangeException(nameof(padding), SR.Cryptography_UnknownPaddingMode);

            long maxLength = 2 * (KeySizeValue / 2);
            if (data.Length > maxLength)
                throw new CryptographicException("Input too large for ElGamal cipher");

            int halfLength = data.Length / 2;
            BigInteger gamma = new BigInteger(data.Slice(0, halfLength), isUnsigned: true, isBigEndian: true);
            BigInteger phi = new BigInteger(data.Slice(halfLength), isUnsigned: true, isBigEndian: true);
            gamma = BigInteger.ModPow(gamma, P - BigInteger.One - X, P);
            var paddedMessage = (gamma * phi % P).ToByteArray(isUnsigned: true, isBigEndian: true);

            if (paddedMessage[0] != 2)
                throw new CryptographicException(SR.Cryptography_InvalidPadding);
            int zeroIndex = Array.IndexOf<byte>(paddedMessage, 0, 1);
            if (zeroIndex < 0)
                throw new CryptographicException(SR.Cryptography_InvalidPadding);

            CryptographicOperations.ZeroMemory(paddedMessage.AsSpan(0, zeroIndex));
            return paddedMessage.AsSpan(zeroIndex + 1).ToArray();
        }

        public ReadOnlySpan<byte> Encrypt(ReadOnlySpan<byte> data, RSAEncryptionPadding padding)
        {
            if (padding != RSAEncryptionPadding.Pkcs1)
                throw new ArgumentOutOfRangeException(nameof(padding), SR.Cryptography_UnknownPaddingMode);

            if (data.Length > (KeySizeValue / 8) - 1 - 2) // - 2 for padding
                throw new CryptographicException("Input too large for ElGamal cipher");

            byte[] paddedData = new byte[(KeySizeValue / 8) - 1];
            paddedData[0] = 2;
            using var rng = RandomNumberGenerator.Create();
            rng.GetNonZeroBytes(paddedData.AsSpan(1, paddedData.Length - 2 - data.Length));
            data.CopyTo(paddedData.AsSpan(paddedData.Length - data.Length));

            BigInteger tmp = new BigInteger(paddedData, isUnsigned: true, isBigEndian: true);

            BigInteger pSub1 = P - BigInteger.One;

            // TODO In theory, a series of 'k', 'g.ModPow(k, p)' and 'y.ModPow(k, p)' can be pre-calculated
            int kSize = (int)P.GetBitLength() - 1;
            BigInteger k;
            do
            {
                k = GenRandomBits(kSize);
            } while (!BigInteger.GreatestCommonDivisor(k, pSub1).IsOne);

            BigInteger g = G;

            var gamma = BigInteger.ModPow(G, k, P);
            var phi = BigInteger.ModPow(Y, k, P) * tmp % P;

            var output = new byte[2 * (KeySizeValue / 8)];

            gamma.TryWriteBytes(output.AsSpan(output.Length / 2 - gamma.GetByteCount(isUnsigned: true)), out var _, isUnsigned: true, isBigEndian: true);
            phi.TryWriteBytes(output.AsSpan(output.Length - phi.GetByteCount(isUnsigned: true)), out var _, isUnsigned: true, isBigEndian: true);

            CryptographicOperations.ZeroMemory(paddedData);

            return output;
        }

        /// <summary>
        /// Returns the specified amount of random bits
        /// </summary>
        private static BigInteger GenRandomBits(int bits)
        {
            if (bits <= 0)
                throw new ArithmeticException("Number of required bits is not valid.");

            var bytes = bits >> 3;
            var remBits = bits % 8;

            if (remBits != 0)
                bytes++;

            var data = new byte[bytes];

            RandomNumberGenerator.Fill(data);

            if (remBits != 0)
            {
                byte mask;

                if (bits != 1)
                {
                    mask = (byte)(0x01 << (remBits - 1));
                    data[bytes - 1] |= mask;
                }

                mask = (byte)(0xFF >> (8 - remBits));
                data[bytes - 1] &= mask;
            }
            else
                data[bytes - 1] |= 0x80;

            data[bytes - 1] &= 0x7F;

            return new BigInteger(data);
        }
    }
}
