using NUnit.Framework;
using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace InflatablePalace.Test.Algorithms
{
    [TestFixture]
    public abstract class SymmetricAlgorithmTest<T>
        where T : SymmetricAlgorithm, new()
    {
        internal static byte[] HexToByteArray(string hexString)
        {
            byte[] bytes = new byte[hexString.Length / 2];

            for (int i = 0; i < hexString.Length; i += 2)
            {
                string s = hexString.Substring(i, 2);
                bytes[i / 2] = byte.Parse(s, NumberStyles.HexNumber, null);
            }

            return bytes;
        }

        internal static string ByteArrayToHex(ReadOnlySpan<byte> bytes)
        {
            StringBuilder builder = new StringBuilder(bytes.Length * 2);

            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("X2"));
            }

            return builder.ToString();
        }

        [Test]
        [TestCaseSource("TestVectors")]
        public void Encrypt(string hexKey, string hexPlainText, string hexCipherText)
        {
            using var encryptor = new T().CreateEncryptor(HexToByteArray(hexKey), null);
            var plainText = HexToByteArray(hexPlainText);
            var encryptedText = encryptor.TransformFinalBlock(plainText, 0, plainText.Length);
            var hexEncryptedText = ByteArrayToHex(encryptedText);
            Assert.AreEqual(hexCipherText.ToUpperInvariant(), hexEncryptedText);
        }

        [Test]
        [TestCaseSource("TestVectors")]
        public void Decrypt(string hexKey, string hexPlainText, string hexCipherText)
        {
            using var decryptor = new T().CreateDecryptor(HexToByteArray(hexKey), null);
            var cipherText = HexToByteArray(hexCipherText);
            var decryptedText = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
            var hexDecryptedText = ByteArrayToHex(decryptedText);
            Assert.AreEqual(hexPlainText.ToUpperInvariant(), hexDecryptedText);
        }
    }
}
