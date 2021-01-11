using NUnit.Framework;
using System.Security.Cryptography;

namespace Springburg.Test.Algorithms
{
    [TestFixture]
    public abstract class SymmetricAlgorithmTest<T>
        where T : SymmetricAlgorithm, new()
    {
        [Test]
        [TestCaseSource("TestVectors")]
        public void Encrypt(string hexKey, string hexPlainText, string hexCipherText)
        {
            using var symmetricAlgorithm = new T();
            using var encryptor = symmetricAlgorithm.CreateEncryptor(HexHelper.HexToByteArray(hexKey), null);
            var plainText = HexHelper.HexToByteArray(hexPlainText);
            var encryptedText = encryptor.TransformFinalBlock(plainText, 0, plainText.Length);
            var hexEncryptedText = HexHelper.ByteArrayToHex(encryptedText);
            Assert.AreEqual(hexCipherText.ToUpperInvariant(), hexEncryptedText);
        }

        [Test]
        [TestCaseSource("TestVectors")]
        public void Decrypt(string hexKey, string hexPlainText, string hexCipherText)
        {
            using var symmetricAlgorithm = new T();
            using var decryptor = symmetricAlgorithm.CreateDecryptor(HexHelper.HexToByteArray(hexKey), null);
            var cipherText = HexHelper.HexToByteArray(hexCipherText);
            var decryptedText = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
            var hexDecryptedText = HexHelper.ByteArrayToHex(decryptedText);
            Assert.AreEqual(hexPlainText.ToUpperInvariant(), hexDecryptedText);
        }

        [Test]
        public void GenerateIV()
        {
            using var symmetricAlgorithm = new T();
            symmetricAlgorithm.GenerateIV();
            var iv1 = symmetricAlgorithm.IV;
            symmetricAlgorithm.GenerateIV();
            var iv2 = symmetricAlgorithm.IV;
            Assert.AreNotEqual(iv1, iv2);
        }
    }
}
