using NUnit.Framework;
using System;
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
            using var encryptor = symmetricAlgorithm.CreateEncryptor(Convert.FromHexString(hexKey), null);
            var plainText = Convert.FromHexString(hexPlainText);
            var encryptedText = encryptor.TransformFinalBlock(plainText, 0, plainText.Length);
            var hexEncryptedText = Convert.ToHexString(encryptedText);
            Assert.AreEqual(hexCipherText.ToUpperInvariant(), hexEncryptedText);
        }

        [Test]
        [TestCaseSource("TestVectors")]
        public void Decrypt(string hexKey, string hexPlainText, string hexCipherText)
        {
            using var symmetricAlgorithm = new T();
            using var decryptor = symmetricAlgorithm.CreateDecryptor(Convert.FromHexString(hexKey), null);
            var cipherText = Convert.FromHexString(hexCipherText);
            var decryptedText = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
            var hexDecryptedText = Convert.ToHexString(decryptedText);
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
