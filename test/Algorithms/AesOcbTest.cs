using Springburg.Cryptography.Algorithms;
using NUnit.Framework;
using System;

namespace Springburg.Test.Algorithms
{
    [TestFixture]
    public class AesOcbTest
    {
        [Test]
        [TestCase("BBAA99887766554433221100", "", "", "", "785407BFFFC8AD9EDCC5520AC9111EE6")]
        [TestCase("BBAA99887766554433221101", "0001020304050607", "0001020304050607", "6820B3657B6F615A", "5725BDA0D3B4EB3A257C9AF1F8F03009")]
        [TestCase("BBAA99887766554433221102", "0001020304050607", "", "", "81017F8203F081277152FADE694A0A00")]
        [TestCase("BBAA9988776655443322110A", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A485", "40FBBA186C5553C68AD9F592A79A4240")]
        public void ReferenceData(
            string nonce,
            string associatedData,
            string plainText,
            string cipherText,
            string tag)
        {
            var aesOcb = new AesOcb(Convert.FromHexString("000102030405060708090A0B0C0D0E0F"));
            byte[] plainTextBytes = Convert.FromHexString(plainText);
            byte[] cipherTextBytes = new byte[plainTextBytes.Length];
            byte[] tagBytes = new byte[16];

            aesOcb.Encrypt(
                Convert.FromHexString(nonce),
                plainTextBytes,
                cipherTextBytes,
                tagBytes,
                Convert.FromHexString(associatedData));

            Assert.AreEqual(cipherText, Convert.ToHexString(cipherTextBytes));
            Assert.AreEqual(tag, Convert.ToHexString(tagBytes));

            cipherTextBytes = Convert.FromHexString(cipherText);
            plainTextBytes = new byte[cipherTextBytes.Length];
            aesOcb.Decrypt(
                Convert.FromHexString(nonce),
                cipherTextBytes,
                Convert.FromHexString(tag),
                plainTextBytes,
                Convert.FromHexString(associatedData));

            Assert.AreEqual(plainText, Convert.ToHexString(plainTextBytes));
        }
    }
}
