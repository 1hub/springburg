using Springburg.Cryptography.Algorithms;
using NUnit.Framework;
using System;

namespace Springburg.Test.Algorithms
{
    [TestFixture]
    public class AesEaxTest
    {
        [Test]
        [TestCase("233952DEE4D5ED5F9B9C6D6FF80FF478", "62EC67F9C3A4A407FCB2A8C49031A8B3", "6BFB914FD07EAE6B", "", "", "E037830E8389F27B025A2D6527E79D01")]
        [TestCase("91945D3F4DCBEE0BF45EF52255F095A4", "BECAF043B0A23D843194BA972C66DEBD", "FA3BFD4806EB53FA", "F7FB", "19DD", "5C4C9331049D0BDAB0277408F67967E5")]
        [TestCase("01F74AD64077F2E704C0F60ADA3DD523", "70C3DB4F0D26368400A10ED05D2BFF5E", "234A3463C1264AC6", "1A47CB4933", "D851D5BAE0", "3A59F238A23E39199DC9266626C40F80")]
        [TestCase("D07CF6CBB7F313BDDE66B727AFD3C5E8", "8408DFFF3C1A2B1292DC199E46B7D617", "33CCE2EABFF5A79D", "481C9E39B1", "632A9D131A", "D4C168A4225D8E1FF755939974A7BEDE")]
        [TestCase("8395FCF1E95BEBD697BD010BC766AAC3", "22E7ADD93CFC6393C57EC0B3C17D6B44", "126735FCC320D25A", "CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7", "CB8920F87A6C75CFF39627B56E3ED197C552D295A7", "CFC46AFC253B4652B1AF3795B124AB6E")]
        public void ReferenceData(
            string key,
            string nonce,
            string associatedData,
            string plainText,
            string cipherText,
            string tag)
        {
            var aesEax = new AesEax(Convert.FromHexString(key));
            byte[] plainTextBytes = Convert.FromHexString(plainText);
            byte[] cipherTextBytes = new byte[plainTextBytes.Length];
            byte[] tagBytes = new byte[16];

            aesEax.Encrypt(
                Convert.FromHexString(nonce),
                plainTextBytes,
                cipherTextBytes,
                tagBytes,
                Convert.FromHexString(associatedData));

            Assert.AreEqual(cipherText, Convert.ToHexString(cipherTextBytes));
            Assert.AreEqual(tag, Convert.ToHexString(tagBytes));

            cipherTextBytes = Convert.FromHexString(cipherText);
            plainTextBytes = new byte[cipherTextBytes.Length];
            aesEax.Decrypt(
                Convert.FromHexString(nonce),
                cipherTextBytes,
                Convert.FromHexString(tag),
                plainTextBytes,
                Convert.FromHexString(associatedData));

            Assert.AreEqual(plainText, Convert.ToHexString(plainTextBytes));
        }
    }
}
