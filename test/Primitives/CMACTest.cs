using NUnit.Framework;
using Springburg.Cryptography.Primitives;
using System.Security.Cryptography;

namespace Springburg.Test.Primitives
{
    [TestFixture]
    public class CMACTest
    {
        [Test]
        public void HashAes()
        {
            using var cmac = new CMAC(Aes.Create(), HexHelper.HexToByteArray("2b7e151628aed2a6abf7158809cf4f3c"));
            cmac.TransformBlock(HexHelper.HexToByteArray("6bc1bee22e409f96e93d7e117393172a"), 0, 16, null, 0);
            cmac.TransformBlock(HexHelper.HexToByteArray("ae2d8a571e03ac9c9eb76fac45af8e51"), 0, 16, null, 0);
            cmac.TransformFinalBlock(HexHelper.HexToByteArray("30c81c46a35ce411"), 0, 8);
            var tag = cmac.Hash;
            Assert.AreEqual("dfa66747de9ae63030ca32611497c827", HexHelper.ByteArrayToHex(tag).ToLowerInvariant());
        }
    }
}
