using System;
using System.IO;
using System.Text;
using Springburg.Cryptography.OpenPgp;
using NUnit.Framework;

using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class Dsa2Test
    {
        [Test]
        //[TestCase("DSA-1024-160.sec", "DSA-1024-160.pub", PgpHashAlgorithm.Sha224)]
        [TestCase("DSA-1024-160.sec", "DSA-1024-160.pub", PgpHashAlgorithm.Sha256)]
        [TestCase("DSA-1024-160.sec", "DSA-1024-160.pub", PgpHashAlgorithm.Sha384)]
        [TestCase("DSA-1024-160.sec", "DSA-1024-160.pub", PgpHashAlgorithm.Sha512)]
        //[TestCase("DSA-2048-224.sec", "DSA-2048-224.pub", PgpHashAlgorithm.Sha256)]
        //[TestCase("DSA-2048-224.sec", "DSA-2048-224.pub", PgpHashAlgorithm.Sha512)]
        public void GenerateTest(string privateKeyFile, string publicKeyFile, PgpHashAlgorithm digest)
        {
            PgpSecretKeyRing secRing = loadSecretKey(privateKeyFile);
            PgpPublicKeyRing pubRing = loadPublicKey(publicKeyFile);
            string data = "hello world!";
            byte[] dataBytes = Encoding.ASCII.GetBytes(data);
            MemoryStream bOut = new MemoryStream();
            DateTime testDate = new DateTime((DateTime.UtcNow.Ticks / TimeSpan.TicksPerSecond) * TimeSpan.TicksPerSecond);

            var messageGenerator = new PgpMessageGenerator(bOut);
            using (var signingGenerator = messageGenerator.CreateSigned(PgpSignatureType.BinaryDocument, secRing.GetSecretKey().ExtractPrivateKey("test"), digest))
            using (var literalStream = signingGenerator.CreateLiteral(PgpDataFormat.Binary, "_CONSOLE", testDate))
            {
                literalStream.Write(dataBytes);
            }

            bOut.Position = 0;
            var signedMessage = (PgpSignedMessage)PgpMessage.ReadMessage(bOut);
            Assert.AreEqual(digest, signedMessage.HashAlgorithm);
            Assert.AreEqual(PgpPublicKeyAlgorithm.Dsa, signedMessage.KeyAlgorithm);
            var literalMessage = (PgpLiteralMessage)signedMessage.ReadMessage();
            Assert.AreEqual(testDate, literalMessage.ModificationTime);
            literalMessage.GetStream().CopyTo(Stream.Null);
            Assert.IsTrue(signedMessage.Verify(pubRing.GetPublicKey()));
        }

        [Test]
        [TestCase("DSA-1024-160.pub", "dsa-1024-160-sign.gpg")]
        //[TestCase("DSA-1024-160.pub", "dsa-1024-224-sign.gpg")]
        [TestCase("DSA-1024-160.pub", "dsa-1024-256-sign.gpg")]
        [TestCase("DSA-1024-160.pub", "dsa-1024-384-sign.gpg")]
        [TestCase("DSA-1024-160.pub", "dsa-1024-512-sign.gpg")]
        //[TestCase("DSA-2048-224.pub", "dsa-2048-224-sign.gpg")]
        [TestCase("DSA-3072-256.pub", "dsa-3072-256-sign.gpg")]
        //[TestCase("DSA-7680-384.pub", "dsa-7680-384-sign.gpg")]
        //[TestCase("DSA-15360-512.pub", "dsa-15360-512-sign.gpg")]
        public void SignatureVerifyTest(string publicKeyFile, string sigFile)
        {
            PgpPublicKeyRing publicKey = loadPublicKey(publicKeyFile);

            var compressedMessage = (PgpCompressedMessage)PgpMessage.ReadMessage(loadSig(sigFile));
            var signedMessage = (PgpSignedMessage)compressedMessage.ReadMessage();
            var literalMessage = (PgpLiteralMessage)signedMessage.ReadMessage();
            literalMessage.GetStream().CopyTo(Stream.Null);
            Assert.IsTrue(signedMessage.Verify(publicKey.GetPublicKey()));
        }

        private Stream loadSig(string sigName)
        {
            return SimpleTest.GetTestDataAsStream("openpgp.dsa.sigs." + sigName);
        }

        private PgpPublicKeyRing loadPublicKey(string keyName)
        {
            Stream fIn = SimpleTest.GetTestDataAsStream("openpgp.dsa.keys." + keyName);
            return new PgpPublicKeyRing(fIn);
        }

        private PgpSecretKeyRing loadSecretKey(string keyName)
        {
            Stream fIn = SimpleTest.GetTestDataAsStream("openpgp.dsa.keys." + keyName);
            return new PgpSecretKeyRing(fIn);
        }
    }
}
