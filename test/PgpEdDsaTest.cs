using System;
using System.IO;
using System.Linq;
using System.Text;
using NUnit.Framework;
using Ed25519Dsa = InflatablePalace.Cryptography.Algorithms.Ed25519;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpEdDsaTest
    {
        private static readonly byte[] testPubKey =
            Convert.FromBase64String(
                "mDMEX9NCKBYJKwYBBAHaRw8BAQdASPhAQySGGPMjoquv5i1IwLRSDJ2QtmLLvER2" +
                "Cm8UZyW0HkVkRFNBIDx0ZXN0LmVkZHNhQGV4YW1wbGUuY29tPoiQBBMWCAA4FiEE" +
                "sh83FOYApIfZuLp0emj2ffveCqEFAl/TQigCGwMFCwkIBwIGFQoJCAsCBBYCAwEC" +
                "HgECF4AACgkQemj2ffveCqF6XQEA2S08fb0Z6LCd9P+eajPNDm1Wrf/y/7nkNwhb" +
                "DvwiU5kBAM16UvHrzX6CvQFvc7aKvPH+4wrvRewvAGK16a4fBHEE");

        private static readonly byte[] testPrivKey =
            Convert.FromBase64String(
                "lIYEX9NCKBYJKwYBBAHaRw8BAQdASPhAQySGGPMjoquv5i1IwLRSDJ2QtmLLvER2" +
                "Cm8UZyX+BwMC7ubvoFJTTXfOpQ3tDoys52w6tb01rHHtjKVWjXMjiyN8tXHBDC9N" +
                "UcMYViTDegBXOEgw4TIKn9mkkTDvP3xVFeMH2XBPzu9e9m8GlBODILQeRWREU0Eg" +
                "PHRlc3QuZWRkc2FAZXhhbXBsZS5jb20+iJAEExYIADgWIQSyHzcU5gCkh9m4unR6" +
                "aPZ9+94KoQUCX9NCKAIbAwULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRB6aPZ9" +
                "+94KoXpdAQDZLTx9vRnosJ30/55qM80ObVat//L/ueQ3CFsO/CJTmQEAzXpS8evN" +
                "foK9AW9ztoq88f7jCu9F7C8AYrXprh8EcQQ=");

        private static readonly char[] testPasswd = "test".ToCharArray();

        private static readonly byte[] sExprKey =
            Convert.FromBase64String(
                "KHByb3RlY3RlZC1wcml2YXRlLWtleSAoZWNjIChjdXJ2ZSBFZDI1NTE5KShmbGFn" +
                "cyBlZGRzYSkocQogICM0MDQ4Rjg0MDQzMjQ4NjE4RjMyM0EyQUJBRkU2MkQ0OEMw" +
                "QjQ1MjBDOUQ5MEI2NjJDQkJDNDQ3NjBBNkYxNDY3MjUjKQogKHByb3RlY3RlZCBv" +
                "cGVucGdwLXMyazMtb2NiLWFlcyAoKHNoYTEgI0IwRkY2MDAzRUE4RkQ4QkIjCiAg" +
                "Ijc2OTUzNjAiKSM5NDZEREU3QTUxMzAyRUEyRDc3NDNEOTQjKSM4NDBFMTIyRTdB" +
                "RDI0RkY1MkE5RUY3QUFDQjgxRUE2CiAyMTkyQjZCMjlCOUI4N0QwNTZBOUE4MTEz" +
                "QjIzNjlEREM4QUVGMTJDNjRBN0QwOTEwM0Q1MTU1Nzc0Q0Q5RkQ4NzczQTEzCiBD" +
                "NTgwQ0Y4RkY5OEZERTU3RDVGIykocHJvdGVjdGVkLWF0ICIyMDIwMTIxMVQwOTU2" +
                "MDEiKSkp");

        private static readonly byte[] referencePubKey =
            Convert.FromBase64String(
                "mDMEU/NfCxYJKwYBBAHaRw8BAQdAPwmJlL3ZFu1AUxl5NOSofIBzOhKA1i+AEJku" +
                "Q+47JAY=");

        private static readonly string referenceMessage = "OpenPGP";

        private static readonly byte[] referenceSignature =
            Convert.FromBase64String(
                "iF4EABYIAAYFAlX5X5UACgkQjP3hIZeWWpr2IgEAVvkMypjiECY3vZg/2xbBMd/S" +
                "ftgr9N3lYG4NdWrtM2YBANCcT6EVJ/A44PV/IgHYLy6iyQMyZfps60iehUuuYbQE");

        [Test]
        public void ReferenceTest()
        {
            PgpPublicKeyRing pubKeyRing = new PgpPublicKeyRing(referencePubKey);
            PgpPublicKey publicKey = pubKeyRing.GetPublicKey();
            PgpObjectFactory pgpFact = new PgpObjectFactory(referenceSignature);
            PgpSignatureList signatureList = (PgpSignatureList)pgpFact.NextPgpObject();
            PgpSignature signature = signatureList[0];
            signature.InitVerify(publicKey);
            signature.Update(Encoding.ASCII.GetBytes(referenceMessage));
            Assert.IsTrue(signature.Verify(), "signature failed to verify!");
        }

        [Test]
        public void GenerateAndSign()
        {
            PgpKeyPair eddsaKeyPair = new PgpKeyPair(new Ed25519Dsa(), DateTime.UtcNow);
            KeyTestHelper.SignAndVerifyTestMessage(eddsaKeyPair.PrivateKey, eddsaKeyPair.PublicKey);

            // generate a key ring
            char[] passPhrase = "test".ToCharArray();
            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, eddsaKeyPair,
                "test@bouncycastle.org", SymmetricKeyAlgorithmTag.Aes256, passPhrase, true, null, null);

            PgpPublicKeyRing pubRing = keyRingGen.GeneratePublicKeyRing();
            PgpSecretKeyRing secRing = keyRingGen.GenerateSecretKeyRing();

            PgpPublicKeyRing pubRingEnc = new PgpPublicKeyRing(pubRing.GetEncoded());
            Assert.That(pubRing.GetEncoded(), Is.EqualTo(pubRingEnc.GetEncoded()), "public key ring encoding failed");

            PgpSecretKeyRing secRingEnc = new PgpSecretKeyRing(secRing.GetEncoded());
            Assert.That(secRing.GetEncoded(), Is.EqualTo(secRingEnc.GetEncoded()), "secret key ring encoding failed");

            // try a signature using encoded key
            KeyTestHelper.SignAndVerifyTestMessage(secRing.GetSecretKey().ExtractPrivateKey(passPhrase), secRing.GetSecretKey().PublicKey);
        }

        [Test]
        public void PublicKeyDecode()
        {
            // Read the public key
            PgpPublicKeyRing pubKeyRing = new PgpPublicKeyRing(testPubKey);
            foreach (PgpSignature certification in pubKeyRing.GetPublicKey().GetSignatures())
            {
                certification.InitVerify(pubKeyRing.GetPublicKey());
                var firstUserId = pubKeyRing.GetPublicKey().GetUserIds().FirstOrDefault() as string;
                Assert.NotNull(firstUserId);
                Assert.IsTrue(certification.VerifyCertification(firstUserId, pubKeyRing.GetPublicKey()));
            }
        }

        [Test]
        public void PrivateKeyDecode()
        {
            // Read the private key
            PgpSecretKeyRing secretKeyRing = new PgpSecretKeyRing(testPrivKey);
            PgpPrivateKey privKey = secretKeyRing.GetSecretKey().ExtractPrivateKey(testPasswd);
        }

        //[Test]
        public void SxprKeyDecode()
        {
            //
            // sExpr
            //
            // TODO: S Expression keys generated by newer GnuPG are not properly supported yet
            /*byte[] msg = Encoding.ASCII.GetBytes("hello world!");

            PgpSecretKey key = PgpSecretKey.ParseSecretKeyFromSExpr(new MemoryStream(sExprKey, false), "test".ToCharArray());

            PgpSignatureGenerator signGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.EdDsa, HashAlgorithmTag.Sha256);
            signGen.InitSign(PgpSignature.BinaryDocument, key.ExtractPrivateKey(null));
            signGen.Update(msg);

            PgpSignature sig = signGen.Generate();
            sig.InitVerify(key.PublicKey);
            sig.Update(msg);

            if (!sig.Verify())
            {
                Fail("signature failed to verify!");
            }*/
        }
    }
}
