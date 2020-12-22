using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using InflatablePalace.Cryptography.Algorithms;
using NUnit.Framework;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpECDHTest
    {
        private static readonly byte[] testPubKey =
            Convert.FromBase64String(
                "mFIEUb4GwBMIKoZIzj0DAQcCAwS8p3TFaRAx58qCG63W+UNthXBPSJDnVDPTb/sT" +
                "iXePaAZ/Gh1GKXTq7k6ab/67MMeVFp/EdySumqdWLtvceFKstFBUZXN0IEVDRFNB" +
                "LUVDREggKEtleSBhbmQgc3Via2V5IGFyZSAyNTYgYml0cyBsb25nKSA8dGVzdC5l" +
                "Y2RzYS5lY2RoQGV4YW1wbGUuY29tPoh6BBMTCAAiBQJRvgbAAhsDBgsJCAcDAgYV" +
                "CAIJCgsEFgIDAQIeAQIXgAAKCRD3wDlWjFo9U5O2AQDi89NO6JbaIObC63jMMWsi" +
                "AaQHrBCPkDZLibgNv73DLgD/faouH4YZJs+cONQBPVnP1baG1NpWR5ppN3JULFcr" +
                "hcq4VgRRvgbAEggqhkjOPQMBBwIDBLtY8Nmfz0zSEa8C1snTOWN+VcT8pXPwgJRy" +
                "z6kSP4nPt1xj1lPKj5zwPXKWxMkPO9ocqhKdg2mOh6/rc1ObIoMDAQgHiGEEGBMI" +
                "AAkFAlG+BsACGwwACgkQ98A5VoxaPVN8cgEAj4dMNMNwRSg2ZBWunqUAHqIedVbS" +
                "dmwmbysD192L3z4A/ReXEa0gtv8OFWjuALD1ovEK8TpDORLUb6IuUb5jUIzY");

        private static readonly byte[] testPrivKey =
            Convert.FromBase64String(
                "lKUEUb4GwBMIKoZIzj0DAQcCAwS8p3TFaRAx58qCG63W+UNthXBPSJDnVDPTb/sT" +
                "iXePaAZ/Gh1GKXTq7k6ab/67MMeVFp/EdySumqdWLtvceFKs/gcDAo11YYCae/K2" +
                "1uKGJ/uU4b4QHYnPIsAdYpuo5HIdoAOL/WwduRa8C6vSFrtMJLDqPK3BUpMz3CXN" +
                "GyMhjuaHKP5MPbBZkIfgUGZO5qvU9+i0UFRlc3QgRUNEU0EtRUNESCAoS2V5IGFu" +
                "ZCBzdWJrZXkgYXJlIDI1NiBiaXRzIGxvbmcpIDx0ZXN0LmVjZHNhLmVjZGhAZXhh" +
                "bXBsZS5jb20+iHoEExMIACIFAlG+BsACGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4B" +
                "AheAAAoJEPfAOVaMWj1Tk7YBAOLz007oltog5sLreMwxayIBpAesEI+QNkuJuA2/" +
                "vcMuAP99qi4fhhkmz5w41AE9Wc/VtobU2lZHmmk3clQsVyuFyg==");

        private static readonly byte[] testMessage =
            Convert.FromBase64String(
                "hH4Dp5+FdoujIBwSAgMErx4BSvgXY3irwthgxU8zPoAoR+8rhmxdpwbw6ZJAO2GX" +
                "azWJ85JNcobHKDeGeUq6wkTFu+g6yG99gIX8J5xJAjBRhyCRcaFgwbdDV4orWTe3" +
                "iewiT8qs4BQ23e0c8t+thdKoK4thMsCJy7wSKqY0sJTSVAELroNbCOi2lcO15YmW" +
                "6HiuFH7VKWcxPUBjXwf5+Z3uOKEp28tBgNyDrdbr1BbqlgYzIKq/pe9zUbUXfitn" +
                "vFc6HcGhvmRQreQ+Yw1x3x0HJeoPwg==");


        private static readonly byte[] testX25519PubKey =
            Convert.FromBase64String(
                "mDMEX9XwXhYJKwYBBAHaRw8BAQdAR5ZghmMHL8wldNlOkmbaiAOdyF5V5bgZdKq7" +
                "L+yb4A20HEVDREggPHRlc3QuZWNkaEBleGFtcGxlLmNvbT6IkAQTFggAOBYhBGoy" +
                "UrxNv7c3S2JjGzewWiN8tfzXBQJf1fBeAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4B" +
                "AheAAAoJEDewWiN8tfzX0ZMA/AhEvrIgu+29eMQeuHOwX1ZY/UssU5TdVROQzGTL" +
                "n5cgAP9hIKtt/mZ112HiAHDuWk2JskdtsuopnrEccz4PSEkSDLg4BF/V8F4SCisG" +
                "AQQBl1UBBQEBB0DLPhNt/6GHDbb7vZW/iMsbXTZpgJNQiT6QA/4EzgYQLwMBCAeI" +
                "eAQYFggAIBYhBGoyUrxNv7c3S2JjGzewWiN8tfzXBQJf1fBeAhsMAAoJEDewWiN8" +
                "tfzXU34BAKJJLDee+qJCmUI20sMy/YoKfWmMnH2RBBHmLV8FAJ7vAP0e2wGixEfs" +
                "oPqe8fHmvjQGxSByOyQGn7yD+oq9nVzTAA==");

        private static readonly byte[] testX25519PrivKey =
            Convert.FromBase64String(
                "lIYEX9XwXhYJKwYBBAHaRw8BAQdAR5ZghmMHL8wldNlOkmbaiAOdyF5V5bgZdKq7" +
                "L+yb4A3+BwMCMscozrXr93fOFmtxu/BJjEJrwRl20Jrv9lryfM+SF4UHgVMmJUpJ" +
                "1RuTbSnM2KaqHwOgmdrvf2FJnpg1vMafBk1CmopqkRzzrbJ6xQhiPrQcRUNESCA8" +
                "dGVzdC5lY2RoQGV4YW1wbGUuY29tPoiQBBMWCAA4FiEEajJSvE2/tzdLYmMbN7Ba" +
                "I3y1/NcFAl/V8F4CGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQN7BaI3y1" +
                "/NfRkwD8CES+siC77b14xB64c7BfVlj9SyxTlN1VE5DMZMuflyAA/2Egq23+ZnXX" +
                "YeIAcO5aTYmyR22y6imesRxzPg9ISRIMnIsEX9XwXhIKKwYBBAGXVQEFAQEHQMs+" +
                "E23/oYcNtvu9lb+IyxtdNmmAk1CJPpAD/gTOBhAvAwEIB/4HAwJ7ShSBrUuUAM5r" +
                "G4I/gJKo+eBmbNC4NM81eALAF1vcovZPsGsiZ8IgXT64XiC1bpeAoINn6vM4vVbi" +
                "LqNKqu6ll3ZgQ4po6vCW9GkhuEMmiHgEGBYIACAWIQRqMlK8Tb+3N0tiYxs3sFoj" +
                "fLX81wUCX9XwXgIbDAAKCRA3sFojfLX811N+AQCiSSw3nvqiQplCNtLDMv2KCn1p" +
                "jJx9kQQR5i1fBQCe7wD9HtsBosRH7KD6nvHx5r40BsUgcjskBp+8g/qKvZ1c0wA=");

        private static readonly byte[] testX25519Message =
            Convert.FromBase64String(
                "hF4DbDc2fNL0VcUSAQdAqdV0v1D4X9cuGrT7+oQBpMFnw1wdfAcxH9xdO00s2HUw" +
                "qB+XkIRETH7yesynLOKajmYftMWZRyTnW2tJUc1w5NFPjPxcbvd2bYmqkY57uAFg" +
                "0kcBKhFklH2LRbBNThtQr3jn2YEFbNnhiGfOpoHfCn0oFh5RbXDwm+P3Q3tksvpZ" +
                "wEGe2VkxLLe7BWnv/sRINQ2YpuaYshe8hw==");

        [Test]
        public void Generate()
        {
            ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            PgpKeyPair ecdsaKeyPair = new PgpKeyPair(ecdsa, DateTime.UtcNow);

            // Generate an encryption key
            ECDiffieHellman ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            PgpKeyPair ecdhKeyPair = new PgpKeyPair(ecdh, DateTime.UtcNow);

            // Generate a key ring
            var passPhrase = "test";
            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, ecdsaKeyPair,
                "test@bouncycastle.org", SymmetricKeyAlgorithmTag.Aes256, passPhrase, true, null, null);
            keyRingGen.AddSubKey(ecdhKeyPair);

            PgpPublicKeyRing pubRing = keyRingGen.GeneratePublicKeyRing();

            // TODO: add check of KdfParameters
            DoBasicKeyRingCheck(pubRing);

            PgpSecretKeyRing secRing = keyRingGen.GenerateSecretKeyRing();

            PgpPublicKeyRing pubRingEnc = new PgpPublicKeyRing(pubRing.GetEncoded());
            Assert.That(pubRing.GetEncoded(), Is.EqualTo(pubRingEnc.GetEncoded()), "public key ring encoding failed");

            PgpSecretKeyRing secRingEnc = new PgpSecretKeyRing(secRing.GetEncoded());
            Assert.That(secRing.GetEncoded(), Is.EqualTo(secRingEnc.GetEncoded()), "secret key ring encoding failed");

            PgpPrivateKey pgpPrivKey = secRing.GetSecretKey().ExtractPrivateKey(passPhrase);
        }

        [Test]
        public void Generate25519()
        {
            // Generate a master key
            PgpKeyPair ecdsaKeyPair = new PgpKeyPair(new Ed25519(), DateTime.UtcNow);

            // Generate an encryption key
            PgpKeyPair ecdhKeyPair = new PgpKeyPair(new X25519(), DateTime.UtcNow);

            // Generate a key ring
            var passPhrase = "test";
            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, ecdsaKeyPair,
                "test@bouncycastle.org", SymmetricKeyAlgorithmTag.Aes256, passPhrase, true, null, null);
            keyRingGen.AddSubKey(ecdhKeyPair);

            PgpPublicKeyRing pubRing = keyRingGen.GeneratePublicKeyRing();

            // TODO: add check of KdfParameters
            DoBasicKeyRingCheck(pubRing);

            PgpSecretKeyRing secRing = keyRingGen.GenerateSecretKeyRing();

            PgpPublicKeyRing pubRingEnc = new PgpPublicKeyRing(pubRing.GetEncoded());
            Assert.That(pubRing.GetEncoded(), Is.EqualTo(pubRingEnc.GetEncoded()), "public key ring encoding failed");

            PgpSecretKeyRing secRingEnc = new PgpSecretKeyRing(secRing.GetEncoded());
            Assert.That(secRing.GetEncoded(), Is.EqualTo(secRingEnc.GetEncoded()), "secret key ring encoding failed");

            // Extract back the ECDH key and verify the encoded values to ensure correct endianness
            PgpSecretKey pgpSecretKey = secRing.GetSecretKey(ecdhKeyPair.KeyId);
            PgpPrivateKey pgpPrivKey = pgpSecretKey.ExtractPrivateKey(passPhrase);

            /*if (!Arrays.AreEqual(((X25519PrivateKeyParameters)kpEnc.Private).GetEncoded(), ((X25519PrivateKeyParameters)pgpPrivKey.Key).GetEncoded()))
            {
                Fail("private key round trip failed");
            }
            if (!Arrays.AreEqual(((X25519PublicKeyParameters)kpEnc.Public).GetEncoded(), ((X25519PublicKeyParameters)pgpSecretKey.PublicKey.GetKey()).GetEncoded()))
            {
                Fail("private key round trip failed");
            }*/
        }

        private void TestDecrypt(PgpSecretKeyRing secretKeyRing)
        {
            var encryptedMessage = (PgpEncryptedMessage)PgpMessage.ReadMessage(testMessage);
            var secretKey = secretKeyRing.GetSecretKey(encryptedMessage.KeyIds.First());
            //Assert.NotNull(secretKey);
            /*var literalMessage = (PgpLiteralMessage)encryptedMessage.DecryptMessage(secretKey.ExtractPrivateKey("test".ToCharArray()));
            var bytes = Streams.ReadAll(literalMessage.GetStream());
            Assert.AreEqual(text, bytes);*/
        }

        private void EncryptDecryptTest(ECDiffieHellman ecdh)
        {
            byte[] text = Encoding.ASCII.GetBytes("hello world!");

            PgpKeyPair ecdhKeyPair = new PgpKeyPair(ecdh, DateTime.UtcNow);

            // Encrypt text
            MemoryStream cbOut = new MemoryStream();
            PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5);
            cPk.AddMethod(ecdhKeyPair.PublicKey);
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            var writer = new PacketWriter(cbOut);
            using (var cOut = cPk.Open(writer))
            using (var pOut = lData.Open(cOut, PgpLiteralDataGenerator.Utf8, PgpLiteralData.Console, DateTime.UtcNow))
                pOut.Write(text);

            // Read it back
            cbOut.Position = 0;
            var encryptedMessage = (PgpEncryptedMessage)PgpMessage.ReadMessage(cbOut);
            var literalMessage = (PgpLiteralMessage)encryptedMessage.DecryptMessage(ecdhKeyPair.PrivateKey);
            var bytes = Streams.ReadAll(literalMessage.GetStream());
            Assert.AreEqual(text, bytes);
        }

        [Test]
        public void EncryptDecryptX25519KeysTest()
        {
            PgpPublicKeyRing publicKeyRing = new PgpPublicKeyRing(testX25519PubKey);
            PgpSecretKeyRing secretKeyRing = new PgpSecretKeyRing(testX25519PrivKey);
            PgpSecretKey secretKey = secretKeyRing.GetSecretKey(0x6c37367cd2f455c5);
            byte[] text = Encoding.ASCII.GetBytes("hello world!");

            // Encrypt text
            MemoryStream cbOut = new MemoryStream();
            PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5);
            cPk.AddMethod(publicKeyRing.GetPublicKey(0x6c37367cd2f455c5));
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            var writer = new PacketWriter(cbOut);
            using (var cOut = cPk.Open(writer))
            using (var pOut = lData.Open(cOut, PgpLiteralDataGenerator.Utf8, PgpLiteralData.Console, DateTime.UtcNow))
                pOut.Write(text);

            // Read it back
            cbOut.Position = 0;
            var encryptedMessage = (PgpEncryptedMessage)PgpMessage.ReadMessage(cbOut);
            var literalMessage = (PgpLiteralMessage)encryptedMessage.DecryptMessage(secretKey.ExtractPrivateKey("test"));
            var bytes = Streams.ReadAll(literalMessage.GetStream());
            Assert.AreEqual(text, bytes);
        }

        [Test]
        public void GnuPGCrossCheck()
        {
            var secretKeyRing = new PgpSecretKeyRing(testX25519PrivKey);
            var secretKey = secretKeyRing.GetSecretKey(0x6c37367cd2f455c5);
            var pgpPrivKey = secretKey.ExtractPrivateKey("test");
            var encryptedMessage = (PgpEncryptedMessage)PgpMessage.ReadMessage(testX25519Message);
            var compressedMessage = (PgpCompressedMessage)encryptedMessage.DecryptMessage(pgpPrivKey);
            var literalMessage = (PgpLiteralMessage)compressedMessage.ReadMessage();
            byte[] bytes = Streams.ReadAll(literalMessage.GetStream());
            Assert.AreEqual(Encoding.ASCII.GetBytes("hello world!"), bytes);
        }

        [Test]
        public void PerformTest()
        {
            // Read the public key
            PgpPublicKeyRing pubKeyRing = new PgpPublicKeyRing(testPubKey);
            DoBasicKeyRingCheck(pubKeyRing);

            // Read the private key
            PgpSecretKeyRing secretKeyRing = new PgpSecretKeyRing(testPrivKey);
            TestDecrypt(secretKeyRing);

            EncryptDecryptTest(ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256));

            EncryptDecryptTest(new X25519());
        }

        [Test]
        public void ReadPublicKey()
        {
            PgpPublicKeyRing pubKeyRing = new PgpPublicKeyRing(testPubKey);
            DoBasicKeyRingCheck(pubKeyRing);
        }

        [Test]
        public void ReadPrivateKey()
        {
            PgpSecretKeyRing secretKeyRing = new PgpSecretKeyRing(testPrivKey);
            TestDecrypt(secretKeyRing);
        }

        [Test]
        public void EncryptDecryptNistP256Test()
        {
            EncryptDecryptTest(ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256));
        }

        [Test]
        public void EncryptDecryptX25519Test()
        {
            EncryptDecryptTest(new X25519());
        }

        private void DoBasicKeyRingCheck(PgpPublicKeyRing pubKeyRing)
        {
            foreach (PgpPublicKey pubKey in pubKeyRing.GetPublicKeys())
            {
                if (pubKey.IsMasterKey)
                {
                    Assert.IsFalse(pubKey.IsEncryptionKey, "master key showed as encryption key!");
                }
                else
                {
                    Assert.IsTrue(pubKey.IsEncryptionKey, "sub key not encryption key!");

                    foreach (PgpSignature certification in pubKeyRing.GetPublicKey().GetSignatures())
                    {
                        certification.InitVerify(pubKeyRing.GetPublicKey());

                        var firstUserId = pubKeyRing.GetPublicKey().GetUserIds().FirstOrDefault() as string;
                        Assert.NotNull(firstUserId);
                        Assert.IsTrue(certification.VerifyCertification(firstUserId, pubKeyRing.GetPublicKey()));
                    }
                }
            }
        }
    }
}
