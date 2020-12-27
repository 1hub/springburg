using System;
using System.IO;
using System.Text;
using InflatablePalace.Cryptography.OpenPgp;
using NUnit.Framework;

using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpUnicodeTest
    {
        private void DoTestKey(long keyId, string passphrase)
        {
            PgpSecretKeyRingBundle secretKeyRing = LoadSecretKeyCollection("secring.gpg");

            PgpSecretKeyRing secretKey = secretKeyRing.GetSecretKeyRing(keyId);
            Assert.NotNull(secretKey, "Could not locate secret keyring with Id=" + keyId);

            PgpSecretKey key = secretKey.GetSecretKey();
            Assert.NotNull(key, "Could not locate secret key!");

            try
            {
                PgpPrivateKey privateKey = key.ExtractPrivateKey(passphrase);
                Assert.IsTrue(privateKey.KeyId == keyId);
            }
            catch (PgpException e)
            {
                throw new PgpException("Password incorrect!", e);
            }

            // all fine!
        }

        [Test]
        public void TestUmlautPassphrase()
        {

            try
            {
                long keyId = unchecked((long)0xEC87272EFCB986D2);

                string passphrase = Encoding.Unicode.GetString(Encoding.Unicode.GetBytes("Händle"));

                DoTestKey(keyId, passphrase);

                // all fine!

            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.StackTrace);
                Assert.Fail(e.Message);
            }
        }

        [Test]
        public void TestAsciiPassphrase()
        {

            try
            {
                long keyId = unchecked((long)0xAA2AAAC7CB417459);

                string passphrase = "Admin123";

                DoTestKey(keyId, passphrase);

                // all fine!
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.StackTrace);
                Assert.Fail(e.Message);
            }
        }

        [Test]
        public void TestCyrillicPassphrase()
        {

            try
            {
                long keyId = 0x4680E7F3960C44E7;

                // XXX The password text file must not have the UTF-8 BOM !
                // Ref: http://stackoverflow.com/questions/2223882/whats-different-between-utf-8-and-utf-8-without-bom

                Stream passwordFile = SimpleTest.GetTestDataAsStream("openpgp.unicode.passphrase_cyr.txt");
                TextReader reader = new StreamReader(passwordFile, Encoding.UTF8);
                string passphrase = reader.ReadLine();
                passwordFile.Close();

                DoTestKey(keyId, passphrase);

                // all fine!
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.StackTrace);
                Assert.Fail(e.Message);
            }
        }

        private PgpSecretKeyRingBundle LoadSecretKeyCollection(string keyName)
        {
            return new PgpSecretKeyRingBundle(SimpleTest.GetTestDataAsStream("openpgp.unicode." + keyName));
        }
    }
}
