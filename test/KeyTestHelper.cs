using NUnit.Framework;
using System;
using System.IO;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    class KeyTestHelper
    {
        public static void SignAndVerifyTestMessage(PgpPrivateKey privateKey, PgpPublicKey publicKey)
        {
            byte[] msg = Encoding.ASCII.GetBytes("hello world!");
            var encodedStream = new MemoryStream();

            var signGen = new PgpSignatureGenerator(PgpSignature.BinaryDocument, privateKey, HashAlgorithmTag.Sha256);
            var literalGen = new PgpLiteralDataGenerator();
            var writer = new PacketWriter(encodedStream);
            using (var signedWriter = signGen.Open(writer, generateOnePass: false))
            using (var literalStram = literalGen.Open(signedWriter, PgpLiteralData.Binary, "", DateTime.UtcNow))
            {
                literalStram.Write(msg);
            }

            encodedStream.Position = 0;
            PgpObjectFactory objectFactory = new PgpObjectFactory(encodedStream);
            PgpLiteralData literalData = (PgpLiteralData)objectFactory.NextPgpObject();
            // Skip over literal data
            literalData.GetDataStream().CopyTo(Stream.Null);
            PgpSignatureList signatureList = (PgpSignatureList)objectFactory.NextPgpObject();
            signatureList[0].InitVerify(publicKey);
            signatureList[0].Update(msg);
            Assert.IsTrue(signatureList[0].Verify(), "signature failed to verify!");
        }
    }
}
