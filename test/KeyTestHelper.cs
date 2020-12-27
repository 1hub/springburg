using InflatablePalace.Cryptography.OpenPgp;
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

            var messageGenerator = new PgpMessageGenerator(encodedStream);
            using (var signedGenerator = messageGenerator.CreateSigned(PgpSignature.BinaryDocument, privateKey, HashAlgorithmTag.Sha256))
            using (var literalStram = signedGenerator.CreateLiteral(PgpLiteralData.Binary, "", DateTime.UtcNow))
            {
                literalStram.Write(msg);
            }

            encodedStream.Position = 0;
            var signedMessage = (PgpSignedMessage)PgpMessage.ReadMessage(encodedStream);
            var literalMessage = (PgpLiteralMessage)signedMessage.ReadMessage();
            // Skip over literal data
            literalMessage.GetStream().CopyTo(Stream.Null);
            Assert.IsTrue(signedMessage.Verify(publicKey), "signature failed to verify!");
            /*
            PgpObjectFactory objectFactory = new PgpObjectFactory(encodedStream);
            PgpLiteralData literalData = (PgpLiteralData)objectFactory.NextPgpObject();
            // Skip over literal data
            literalData.GetDataStream().CopyTo(Stream.Null);
            PgpSignatureList signatureList = (PgpSignatureList)objectFactory.NextPgpObject();
            signatureList[0].InitVerify(publicKey);
            signatureList[0].Update(msg);
            Assert.IsTrue(signatureList[0].Verify(), "signature failed to verify!");*/
        }
    }
}
