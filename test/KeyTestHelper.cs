using Springburg.Cryptography.OpenPgp;
using NUnit.Framework;
using System;
using System.IO;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    class KeyTestHelper
    {
        public static void SignAndVerifyTestMessage(PgpPrivateKey privateKey, PgpKey publicKey)
        {
            byte[] msg = Encoding.ASCII.GetBytes("hello world!");
            var encodedStream = new MemoryStream();

            var messageGenerator = new PgpMessageGenerator(encodedStream);
            using (var signedGenerator = messageGenerator.CreateSigned(PgpSignatureType.BinaryDocument, privateKey, PgpHashAlgorithm.Sha256))
            using (var literalStream = signedGenerator.CreateLiteral(PgpDataFormat.Binary, "", DateTime.UtcNow))
            {
                literalStream.Write(msg);
            }

            encodedStream.Position = 0;
            var signedMessage = (PgpSignedMessage)PgpMessage.ReadMessage(encodedStream);
            var literalMessage = (PgpLiteralMessage)signedMessage.ReadMessage();
            // Skip over literal data
            literalMessage.GetStream().CopyTo(Stream.Null);
            Assert.IsTrue(signedMessage.Verify(publicKey));
        }
    }
}
