using InflatablePalace.Cryptography.OpenPgp;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace InflatablePalace.Test
{
    [TestFixture]
    public class PgpCompositionTest
    {
        [Test]
        public void CompressedDataInSignature()
        {
            var keyPair = new PgpKeyPair(DSA.Create(512), DateTime.UtcNow);

            byte[] msg = Encoding.ASCII.GetBytes("hello world!");
            var encodedStream = new MemoryStream();

            var messageGenerator = new PgpMessageGenerator(encodedStream);
            using (var signedGenerator = messageGenerator.CreateSigned(PgpSignature.BinaryDocument, keyPair.PrivateKey, PgpHashAlgorithm.Sha256))
            using (var compressedGenerator = signedGenerator.CreateCompressed(PgpCompressionAlgorithm.Zip))
            using (var literalStream = compressedGenerator.CreateLiteral(PgpDataFormat.Binary, "", DateTime.UtcNow))
            {
                literalStream.Write(msg);
            }

            encodedStream.Position = 0;
            var signedMessage = (PgpSignedMessage)PgpMessage.ReadMessage(encodedStream);
            var compressedMessage = (PgpCompressedMessage)signedMessage.ReadMessage();
            var literalMessage = (PgpLiteralMessage)compressedMessage.ReadMessage();
            // Skip over literal data
            literalMessage.GetStream().CopyTo(Stream.Null);
            Assert.IsTrue(signedMessage.Verify(keyPair.PublicKey));

        }
    }
}
