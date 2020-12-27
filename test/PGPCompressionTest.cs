using System;
using System.IO;
using System.Text;
using InflatablePalace.Cryptography.OpenPgp;
using NUnit.Framework;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpCompressionTest
    {
        private static readonly byte[] Data = Encoding.ASCII.GetBytes("hello world! !dlrow olleh");

        [Test]
        public void TestUncompressed()
        {
            doTestCompression(PgpCompressionAlgorithm.Uncompressed);
        }

        [Test]
        public void TestZip()
        {
            doTestCompression(PgpCompressionAlgorithm.Zip);
        }

        [Test]
        public void TestZLib()
        {
            doTestCompression(PgpCompressionAlgorithm.ZLib);
        }

        [Test]
        public void TestBZip2()
        {
            doTestCompression(PgpCompressionAlgorithm.BZip2);
        }

        private void doTestCompression(PgpCompressionAlgorithm type)
        {
            using MemoryStream bOut = new MemoryStream();

            // Compress data
            var messageGenerator = new PgpMessageGenerator(bOut);
            using (var compressedGenerator = messageGenerator.CreateCompressed(type))
            using (var literalStream = compressedGenerator.CreateLiteral(PgpDataFormat.Binary, "", DateTime.UtcNow))
                literalStream.Write(Data);

            // Read it back
            bOut.Position = 0;
            var compressedMessage = (PgpCompressedMessage)PgpMessage.ReadMessage(bOut);
            var literalMessage = (PgpLiteralMessage)compressedMessage.ReadMessage();
            byte[] bytes = Streams.ReadAll(literalMessage.GetStream());
            Assert.That(bytes, Is.EqualTo(Data));
        }
    }
}
