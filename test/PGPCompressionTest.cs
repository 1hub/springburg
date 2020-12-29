using System;
using System.IO;
using System.Text;
using Springburg.Cryptography.OpenPgp;
using NUnit.Framework;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpCompressionTest
    {
        private static readonly byte[] Data = Encoding.ASCII.GetBytes("hello world! !dlrow olleh");

        [Test]
        [TestCase(PgpCompressionAlgorithm.Uncompressed)]
        [TestCase(PgpCompressionAlgorithm.Zip)]
        [TestCase(PgpCompressionAlgorithm.ZLib)]
        //[TestCase(PgpCompressionAlgorithm.BZip2)]
        public void TestCompression(PgpCompressionAlgorithm type)
        {
            using MemoryStream bOut = new MemoryStream();

            // Compress data
            var messageGenerator = new PgpMessageGenerator(bOut);
            using (var compressedGenerator = messageGenerator.CreateCompressed(type))
            using (var literalStream = compressedGenerator.CreateLiteral(PgpDataFormat.Binary, "", DateTime.UtcNow))
                literalStream.Write(Data);

            // Read it back
            bOut.Position = 0;
            var literalMessage = (PgpLiteralMessage)PgpMessage.ReadMessage(bOut);
            byte[] bytes = Streams.ReadAll(literalMessage.GetStream());
            Assert.That(bytes, Is.EqualTo(Data));
        }
    }
}
