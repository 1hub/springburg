using System;
using System.IO;
using System.Text;
using NUnit.Framework;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpCompressionTest
    {
        private static readonly byte[] Data = Encoding.ASCII.GetBytes("hello world! !dlrow olleh");

        [Test]
        public void TestUncompressed()
        {
            doTestCompression(CompressionAlgorithmTag.Uncompressed);
        }

        [Test]
        public void TestZip()
        {
            doTestCompression(CompressionAlgorithmTag.Zip);
        }

        [Test]
        public void TestZLib()
        {
            doTestCompression(CompressionAlgorithmTag.ZLib);
        }

        [Test]
        public void TestBZip2()
        {
            doTestCompression(CompressionAlgorithmTag.BZip2);
        }

        private void doTestCompression(CompressionAlgorithmTag type)
        {
            using MemoryStream bOut = new MemoryStream();

            // Compress data
            PgpCompressedDataGenerator cPacket = new PgpCompressedDataGenerator(type);
            PgpLiteralDataGenerator lPacket = new PgpLiteralDataGenerator();
            var writer = new PacketWriter(bOut);
            using (var compressedWriter = cPacket.Open(writer))
            using (var literalStream = lPacket.Open(compressedWriter, PgpLiteralData.Binary, "", DateTime.UtcNow))
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
