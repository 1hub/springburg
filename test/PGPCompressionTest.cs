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

        private void doTestCompression(
            CompressionAlgorithmTag type)
        {
            using MemoryStream bOut = new MemoryStream();
            PgpCompressedDataGenerator cPacket = new PgpCompressedDataGenerator(type);
            using (Stream os = cPacket.Open(bOut, new byte[Data.Length - 1]))
                os.Write(Data, 0, Data.Length);
            ValidateData(bOut.ToArray());
        }

        private void ValidateData(byte[] compressed)
        {
            PgpObjectFactory pgpFact = new PgpObjectFactory(compressed);
            PgpCompressedData c1 = (PgpCompressedData)pgpFact.NextPgpObject();

            Stream pIn = c1.GetDataStream();
            byte[] bytes = Streams.ReadAll(pIn);
            pIn.Close();

            Assert.That(bytes, Is.EqualTo(Data));
        }
    }
}
