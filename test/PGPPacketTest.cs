using System;
using System.IO;
using NUnit.Framework;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpPacketTest
    {
        private static int MAX = 32000;

        [Test]
        [TestCase(true)]
        [TestCase(false)]
        public void ReadBackTest(bool oldFormat)
        {
            var generator = new PgpLiteralDataGenerator(oldFormat);
            Random rand = new Random();
            byte[] buf = new byte[MAX];
            byte[] buf2 = new byte[MAX];

            rand.NextBytes(buf);

            for (int i = 1; i != MAX; i++)
            {
                using MemoryStream bOut = new MemoryStream();
                using (var outputStream = generator.Open(bOut, PgpLiteralData.Binary, PgpLiteralData.Console, i, DateTime.UtcNow))
                    outputStream.Write(buf, 0, i);

                PgpObjectFactory fact = new PgpObjectFactory(bOut.ToArray());
                PgpLiteralData data = (PgpLiteralData)fact.NextPgpObject();
                Stream inputStream = new BufferedStream(data.GetInputStream());
                Array.Clear(buf2, 0, i);
                inputStream.Read(buf2.AsSpan(0, i));
                Assert.IsTrue(buf2.AsSpan(0, i).SequenceEqual(buf.AsSpan(0, i)), "failed readback test");
            }
        }
    }
}
