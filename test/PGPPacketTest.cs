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
            Random rand = new Random();
            byte[] buf = new byte[MAX];
            byte[] buf2 = new byte[MAX];

            rand.NextBytes(buf);

            for (int i = 1; i != MAX; i++)
            {
                using MemoryStream bOut = new MemoryStream();

                var messageGenerator = new PgpMessageGenerator(new PacketWriter(bOut, oldFormat));
                using (var outputStream = messageGenerator.CreateLiteral(PgpLiteralData.Binary, PgpLiteralData.Console, DateTime.UtcNow))
                    outputStream.Write(buf, 0, i);

                bOut.Position = 0;
                var literalMessage = (PgpLiteralMessage)PgpMessage.ReadMessage(bOut);
                Array.Clear(buf2, 0, i);
                int bytesRead = literalMessage.GetStream().Read(buf2.AsSpan(0, i));
                Assert.AreEqual(i, bytesRead);
                Assert.IsTrue(buf2.AsSpan(0, i).SequenceEqual(buf.AsSpan(0, i)), "failed readback test");
            }
        }
    }
}
