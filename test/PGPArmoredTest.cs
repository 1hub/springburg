using System;
using System.IO;
using System.Text;
using NUnit.Framework;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpArmoredTest
    {
        private static readonly byte[] sample = Convert.FromBase64String(
                "mQGiBEA83v0RBADzKVLVCnpWQxX0LCsevw/3OLs0H7MOcLBQ4wMO9sYmzGYn"
            + "xpVj+4e4PiCP7QBayWyy4lugL6Lnw7tESvq3A4v3fefcxaCTkJrryiKn4+Cg"
            + "y5rIBbrSKNtCEhVi7xjtdnDjP5kFKgHYjVOeIKn4Cz/yzPG3qz75kDknldLf"
            + "yHxp2wCgwW1vAE5EnZU4/UmY7l8kTNkMltMEAJP4/uY4zcRwLI9Q2raPqAOJ"
            + "TYLd7h+3k/BxI0gIw96niQ3KmUZDlobbWBI+VHM6H99vcttKU3BgevNf8M9G"
            + "x/AbtW3SS4De64wNSU3189XDG8vXf0vuyW/K6Pcrb8exJWY0E1zZQ1WXT0gZ"
            + "W0kH3g5ro//Tusuil9q2lVLF2ovJA/0W+57bPzi318dWeNs0tTq6Njbc/GTG"
            + "FUAVJ8Ss5v2u6h7gyJ1DB334ExF/UdqZGldp0ugkEXaSwBa2R7d3HBgaYcoP"
            + "Ck1TrovZzEY8gm7JNVy7GW6mdOZuDOHTxyADEEP2JPxh6eRcZbzhGuJuYIif"
            + "IIeLOTI5Dc4XKeV32a+bWrQidGVzdCAoVGVzdCBrZXkpIDx0ZXN0QHViaWNh"
            + "bGwuY29tPohkBBMRAgAkBQJAPN79AhsDBQkB4TOABgsJCAcDAgMVAgMDFgIB"
            + "Ah4BAheAAAoJEJh8Njfhe8KmGDcAoJWr8xgPr75y/Cp1kKn12oCCOb8zAJ4p"
            + "xSvk4K6tB2jYbdeSrmoWBZLdMLACAAC5AQ0EQDzfARAEAJeUAPvUzJJbKcc5"
            + "5Iyb13+Gfb8xBWE3HinQzhGr1v6A1aIZbRj47UPAD/tQxwz8VAwJySx82ggN"
            + "LxCk4jW9YtTL3uZqfczsJngV25GoIN10f4/j2BVqZAaX3q79a3eMiql1T0oE"
            + "AGmD7tO1LkTvWfm3VvA0+t8/6ZeRLEiIqAOHAAQNBACD0mVMlAUgd7REYy/1"
            + "mL99Zlu9XU0uKyUex99sJNrcx1aj8rIiZtWaHz6CN1XptdwpDeSYEOFZ0PSu"
            + "qH9ByM3OfjU/ya0//xdvhwYXupn6P1Kep85efMBA9jUv/DeBOzRWMFG6sC6y"
            + "k8NGG7Swea7EHKeQI40G3jgO/+xANtMyTIhPBBgRAgAPBQJAPN8BAhsMBQkB"
            + "4TOAAAoJEJh8Njfhe8KmG7kAn00mTPGJCWqmskmzgdzeky5fWd7rAKCNCp3u"
            + "ZJhfg0htdgAfIy8ppm05vLACAAA=");

        private static readonly byte[] marker = Convert.FromBase64String("LS0tLS1FTkQgUEdQIFBVQkxJQyBLRVkgQkxPQ0stLS0tLQ==");

        // Contains "Hello World!" as an armored message
        // The 'blank line' after the headers contains (legal) whitespace - see RFC2440 6.2
        private static readonly string blankLineData =
              "-----BEGIN PGP MESSAGE-----\n"
            + "Version: BCPG v1.32\n"
            + "Comment: A dummy message\n"
            + " \t \t\n"
            + "SGVsbG8gV29ybGQh\n"
            + "=d9Xi\n"
            + "-----END PGP MESSAGE-----\n";

        private void pgpUtilTest()
        {
            // check decoder exception isn't escaping.
            /*MemoryStream bIn = new MemoryStream(Encoding.ASCII.GetBytes("abcde"), false);

            try
            {
                PgpUtilities.GetDecoderStream(bIn);
                Fail("no exception");
            }
            catch (IOException)
            {
                // expected: ignore.
            }*/
        }

        [Test]
        public void BlankLineTest()
        {
            byte[] blankLineBytes = Encoding.ASCII.GetBytes(blankLineData);
            MemoryStream bIn = new MemoryStream(blankLineBytes, false);
            ArmoredInputStream aIn = new ArmoredInputStream(bIn, true);

            MemoryStream bOut = new MemoryStream();
            int c;
            while ((c = aIn.ReadByte()) >= 0)
            {
                bOut.WriteByte((byte)c);
            }

            byte[] expected = Encoding.ASCII.GetBytes("Hello World!");
            Assert.That(bOut.ToArray(), Is.EqualTo(expected));
        }

        [Test]
        public void ImmediateClose()
        {
            using MemoryStream bOut = new MemoryStream();
            using (var aOut = new ArmoredPacketWriter(bOut))
                ;
            byte[] data = bOut.ToArray();
            Assert.AreEqual(0, data.Length, "No data should have been written");
        }

        [Test]
        public void MultipleClose()
        {
            using var bOut = new MemoryStream();
            using var aOut = new ArmoredPacketWriter(bOut);

            aOut.WritePacket(new MarkerPacket());

            aOut.Dispose();
            aOut.Dispose();

            //int mc = markerCount(bOut.ToArray());
            //Assert.AreEqual(1, mc);
        }

        /*
        [Test]
        public void SingleObjectReadWrite()
        {
            using var bOut = new MemoryStream();
            using var aOut = new ArmoredOutputStream(bOut);

            aOut.Write(sample, 0, sample.Length);

            aOut.Close();

            ArmoredInputStream aIn = new ArmoredInputStream(
                new MemoryStream(bOut.ToArray(), false));

            var reader = new PacketReader(aIn);
            int count = 0;

            while (reader.ReadPacket() != null)
            {
                count++;
            }

            Assert.AreEqual(1, count, "wrong number of objects found: {0}", count);
        }

        [Test]
        public void MultipleObjectReadWrite()
        {
            var bOut = new MemoryStream();
            var aOut = new ArmoredOutputStream(bOut);

            aOut.Write(sample, 0, sample.Length);
            aOut.Write(sample, 0, sample.Length);

            aOut.Close();

            var aIn = new ArmoredInputStream(
                new MemoryStream(bOut.ToArray(), false));

            var reader = new PacketReader(aIn);
            int count = 0;

            while (reader.ReadPacket() != null)
            {
                count++;
            }

            Assert.AreEqual(2, count, "wrong number of objects found: {0}", count);

            //
            // writing and reading multiple objects  - in single block
            //
            bOut = new MemoryStream();
            aOut = new ArmoredOutputStream(bOut);

            aOut.Write(sample, 0, sample.Length);

            aOut.Close();     // does not close underlying stream

            aOut = new ArmoredOutputStream(bOut);

            aOut.Write(sample, 0, sample.Length);

            aOut.Close();

            aIn = new ArmoredInputStream(
                new MemoryStream(bOut.ToArray(), false));

            count = 0;
            bool atLeastOne;
            do
            {
                atLeastOne = false;
                
                reader = new PacketReader(aIn);
                while (reader.ReadPacket() != null)
                {
                    atLeastOne = true;
                    count++;
                }
            }
            while (atLeastOne);

            Assert.AreEqual(2, count, "wrong number of objects found: {0}", count);
        }*/
    }
}
