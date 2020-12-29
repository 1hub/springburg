using InflatablePalace.Cryptography.OpenPgp.Packet;
using NUnit.Framework;
using System.IO;
using System.Text;

namespace InflatablePalace.Test
{
    [TestFixture]
    public class PgpArmorTest
    {
        // Contains PGP marker packet as an armored message
        // The 'blank line' after the headers contains (legal) whitespace - see RFC2440 6.2
        private static readonly string blankLineData =
            "-----BEGIN PGP MESSAGE-----\n" +
            "Version: BCPG v1.32\n" +
            "Comment: A dummy message\n" +
            " \t \t\n" +
            "qANQR1A=\n" +
            "=1VfW\n" +
            "-----END PGP MESSAGE-----\n";

        private static readonly string incorrectCrc =
            "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "qANQR1A=\n" +
            "=aaaa\n" +
            "-----END PGP MESSAGE-----\n";

        [Test]
        public void BlankLineTest()
        {
            using var data = new MemoryStream(Encoding.ASCII.GetBytes(blankLineData), false);
            using var packetReader = new ArmoredPacketReader(data);
            var packet = packetReader.ReadContainedPacket();
            Assert.NotNull(packet);
            Assert.AreEqual(PacketTag.Marker, packet.Tag);
            Assert.IsTrue(packetReader.VerifyCrc());
        }

        [Test]
        public void TwoMessages()
        {
            using var data = new MemoryStream(Encoding.ASCII.GetBytes(blankLineData + blankLineData), false);
            using (var packetReader = new ArmoredPacketReader(data))
            {
                var packet = packetReader.ReadContainedPacket();
                Assert.NotNull(packet);
                Assert.AreEqual(PacketTag.Marker, packet.Tag);
                Assert.IsTrue(packetReader.VerifyCrc());
            }
            using (var packetReader = new ArmoredPacketReader(data))
            {
                var packet = packetReader.ReadContainedPacket();
                Assert.NotNull(packet);
                Assert.AreEqual(PacketTag.Marker, packet.Tag);
                Assert.IsTrue(packetReader.VerifyCrc());
            }
        }

        [Test]
        public void IncorrectCrcTest()
        {
            using var data = new MemoryStream(Encoding.ASCII.GetBytes(incorrectCrc), false);
            using var packetReader = new ArmoredPacketReader(data);
            var packet = packetReader.ReadContainedPacket();
            Assert.NotNull(packet);
            Assert.AreEqual(PacketTag.Marker, packet.Tag);
            Assert.IsFalse(packetReader.VerifyCrc());
        }
    }
}
