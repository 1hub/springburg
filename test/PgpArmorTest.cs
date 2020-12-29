using InflatablePalace.Cryptography.OpenPgp;
using InflatablePalace.Cryptography.OpenPgp.Packet;
using NUnit.Framework;
using Org.BouncyCastle.Bcpg.OpenPgp.Tests;
using System;
using System.IO;
using System.Security.Cryptography;
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

        private static readonly string incorrectDashEncoding =
            "-----BEGIN PGP SIGNED MESSAGE-----\n" +
            "Hash: SHA256\n" +
            "\n" +
            "\n" +
            " hello world!\n" +
            "\n" +
            "-a- dash\n" +
            "-----BEGIN PGP SIGNATURE-----\n" +
            "Version: GnuPG v1.4.2.1 (GNU/Linux)\n" +
            "\n" +
            "iQEVAwUBRCNS8+DPyHq93/cWAQi6SwgAj3ItmSLr/sd/ixAQLW7/12jzEjfNmFDt\n" +
            "WOZpJFmXj0fnMzTrOILVnbxHv2Ru+U8Y1K6nhzFSR7d28n31/XGgFtdohDEaFJpx\n" +
            "Fl+KvASKIonnpEDjFJsPIvT1/G/eCPalwO9IuxaIthmKj0z44SO1VQtmNKxdLAfK\n" +
            "+xTnXGawXS1WUE4CQGPM45mIGSqXcYrLtJkAg3jtRa8YRUn2d7b2BtmWH+jVaVuC\n" +
            "hNrXYv7iHFOu25yRWhUQJisvdC13D/gKIPRvARXPgPhAC2kovIy6VS8tDoyG6Hm5\n" +
            "dMgLEGhmqsgaetVq1ZIuBZj5S4j2apBJCDpF6GBfpBOfwIZs0Tpmlw==\n" +
            "=84Nd\n" +
            "-----END PGP SIGNATURE-----\n";

        private static readonly string incorrectDashMessage =
            "\r\n" +
            " hello world!\r\n" +
            "\r\n" +
            "-a- dash";

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
        public void VerifyCrcWithoutReadingTest()
        {
            using var data = new MemoryStream(Encoding.ASCII.GetBytes(blankLineData), false);
            using var packetReader = new ArmoredPacketReader(data);
            Assert.IsTrue(packetReader.VerifyCrc());
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


        [Test]
        public void CloseWithoutReadingTest()
        {
            using var data = new MemoryStream(Encoding.ASCII.GetBytes(blankLineData), false);
            using (var packetReader = new ArmoredPacketReader(data))
            {
            }
            // We should be past blankLineData.Length - 1 (ie. without the last \n)
            Assert.LessOrEqual(blankLineData.Length - 1, data.Position);
        }

        [Test]
        public void IncorrectDashEncoding()
        {
            var reader = new ArmoredPacketReader(new MemoryStream(Encoding.ASCII.GetBytes(incorrectDashEncoding)));
            var signedMessage = (PgpSignedMessage)PgpMessage.ReadMessage(reader);
            var literalMessage = (PgpLiteralMessage)signedMessage.ReadMessage();
            var bytes = Streams.ReadAll(literalMessage.GetStream());
            // NOTE: We normalize to CRLF line ending. If we change that then this test needs to be adjusted.
            Assert.AreEqual(incorrectDashMessage, Encoding.ASCII.GetString(bytes));
            // NOTE: The signature is bogus but that's not what we test here
        }

        [Test]
        public void SimpleSignature()
        {
            var keyPair = new PgpKeyPair(DSA.Create(512), DateTime.UtcNow);

            byte[] msg = Encoding.ASCII.GetBytes("hello world!");
            var encodedStream = new MemoryStream();

            using (var messageGenerator = new PgpMessageGenerator(new ArmoredPacketWriter(encodedStream, useClearText: true)))
            using (var signedGenerator = messageGenerator.CreateSigned(PgpSignature.CanonicalTextDocument, keyPair.PrivateKey, PgpHashAlgorithm.Sha256))
            using (var literalStream = signedGenerator.CreateLiteral(PgpDataFormat.Binary, "", DateTime.UtcNow))
            {
                literalStream.Write(msg);
            }

            encodedStream = new MemoryStream(encodedStream.ToArray(), false);
            var signedMessage = (PgpSignedMessage)PgpMessage.ReadMessage(new ArmoredPacketReader(encodedStream));
            var literalMessage = (PgpLiteralMessage)signedMessage.ReadMessage();
            // Skip over literal data
            var bytes = Streams.ReadAll(literalMessage.GetStream());
            Assert.AreEqual(msg, bytes);
            // NOTE: The order is significant
            Assert.IsTrue(signedMessage.Verify(keyPair.PublicKey));
        }

        [Test]
        public void NestedSignatures()
        {
            var keyPairOuter = new PgpKeyPair(DSA.Create(512), DateTime.UtcNow);
            var keyPairInner = new PgpKeyPair(DSA.Create(512), DateTime.UtcNow);

            byte[] msg = Encoding.ASCII.GetBytes("hello world!");
            var encodedStream = new MemoryStream();

            using (var messageGenerator = new PgpMessageGenerator(new ArmoredPacketWriter(encodedStream, useClearText: true)))
            using (var signedGeneratorOuter = messageGenerator.CreateSigned(PgpSignature.CanonicalTextDocument, keyPairOuter.PrivateKey, PgpHashAlgorithm.Sha256))
            using (var signedGeneratorInner = signedGeneratorOuter.CreateSigned(PgpSignature.CanonicalTextDocument, keyPairInner.PrivateKey, PgpHashAlgorithm.Sha1))
            using (var literalStream = signedGeneratorInner.CreateLiteral(PgpDataFormat.Binary, "", DateTime.UtcNow))
            {
                literalStream.Write(msg);
            }

            encodedStream = new MemoryStream(encodedStream.ToArray(), false);
            var signedMessageOuter = (PgpSignedMessage)PgpMessage.ReadMessage(new ArmoredPacketReader(encodedStream));
            var signedMessageInner = (PgpSignedMessage)signedMessageOuter.ReadMessage();
            var literalMessage = (PgpLiteralMessage)signedMessageInner.ReadMessage();
            // Skip over literal data
            var bytes = Streams.ReadAll(literalMessage.GetStream());
            Assert.AreEqual(msg, bytes);
            // NOTE: The order is significant
            Assert.IsTrue(signedMessageInner.Verify(keyPairInner.PublicKey));
            Assert.IsTrue(signedMessageOuter.Verify(keyPairOuter.PublicKey));
        }

        // TODO:
        // - Incorrect headers
        // - Multiple Hash headers / multiple values in Hash header, trailing spaces after hash name
        // - Unknown Hash names
        // - No Hash header implies MD5
    }
}
