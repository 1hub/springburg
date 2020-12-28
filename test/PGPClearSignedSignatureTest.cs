using System;
using System.IO;
using System.Linq;
using System.Text;
using InflatablePalace.Cryptography.OpenPgp;
using InflatablePalace.Cryptography.OpenPgp.Packet;
using NUnit.Framework;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpClearSignedSignatureTest
    {
        private static readonly byte[] publicKey = Convert.FromBase64String(
              "mQELBEQh2+wBCAD26kte0hO6flr7Y2aetpPYutHY4qsmDPy+GwmmqVeCDkX+"
            + "r1g7DuFbMhVeu0NkKDnVl7GsJ9VarYsFYyqu0NzLa9XS2qlTIkmJV+2/xKa1"
            + "tzjn18fT/cnAWL88ZLCOWUr241aPVhLuIc6vpHnySpEMkCh4rvMaimnTrKwO"
            + "42kgeDGd5cXfs4J4ovRcTbc4hmU2BRVsRjiYMZWWx0kkyL2zDVyaJSs4yVX7"
            + "Jm4/LSR1uC/wDT0IJJuZT/gQPCMJNMEsVCziRgYkAxQK3OWojPSuv4rXpyd4"
            + "Gvo6IbvyTgIskfpSkCnQtORNLIudQSuK7pW+LkL62N+ohuKdMvdxauOnAAYp"
            + "tBNnZ2dnZ2dnZyA8Z2dnQGdnZ2c+iQE2BBMBAgAgBQJEIdvsAhsDBgsJCAcD"
            + "AgQVAggDBBYCAwECHgECF4AACgkQ4M/Ier3f9xagdAf/fbKWBjLQM8xR7JkR"
            + "P4ri8YKOQPhK+VrddGUD59/wzVnvaGyl9MZE7TXFUeniQq5iXKnm22EQbYch"
            + "v2Jcxyt2H9yptpzyh4tP6tEHl1C887p2J4qe7F2ATua9CzVGwXQSUbKtj2fg"
            + "UZP5SsNp25guhPiZdtkf2sHMeiotmykFErzqGMrvOAUThrO63GiYsRk4hF6r"
            + "cQ01d+EUVpY/sBcCxgNyOiB7a84sDtrxnX5BTEZDTEj8LvuEyEV3TMUuAjx1"
            + "7Eyd+9JtKzwV4v3hlTaWOvGro9nPS7YaPuG+RtufzXCUJPbPfTjTvtGOqvEz"
            + "oztls8tuWA0OGHba9XfX9rfgorACAAM=");

        private static readonly byte[] secretKey = Convert.FromBase64String(
              "lQOWBEQh2+wBCAD26kte0hO6flr7Y2aetpPYutHY4qsmDPy+GwmmqVeCDkX+"
            + "r1g7DuFbMhVeu0NkKDnVl7GsJ9VarYsFYyqu0NzLa9XS2qlTIkmJV+2/xKa1"
            + "tzjn18fT/cnAWL88ZLCOWUr241aPVhLuIc6vpHnySpEMkCh4rvMaimnTrKwO"
            + "42kgeDGd5cXfs4J4ovRcTbc4hmU2BRVsRjiYMZWWx0kkyL2zDVyaJSs4yVX7"
            + "Jm4/LSR1uC/wDT0IJJuZT/gQPCMJNMEsVCziRgYkAxQK3OWojPSuv4rXpyd4"
            + "Gvo6IbvyTgIskfpSkCnQtORNLIudQSuK7pW+LkL62N+ohuKdMvdxauOnAAYp"
            + "AAf+JCJJeAXEcrTVHotsrRR5idzmg6RK/1MSQUijwPmP7ZGy1BmpAmYUfbxn"
            + "B56GvXyFV3Pbj9PgyJZGS7cY+l0BF4ZqN9USiQtC9OEpCVT5LVMCFXC/lahC"
            + "/O3EkjQy0CYK+GwyIXa+Flxcr460L/Hvw2ZEXJZ6/aPdiR+DU1l5h99Zw8V1"
            + "Y625MpfwN6ufJfqE0HLoqIjlqCfi1iwcKAK2oVx2SwnT1W0NwUUXjagGhD2s"
            + "VzJVpLqhlwmS0A+RE9Niqrf80/zwE7QNDF2DtHxmMHJ3RY/pfu5u1rrFg9YE"
            + "lmS60mzOe31CaD8Li0k5YCJBPnmvM9mN3/DWWprSZZKtmQQA96C2/VJF5EWm"
            + "+/Yxi5J06dG6Bkz311Ui4p2zHm9/4GvTPCIKNpGx9Zn47YFD3tIg3fIBVPOE"
            + "ktG38pEPx++dSSFF9Ep5UgmYFNOKNUVq3yGpatBtCQBXb1LQLAMBJCJ5TQmk"
            + "68hMOEaqjMHSOa18cS63INgA6okb/ueAKIHxYQcEAP9DaXu5n9dZQw7pshbN"
            + "Nu/T5IP0/D/wqM+W5r+j4P1N7PgiAnfKA4JjKrUgl8PGnI2qM/Qu+g3qK++c"
            + "F1ESHasnJPjvNvY+cfti06xnJVtCB/EBOA2UZkAr//Tqa76xEwYAWRBnO2Y+"
            + "KIVOT+nMiBFkjPTrNAD6fSr1O4aOueBhBAC6aA35IfjC2h5MYk8+Z+S4io2o"
            + "mRxUZ/dUuS+kITvWph2e4DT28Xpycpl2n1Pa5dCDO1lRqe/5JnaDYDKqxfmF"
            + "5tTG8GR4d4nVawwLlifXH5Ll7t5NcukGNMCsGuQAHMy0QHuAaOvMdLs5kGHn"
            + "8VxfKEVKhVrXsvJSwyXXSBtMtUcRtBNnZ2dnZ2dnZyA8Z2dnQGdnZ2c+iQE2"
            + "BBMBAgAgBQJEIdvsAhsDBgsJCAcDAgQVAggDBBYCAwECHgECF4AACgkQ4M/I"
            + "er3f9xagdAf/fbKWBjLQM8xR7JkRP4ri8YKOQPhK+VrddGUD59/wzVnvaGyl"
            + "9MZE7TXFUeniQq5iXKnm22EQbYchv2Jcxyt2H9yptpzyh4tP6tEHl1C887p2"
            + "J4qe7F2ATua9CzVGwXQSUbKtj2fgUZP5SsNp25guhPiZdtkf2sHMeiotmykF"
            + "ErzqGMrvOAUThrO63GiYsRk4hF6rcQ01d+EUVpY/sBcCxgNyOiB7a84sDtrx"
            + "nX5BTEZDTEj8LvuEyEV3TMUuAjx17Eyd+9JtKzwV4v3hlTaWOvGro9nPS7Ya"
            + "PuG+RtufzXCUJPbPfTjTvtGOqvEzoztls8tuWA0OGHba9XfX9rfgorACAAA=");

        private static readonly string crOnlyMessage =
                "\r"
            + " hello world!\r"
            + "\r"
            + "- dash\r";

        private static readonly string nlOnlyMessage =
            "\n"
            + " hello world!\n"
            + "\n"
            + "- dash\n";

        private static readonly string crNlMessage =
            "\r\n"
            + " hello world!\r\n"
            + "\r\n"
            + "- dash\r\n";

        private static readonly string crOnlySignedMessage =
                "-----BEGIN PGP SIGNED MESSAGE-----\r"
            + "Hash: SHA256\r"
            + "\r"
            + "\r"
            + " hello world!\r"
            + "\r"
            + "- - dash\r"
            + "-----BEGIN PGP SIGNATURE-----\r"
            + "Version: GnuPG v1.4.2.1 (GNU/Linux)\r"
            + "\r"
            + "iQEVAwUBRCNS8+DPyHq93/cWAQi6SwgAj3ItmSLr/sd/ixAQLW7/12jzEjfNmFDt\r"
            + "WOZpJFmXj0fnMzTrOILVnbxHv2Ru+U8Y1K6nhzFSR7d28n31/XGgFtdohDEaFJpx\r"
            + "Fl+KvASKIonnpEDjFJsPIvT1/G/eCPalwO9IuxaIthmKj0z44SO1VQtmNKxdLAfK\r"
            + "+xTnXGawXS1WUE4CQGPM45mIGSqXcYrLtJkAg3jtRa8YRUn2d7b2BtmWH+jVaVuC\r"
            + "hNrXYv7iHFOu25yRWhUQJisvdC13D/gKIPRvARXPgPhAC2kovIy6VS8tDoyG6Hm5\r"
            + "dMgLEGhmqsgaetVq1ZIuBZj5S4j2apBJCDpF6GBfpBOfwIZs0Tpmlw==\r"
            + "=84Nd\r"
            + "-----END PGP SIGNATURE-----\r";

        private static readonly string nlOnlySignedMessage =
            "-----BEGIN PGP SIGNED MESSAGE-----\n"
            + "Hash: SHA256\n"
            + "\n"
            + "\n"
            + " hello world!\n"
            + "\n"
            + "- - dash\n"
            + "-----BEGIN PGP SIGNATURE-----\n"
            + "Version: GnuPG v1.4.2.1 (GNU/Linux)\n"
            + "\n"
            + "iQEVAwUBRCNS8+DPyHq93/cWAQi6SwgAj3ItmSLr/sd/ixAQLW7/12jzEjfNmFDt\n"
            + "WOZpJFmXj0fnMzTrOILVnbxHv2Ru+U8Y1K6nhzFSR7d28n31/XGgFtdohDEaFJpx\n"
            + "Fl+KvASKIonnpEDjFJsPIvT1/G/eCPalwO9IuxaIthmKj0z44SO1VQtmNKxdLAfK\n"
            + "+xTnXGawXS1WUE4CQGPM45mIGSqXcYrLtJkAg3jtRa8YRUn2d7b2BtmWH+jVaVuC\n"
            + "hNrXYv7iHFOu25yRWhUQJisvdC13D/gKIPRvARXPgPhAC2kovIy6VS8tDoyG6Hm5\n"
            + "dMgLEGhmqsgaetVq1ZIuBZj5S4j2apBJCDpF6GBfpBOfwIZs0Tpmlw==\n"
            + "=84Nd\n"
            + "-----END PGP SIGNATURE-----\n";

        private static readonly string crNlSignedMessage =
                "-----BEGIN PGP SIGNED MESSAGE-----\r\n"
            + "Hash: SHA256\r\n"
            + "\r\n"
            + "\r\n"
            + " hello world!\r\n"
            + "\r\n"
            + "- - dash\r\n"
            + "-----BEGIN PGP SIGNATURE-----\r\n"
            + "Version: GnuPG v1.4.2.1 (GNU/Linux)\r\n"
            + "\r\n"
            + "iQEVAwUBRCNS8+DPyHq93/cWAQi6SwgAj3ItmSLr/sd/ixAQLW7/12jzEjfNmFDt\r\n"
            + "WOZpJFmXj0fnMzTrOILVnbxHv2Ru+U8Y1K6nhzFSR7d28n31/XGgFtdohDEaFJpx\r\n"
            + "Fl+KvASKIonnpEDjFJsPIvT1/G/eCPalwO9IuxaIthmKj0z44SO1VQtmNKxdLAfK\r\n"
            + "+xTnXGawXS1WUE4CQGPM45mIGSqXcYrLtJkAg3jtRa8YRUn2d7b2BtmWH+jVaVuC\r\n"
            + "hNrXYv7iHFOu25yRWhUQJisvdC13D/gKIPRvARXPgPhAC2kovIy6VS8tDoyG6Hm5\r\n"
            + "dMgLEGhmqsgaetVq1ZIuBZj5S4j2apBJCDpF6GBfpBOfwIZs0Tpmlw==\r\n"
            + "=84Nd\r"
            + "-----END PGP SIGNATURE-----\r\n";

        private static readonly string crNlSignedMessageTrailingWhiteSpace =
            "-----BEGIN PGP SIGNED MESSAGE-----\r\n"
            + "Hash: SHA256\r\n"
            + "\r\n"
            + "\r\n"
            + " hello world! \t\r\n"
            + "\r\n"
            + "- - dash\r\n"
            + "-----BEGIN PGP SIGNATURE-----\r\n"
            + "Version: GnuPG v1.4.2.1 (GNU/Linux)\r\n"
            + "\r\n"
            + "iQEVAwUBRCNS8+DPyHq93/cWAQi6SwgAj3ItmSLr/sd/ixAQLW7/12jzEjfNmFDt\r\n"
            + "WOZpJFmXj0fnMzTrOILVnbxHv2Ru+U8Y1K6nhzFSR7d28n31/XGgFtdohDEaFJpx\r\n"
            + "Fl+KvASKIonnpEDjFJsPIvT1/G/eCPalwO9IuxaIthmKj0z44SO1VQtmNKxdLAfK\r\n"
            + "+xTnXGawXS1WUE4CQGPM45mIGSqXcYrLtJkAg3jtRa8YRUn2d7b2BtmWH+jVaVuC\r\n"
            + "hNrXYv7iHFOu25yRWhUQJisvdC13D/gKIPRvARXPgPhAC2kovIy6VS8tDoyG6Hm5\r\n"
            + "dMgLEGhmqsgaetVq1ZIuBZj5S4j2apBJCDpF6GBfpBOfwIZs0Tpmlw==\r\n"
            + "=84Nd\r"
            + "-----END PGP SIGNATURE-----\r\n";

        public static object[] MessageTestCases =
        {
            new object[] { "\\r", crOnlySignedMessage },
            new object[] { "\\n", nlOnlySignedMessage },
            new object[] { "\\r\\n", crNlSignedMessage },
            new object[] { "\\r\\n + trailing", crNlSignedMessageTrailingWhiteSpace }
        };

        public static object[] GenerateTestCases =
        {
            new object[] { "\\r", nlOnlyMessage },
            new object[] { "\\n", crOnlyMessage },
            new object[] { "\\r\\n", crNlMessage }
        };

        [Test]
        [TestCaseSource(nameof(MessageTestCases))]
        public void MessageTest(string type, string message)
        {
            ArmoredInputStream aIn = new ArmoredInputStream(
                new MemoryStream(Encoding.ASCII.GetBytes(message)));

            string[] headers = aIn.GetArmorHeaders();

            Assert.NotNull(headers);
            Assert.AreEqual(1, headers.Length);

            //
            // read the input, making sure we ingore the last newline.
            //
            MemoryStream bOut = new MemoryStream();
            int ch;

            while ((ch = aIn.ReadByte()) >= 0 && aIn.IsClearText())
            {
                bOut.WriteByte((byte)ch);
            }

            PgpPublicKeyRingBundle pgpRings = new PgpPublicKeyRingBundle(publicKey);

            PgpSignature sig = new PgpSignature(aIn);

            // FIXME: This belongs directly to the armor reader
            byte[] clearText = bOut.ToArray();
            int clearTextLength = clearText.Length;
            if (clearTextLength > 0 && clearText[clearTextLength - 1] == '\n')
                clearTextLength--;
            if (clearTextLength > 0 && clearText[clearTextLength - 1] == '\r')
                clearTextLength--;

            bool verified = sig.Verify(pgpRings.GetPublicKey(sig.KeyId), new MemoryStream(clearText, 0, clearTextLength, false), ignoreTrailingWhitespace: true);
            Assert.IsTrue(verified, "signature failed to verify m_in " + type);

            var reader = new ArmoredPacketReader(new MemoryStream(Encoding.ASCII.GetBytes(message)));
            var signedMessage = (PgpSignedMessage)PgpMessage.ReadMessage(reader);
            var literalMessage = (PgpLiteralMessage)signedMessage.ReadMessage();
            //var bytes = literalMessage.GetStream().ReadAll();
            //Assert.IsTrue(signedMessage.Verify(pgpRings.GetPublicKey(sig.KeyId)));
        }

        private PgpSecretKey ReadSecretKey(Stream inputStream)
        {
            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(inputStream);

            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //
            //
            // iterate through the key rings.
            //
            foreach (PgpSecretKeyRing kRing in pgpSec.GetKeyRings())
            {
                foreach (PgpSecretKey k in kRing.GetSecretKeys())
                {
                    if (k.IsSigningKey)
                    {
                        return k;
                    }
                }
            }

            Assert.Fail("Can't find signing key in key ring.");
            return null;
        }

        [Test]
        [TestCaseSource(nameof(GenerateTestCases))]
        public void GenerateTest(string type, string message)
        {
            PgpSecretKey pgpSecKey = ReadSecretKey(new MemoryStream(secretKey));
            PgpPrivateKey pgpPrivKey = pgpSecKey.ExtractPrivateKey("");
            MemoryStream bOut = new MemoryStream();
            using (var messageGenerator = new PgpMessageGenerator(new ArmoredPacketWriter(bOut)))
            using (var signedGenerator = messageGenerator.CreateSigned(PgpSignature.CanonicalTextDocument, pgpPrivKey, PgpHashAlgorithm.Sha256))
            {
                signedGenerator.HashedAttributes.SetSignerUserId(false, pgpSecKey.PublicKey.GetUserIds().First().UserId);
                using (var literalStream = signedGenerator.CreateLiteral(PgpDataFormat.Text, "", DateTime.MinValue))
                {
                    literalStream.Write(Encoding.UTF8.GetBytes(message));
                }
            }
            byte[] bs = bOut.ToArray();
            MessageTest(type, Encoding.ASCII.GetString(bs, 0, bs.Length));
        }
    }
}
