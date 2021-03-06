﻿using System;
using System.IO;
using System.Linq;
using Springburg.Cryptography.OpenPgp;
using NUnit.Framework;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpECMessageTest
    {
        private static readonly byte[] testPubKey =
            Convert.FromBase64String(
                "mFIEU5SAxhMIKoZIzj0DAQcCAwRqnFLCB8EEZkAELNqznk8yQau/f1PACUTU/Qe9\n" +
                    "jlybc22bO55BdvZdFoa3RmNQHhR980/KeVwCQ3cPpe6OQJFAtD9OSVNUIFAtMjU2\n" +
                    "IChHZW5lcmF0ZWQgYnkgR1BHIDIuMSBiZXRhKSA8bmlzdC1wLTI1NkBleGFtcGxl\n" +
                    "LmNvbT6IeQQTEwgAIQUCU5SAxgIbAwYLCQgHAwIGFQgCCQoLAxYCAQIeAQIXgAAK\n" +
                    "CRA2iYNe+deDntxvAP90U2BUL2YcxrJYnsK783VIPM5U5/2IhH7azbRfaHiLZgEA\n" +
                    "1/BVNxRG/Q07gPSdEGagRZcrzPxMQPLjBL4T7Nq5eSG4VgRTlIDqEggqhkjOPQMB\n" +
                    "BwIDBJlWEj5qR12xbmp5dkjEkV+PRSfk37NKnw8axSJkyDTsFNZLIugMLX/zTn3r\n" +
                    "rOamvHUdXNbLy1s8PeyrztMcOnwDAQgHiGEEGBMIAAkFAlOUgOoCGwwACgkQNomD\n" +
                    "XvnXg556SQD+MCXRkYgLPd0NWWbCKl5wYk4NwWRvOCDFGk7eYoRTKaYBAIkt3J86\n" +
                    "Bn0zCzsphjrIUlGPXhLSX/2aJQDuuK3zzLmn");

        private static readonly byte[] sExprKeySub =
            Convert.FromBase64String(
                "KDIxOnByb3RlY3RlZC1wcml2YXRlLWtleSgzOmVjYyg1OmN1cnZlMTA6TklT"
                 + "VCBQLTI1NikoMTpxNjU6BJlWEj5qR12xbmp5dkjEkV+PRSfk37NKnw8axSJk"
                 + "yDTsFNZLIugMLX/zTn3rrOamvHUdXNbLy1s8PeyrztMcOnwpKDk6cHJvdGVj"
                 + "dGVkMjU6b3BlbnBncC1zMmszLXNoYTEtYWVzLWNiYygoNDpzaGExODpu2e7w"
                 + "pW4L5jg6MTI5MDU0NzIpMTY6ohIkbi1P1O7QX1zgPd7Ejik5NjrCoM9qBxzy"
                 + "LVJJMVRGlsjltF9/CeLnRPN1sjeiQrP1vAlZMPiOpYTmGDVRcZhdkCRO06MY"
                 + "UTLDZK1wsxELVD0s9irpbskcOnXwqtXbIqhoK4B+9pnkR0h5gi0xPIGSTtYp"
                 + "KDEyOnByb3RlY3RlZC1hdDE1OjIwMTQwNjA4VDE1MjgxMCkpKQ==");

        private static readonly byte[] sExprKeyMaster =
            Convert.FromBase64String(
                "KDIxOnByb3RlY3RlZC1wcml2YXRlLWtleSgzOmVjYyg1OmN1cnZlMTA6TklT"
              + "VCBQLTI1NikoMTpxNjU6BGqcUsIHwQRmQAQs2rOeTzJBq79/U8AJRNT9B72O"
              + "XJtzbZs7nkF29l0WhrdGY1AeFH3zT8p5XAJDdw+l7o5AkUApKDk6cHJvdGVj"
              + "dGVkMjU6b3BlbnBncC1zMmszLXNoYTEtYWVzLWNiYygoNDpzaGExODr4PqHT"
              + "9W4lpTg6MTI5MDU0NzIpMTY6VsooQy9aGsuMpiObZk4y1ik5NjoCArOSmSsJ"
              + "IYUzxkRwy/HyDYPqjAqrNrh3m8lQco6k64Pf4SDda/0gKjkum7zYDEzBEvXI"
              + "+ZodAST6z3IDkPHL7LUy5qp2LdG73xLRFjfsqOsZgP+nwoOSUiC7N4AWJPAp"
              + "KDEyOnByb3RlY3RlZC1hdDE1OjIwMTQwNjA4VDE1MjcwOSkpKQ==");

        private static readonly byte[] encMessage =
            Convert.FromBase64String("hH4DrQCblwYU61MSAgMEVXjgPW2hvIhUMQ2qlAQlAliZKbyujaYfLnwZTeGvu+pt\n"+
                "gJXt+JJ8zWoENxLAp+Nb3PxJW4CjvkXQ2dEmmvkhBzAhDer86XJBrQLBQUL+6EmE\n"+
                "l+/3Yzt+cPEyEn32BSpkt31F2yGncoefCUDgj9tKiFXSRwGhjRno0qzB3CfRWzDu\n"+
                "eelwwtRcxnvXNc44TuHRf4PgZ3d4dDU69bWQswdQ5UTP/Bjjo92yMLtJ3HtBuym+\n"+
                "NazbQUh4M+SP");

        private static readonly byte[] signedEncMessage =
            Convert.FromBase64String("hH4DrQCblwYU61MSAgMEC/jpqjgnqotzKWNWJ3bhOxmmChghrV2PLQbQqtHtVvbj\n" +
                "zyLpaPgeqLslMAjsdy8rlANCjlweZhtP1DmvHiYgjDAA54eptpLMtbULaQOoRcsZ\n" +
                "ZnMqhx9s5phAohNFGC+DnVU/IwxDOnI+ya54LOoXUrrSsgEKDTlAmYr4/oDmLTXt\n" +
                "TaLgk0T9nBxGe8WbLwhPRBIyq6NX151aQ+pOobajrRiLwg/CwUsbAZ50bBPn2JjX\n" +
                "wgBhBjyAn7D6bZ4hMl3YSluSiFkJhxZcYSydtIAlX35q4D/pJjT4mPT/y7ypytCU\n" +
                "0wWo53O6NCSeM/EpeFw8RRh8fe+m33qpA6T5sR3Alg4ZukiIxLa36k6Cv5KTHmB3\n" +
                "6lKZcgQDHNIKStV1bW4Cva1aXXQ=");

        [Test]
        public void DoTestMasterKey()
        {
            PgpSecretKey key = PgpSecretKey.ParseSecretKeyFromSExpr(new MemoryStream(sExprKeyMaster, false), "test");
            PgpPublicKey publicKey = new PgpPublicKeyRing(testPubKey).GetPublicKey();
            KeyTestHelper.SignAndVerifyTestMessage(key.ExtractPrivateKey(""), publicKey);
        }

        [Test]
        public void DoTestEncMessage()
        {
            var encryptedMessage = (PgpEncryptedMessage)PgpMessage.ReadMessage(encMessage);

            var publicKeyRing = new PgpPublicKeyRing(testPubKey);
            var publicKey = publicKeyRing.GetPublicKey(encryptedMessage.KeyIds.First());
            var secretKey = PgpSecretKey.ParseSecretKeyFromSExpr(new MemoryStream(sExprKeySub, false), "test", publicKey);
            var privateKey = secretKey.ExtractPrivateKey("");

            var compressedMessage = (PgpCompressedMessage)encryptedMessage.DecryptMessage(privateKey);
            var literalMessage = (PgpLiteralMessage)compressedMessage.ReadMessage();
            Assert.AreEqual("test.txt", literalMessage.FileName);
        }

        [Test]
        public void DoTestSignedEncMessage()
        {
            var encryptedMessage = (PgpEncryptedMessage)PgpMessage.ReadMessage(signedEncMessage);

            var publicKeyRing = new PgpPublicKeyRing(testPubKey);
            var publicKey = publicKeyRing.GetPublicKey(encryptedMessage.KeyIds.First());
            var secretKey = PgpSecretKey.ParseSecretKeyFromSExpr(new MemoryStream(sExprKeySub, false), "test", publicKey);
            var privateKey = secretKey.ExtractPrivateKey("");

            var compressedMessage = (PgpCompressedMessage)encryptedMessage.DecryptMessage(privateKey);
            var signedMessage = (PgpSignedMessage)compressedMessage.ReadMessage();
            var literalMessage = (PgpLiteralMessage)signedMessage.ReadMessage();
            Assert.AreEqual("test.txt", literalMessage.FileName);
            literalMessage.GetStream().CopyTo(Stream.Null);
            Assert.IsTrue(signedMessage.Verify(publicKeyRing.GetPublicKey(signedMessage.KeyId)));
        }
    }
}
