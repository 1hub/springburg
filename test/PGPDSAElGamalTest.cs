using InflatablePalace.Cryptography.Algorithms;
using NUnit.Framework;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpDsaElGamalTest
    {
        private static readonly byte[] testPubKeyRing = Convert.FromBase64String(
              "mQGiBEAR8jYRBADNifuSopd20JOQ5x30ljIaY0M6927+vo09NeNxS3KqItba"
            + "nz9o5e2aqdT0W1xgdHYZmdElOHTTsugZxdXTEhghyxoo3KhVcNnTABQyrrvX"
            + "qouvmP2fEDEw0Vpyk+90BpyY9YlgeX/dEA8OfooRLCJde/iDTl7r9FT+mts8"
            + "g3azjwCgx+pOLD9LPBF5E4FhUOdXISJ0f4EEAKXSOi9nZzajpdhe8W2ZL9gc"
            + "BpzZi6AcrRZBHOEMqd69gtUxA4eD8xycUQ42yH89imEcwLz8XdJ98uHUxGJi"
            + "qp6hq4oakmw8GQfiL7yQIFgaM0dOAI9Afe3m84cEYZsoAFYpB4/s9pVMpPRH"
            + "NsVspU0qd3NHnSZ0QXs8L8DXGO1uBACjDUj+8GsfDCIP2QF3JC+nPUNa0Y5t"
            + "wKPKl+T8hX/0FBD7fnNeC6c9j5Ir/Fp/QtdaDAOoBKiyNLh1JaB1NY6US5zc"
            + "qFks2seZPjXEiE6OIDXYra494mjNKGUobA4hqT2peKWXt/uBcuL1mjKOy8Qf"
            + "JxgEd0MOcGJO+1PFFZWGzLQ3RXJpYyBILiBFY2hpZG5hICh0ZXN0IGtleSBv"
            + "bmx5KSA8ZXJpY0Bib3VuY3ljYXN0bGUub3JnPohZBBMRAgAZBQJAEfI2BAsH"
            + "AwIDFQIDAxYCAQIeAQIXgAAKCRAOtk6iUOgnkDdnAKC/CfLWikSBdbngY6OK"
            + "5UN3+o7q1ACcDRqjT3yjBU3WmRUNlxBg3tSuljmwAgAAuQENBEAR8jgQBAC2"
            + "kr57iuOaV7Ga1xcU14MNbKcA0PVembRCjcVjei/3yVfT/fuCVtGHOmYLEBqH"
            + "bn5aaJ0P/6vMbLCHKuN61NZlts+LEctfwoya43RtcubqMc7eKw4k0JnnoYgB"
            + "ocLXOtloCb7jfubOsnfORvrUkK0+Ne6anRhFBYfaBmGU75cQgwADBQP/XxR2"
            + "qGHiwn+0YiMioRDRiIAxp6UiC/JQIri2AKSqAi0zeAMdrRsBN7kyzYVVpWwN"
            + "5u13gPdQ2HnJ7d4wLWAuizUdKIQxBG8VoCxkbipnwh2RR4xCXFDhJrJFQUm+"
            + "4nKx9JvAmZTBIlI5Wsi5qxst/9p5MgP3flXsNi1tRbTmRhqIRgQYEQIABgUC"
            + "QBHyOAAKCRAOtk6iUOgnkBStAJoCZBVM61B1LG2xip294MZecMtCwQCbBbsk"
            + "JVCXP0/Szm05GB+WN+MOCT2wAgAA");

        private static readonly byte[] testPrivKeyRing = Convert.FromBase64String(
              "lQHhBEAR8jYRBADNifuSopd20JOQ5x30ljIaY0M6927+vo09NeNxS3KqItba"
            + "nz9o5e2aqdT0W1xgdHYZmdElOHTTsugZxdXTEhghyxoo3KhVcNnTABQyrrvX"
            + "qouvmP2fEDEw0Vpyk+90BpyY9YlgeX/dEA8OfooRLCJde/iDTl7r9FT+mts8"
            + "g3azjwCgx+pOLD9LPBF5E4FhUOdXISJ0f4EEAKXSOi9nZzajpdhe8W2ZL9gc"
            + "BpzZi6AcrRZBHOEMqd69gtUxA4eD8xycUQ42yH89imEcwLz8XdJ98uHUxGJi"
            + "qp6hq4oakmw8GQfiL7yQIFgaM0dOAI9Afe3m84cEYZsoAFYpB4/s9pVMpPRH"
            + "NsVspU0qd3NHnSZ0QXs8L8DXGO1uBACjDUj+8GsfDCIP2QF3JC+nPUNa0Y5t"
            + "wKPKl+T8hX/0FBD7fnNeC6c9j5Ir/Fp/QtdaDAOoBKiyNLh1JaB1NY6US5zc"
            + "qFks2seZPjXEiE6OIDXYra494mjNKGUobA4hqT2peKWXt/uBcuL1mjKOy8Qf"
            + "JxgEd0MOcGJO+1PFFZWGzP4DAwLeUcsVxIC2s2Bb9ab2XD860TQ2BI2rMD/r"
            + "7/psx9WQ+Vz/aFAT3rXkEJ97nFeqEACgKmUCAEk9939EwLQ3RXJpYyBILiBF"
            + "Y2hpZG5hICh0ZXN0IGtleSBvbmx5KSA8ZXJpY0Bib3VuY3ljYXN0bGUub3Jn"
            + "PohZBBMRAgAZBQJAEfI2BAsHAwIDFQIDAxYCAQIeAQIXgAAKCRAOtk6iUOgn"
            + "kDdnAJ9Ala3OcwEV1DbK906CheYWo4zIQwCfUqUOLMp/zj6QAk02bbJAhV1r"
            + "sAewAgAAnQFYBEAR8jgQBAC2kr57iuOaV7Ga1xcU14MNbKcA0PVembRCjcVj"
            + "ei/3yVfT/fuCVtGHOmYLEBqHbn5aaJ0P/6vMbLCHKuN61NZlts+LEctfwoya"
            + "43RtcubqMc7eKw4k0JnnoYgBocLXOtloCb7jfubOsnfORvrUkK0+Ne6anRhF"
            + "BYfaBmGU75cQgwADBQP/XxR2qGHiwn+0YiMioRDRiIAxp6UiC/JQIri2AKSq"
            + "Ai0zeAMdrRsBN7kyzYVVpWwN5u13gPdQ2HnJ7d4wLWAuizUdKIQxBG8VoCxk"
            + "bipnwh2RR4xCXFDhJrJFQUm+4nKx9JvAmZTBIlI5Wsi5qxst/9p5MgP3flXs"
            + "Ni1tRbTmRhr+AwMC3lHLFcSAtrNg/EiWFLAnKNXH27zjwuhje8u2r+9iMTYs"
            + "GjbRxaxRY0GKRhttCwqe2BC0lHhzifdlEcc9yjIjuKfepG2fnnSIRgQYEQIA"
            + "BgUCQBHyOAAKCRAOtk6iUOgnkBStAJ9HFejVtVJ/A9LM/mDPe0ExhEXt/QCg"
            + "m/KM7hJ/JrfnLQl7IaZsdg1F6vCwAgAA");

        private static readonly byte[] encMessage = Convert.FromBase64String(
              "hQEOAynbo4lhNjcHEAP/dgCkMtPB6mIgjFvNiotjaoh4sAXf4vFNkSeehQ2c"
            + "r+IMt9CgIYodJI3FoJXxOuTcwesqTp5hRzgUBJS0adLDJwcNubFMy0M2tp5o"
            + "KTWpXulIiqyO6f5jI/oEDHPzFoYgBmR4x72l/YpMy8UoYGtNxNvR7LVOfqJv"
            + "uDY/71KMtPQEAIadOWpf1P5Td+61Zqn2VH2UV7H8eI6hGa6Lsy4sb9iZNE7f"
            + "c+spGJlgkiOt8TrQoq3iOK9UN9nHZLiCSIEGCzsEn3uNuorD++Qs065ij+Oy"
            + "36TKeuJ+38CfT7u47dEshHCPqWhBKEYrxZWHUJU/izw2Q1Yxd2XRxN+nafTL"
            + "X1fQ0lABQUASa18s0BkkEERIdcKQXVLEswWcGqWNv1ZghC7xO2VDBX4HrPjp"
            + "drjL63p2UHzJ7/4gPWGGtnqq1Xita/1mrImn7pzLThDWiT55vjw6Hw==");

        private static readonly byte[] signedAndEncMessage = Convert.FromBase64String(
              "hQEOAynbo4lhNjcHEAP+K20MVhzdX57hf/cU8TH0prP0VePr9mmeBedzqqMn"
            + "fp2p8Zb68zmcMlI/WiL5XMNLYRmCgEcXyWbKdP/XV9m9LDBe1CMAGrkCeGBy"
            + "je69IQQ5LS9vDPyEMF4iAAv/EqACjqHkizdY/a/FRx/t2ioXYdEC2jA6kS9C"
            + "McpsNz16DE8EAIk3uKn4bGo/+15TXkyFYzW5Cf71SfRoHNmU2zAI93zhjN+T"
            + "B7mGJwWXzsMkIO6FkMU5TCSrwZS3DBWCIaJ6SYoaawE/C/2j9D7bX1Jv8kum"
            + "4cq+eZM7z6JYs6xend+WAwittpUxbEiyC2AJb3fBSXPAbLqWd6J6xbZZ7GDK"
            + "r2Ca0pwBxwGhbMDyi2zpHLzw95H7Ah2wMcGU6kMLB+hzBSZ6mSTGFehqFQE3"
            + "2BnAj7MtnbghiefogacJ891jj8Y2ggJeKDuRz8j2iICaTOy+Y2rXnnJwfYzm"
            + "BMWcd2h1C5+UeBJ9CrrLniCCI8s5u8z36Rno3sfhBnXdRmWSxExXtocbg1Ht"
            + "dyiThf6TK3W29Yy/T6x45Ws5zOasaJdsFKM=");

        private static readonly char[] pass = "hello world".ToCharArray();

        private static readonly byte[] text = Encoding.ASCII.GetBytes("hello world!\n");

        [Test]
        public void SignatureGenerateAndVerify()
        {
            var pgpPub = new PgpPublicKeyRing(testPubKeyRing);
            var pubKey = pgpPub.GetPublicKey();
            var sKey = new PgpSecretKeyRing(testPrivKeyRing);
            var secretKey = sKey.GetSecretKey();
            var privKey = secretKey.ExtractPrivateKey(pass);

            // Generate signature
            MemoryStream bOut = new MemoryStream();
            PgpSignatureGenerator sGen = new PgpSignatureGenerator(PgpSignature.BinaryDocument, privKey, HashAlgorithmTag.Sha1);
            PgpCompressedDataGenerator cGen = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
            PgpLiteralDataGenerator lGen = new PgpLiteralDataGenerator();
            DateTime testDateTime = new DateTime(1973, 7, 27);

            var writer = new PacketWriter(bOut);
            using (var compressedWriter = cGen.Open(writer))
            using (var signingWriter = sGen.Open(compressedWriter))
            using (var literalStream = lGen.Open(signingWriter, PgpLiteralData.Binary, "_CONSOLE", testDateTime))
                literalStream.Write(text);

            // Verify generated signature
            bOut.Position = 0;
            var compressedMessage = (PgpCompressedMessage)PgpMessage.ReadMessage(bOut);
            var signedMessage = (PgpSignedMessage)compressedMessage.ReadMessage();
            var literalMessage = (PgpLiteralMessage)signedMessage.ReadMessage();
            Assert.AreEqual(testDateTime, literalMessage.ModificationTime);
            literalMessage.GetStream().CopyTo(Stream.Null);
            Assert.IsTrue(signedMessage.Verify(pubKey));
        }

        [Test]
        public void DecryptMessage()
        {
            var secretKey = FindSuitableKeyForEncryption();
            var privateKey = secretKey.ExtractPrivateKey(pass);
            var encryptedMessage = (PgpEncryptedMessage)PgpMessage.ReadMessage(encMessage);
            var compressedMessage = (PgpCompressedMessage)encryptedMessage.DecryptMessage(privateKey);
            var literalMessage = (PgpLiteralMessage)compressedMessage.ReadMessage();
            Assert.AreEqual("test.txt", literalMessage.FileName);
            byte[] bytes = Streams.ReadAll(literalMessage.GetStream());
            Assert.AreEqual(text, bytes);
        }

        [Test]
        public void DecryptAndVerifyMessage()
        {
            var pgpPub = new PgpPublicKeyRing(testPubKeyRing);
            var pubKey = pgpPub.GetPublicKey();
            var secretKey = FindSuitableKeyForEncryption();
            var privateKey = secretKey.ExtractPrivateKey(pass);
            var encryptedMessage = (PgpEncryptedMessage)PgpMessage.ReadMessage(signedAndEncMessage);
            var compressedMessage = (PgpCompressedMessage)encryptedMessage.DecryptMessage(privateKey);
            var signedMessage = (PgpSignedMessage)compressedMessage.ReadMessage();
            var literalMessage = (PgpLiteralMessage)signedMessage.ReadMessage();
            Assert.AreEqual("test.txt", literalMessage.FileName);
            var bytes = Streams.ReadAll(literalMessage.GetStream());
            Assert.AreEqual(text, bytes);
            Assert.IsTrue(signedMessage.Verify(pubKey));
        }

        [Test]
        public void EncryptMessage()
        {
            var secretKey = FindSuitableKeyForEncryption();
            var privateKey = secretKey.ExtractPrivateKey(pass);

            MemoryStream cbOut = new MemoryStream();
            PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.TripleDes);
            cPk.AddMethod(secretKey.PublicKey);
            var writer = new PacketWriter(cbOut);
            using (var cOut = cPk.Open(writer))
            using (var pOut = new PgpLiteralDataGenerator().Open(cOut, PgpLiteralData.Utf8, "", DateTime.UtcNow))
                pOut.Write(text, 0, text.Length);

            cbOut.Position = 0;
            var encryptedMessage = (PgpEncryptedMessage)PgpMessage.ReadMessage(cbOut);
            var literalMessage = (PgpLiteralMessage)encryptedMessage.DecryptMessage(privateKey);
            var bytes = Streams.ReadAll(literalMessage.GetStream());
            Assert.AreEqual(text, bytes);
        }

        private PgpSecretKey FindSuitableKeyForEncryption()
        {
            var pgpPub = new PgpPublicKeyRing(testPubKeyRing);
            var pubKey = pgpPub.GetPublicKey();
            var sKey = new PgpSecretKeyRing(testPrivKeyRing);
            long pgpKeyID = 0;
            AsymmetricAlgorithm pKey = null;

            foreach (PgpPublicKey pgpKey in pgpPub.GetPublicKeys())
            {
                if (pgpKey.Algorithm == PublicKeyAlgorithmTag.ElGamalEncrypt || pgpKey.Algorithm == PublicKeyAlgorithmTag.ElGamalGeneral)
                {
                    pKey = pgpKey.GetKey();
                    pgpKeyID = pgpKey.KeyId;
                    Assert.AreEqual(1024, pgpKey.BitStrength);
                }
            }

            return sKey.GetSecretKey(pgpKeyID);
        }

        public void KeyPairPSizeTest()
        {
            // Test bug with ElGamal P size != 0 mod 8 (don't use these sizes at home!)
            for (int pSize = 257; pSize < 264; ++pSize)
            {
                PgpKeyPair elGamalKeyPair = new PgpKeyPair(ElGamal.Create(pSize), DateTime.UtcNow);

                var cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5);
                cPk.AddMethod(elGamalKeyPair.PublicKey);

                var cbOut = new MemoryStream();
                var writer = new PacketWriter(cbOut);
                using (var encryptedWriter = cPk.Open(writer))
                using (var literalStream = new PgpLiteralDataGenerator().Open(encryptedWriter, PgpLiteralData.Binary, "", DateTime.UtcNow))
                    literalStream.Write(text);

                cbOut.Position = 0;
                var encryptedMessage = (PgpEncryptedMessage)PgpMessage.ReadMessage(cbOut);
                var literalMessage = (PgpLiteralMessage)encryptedMessage.DecryptMessage(elGamalKeyPair.PrivateKey);
                var bytes = Streams.ReadAll(literalMessage.GetStream());
                Assert.AreEqual(text, bytes);
            }
        }
    }
}
