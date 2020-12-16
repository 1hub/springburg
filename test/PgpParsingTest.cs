using NUnit.Framework;
using Org.BouncyCastle.Utilities.Test;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpParsingTest
    {
        [Test]
        public void BigPub()
        {
            using Stream fIn = SimpleTest.GetTestDataAsStream("openpgp.bigpub.asc");
            using Stream keyIn = new ArmoredInputStream(fIn);
            PgpPublicKeyRingBundle pubRings = new PgpPublicKeyRingBundle(keyIn);
        }
    }
}
