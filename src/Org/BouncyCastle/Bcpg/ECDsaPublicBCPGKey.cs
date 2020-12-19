using System.IO;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg
{
    public class ECDsaPublicBcpgKey : ECPublicBcpgKey
    {
        protected internal ECDsaPublicBcpgKey(Stream bcpgIn)
            : base(bcpgIn)
        {
        }

        public ECDsaPublicBcpgKey(Oid oid, MPInteger encodedPoint)
            : base(oid, encodedPoint)
        {
        }
    }
}
