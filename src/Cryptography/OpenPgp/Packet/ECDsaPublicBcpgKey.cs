using System.IO;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    class ECDsaPublicBcpgKey : ECPublicBcpgKey
    {
        public ECDsaPublicBcpgKey(Stream bcpgIn)
            : base(bcpgIn)
        {
        }

        public ECDsaPublicBcpgKey(Oid oid, MPInteger encodedPoint)
            : base(oid, encodedPoint)
        {
        }
    }
}
