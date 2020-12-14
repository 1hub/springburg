using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Base class for an ECDSA Public Key.</remarks>
    public class ECDsaPublicBcpgKey
        : ECPublicBcpgKey
    {
        /// <param name="bcpgIn">The stream to read the packet from.</param>
        protected internal ECDsaPublicBcpgKey(BcpgInputStream bcpgIn)
            : base(bcpgIn)
        {
        }

        /*public ECDsaPublicBcpgKey(Oid oid, ECPoint point)
            : base(oid, point)
        {
        }*/

        public ECDsaPublicBcpgKey(Oid oid, MPInteger encodedPoint)
            : base(oid, encodedPoint)
        {
        }
    }
}
