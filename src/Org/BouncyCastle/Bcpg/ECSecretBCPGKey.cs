using System;
using System.IO;
using System.Numerics;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for an EC Secret Key.</summary>
    public class ECSecretBcpgKey : BcpgObject, IBcpgKey
    {
        private MPInteger x;

        public ECSecretBcpgKey(BcpgInputStream bcpgIn)
        {
            this.x = new MPInteger(bcpgIn);
        }

        public ECSecretBcpgKey(MPInteger x)
        {
            this.x = x;
        }

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format
        {
            get { return "PGP"; }
        }

        public override void Encode(Stream bcpgOut)
        {
            x.Encode(bcpgOut);
        }

        public virtual MPInteger X
        {
            get { return x; }
        }
    }
}
