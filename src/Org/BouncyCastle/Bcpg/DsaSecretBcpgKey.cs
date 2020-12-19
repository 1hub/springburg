using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for a DSA secret key.</summary>
    public class DsaSecretBcpgKey : BcpgObject, IBcpgKey
    {
        private MPInteger x;

        public DsaSecretBcpgKey(BcpgInputStream bcpgIn)
        {
            this.x = new MPInteger(bcpgIn);
        }

        public DsaSecretBcpgKey(MPInteger x)
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

        public MPInteger X => x;
    }
}
