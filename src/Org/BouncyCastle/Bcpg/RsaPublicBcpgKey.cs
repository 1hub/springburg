using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for an RSA public key.</summary>
    public class RsaPublicBcpgKey : BcpgObject, IBcpgKey
    {
        private readonly MPInteger n, e;

        /// <summary>Construct an RSA public key from the passed in stream.</summary>
        public RsaPublicBcpgKey(
            BcpgInputStream bcpgIn)
        {
            this.n = new MPInteger(bcpgIn);
            this.e = new MPInteger(bcpgIn);
        }

        /// <param name="n">The modulus.</param>
        /// <param name="e">The public exponent.</param>
        public RsaPublicBcpgKey(
            MPInteger n,
            MPInteger e)
        {
            this.n = n;
            this.e = e;
        }

        public MPInteger PublicExponent => e;

        public MPInteger Modulus => n;

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format
        {
            get { return "PGP"; }
        }

        public override void Encode(Stream bcpgOut)
        {
            n.Encode(bcpgOut);
            e.Encode(bcpgOut);
        }
    }
}
