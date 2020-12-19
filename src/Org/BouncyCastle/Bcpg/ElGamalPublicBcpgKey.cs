using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for an ElGamal public key.</summary>
    public class ElGamalPublicBcpgKey : BcpgObject, IBcpgKey
    {
        internal MPInteger p, g, y;

        public ElGamalPublicBcpgKey(BcpgInputStream bcpgIn)
        {
            this.p = new MPInteger(bcpgIn);
            this.g = new MPInteger(bcpgIn);
            this.y = new MPInteger(bcpgIn);
        }

        public ElGamalPublicBcpgKey(
            MPInteger p,
            MPInteger g,
            MPInteger y)
        {
            this.p = p;
            this.g = g;
            this.y = y;
        }

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format
        {
            get { return "PGP"; }
        }

        public MPInteger P => p;

        public MPInteger G => g;

        public MPInteger Y => y;

        public override void Encode(Stream bcpgOut)
        {
            p.Encode(bcpgOut);
            g.Encode(bcpgOut);
            y.Encode(bcpgOut);
        }
    }
}
