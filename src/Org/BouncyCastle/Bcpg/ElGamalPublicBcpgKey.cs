using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class ElGamalPublicBcpgKey : BcpgKey
    {
        internal MPInteger p, g, y;

        public ElGamalPublicBcpgKey(Stream bcpgIn)
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
