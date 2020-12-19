using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class ElGamalSecretBcpgKey : BcpgObject
    {
        private MPInteger x;

        public ElGamalSecretBcpgKey(Stream bcpgIn)
        {
            this.x = new MPInteger(bcpgIn);
        }

        public ElGamalSecretBcpgKey(MPInteger x)
        {
            this.x = x;
        }

        public MPInteger X => x;

        public override void Encode(Stream bcpgOut)
        {
            x.Encode(bcpgOut);
        }
    }
}
