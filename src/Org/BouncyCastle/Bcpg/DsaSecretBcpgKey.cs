using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class DsaSecretBcpgKey : BcpgObject
    {
        private MPInteger x;

        public DsaSecretBcpgKey(Stream bcpgIn)
        {
            this.x = new MPInteger(bcpgIn);
        }

        public DsaSecretBcpgKey(MPInteger x)
        {
            this.x = x;
        }

        public override void Encode(Stream bcpgOut)
        {
            x.Encode(bcpgOut);
        }

        public MPInteger X => x;
    }
}
