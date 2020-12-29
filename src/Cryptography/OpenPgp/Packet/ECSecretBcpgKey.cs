using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    class ECSecretBcpgKey : BcpgKey
    {
        private MPInteger x;

        public ECSecretBcpgKey(Stream bcpgIn)
        {
            this.x = new MPInteger(bcpgIn);
        }

        public ECSecretBcpgKey(MPInteger x)
        {
            this.x = x;
        }

        public override void Encode(Stream bcpgOut)
        {
            x.Encode(bcpgOut);
        }

        public virtual MPInteger X => x;
    }
}
