using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    class ElGamalSecretBcpgKey : BcpgKey
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
