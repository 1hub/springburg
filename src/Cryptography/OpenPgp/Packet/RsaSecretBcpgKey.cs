using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    class RsaSecretBcpgKey : BcpgKey
    {
        private readonly MPInteger d, p, q, u;

        public RsaSecretBcpgKey(Stream bcpgIn)
        {
            this.d = new MPInteger(bcpgIn);
            this.p = new MPInteger(bcpgIn);
            this.q = new MPInteger(bcpgIn);
            this.u = new MPInteger(bcpgIn);
        }

        public RsaSecretBcpgKey(
            MPInteger d,
            MPInteger p,
            MPInteger q,
            MPInteger u)
        {
            // PGP requires (p < q)
            /*int cmp = p.Value.CompareTo(q.Value);
            if (cmp >= 0)
            {
                if (cmp == 0)
                    throw new ArgumentException("p and q cannot be equal");

                MPInteger tmp = p;
                p = q;
                q = tmp;
            }*/

            this.d = d;
            this.p = p;
            this.q = q;
            this.u = u;
        }

        public MPInteger PrivateExponent => d;

        public MPInteger PrimeP => p;

        public MPInteger PrimeQ => q;

        public MPInteger InverseQ => u;

        public override void Encode(Stream bcpgOut)
        {
            d.Encode(bcpgOut);
            p.Encode(bcpgOut);
            q.Encode(bcpgOut);
            u.Encode(bcpgOut);
        }
    }
}
