using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for an RSA secret (or priate) key.</summary>
    public class RsaSecretBcpgKey : BcpgObject, IBcpgKey
    {
        private readonly MPInteger d, p, q, u;

        public RsaSecretBcpgKey(BcpgInputStream bcpgIn)
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

        /*public BigInteger Modulus
        {
            get { return p.Value * q.Value; }
        }*/

        public MPInteger PrivateExponent => d;

        public MPInteger PrimeP => p;

        public MPInteger PrimeQ => q;

        public MPInteger InverseQ => u;

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format
        {
            get { return "PGP"; }
        }

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WriteObjects(d, p, q, u);
        }
    }
}
