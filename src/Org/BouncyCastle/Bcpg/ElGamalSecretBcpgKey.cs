namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for an ElGamal secret key.</summary>
    public class ElGamalSecretBcpgKey : BcpgObject, IBcpgKey
    {
        private MPInteger x;

        public ElGamalSecretBcpgKey(BcpgInputStream bcpgIn)
        {
            this.x = new MPInteger(bcpgIn);
        }

        public ElGamalSecretBcpgKey(MPInteger x)
        {
            this.x = x;
        }

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format
        {
            get { return "PGP"; }
        }

        public MPInteger X => x;

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WriteObject(x);
        }
    }
}
