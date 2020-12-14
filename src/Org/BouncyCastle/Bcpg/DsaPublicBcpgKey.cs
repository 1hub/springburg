namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Base class for a DSA public key.</remarks>
    public class DsaPublicBcpgKey
        : BcpgObject, IBcpgKey
    {
        private readonly MPInteger p, q, g, y;

        /// <param name="bcpgIn">The stream to read the packet from.</param>
        public DsaPublicBcpgKey(
            BcpgInputStream bcpgIn)
        {
            this.p = new MPInteger(bcpgIn);
            this.q = new MPInteger(bcpgIn);
            this.g = new MPInteger(bcpgIn);
            this.y = new MPInteger(bcpgIn);
        }

        public DsaPublicBcpgKey(
            MPInteger p,
            MPInteger q,
            MPInteger g,
            MPInteger y)
        {
            this.p = p;
            this.q = q;
            this.g = g;
            this.y = y;
        }

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format
        {
            get { return "PGP"; }
        }

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WriteObjects(p, q, g, y);
        }

        public MPInteger G => g;

        public MPInteger P => p;

        public MPInteger Q => q;

        public MPInteger Y => y;
    }
}
