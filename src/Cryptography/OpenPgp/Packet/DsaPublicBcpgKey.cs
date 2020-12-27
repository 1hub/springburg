using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    class DsaPublicBcpgKey : BcpgKey
    {
        private readonly MPInteger p, q, g, y;

        /// <param name="bcpgIn">The stream to read the packet from.</param>
        public DsaPublicBcpgKey(Stream bcpgIn)
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

        public override void Encode(Stream bcpgOut)
        {
            p.Encode(bcpgOut);
            q.Encode(bcpgOut);
            g.Encode(bcpgOut);
            y.Encode(bcpgOut);
        }

        public MPInteger G => g;

        public MPInteger P => p;

        public MPInteger Q => q;

        public MPInteger Y => y;
    }
}
