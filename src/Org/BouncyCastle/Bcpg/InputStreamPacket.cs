using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public abstract class InputStreamPacket : Packet
    {
        private readonly Stream bcpgIn;

        internal InputStreamPacket(Stream bcpgIn)
        {
            this.bcpgIn = bcpgIn;
        }

        /// <summary>Note: you can only read from this once...</summary>
        public Stream GetInputStream()
        {
            return bcpgIn;
        }
    }
}
