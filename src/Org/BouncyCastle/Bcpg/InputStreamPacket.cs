using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public abstract class InputStreamPacket : Packet
    {
        internal Stream inputStream;

        protected InputStreamPacket(Stream inputStream)
        {
            this.inputStream = inputStream;
        }

        protected InputStreamPacket()
        {
            // TODO
        }

        /// <summary>Note: you can only read from this once...</summary>
        public Stream GetInputStream() => inputStream;

        public virtual void EncodeHeader(Stream bcpgOut)
        {
        }
    }
}
