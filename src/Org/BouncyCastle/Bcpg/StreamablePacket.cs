using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public abstract class StreamablePacket : Packet
    {
        public abstract void EncodeHeader(Stream bcpgOut);
    }
}
