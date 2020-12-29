using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    public abstract class StreamablePacket : Packet
    {
        public abstract void EncodeHeader(Stream bcpgOut);
    }
}
