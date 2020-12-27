using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    public abstract class StreamablePacket : Packet
    {
        public abstract void EncodeHeader(Stream bcpgOut);
    }
}
