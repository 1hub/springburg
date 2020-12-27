using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    public abstract class ContainedPacket : Packet
    {
        public abstract void Encode(Stream bcpgOut);
    }
}
