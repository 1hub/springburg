using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public abstract class ContainedPacket : Packet
    {
        public abstract void Encode(Stream bcpgOut);
    }
}
