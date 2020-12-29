using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    public abstract class ContainedPacket : Packet
    {
        public abstract void Encode(Stream bcpgOut);
    }
}
