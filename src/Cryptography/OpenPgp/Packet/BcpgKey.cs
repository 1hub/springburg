using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    abstract class BcpgKey
    {
        public abstract void Encode(Stream bcpgOut);
    }
}
