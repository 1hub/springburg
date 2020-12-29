using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    abstract class BcpgKey
    {
        public abstract void Encode(Stream bcpgOut);
    }
}
