using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    class ReservedPacket : StreamablePacket
    {
        public override PacketTag Tag => PacketTag.Reserved;

        public override void EncodeHeader(Stream bcpgOut)
        {
        }
    }
}
