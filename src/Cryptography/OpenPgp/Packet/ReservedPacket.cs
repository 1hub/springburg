using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    class ReservedPacket : StreamablePacket
    {
        public override PacketTag Tag => PacketTag.Reserved;

        public override void EncodeHeader(Stream bcpgOut)
        {
        }
    }
}
