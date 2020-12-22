using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class ReservedPacket : StreamablePacket
    {
        public override PacketTag Tag => PacketTag.Reserved;

        public override void EncodeHeader(Stream bcpgOut)
        {
        }
    }
}
