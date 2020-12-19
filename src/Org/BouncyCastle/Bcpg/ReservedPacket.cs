using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class ReservedPacket : InputStreamPacket
    {
        internal ReservedPacket(Stream bcpgIn)
            : base(bcpgIn)
        {
        }

        public override PacketTag Tag => PacketTag.Reserved;
    }
}
