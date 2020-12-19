using Org.BouncyCastle.Utilities.IO;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class MarkerPacket : ContainedPacket
    {
        // "PGP"
        byte[] marker = { (byte)0x50, (byte)0x47, (byte)0x50 };

        internal MarkerPacket(Stream bcpgIn)
        {
            Streams.ReadFully(bcpgIn, marker);
        }

        public override void Encode(Stream bcpgOut)
        {
            WritePacket(bcpgOut, PacketTag.Marker, marker, useOldPacket: true);
        }
    }
}
