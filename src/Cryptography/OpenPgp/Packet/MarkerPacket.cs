using InflatablePalace.IO;
using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    class MarkerPacket : ContainedPacket
    {
        // "PGP"
        byte[] marker = { (byte)0x50, (byte)0x47, (byte)0x50 };

        internal MarkerPacket(Stream bcpgIn)
        {
            if (bcpgIn.ReadFully(marker) < marker.Length)
                throw new EndOfStreamException();
        }

        public MarkerPacket()
        {
        }

        public override PacketTag Tag => PacketTag.Marker;

        public override void Encode(Stream bcpgOut)
        {
            bcpgOut.Write(marker);
        }
    }
}
