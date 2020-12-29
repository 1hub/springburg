using Springburg.Cryptography.OpenPgp.Packet;
using System.IO;

namespace Springburg.Cryptography.OpenPgp
{
    public abstract class PgpEncodable
    {
        public byte[] GetEncoded()
        {
            using MemoryStream bOut = new MemoryStream();
            Encode(new PacketWriter(bOut));
            return bOut.ToArray();
        }

        public void Encode(Stream s)
        {
            Encode(new PacketWriter(s));
        }

        public abstract void Encode(IPacketWriter packetWriter);
    }
}
