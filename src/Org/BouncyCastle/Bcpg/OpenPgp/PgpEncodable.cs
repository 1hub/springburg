using Org.BouncyCastle.Bcpg;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
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

        public abstract void Encode(PacketWriter packetWriter);
    }
}
