using Org.BouncyCastle.Utilities.IO;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class ExperimentalPacket : ContainedPacket
    {
        private readonly PacketTag tag;
        private readonly byte[] contents;

        internal ExperimentalPacket(
            PacketTag tag,
            Stream bcpgIn)
        {
            this.tag = tag;
            this.contents = Streams.ReadAll(bcpgIn);
        }

        public byte[] GetContents()
        {
            return (byte[])contents.Clone();
        }

        public override PacketTag Tag => tag;

        public override void Encode(Stream bcpgOut)
        {
            bcpgOut.Write(contents);
        }
    }
}
