using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class ExperimentalPacket : ContainedPacket
    {
        private readonly PacketTag tag;
        private readonly byte[] contents;

        internal ExperimentalPacket(
            PacketTag tag,
            BcpgInputStream bcpgIn)
        {
            this.tag = tag;

            this.contents = bcpgIn.ReadAll();
        }

        public PacketTag Tag
        {
            get { return tag; }
        }

        public byte[] GetContents()
        {
            return (byte[])contents.Clone();
        }

        public override void Encode(Stream bcpgOut)
        {
            WritePacket(bcpgOut, tag, contents, useOldPacket: true);
        }
    }
}
