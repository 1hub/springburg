using Springburg.IO;
using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    class ExperimentalPacket : ContainedPacket
    {
        private readonly PacketTag tag;
        private readonly byte[] contents;

        internal ExperimentalPacket(
            PacketTag tag,
            Stream bcpgIn)
        {
            this.tag = tag;
            this.contents = bcpgIn.ReadAll();
        }

        public ReadOnlySpan<byte> GetContents() => contents;

        public override PacketTag Tag => tag;

        public override void Encode(Stream bcpgOut)
        {
            bcpgOut.Write(contents);
        }
    }
}
