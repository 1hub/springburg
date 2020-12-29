using InflatablePalace.IO;
using System;
using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    class ModDetectionCodePacket : ContainedPacket
    {
        private readonly byte[] digest;

        internal ModDetectionCodePacket(Stream bcpgIn)
        {
            if (bcpgIn == null)
                throw new ArgumentNullException(nameof(bcpgIn));
            this.digest = new byte[20];
            bcpgIn.ReadFully(this.digest);
        }

        public ModDetectionCodePacket(byte[] digest)
        {
            if (digest == null)
                throw new ArgumentNullException(nameof(digest));

            this.digest = (byte[])digest.Clone();
        }

        public ReadOnlySpan<byte> Digest => digest;

        public override PacketTag Tag => PacketTag.ModificationDetectionCode;

        public override void Encode(Stream bcpgOut)
        {
            bcpgOut.Write(digest);
        }
    }
}
