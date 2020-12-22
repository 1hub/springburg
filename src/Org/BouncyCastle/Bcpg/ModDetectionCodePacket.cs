using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class ModDetectionCodePacket : ContainedPacket
    {
        private readonly byte[] digest;

        internal ModDetectionCodePacket(Stream bcpgIn)
        {
            if (bcpgIn == null)
                throw new ArgumentNullException("bcpgIn");
            this.digest = new byte[20];
            Streams.ReadFully(bcpgIn, this.digest);
        }

        public ModDetectionCodePacket(byte[] digest)
        {
            if (digest == null)
                throw new ArgumentNullException("digest");

            this.digest = (byte[])digest.Clone();
        }

        public byte[] GetDigest()
        {
            return (byte[])digest.Clone();
        }

        public override PacketTag Tag => PacketTag.ModificationDetectionCode;

        public override void Encode(Stream bcpgOut)
        {
            bcpgOut.Write(digest);
        }
    }
}
