using Springburg.IO;
using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    /// <summary>Basic type for a trust packet.</summary>
    class TrustPacket : ContainedPacket
    {
        private readonly byte[] levelAndTrustAmount;
 
        internal TrustPacket(Stream bcpgIn)
        {
            levelAndTrustAmount = bcpgIn.ReadAll();
        }

        public TrustPacket(int trustCode)
        {
            this.levelAndTrustAmount = new byte[] { (byte)trustCode };
        }

        public ReadOnlySpan<byte> GetLevelAndTrustAmount() => levelAndTrustAmount;

        public override PacketTag Tag => PacketTag.Trust;

        public override void Encode(Stream bcpgOut)
        {
            bcpgOut.Write(levelAndTrustAmount);
        }
    }
}
