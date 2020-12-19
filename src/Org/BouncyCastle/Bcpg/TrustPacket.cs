using Org.BouncyCastle.Utilities.IO;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic type for a trust packet.</summary>
    public class TrustPacket
        : ContainedPacket
    {
        private readonly byte[] levelAndTrustAmount;
 
        internal TrustPacket(Stream bcpgIn)
        {
            levelAndTrustAmount = Streams.ReadAll(bcpgIn);
        }

        public TrustPacket(int trustCode)
        {
            this.levelAndTrustAmount = new byte[] { (byte)trustCode };
        }

        public byte[] GetLevelAndTrustAmount()
        {
            return (byte[])levelAndTrustAmount.Clone();
        }

        public override void Encode(Stream bcpgOut)
        {
            WritePacket(bcpgOut, PacketTag.Trust, levelAndTrustAmount, useOldPacket: true);
        }
    }
}
