using Org.BouncyCastle.Utilities.IO;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic type for a trust packet.</summary>
    public class TrustPacket : ContainedPacket
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

        public override PacketTag Tag => PacketTag.Trust;

        public override void Encode(Stream bcpgOut)
        {
            bcpgOut.Write(levelAndTrustAmount);
        }
    }
}
