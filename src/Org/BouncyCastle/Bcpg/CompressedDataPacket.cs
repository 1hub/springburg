using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class CompressedDataPacket : StreamablePacket
    {
        private readonly CompressionAlgorithmTag algorithm;

        internal CompressedDataPacket(Stream bcpgIn)
        {
            this.algorithm = (CompressionAlgorithmTag)bcpgIn.ReadByte();
        }

        public CompressedDataPacket(CompressionAlgorithmTag algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <summary>The algorithm tag value.</summary>
        public CompressionAlgorithmTag Algorithm
        {
            get { return algorithm; }
        }

        public override PacketTag Tag => PacketTag.CompressedData;

        public override void EncodeHeader(Stream bcpgOut)
        {
            bcpgOut.WriteByte((byte)algorithm);
        }
    }
}
