using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class CompressedDataPacket : InputStreamPacket
    {
        private readonly CompressionAlgorithmTag algorithm;

        internal CompressedDataPacket(Stream bcpgIn)
            : base(bcpgIn)
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
