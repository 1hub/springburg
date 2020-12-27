using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    class CompressedDataPacket : StreamablePacket
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

        public CompressionAlgorithmTag Algorithm => algorithm;

        public override PacketTag Tag => PacketTag.CompressedData;

        public override void EncodeHeader(Stream bcpgOut)
        {
            bcpgOut.WriteByte((byte)algorithm);
        }
    }
}
