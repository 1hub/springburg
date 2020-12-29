using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    class CompressedDataPacket : StreamablePacket
    {
        private readonly PgpCompressionAlgorithm algorithm;

        internal CompressedDataPacket(Stream bcpgIn)
        {
            this.algorithm = (PgpCompressionAlgorithm)bcpgIn.ReadByte();
        }

        public CompressedDataPacket(PgpCompressionAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        public PgpCompressionAlgorithm Algorithm => algorithm;

        public override PacketTag Tag => PacketTag.CompressedData;

        public override void EncodeHeader(Stream bcpgOut)
        {
            bcpgOut.WriteByte((byte)algorithm);
        }
    }
}
