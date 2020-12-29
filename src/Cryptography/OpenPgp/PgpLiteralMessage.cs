using Springburg.Cryptography.OpenPgp.Packet;
using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp
{
    public class PgpLiteralMessage : PgpMessage
    {
        private LiteralDataPacket literalDataPacket;
        private Stream inputStream;

        internal PgpLiteralMessage(IPacketReader packetReader)
        {
            var packet = packetReader.ReadStreamablePacket();
            this.literalDataPacket = (LiteralDataPacket)packet.Packet;
            this.inputStream = packet.Stream;
        }

        public PgpDataFormat Format => literalDataPacket.Format;

        public DateTime ModificationTime => literalDataPacket.ModificationTime;

        public string FileName => literalDataPacket.FileName;

        public Stream GetStream() => inputStream;
    }
}
