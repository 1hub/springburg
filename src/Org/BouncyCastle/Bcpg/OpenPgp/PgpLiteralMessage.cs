using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
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

        public DateTime ModificationTime => literalDataPacket.ModificationTime;

        public string FileName => literalDataPacket.FileName;

        public Stream GetStream() => inputStream;
    }
}
