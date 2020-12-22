using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpLiteralMessage : PgpMessage
    {
        private LiteralDataPacket literalDataPacket;

        internal PgpLiteralMessage(IPacketReader packetReader)
        {
            this.literalDataPacket = (LiteralDataPacket)packetReader.ReadPacket();
        }

        public DateTime ModificationTime => literalDataPacket.ModificationTime;

        public string FileName => literalDataPacket.FileName;

        public Stream GetStream()
        {
            return this.literalDataPacket.GetInputStream();
        }
    }
}
