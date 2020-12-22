using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class SymmetricEncDataPacket : StreamablePacket
    {
        public override PacketTag Tag => PacketTag.SymmetricKeyEncrypted;

        public override void EncodeHeader(Stream bcpgOut)
        {
        }
    }
}
