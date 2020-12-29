using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    class SymmetricEncDataPacket : StreamablePacket
    {
        public override PacketTag Tag => PacketTag.SymmetricKeyEncrypted;

        public override void EncodeHeader(Stream bcpgOut)
        {
        }
    }
}
