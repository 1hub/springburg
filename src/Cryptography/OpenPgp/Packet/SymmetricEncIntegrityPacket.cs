using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    class SymmetricEncIntegrityPacket : StreamablePacket
    {
        private readonly byte version;

        internal SymmetricEncIntegrityPacket(Stream bcpgIn)
        {
            version = (byte)bcpgIn.ReadByte();
        }

        public SymmetricEncIntegrityPacket()
        {
            version = 1;
        }

        public override PacketTag Tag => PacketTag.SymmetricEncryptedIntegrityProtected;

        public override void EncodeHeader(Stream bcpgOut)
        {
            bcpgOut.WriteByte(version);
        }
    }
}
