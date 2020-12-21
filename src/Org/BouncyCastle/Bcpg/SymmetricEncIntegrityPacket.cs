using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class SymmetricEncIntegrityPacket : InputStreamPacket
    {
        private readonly byte version;

        internal SymmetricEncIntegrityPacket(Stream bcpgIn)
            : base(bcpgIn)
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
