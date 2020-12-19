using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class SymmetricEncIntegrityPacket : InputStreamPacket
    {
        private readonly int version;

        internal SymmetricEncIntegrityPacket(Stream bcpgIn)
            : base(bcpgIn)
        {
            version = bcpgIn.ReadByte();
        }

        public override PacketTag Tag => PacketTag.SymmetricEncryptedIntegrityProtected;
    }
}
