using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class SymmetricEncDataPacket : InputStreamPacket
    {
        internal SymmetricEncDataPacket(Stream bcpgIn)
            : base(bcpgIn)
        {
        }

        public SymmetricEncDataPacket()
        {
        }

        public override PacketTag Tag => PacketTag.SymmetricKeyEncrypted;
    }
}
