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

        public override PacketTag Tag => PacketTag.SymmetricKeyEncrypted;
    }
}
