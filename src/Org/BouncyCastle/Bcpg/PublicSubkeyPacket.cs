using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class PublicSubkeyPacket : PublicKeyPacket
    {
        internal PublicSubkeyPacket(BcpgInputStream bcpgIn)
            : base(bcpgIn)
        {
        }

        /// <summary>Construct a version 4 public subkey packet.</summary>
        public PublicSubkeyPacket(PublicKeyAlgorithmTag algorithm, DateTime time, IBcpgKey key)
            : base(algorithm, time, key)
        {
        }

        public override void Encode(Stream bcpgOut)
        {
            WritePacket(bcpgOut, PacketTag.PublicSubkey, GetEncodedContents(), useOldPacket: true);
        }
    }
}
