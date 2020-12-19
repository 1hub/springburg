using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class PublicSubkeyPacket : PublicKeyPacket
    {
        internal PublicSubkeyPacket(Stream bcpgIn)
            : base(bcpgIn)
        {
        }

        /// <summary>Construct a version 4 public subkey packet.</summary>
        public PublicSubkeyPacket(PublicKeyAlgorithmTag algorithm, DateTime time, BcpgKey key)
            : base(algorithm, time, key)
        {
        }

        public override PacketTag Tag => PacketTag.PublicSubkey;
    }
}
