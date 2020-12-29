using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    class PublicSubkeyPacket : PublicKeyPacket
    {
        internal PublicSubkeyPacket(Stream bcpgIn)
            : base(bcpgIn)
        {
        }

        /// <summary>Construct a version 4 public subkey packet.</summary>
        public PublicSubkeyPacket(PgpPublicKeyAlgorithm algorithm, DateTime time, BcpgKey key)
            : base(algorithm, time, key)
        {
        }

        public override PacketTag Tag => PacketTag.PublicSubkey;
    }
}
