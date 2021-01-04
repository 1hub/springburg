using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    class PublicSubkeyPacket : PublicKeyPacket
    {
        public PublicSubkeyPacket(Stream bcpgIn)
            : base(bcpgIn)
        {
        }

        public PublicSubkeyPacket(PgpPublicKeyAlgorithm algorithm, DateTime creationTime, byte[] keyBytes)
            : base(algorithm, creationTime, keyBytes)
        {
        }

        public PublicSubkeyPacket(SecretSubkeyPacket secretSubkeyPacket)
            : base(secretSubkeyPacket)
        {
        }

        public override PacketTag Tag => PacketTag.PublicSubkey;
    }
}
