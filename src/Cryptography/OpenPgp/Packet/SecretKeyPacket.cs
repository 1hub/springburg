using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    class SecretKeyPacket : KeyPacket
    {
        public SecretKeyPacket(Stream bcpgIn)
            : base(bcpgIn)
        {
        }

        public SecretKeyPacket(PgpPublicKeyAlgorithm algorithm, DateTime creationTime, byte[] keyBytes)
            : base(algorithm, creationTime, keyBytes)
        {
        }

        public override PacketTag Tag => PacketTag.SecretKey;
    }
}
