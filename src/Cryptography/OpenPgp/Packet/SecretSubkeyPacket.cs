using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    class SecretSubkeyPacket : SecretKeyPacket
    {
        public SecretSubkeyPacket(Stream bcpgIn)
            : base(bcpgIn)
        {
        }

        public SecretSubkeyPacket(PgpPublicKeyAlgorithm algorithm, DateTime creationTime, byte[] keyBytes)
            : base(algorithm, creationTime, keyBytes)
        {
        }

        public override PacketTag Tag => PacketTag.SecretSubkey;
    }
}
