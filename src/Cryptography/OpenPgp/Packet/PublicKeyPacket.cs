using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    class PublicKeyPacket : KeyPacket
    {
        public PublicKeyPacket(Stream bcpgIn)
            : base(bcpgIn)
        {
        }

        public PublicKeyPacket(PgpPublicKeyAlgorithm algorithm, DateTime creationTime, byte[] keyBytes)
            : base(algorithm, creationTime, keyBytes)
        {
        }

        public PublicKeyPacket(SecretKeyPacket secretKeyPacket)
            : base(secretKeyPacket)
        {
        }

        public override PacketTag Tag => PacketTag.PublicKey;
    }
}
