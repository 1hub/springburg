using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    class SecretSubkeyPacket : SecretKeyPacket
    {
        internal SecretSubkeyPacket(Stream bcpgIn)
            : base(bcpgIn)
        {
        }

        public SecretSubkeyPacket(
            PublicKeyPacket pubKeyPacket,
            PgpSymmetricKeyAlgorithm encAlgorithm,
            S2k? s2k,
            byte[]? iv,
            byte[]? secKeyData)
            : base(pubKeyPacket, encAlgorithm, s2k, iv, secKeyData)
        {
        }

        public SecretSubkeyPacket(
            PublicKeyPacket pubKeyPacket,
            PgpSymmetricKeyAlgorithm encAlgorithm,
            S2kUsageTag s2kUsage,
            S2k? s2k,
            byte[]? iv,
            byte[]? secKeyData)
            : base(pubKeyPacket, encAlgorithm, s2kUsage, s2k, iv, secKeyData)
        {
        }

        public override PacketTag Tag => PacketTag.SecretSubkey;
    }
}
