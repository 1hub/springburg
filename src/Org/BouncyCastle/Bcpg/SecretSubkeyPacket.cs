using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class SecretSubkeyPacket : SecretKeyPacket
    {
        internal SecretSubkeyPacket(Stream bcpgIn)
            : base(bcpgIn)
        {
        }

        public SecretSubkeyPacket(
            PublicKeyPacket pubKeyPacket,
            SymmetricKeyAlgorithmTag encAlgorithm,
            S2k s2k,
            byte[] iv,
            byte[] secKeyData)
            : base(pubKeyPacket, encAlgorithm, s2k, iv, secKeyData)
        {
        }

        public SecretSubkeyPacket(
            PublicKeyPacket pubKeyPacket,
            SymmetricKeyAlgorithmTag encAlgorithm,
            int s2kUsage,
            S2k s2k,
            byte[] iv,
            byte[] secKeyData)
            : base(pubKeyPacket, encAlgorithm, s2kUsage, s2k, iv, secKeyData)
        {
        }

        public override void Encode(Stream bcpgOut)
        {
            WritePacket(bcpgOut, PacketTag.SecretSubkey, GetEncodedContents(), useOldPacket: true);
        }
    }
}
