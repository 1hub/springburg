using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class SymmetricKeyEncSessionPacket : ContainedPacket
    {
        private int version;
        private SymmetricKeyAlgorithmTag encAlgorithm;
        private S2k s2k;
        private readonly byte[] secKeyData;

        public SymmetricKeyEncSessionPacket(BcpgInputStream bcpgIn)
        {
            version = bcpgIn.ReadByte();
            encAlgorithm = (SymmetricKeyAlgorithmTag)bcpgIn.ReadByte();

            s2k = new S2k(bcpgIn);

            secKeyData = bcpgIn.ReadAll();
        }

        public SymmetricKeyEncSessionPacket(SymmetricKeyAlgorithmTag encAlgorithm, S2k s2k, byte[] secKeyData)
        {
            this.version = 4;
            this.encAlgorithm = encAlgorithm;
            this.s2k = s2k;
            this.secKeyData = secKeyData;
        }

        public SymmetricKeyAlgorithmTag EncAlgorithm => encAlgorithm;

        public S2k S2k => s2k;

        public byte[] SecKeyData => secKeyData;

        public int Version => version;

        public override void Encode(Stream bcpgOut)
        {
            using MemoryStream bOut = new MemoryStream();

            bOut.WriteByte((byte)version);
            bOut.WriteByte((byte)encAlgorithm);

            s2k.Encode(bOut);

            if (secKeyData != null && secKeyData.Length > 0)
            {
                bOut.Write(secKeyData);
            }

            WritePacket(bcpgOut, PacketTag.SymmetricKeyEncryptedSessionKey, bOut.ToArray(), useOldPacket: true);
        }
    }
}
