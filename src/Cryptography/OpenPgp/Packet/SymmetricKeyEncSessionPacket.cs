using InflatablePalace.IO;
using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    class SymmetricKeyEncSessionPacket : ContainedPacket
    {
        private int version;
        private SymmetricKeyAlgorithmTag encAlgorithm;
        private S2k s2k;
        private readonly byte[] secKeyData;

        internal SymmetricKeyEncSessionPacket(Stream bcpgIn)
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

        public override PacketTag Tag => PacketTag.SymmetricKeyEncryptedSessionKey;

        public override void Encode(Stream bcpgOut)
        {
            bcpgOut.WriteByte((byte)version);
            bcpgOut.WriteByte((byte)encAlgorithm);

            s2k.Encode(bcpgOut);

            if (secKeyData != null && secKeyData.Length > 0)
            {
                bcpgOut.Write(secKeyData);
            }
        }
    }
}
