using InflatablePalace.IO;
using System.IO;
using System.Text;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    class UserIdPacket : ContainedPacket
    {
        private readonly byte[] idData;

        internal UserIdPacket(Stream bcpgIn)
        {
            this.idData = bcpgIn.ReadAll();
        }

        public UserIdPacket(string id)
        {
            this.idData = Encoding.UTF8.GetBytes(id);
        }

        public string GetId()
        {
            return Encoding.UTF8.GetString(idData, 0, idData.Length);
        }

        public override PacketTag Tag => PacketTag.UserId;

        public override void Encode(Stream bcpgOut)
        {
            bcpgOut.Write(idData);
        }
    }
}
