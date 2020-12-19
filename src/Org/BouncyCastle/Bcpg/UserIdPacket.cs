using System.IO;
using System.Text;

namespace Org.BouncyCastle.Bcpg
{
    public class UserIdPacket : ContainedPacket
    {
        private readonly byte[] idData;

        public UserIdPacket(BcpgInputStream bcpgIn)
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

        public override void Encode(Stream bcpgOut)
        {
            WritePacket(bcpgOut, PacketTag.UserId, idData, useOldPacket: true);
        }
    }
}
