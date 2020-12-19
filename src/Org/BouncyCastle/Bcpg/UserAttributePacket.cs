using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class UserAttributePacket : ContainedPacket
    {
        private readonly UserAttributeSubpacket[] subpackets;

        public UserAttributePacket(Stream bcpgIn)
        {
            UserAttributeSubpacketsParser sIn = new UserAttributeSubpacketsParser(bcpgIn);
            UserAttributeSubpacket sub;

            IList<UserAttributeSubpacket> v = new List<UserAttributeSubpacket>();
            while ((sub = sIn.ReadPacket()) != null)
            {
                v.Add(sub);
            }

            subpackets = new UserAttributeSubpacket[v.Count];

            for (int i = 0; i != subpackets.Length; i++)
            {
                subpackets[i] = (UserAttributeSubpacket)v[i];
            }
        }

        public UserAttributePacket(
            UserAttributeSubpacket[] subpackets)
        {
            this.subpackets = subpackets;
        }

        public UserAttributeSubpacket[] GetSubpackets()
        {
            return subpackets;
        }

        public override PacketTag Tag => PacketTag.UserAttribute;

        public override void Encode(Stream bcpgOut)
        {
            for (int i = 0; i != subpackets.Length; i++)
            {
                subpackets[i].Encode(bcpgOut);
            }
        }
    }
}
