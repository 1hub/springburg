using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    class UserAttributePacket : ContainedPacket
    {
        private readonly UserAttributeSubpacket[] subpackets;

        public UserAttributePacket(Stream bcpgIn)
        {
            UserAttributeSubpacketParser sIn = new UserAttributeSubpacketParser(bcpgIn);
            UserAttributeSubpacket? sub;

            IList<UserAttributeSubpacket> v = new List<UserAttributeSubpacket>();
            while ((sub = sIn.ReadPacket()) != null)
            {
                v.Add(sub);
            }

            subpackets = v.ToArray();
        }

        public UserAttributePacket(
            UserAttributeSubpacket[] subpackets)
        {
            this.subpackets = subpackets;
        }

        public UserAttributeSubpacket[] GetSubpackets() => subpackets;

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
