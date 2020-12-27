using InflatablePalace.Cryptography.OpenPgp.Packet.Attr;
using InflatablePalace.IO;
using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    class UserAttributeSubpacketsParser
    {
        private readonly Stream input;

        public UserAttributeSubpacketsParser(
            Stream input)
        {
            this.input = input;
        }

        public virtual UserAttributeSubpacket ReadPacket()
        {
            int l = input.ReadByte();
            if (l < 0)
                return null;

            int bodyLen = 0;
            bool longLength = false;
            if (l < 192)
            {
                bodyLen = l;
            }
            else if (l <= 223)
            {
                bodyLen = ((l - 192) << 8) + (input.ReadByte()) + 192;
            }
            else if (l == 255)
            {
                bodyLen = (input.ReadByte() << 24) | (input.ReadByte() << 16)
                    | (input.ReadByte() << 8) | input.ReadByte();
                longLength = true;
            }
            else
            {
                throw new IOException("unrecognised length reading user attribute sub packet");
            }

            int tag = input.ReadByte();
            if (tag < 0)
                throw new EndOfStreamException("unexpected EOF reading user attribute sub packet");

            byte[] data = new byte[bodyLen - 1];
            if (input.ReadFully(data) < data.Length)
                throw new EndOfStreamException();

            UserAttributeSubpacketTag type = (UserAttributeSubpacketTag)tag;
            switch (type)
            {
                case UserAttributeSubpacketTag.ImageAttribute:
                    return new ImageAttrib(longLength, data);
            }
            return new UserAttributeSubpacket(type, longLength, data);
        }
    }
}
