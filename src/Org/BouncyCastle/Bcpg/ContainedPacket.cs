using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public abstract class ContainedPacket : Packet
    {
        protected static void WriteHeader(Stream stream, PacketTag tag, long bodyLen, bool useOldPacket = false)
        {
            int hdr = 0x80;

            if (useOldPacket)
            {
                hdr |= ((int)tag) << 2;

                if (bodyLen <= 0xff)
                {
                    stream.WriteByte((byte)hdr);
                    stream.WriteByte((byte)bodyLen);
                }
                else if (bodyLen <= 0xffff)
                {
                    stream.WriteByte((byte)(hdr | 0x01));
                    stream.WriteByte((byte)(bodyLen >> 8));
                    stream.WriteByte((byte)(bodyLen));
                }
                else
                {
                    stream.WriteByte((byte)(hdr | 0x02));
                    stream.WriteByte((byte)(bodyLen >> 24));
                    stream.WriteByte((byte)(bodyLen >> 16));
                    stream.WriteByte((byte)(bodyLen >> 8));
                    stream.WriteByte((byte)bodyLen);
                }
            }
            else
            {
                hdr |= 0x40 | (int)tag;
                stream.WriteByte((byte)hdr);

                if (bodyLen < 192)
                {
                    stream.WriteByte((byte)bodyLen);
                }
                else if (bodyLen <= 8383)
                {
                    bodyLen -= 192;
                    stream.WriteByte((byte)(((bodyLen >> 8) & 0xff) + 192));
                    stream.WriteByte((byte)bodyLen);
                }
                else
                {
                    stream.WriteByte(0xff);
                    stream.WriteByte((byte)(bodyLen >> 24));
                    stream.WriteByte((byte)(bodyLen >> 16));
                    stream.WriteByte((byte)(bodyLen >> 8));
                    stream.WriteByte((byte)bodyLen);
                }
            }
        }

        protected static void WritePacket(Stream stream, PacketTag tag, byte[] body, bool useOldPacket = false)
        {
            WriteHeader(stream, tag, body.Length, useOldPacket);
            stream.Write(body);
        }

        public abstract void Encode(Stream bcpgOut);
    }
}
