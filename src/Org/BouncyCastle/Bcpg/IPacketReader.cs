using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public interface IPacketReader : IDisposable
    {
        PacketTag NextPacketTag();

        ContainedPacket ReadContainedPacket();

        (StreamablePacket Packet, Stream Stream) ReadStreamablePacket();

        IPacketReader CreateNestedReader(Stream stream);
    }
}