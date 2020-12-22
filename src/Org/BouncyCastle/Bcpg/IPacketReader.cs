using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public interface IPacketReader : IDisposable
    {
        PacketTag NextPacketTag();

        // TODO: ContainedPacket
        Packet ReadPacket();

        IPacketReader CreateNestedReader(Stream stream);
    }
}