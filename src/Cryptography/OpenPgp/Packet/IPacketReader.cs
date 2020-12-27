using System;
using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    public interface IPacketReader : IDisposable
    {
        PacketTag NextPacketTag();

        ContainedPacket ReadContainedPacket();

        (StreamablePacket Packet, Stream Stream) ReadStreamablePacket();

        IPacketReader CreateNestedReader(Stream stream);
    }
}