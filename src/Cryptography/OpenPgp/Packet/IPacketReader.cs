using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    public interface IPacketReader : IDisposable
    {
        PacketTag NextPacketTag();

        ContainedPacket ReadContainedPacket();

        (StreamablePacket Packet, Stream Stream) ReadStreamablePacket();

        IPacketReader CreateNestedReader(Stream stream);
    }
}