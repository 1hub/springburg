using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp.Packet
{
    public interface IPacketWriter : IDisposable
    {
        void WritePacket(ContainedPacket packet);

        Stream GetPacketStream(StreamablePacket packet);

        IPacketWriter CreateNestedWriter(Stream stream);
    }
}
