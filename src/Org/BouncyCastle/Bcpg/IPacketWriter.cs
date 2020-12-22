using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public interface IPacketWriter : IDisposable
    {
        void WritePacket(ContainedPacket packet);

        Stream GetPacketStream(StreamablePacket packet);

        IPacketWriter CreateNestedWriter(Stream stream);
    }
}
