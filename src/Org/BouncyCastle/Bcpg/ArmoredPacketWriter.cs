using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class ArmoredPacketWriter : IPacketWriter, IStreamGenerator
    {
        private Stream stream;
        private PacketWriter writer;
        private ArmoredOutputStream armoredOutputStream;
        private bool useClearText;
        private bool inClearText;

        public ArmoredPacketWriter(Stream stream, bool useClearText = true)
        {
            this.stream = stream;
            this.armoredOutputStream = new ArmoredOutputStream(stream);
            this.writer = new PacketWriter(armoredOutputStream);
            this.useClearText = useClearText;
        }

        public IPacketWriter CreateNestedWriter(Stream stream)
        {
            useClearText = false;
            return new PacketWriter(stream);
        }

        public void Dispose()
        {
            this.armoredOutputStream.Dispose();
            this.stream.Dispose();
        }

        public Stream GetPacketStream(InputStreamPacket packet)
        {
            if (inClearText)
            {
                if (packet is LiteralDataPacket literalDataPacket)
                {
                    return new WrappedGeneratorStream(this, this.armoredOutputStream);
                }
                else
                {
                    throw new NotSupportedException();
                }
            }

            useClearText = false;
            return this.writer.GetPacketStream(packet);
        }

        void IStreamGenerator.Close()
        {
            armoredOutputStream.WriteByte((byte)'\r');
            armoredOutputStream.WriteByte((byte)'\n');
            armoredOutputStream.EndClearText();
            inClearText = false;
        }

        public void WritePacket(ContainedPacket packet)
        {
            if (packet is OnePassSignaturePacket onePassSignaturePacket && useClearText)
            {
                this.armoredOutputStream.BeginClearText(onePassSignaturePacket.HashAlgorithm);
                inClearText = true;
            }
            else if (inClearText)
            {
                throw new NotSupportedException();
            }
            else
            {
                useClearText = false;
                this.writer.WritePacket(packet);
            }
        }
    }
}
