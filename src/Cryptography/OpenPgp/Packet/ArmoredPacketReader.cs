using System;
using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    public class ArmoredPacketReader : IPacketReader
    {
        private Stream stream;
        private ArmoredInputStream armoredInputStream;
        private PacketReader packetReader;
        private bool generatedOnePassPacket;

        public ArmoredPacketReader(Stream stream)
        {
            this.stream = stream;
            this.armoredInputStream = new ArmoredInputStream(stream);
            //this.packetReader = new PacketReader(armoredInputStream);
        }

        public IPacketReader CreateNestedReader(Stream stream)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            this.armoredInputStream.Dispose();
            this.stream.Dispose();
        }

        public PacketTag NextPacketTag()
        {
            if (this.armoredInputStream.IsClearText())
            {
                if (!generatedOnePassPacket)
                    return PacketTag.OnePassSignature;
                return PacketTag.LiteralData;
            }

            if (this.packetReader == null)
            {
                this.packetReader = new PacketReader(armoredInputStream);
            }

            return this.packetReader.NextPacketTag();
        }

        public ContainedPacket ReadContainedPacket()
        {
            if (this.armoredInputStream.IsClearText())
            {
                if (!generatedOnePassPacket)
                {
                    generatedOnePassPacket = true;
                    HashAlgorithmTag hashAlgorithmTag = HashAlgorithmTag.MD5;
                    foreach (var header in armoredInputStream.GetArmorHeaders())
                    {
                        if (header.StartsWith("Hash: ", StringComparison.OrdinalIgnoreCase))
                        {
                            // FIXME: Multiple hashes
                            hashAlgorithmTag = PgpUtilities.GetHashAlgorithm(header.Substring(6));
                        }
                    }
                    return new OnePassSignaturePacket(PgpSignature.CanonicalTextDocument, hashAlgorithmTag, 0, 0, false);
                }

                throw new NotSupportedException();
            }

            if (this.packetReader == null)
            {
                this.packetReader = new PacketReader(armoredInputStream);
            }

            return this.packetReader.ReadContainedPacket();
        }

        public (StreamablePacket Packet, Stream Stream) ReadStreamablePacket()
        {
            if (this.armoredInputStream.IsClearText())
            {
                if (!generatedOnePassPacket)
                    throw new NotSupportedException();

                var stream = new LiteralDataStream(armoredInputStream);
                return (new LiteralDataPacket(PgpLiteralData.Utf8, "", DateTime.MinValue), stream);
            }

            if (this.packetReader == null)
            {
                this.packetReader = new PacketReader(armoredInputStream);
            }

            return this.packetReader.ReadStreamablePacket();
        }

        class LiteralDataStream : Stream
        {
            private ArmoredInputStream armoredInputStream;

            public LiteralDataStream(ArmoredInputStream armoredInputStream)
            {
                this.armoredInputStream = armoredInputStream;
            }

            public override bool CanRead => true;

            public override bool CanSeek => false;

            public override bool CanWrite => false;

            public override long Length => throw new NotSupportedException();

            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

            public override void Flush()
            {
                throw new NotSupportedException();
            }

            public override int ReadByte()
            {
                if (armoredInputStream.IsClearText())
                    return armoredInputStream.ReadByte();
                return -1;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (armoredInputStream.IsClearText())
                    return armoredInputStream.Read(buffer, offset, count);
                return 0;
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotSupportedException();
            }

            public override void SetLength(long value)
            {
                throw new NotSupportedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }
        }
    }
}
