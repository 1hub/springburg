using System.Diagnostics;
using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    public class PacketReader : IPacketReader
    {
        private Stream inputStream;
        private bool next;
        private int nextB;

        public PacketReader(Stream inputStream)
        {
            this.inputStream = inputStream;
        }

        public void Dispose()
        {
            this.inputStream.Close();
        }

        public IPacketReader CreateNestedReader(Stream stream)
        {
            return new PacketReader(stream);
        }

        /// <summary>Returns the next packet tag in the stream.</summary>
        public PacketTag NextPacketTag()
        {
            if (!next)
            {
                try
                {
                    nextB = inputStream.ReadByte();
                }
                catch (EndOfStreamException)
                {
                    nextB = -1;
                }

                next = true;
            }

            if (nextB < 0)
                return PacketTag.EndOfFile;

            int maskB = nextB & 0x3f;
            if ((nextB & 0x40) == 0)    // old
            {
                maskB >>= 2;
            }

            return (PacketTag)maskB;
        }

        private (Packet Packet, Stream? Stream) ReadPacket()
        {
            int hdr = next ? nextB : inputStream.ReadByte();

            next = false;

            if (hdr < 0)
                throw new EndOfStreamException();

            if ((hdr & 0x80) == 0)
            {
                throw new IOException("invalid header encountered");
            }

            bool newPacket = (hdr & 0x40) != 0;
            PacketTag tag = 0;
            int bodyLen = 0;
            bool partial = false;

            if (newPacket)
            {
                tag = (PacketTag)(hdr & 0x3f);

                int l = inputStream.ReadByte();

                if (l < 192)
                {
                    bodyLen = l;
                }
                else if (l <= 223)
                {
                    int b = inputStream.ReadByte();
                    bodyLen = ((l - 192) << 8) + (b) + 192;
                }
                else if (l == 255)
                {
                    bodyLen =
                        (inputStream.ReadByte() << 24) |
                        (inputStream.ReadByte() << 16) |
                        (inputStream.ReadByte() << 8) |
                        inputStream.ReadByte();
                }
                else
                {
                    partial = true;
                    bodyLen = 1 << (l & 0x1f);
                }
            }
            else
            {
                int lengthType = hdr & 0x3;

                tag = (PacketTag)((hdr & 0x3f) >> 2);

                switch (lengthType)
                {
                    case 0:
                        bodyLen = inputStream.ReadByte();
                        break;
                    case 1:
                        bodyLen = (inputStream.ReadByte() << 8) | inputStream.ReadByte();
                        break;
                    case 2:
                        bodyLen =
                            (inputStream.ReadByte() << 24) |
                            (inputStream.ReadByte() << 16) |
                            (inputStream.ReadByte() << 8) |
                            inputStream.ReadByte();
                        break;
                    case 3:
                        partial = true;
                        break;
                    default:
                        throw new IOException("unknown length type encountered");
                }
            }

            Stream objStream;
            if (bodyLen == 0 && partial)
            {
                objStream = inputStream;
            }
            else
            {
                objStream = new PartialInputStream(inputStream, partial, bodyLen);
            }

            switch (tag)
            {
                case PacketTag.Reserved:
                    return (new ReservedPacket(), objStream);
                case PacketTag.PublicKeyEncryptedSession:
                    return (new PublicKeyEncSessionPacket(objStream), null);
                case PacketTag.Signature:
                    return (new SignaturePacket(objStream), null);
                case PacketTag.SymmetricKeyEncryptedSessionKey:
                    return (new SymmetricKeyEncSessionPacket(objStream), null);
                case PacketTag.OnePassSignature:
                    return (new OnePassSignaturePacket(objStream), null);
                case PacketTag.SecretKey:
                    return (new SecretKeyPacket(objStream), null);
                case PacketTag.PublicKey:
                    return (new PublicKeyPacket(objStream), null);
                case PacketTag.SecretSubkey:
                    return (new SecretSubkeyPacket(objStream), null);
                case PacketTag.CompressedData:
                    return (new CompressedDataPacket(objStream), objStream);
                case PacketTag.SymmetricKeyEncrypted:
                    return (new SymmetricEncDataPacket(), objStream);
                case PacketTag.Marker:
                    return (new MarkerPacket(objStream), null);
                case PacketTag.LiteralData:
                    return (new LiteralDataPacket(objStream), objStream);
                case PacketTag.Trust:
                    return (new TrustPacket(objStream), null);
                case PacketTag.UserId:
                    return (new UserIdPacket(objStream), null);
                case PacketTag.UserAttribute:
                    return (new UserAttributePacket(objStream), null);
                case PacketTag.PublicSubkey:
                    return (new PublicSubkeyPacket(objStream), null);
                case PacketTag.SymmetricEncryptedIntegrityProtected:
                    return (new SymmetricEncIntegrityPacket(objStream), objStream);
                case PacketTag.ModificationDetectionCode:
                    return (new ModDetectionCodePacket(objStream), null);
                case PacketTag.Experimental1:
                case PacketTag.Experimental2:
                case PacketTag.Experimental3:
                case PacketTag.Experimental4:
                    return (new ExperimentalPacket(tag, objStream), null);
                default:
                    throw new IOException("unknown packet type encountered: " + tag);
            }
        }

        public ContainedPacket ReadContainedPacket()
        {
            var packet = ReadPacket();
            Debug.Assert(packet.Packet is ContainedPacket);
            return (ContainedPacket)packet.Packet;
        }

        public (StreamablePacket Packet, Stream Stream) ReadStreamablePacket()
        {
            var packet = ReadPacket();
            Debug.Assert(packet.Packet is StreamablePacket);
            Debug.Assert(packet.Stream is Stream);
            return ((StreamablePacket)packet.Packet, packet.Stream);
        }

        /// <summary>
        /// A stream that overlays our input stream, allowing the user to only read a segment of it.
        /// NB: dataLength will be negative if the segment length is in the upper range above 2**31.
        /// </summary>
        private class PartialInputStream : Stream
        {
            private Stream inputStream;
            private bool partial;
            private int dataLength;

            public override bool CanRead => true;

            public override bool CanSeek => false;

            public override bool CanWrite => false;

            public override long Length => throw new System.NotSupportedException();

            public override long Position { get => throw new System.NotSupportedException(); set => throw new System.NotSupportedException(); }

            public PartialInputStream(
                Stream inputStream,
                bool partial,
                int dataLength)
            {
                this.inputStream = inputStream;
                this.partial = partial;
                this.dataLength = dataLength;
            }

            public override int ReadByte()
            {
                do
                {
                    if (dataLength != 0)
                    {
                        int ch = inputStream.ReadByte();
                        if (ch < 0)
                        {
                            throw new EndOfStreamException("Premature end of stream in PartialInputStream");
                        }
                        dataLength--;
                        return ch;
                    }
                }
                while (partial && ReadPartialDataLength() >= 0);

                return -1;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                do
                {
                    if (dataLength != 0)
                    {
                        int readLen = (dataLength > count || dataLength < 0) ? count : dataLength;
                        int len = inputStream.Read(buffer, offset, readLen);
                        if (len < 1)
                        {
                            throw new EndOfStreamException("Premature end of stream in PartialInputStream");
                        }
                        dataLength -= len;
                        return len;
                    }
                }
                while (partial && ReadPartialDataLength() >= 0);

                return 0;
            }

            private int ReadPartialDataLength()
            {
                int l = inputStream.ReadByte();

                if (l < 0)
                {
                    return -1;
                }

                partial = false;

                if (l < 192)
                {
                    dataLength = l;
                }
                else if (l <= 223)
                {
                    dataLength = ((l - 192) << 8) + (inputStream.ReadByte()) + 192;
                }
                else if (l == 255)
                {
                    dataLength = (inputStream.ReadByte() << 24) | (inputStream.ReadByte() << 16)
                        | (inputStream.ReadByte() << 8) | inputStream.ReadByte();
                }
                else
                {
                    partial = true;
                    dataLength = 1 << (l & 0x1f);
                }

                return 0;
            }

            public override void Flush()
            {
                throw new System.NotSupportedException();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new System.NotSupportedException();
            }

            public override void SetLength(long value)
            {
                throw new System.NotSupportedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new System.NotSupportedException();
            }
        }
    }
}
