using Org.BouncyCastle.Utilities.IO;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class PacketReader
    {
        private Stream inputStream;
        private bool next = false;
        private int nextB;

        public PacketReader(Stream inputStream)
        {
            this.inputStream = inputStream;
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
                return (PacketTag)nextB;

            int maskB = nextB & 0x3f;
            if ((nextB & 0x40) == 0)    // old
            {
                maskB >>= 2;
            }

            return (PacketTag)maskB;
        }

        public Packet ReadPacket()
        {
            int hdr = next ? nextB : inputStream.ReadByte();

            next = false;

            if (hdr < 0)
            {
                return null;
            }

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
                    return new InputStreamPacket(objStream);
                case PacketTag.PublicKeyEncryptedSession:
                    return new PublicKeyEncSessionPacket(objStream);
                case PacketTag.Signature:
                    return new SignaturePacket(objStream);
                case PacketTag.SymmetricKeyEncryptedSessionKey:
                    return new SymmetricKeyEncSessionPacket(objStream);
                case PacketTag.OnePassSignature:
                    return new OnePassSignaturePacket(objStream);
                case PacketTag.SecretKey:
                    return new SecretKeyPacket(objStream);
                case PacketTag.PublicKey:
                    return new PublicKeyPacket(objStream);
                case PacketTag.SecretSubkey:
                    return new SecretSubkeyPacket(objStream);
                case PacketTag.CompressedData:
                    return new CompressedDataPacket(objStream);
                case PacketTag.SymmetricKeyEncrypted:
                    return new SymmetricEncDataPacket(objStream);
                case PacketTag.Marker:
                    return new MarkerPacket(objStream);
                case PacketTag.LiteralData:
                    return new LiteralDataPacket(objStream);
                case PacketTag.Trust:
                    return new TrustPacket(objStream);
                case PacketTag.UserId:
                    return new UserIdPacket(objStream);
                case PacketTag.UserAttribute:
                    return new UserAttributePacket(objStream);
                case PacketTag.PublicSubkey:
                    return new PublicSubkeyPacket(objStream);
                case PacketTag.SymmetricEncryptedIntegrityProtected:
                    return new SymmetricEncIntegrityPacket(objStream);
                case PacketTag.ModificationDetectionCode:
                    return new ModDetectionCodePacket(objStream);
                case PacketTag.Experimental1:
                case PacketTag.Experimental2:
                case PacketTag.Experimental3:
                case PacketTag.Experimental4:
                    return new ExperimentalPacket(tag, objStream);
                default:
                    throw new IOException("unknown packet type encountered: " + tag);
            }
        }

        /// <summary>
        /// A stream that overlays our input stream, allowing the user to only read a segment of it.
        /// NB: dataLength will be negative if the segment length is in the upper range above 2**31.
        /// </summary>
        private class PartialInputStream : BaseInputStream
        {
            private Stream m_in;
            private bool partial;
            private int dataLength;

            internal PartialInputStream(
                Stream bcpgIn,
                bool partial,
                int dataLength)
            {
                this.m_in = bcpgIn;
                this.partial = partial;
                this.dataLength = dataLength;
            }

            public override int ReadByte()
            {
                do
                {
                    if (dataLength != 0)
                    {
                        int ch = m_in.ReadByte();
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
                        int len = m_in.Read(buffer, offset, readLen);
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
                int l = m_in.ReadByte();

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
                    dataLength = ((l - 192) << 8) + (m_in.ReadByte()) + 192;
                }
                else if (l == 255)
                {
                    dataLength = (m_in.ReadByte() << 24) | (m_in.ReadByte() << 16)
                        | (m_in.ReadByte() << 8) | m_in.ReadByte();
                }
                else
                {
                    partial = true;
                    dataLength = 1 << (l & 0x1f);
                }

                return 0;
            }
        }
    }
}
