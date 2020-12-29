using Springburg.Cryptography.OpenPgp.Packet;
using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp
{
    public abstract class PgpMessage
    {
        public static PgpMessage ReadMessage(byte[] data, bool automaticallyDecompress = true)
        {
            return ReadMessage(new PacketReader(new MemoryStream(data, false)), automaticallyDecompress);
        }

        public static PgpMessage ReadMessage(Stream stream, bool automaticallyDecompress = true)
        {
            return ReadMessage(new PacketReader(stream), automaticallyDecompress);
        }

        public static PgpMessage ReadMessage(IPacketReader packetReader, bool automaticallyDecompress = true)
        {
            // Skip over marker packets
            while (IsSkippablePacket(packetReader.NextPacketTag()))
            {
                packetReader.ReadContainedPacket();
            }

            switch (packetReader.NextPacketTag())
            {
                case PacketTag.Signature:
                case PacketTag.OnePassSignature:
                    return new PgpSignedMessage(packetReader);

                case PacketTag.CompressedData:
                    var compressedMessage = new PgpCompressedMessage(packetReader);
                    if (automaticallyDecompress)
                        return compressedMessage.ReadMessage();
                    return compressedMessage;

                case PacketTag.LiteralData:
                    return new PgpLiteralMessage(packetReader);

                case PacketTag.PublicKeyEncryptedSession:
                case PacketTag.SymmetricKeyEncryptedSessionKey:
                    return new PgpEncryptedMessage(packetReader);

                default:
                    throw new PgpUnexpectedPacketException();
            }
        }

        private static bool IsSkippablePacket(PacketTag packetTag)
        {
            return packetTag == PacketTag.Marker;
        }
    }
}
