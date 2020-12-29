using Springburg.Cryptography.OpenPgp.Packet;
using System;
using System.IO;

namespace Springburg.Cryptography.OpenPgp
{
    public abstract class PgpMessage
    {
        public static PgpMessage ReadMessage(byte[] data)
        {
            return ReadMessage(new PacketReader(new MemoryStream(data, false)));
        }

        public static PgpMessage ReadMessage(Stream stream)
        {
            return ReadMessage(new PacketReader(stream));
        }

        public static PgpMessage ReadMessage(IPacketReader packetReader)
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
                    return new PgpCompressedMessage(packetReader);

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
