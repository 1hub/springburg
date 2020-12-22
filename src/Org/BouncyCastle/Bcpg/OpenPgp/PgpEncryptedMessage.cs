using System;
using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpEncryptedMessage : PgpMessage
    {
        List<PgpEncryptedData> encryptedData;
        InputStreamPacket encryptedPacket;
        IPacketReader packetReader;

        internal PgpEncryptedMessage(IPacketReader packetReader)
        {
            this.packetReader = packetReader;
            this.encryptedData = new List<PgpEncryptedData>();

            var packets = new List<Packet>();
            while (packetReader.NextPacketTag() == PacketTag.PublicKeyEncryptedSession ||
                   packetReader.NextPacketTag() == PacketTag.SymmetricKeyEncryptedSessionKey)
            {
                var keyPacket = packetReader.ReadPacket();
                packets.Add(keyPacket);
            }

            Packet packet = packetReader.ReadPacket();
            if (!(packet is InputStreamPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            this.encryptedPacket = (InputStreamPacket)packet;
            foreach (var keyPacket in packets)
            {
                if (keyPacket is SymmetricKeyEncSessionPacket symmetricKeyEncSessionPacket)
                {
                    encryptedData.Add(new PgpPbeEncryptedData(symmetricKeyEncSessionPacket, encryptedPacket));
                }
                else
                {
                    encryptedData.Add(new PgpPublicKeyEncryptedData((PublicKeyEncSessionPacket)keyPacket, encryptedPacket));
                }
            }
        }

        public IList<PgpEncryptedData> Methods => encryptedData.AsReadOnly();

        public PgpMessage DecryptMessage(PgpPrivateKey privateKey)
        {
            foreach (var e in encryptedData)
            {
                if (e is PgpPublicKeyEncryptedData publicKeyEncryptedData)
                {
                    if (publicKeyEncryptedData.KeyId == privateKey.KeyId)
                    {
                        return ReadMessage(packetReader.CreateNestedReader(publicKeyEncryptedData.GetDataStream(privateKey)));
                    }
                }
            }

            throw new NotImplementedException();
        }

        public PgpMessage DecryptMessage(char[] password)
        {
            foreach (var e in encryptedData)
            {
                if (e is PgpPbeEncryptedData pbeEncryptedData)
                {
                    return ReadMessage(packetReader.CreateNestedReader(pbeEncryptedData.GetDataStream(password)));
                }
            }

            throw new NotImplementedException();
        }
    }
}
