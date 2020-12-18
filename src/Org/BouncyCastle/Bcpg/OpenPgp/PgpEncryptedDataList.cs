using System;
using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>A holder for a list of PGP encryption method packets.</summary>
    public class PgpEncryptedDataList : PgpObject
    {
        private readonly IList<PgpEncryptedData> list = new List<PgpEncryptedData>();
        private readonly InputStreamPacket data;

        internal PgpEncryptedDataList(BcpgInputStream bcpgInput)
        {
            var packets = new List<Packet>();

            while (bcpgInput.NextPacketTag() == PacketTag.PublicKeyEncryptedSession
                || bcpgInput.NextPacketTag() == PacketTag.SymmetricKeyEncryptedSessionKey)
            {
                packets.Add(bcpgInput.ReadPacket());
            }

            Packet packet = bcpgInput.ReadPacket();
            if (!(packet is InputStreamPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            this.data = (InputStreamPacket)packet;

            for (int i = 0; i != packets.Count; i++)
            {
                if (packets[i] is SymmetricKeyEncSessionPacket)
                {
                    list.Add(new PgpPbeEncryptedData((SymmetricKeyEncSessionPacket)packets[i], data));
                }
                else
                {
                    list.Add(new PgpPublicKeyEncryptedData((PublicKeyEncSessionPacket)packets[i], data));
                }
            }
        }

        public PgpEncryptedData this[int index] => list[index];

        public int Count => list.Count;

        public bool IsEmpty => list.Count == 0;

        public IEnumerable<PgpEncryptedData> GetEncryptedDataObjects() => list;
    }
}
