using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A holder for a list of PGP encryption method packets.</remarks>
    public class PgpEncryptedDataList
        : PgpObject
    {
        private readonly IList<PgpEncryptedData> list = new List<PgpEncryptedData>();
        private readonly InputStreamPacket data;

        public PgpEncryptedDataList(
            BcpgInputStream bcpgInput)
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

        public PgpEncryptedData this[int index]
        {
            get { return (PgpEncryptedData)list[index]; }
        }

        [Obsolete("Use 'object[index]' syntax instead")]
        public object Get(int index)
        {
            return this[index];
        }

        [Obsolete("Use 'Count' property instead")]
        public int Size
        {
            get { return list.Count; }
        }

        public int Count
        {
            get { return list.Count; }
        }

        public bool IsEmpty
        {
            get { return list.Count == 0; }
        }

        public IEnumerable GetEncryptedDataObjects()
        {
            return list;
        }
    }
}
