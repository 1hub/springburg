using InflatablePalace.Cryptography.OpenPgp.Packet;
using System;
using System.Collections.Generic;
using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp
{
    public abstract class PgpKeyRing : PgpEncodable
    {
        private protected static PgpPublicKey ReadPublicKey(
            IPacketReader packetReader,
            PublicKeyPacket publicKeyPacket,
            bool subKey = false)
        {
            return new PgpPublicKey(packetReader, publicKeyPacket, subKey);
        }

        private protected static void InsertKey<T>(
            IList<T> keys,
            T keyToInsert)
            where T : IPgpKey
        {
            bool found = false;
            bool masterFound = false;

            for (int i = 0; i != keys.Count; i++)
            {
                T key = keys[i];
                if (key.KeyId == keyToInsert.KeyId)
                {
                    found = true;
                    keys[i] = keyToInsert;
                }
                if (key.IsMasterKey)
                {
                    masterFound = true;
                }
            }

            if (!found)
            {
                if (keyToInsert.IsMasterKey)
                {
                    if (masterFound)
                        throw new ArgumentException("cannot add a master key to a ring that already has one");
                    keys.Insert(0, keyToInsert);
                }
                else
                {
                    keys.Add(keyToInsert);
                }
            }
        }

        protected private static bool RemoveKey<T>(
            IList<T> keys,
            T keyToRemove)
            where T : IPgpKey
        {
            // FIXME: Disallow removing the master key?

            for (int i = 0; i < keys.Count; i++)
            {
                if (keys[i].KeyId == keyToRemove.KeyId)
                {
                    keys.RemoveAt(i);
                    return true;
                }
            }

            return false;
        }
    }
}
