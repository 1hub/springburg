using System;
using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public abstract class PgpKeyRing : PgpObject
    {
        private static TrustPacket ReadOptionalTrustPacket(PacketReader packetReader)
        {
            return packetReader.NextPacketTag() == PacketTag.Trust ? (TrustPacket)packetReader.ReadPacket() : null;
        }

        private static IList<PgpSignature> ReadSignaturesAndTrust(PacketReader packetReader)
        {
            try
            {
                IList<PgpSignature> sigList = new List<PgpSignature>();

                while (packetReader.NextPacketTag() == PacketTag.Signature)
                {
                    SignaturePacket signaturePacket = (SignaturePacket)packetReader.ReadPacket();
                    TrustPacket trustPacket = ReadOptionalTrustPacket(packetReader);
                    sigList.Add(new PgpSignature(signaturePacket, trustPacket));
                }

                return sigList;
            }
            catch (PgpException e)
            {
                throw new IOException("can't create signature object: " + e.Message, e);
            }
        }

        protected static PgpPublicKey ReadPublicKey(
            PacketReader packetReader,
            PublicKeyPacket publicKeyPacket,
            bool subKey = false)
        {
            // Ignore GPG comment packets if found.
            while (packetReader.NextPacketTag() == PacketTag.Experimental2)
            {
                packetReader.ReadPacket();
            }

            TrustPacket trust = ReadOptionalTrustPacket(packetReader);
            var keySigs = ReadSignaturesAndTrust(packetReader); // Revocation and direct signatures

            if (subKey)
            {
                return new PgpPublicKey(publicKeyPacket, trust, keySigs);
            }

            var ids = new List<object>();
            var idTrusts = new List<TrustPacket>();
            var idSigs = new List<IList<PgpSignature>>();

            while (packetReader.NextPacketTag() == PacketTag.UserId
                || packetReader.NextPacketTag() == PacketTag.UserAttribute)
            {
                Packet obj = packetReader.ReadPacket();
                if (obj is UserIdPacket)
                {
                    UserIdPacket id = (UserIdPacket)obj;
                    ids.Add(id.GetId());
                }
                else
                {
                    UserAttributePacket user = (UserAttributePacket)obj;
                    ids.Add(new PgpUserAttributeSubpacketVector(user.GetSubpackets()));
                }

                idTrusts.Add(ReadOptionalTrustPacket(packetReader));
                idSigs.Add(ReadSignaturesAndTrust(packetReader));
            }

            return new PgpPublicKey(publicKeyPacket, trust, keySigs, ids, idTrusts, idSigs);
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
