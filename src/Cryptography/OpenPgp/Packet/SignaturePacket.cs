using InflatablePalace.Cryptography.OpenPgp.Packet.Signature;
using InflatablePalace.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    class SignaturePacket : ContainedPacket
    {
        private int version;
        private int signatureType;
        private DateTime creationTime;
        private long keyId;
        private PgpPublicKeyAlgorithm keyAlgorithm;
        private PgpHashAlgorithm hashAlgorithm;
        private byte[] fingerprint;
        private SignatureSubpacket[] hashedData;
        private SignatureSubpacket[] unhashedData;
        private byte[] signature;

        internal SignaturePacket(Stream bcpgIn)
        {
            version = bcpgIn.ReadByte();

            if (version == 3 || version == 2)
            {
                //                int l =
                bcpgIn.ReadByte();

                signatureType = bcpgIn.ReadByte();
                creationTime = DateTimeOffset.FromUnixTimeSeconds(
                    ((long)bcpgIn.ReadByte() << 24) | ((long)bcpgIn.ReadByte() << 16) | ((long)bcpgIn.ReadByte() << 8) | (uint)bcpgIn.ReadByte()).UtcDateTime;

                keyId |= (long)bcpgIn.ReadByte() << 56;
                keyId |= (long)bcpgIn.ReadByte() << 48;
                keyId |= (long)bcpgIn.ReadByte() << 40;
                keyId |= (long)bcpgIn.ReadByte() << 32;
                keyId |= (long)bcpgIn.ReadByte() << 24;
                keyId |= (long)bcpgIn.ReadByte() << 16;
                keyId |= (long)bcpgIn.ReadByte() << 8;
                keyId |= (uint)bcpgIn.ReadByte();

                keyAlgorithm = (PgpPublicKeyAlgorithm)bcpgIn.ReadByte();
                hashAlgorithm = (PgpHashAlgorithm)bcpgIn.ReadByte();

                hashedData = Array.Empty<SignatureSubpacket>();
                unhashedData = Array.Empty<SignatureSubpacket>();
            }
            else if (version == 4)
            {
                signatureType = bcpgIn.ReadByte();
                keyAlgorithm = (PgpPublicKeyAlgorithm)bcpgIn.ReadByte();
                hashAlgorithm = (PgpHashAlgorithm)bcpgIn.ReadByte();

                int hashedLength = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
                byte[] hashed = new byte[hashedLength];

                if (bcpgIn.ReadFully(hashed) < hashed.Length)
                    throw new EndOfStreamException();

                //
                // read the signature sub packet data.
                //
                SignatureSubpacketParser sIn = new SignatureSubpacketParser(new MemoryStream(hashed, false));

                IList<SignatureSubpacket> v = new List<SignatureSubpacket>();
                SignatureSubpacket? sub;
                while ((sub = sIn.ReadPacket()) != null)
                {
                    v.Add(sub);
                    if (sub is IssuerKeyId issuerKeyId)
                        keyId = issuerKeyId.KeyId;
                    else if (sub is SignatureCreationTime signatureCreationTime)
                        creationTime = signatureCreationTime.Time;
                }

                hashedData = v.ToArray();

                int unhashedLength = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
                byte[] unhashed = new byte[unhashedLength];

                if (bcpgIn.ReadFully(unhashed) < unhashed.Length)
                    throw new EndOfStreamException();

                sIn = new SignatureSubpacketParser(new MemoryStream(unhashed, false));

                v.Clear();
                while ((sub = sIn.ReadPacket()) != null)
                {
                    v.Add(sub);
                    if (sub is IssuerKeyId issuerKeyId && keyId == 0)
                        keyId = issuerKeyId.KeyId;
                }

                unhashedData = v.ToArray();
            }
            else
            {
                throw new PgpException("unsupported version: " + version);
            }

            fingerprint = new byte[2];
            if (bcpgIn.ReadFully(fingerprint) < fingerprint.Length)
                throw new EndOfStreamException();

            switch (keyAlgorithm)
            {
                case PgpPublicKeyAlgorithm.RsaGeneral:
                case PgpPublicKeyAlgorithm.RsaSign:
                    MPInteger v = new MPInteger(bcpgIn);
                    signature = v.Value;
                    break;
                case PgpPublicKeyAlgorithm.Dsa:
                case PgpPublicKeyAlgorithm.ECDsa:
                case PgpPublicKeyAlgorithm.EdDsa:
                    MPInteger r = new MPInteger(bcpgIn);
                    MPInteger s = new MPInteger(bcpgIn);
                    int halfLength = Math.Max(r.Value.Length, s.Value.Length);
                    signature = new byte[halfLength * 2];
                    r.Value.CopyTo(signature.AsSpan(halfLength - r.Value.Length));
                    s.Value.CopyTo(signature.AsSpan(signature.Length - s.Value.Length));
                    break;
                default:
                    signature = bcpgIn.ReadAll();
                    break;
            }
        }

        public SignaturePacket(
            int version,
            int signatureType,
            long keyId,
            PgpPublicKeyAlgorithm keyAlgorithm,
            PgpHashAlgorithm hashAlgorithm,
            DateTime creationTime,
            SignatureSubpacket[] hashedData,
            SignatureSubpacket[] unhashedData,
            byte[] fingerprint,
            byte[] signature)
        {
            this.version = version;
            this.signatureType = signatureType;
            this.keyId = keyId;
            this.keyAlgorithm = keyAlgorithm;
            this.hashAlgorithm = hashAlgorithm;
            this.hashedData = hashedData;
            this.unhashedData = unhashedData;
            this.fingerprint = fingerprint;
            this.signature = signature;
            this.creationTime = creationTime;
        }

        public int Version => version;

        public int SignatureType => signatureType;

        public long KeyId => keyId;

        public PgpPublicKeyAlgorithm KeyAlgorithm => keyAlgorithm;

        public PgpHashAlgorithm HashAlgorithm => hashAlgorithm;

        public byte[] GetSignature() => signature;

        public SignatureSubpacket[] GetHashedSubPackets() => hashedData;

        public SignatureSubpacket[] GetUnhashedSubPackets() => unhashedData;

        public DateTime CreationTime => creationTime;

        public override PacketTag Tag => PacketTag.Signature;

        public override void Encode(Stream bcpgOut)
        {
            bcpgOut.WriteByte((byte)version);

            if (version == 3 || version == 2)
            {
                bcpgOut.WriteByte(5); // the length of the next block
                bcpgOut.WriteByte((byte)signatureType);

                long time = new DateTimeOffset(creationTime, TimeSpan.Zero).ToUnixTimeSeconds();
                bcpgOut.Write(new byte[] { (byte)(time >> 24), (byte)(time >> 16), (byte)(time >> 8), (byte)time });

                bcpgOut.Write(PgpUtilities.KeyIdToBytes(keyId));

                bcpgOut.WriteByte((byte)keyAlgorithm);
                bcpgOut.WriteByte((byte)hashAlgorithm);
            }
            else if (version == 4)
            {
                bcpgOut.Write(new[] {
                    (byte)signatureType,
                    (byte)keyAlgorithm,
                    (byte)hashAlgorithm });

                EncodeLengthAndData(bcpgOut, GetEncodedSubpackets(hashedData));
                EncodeLengthAndData(bcpgOut, GetEncodedSubpackets(unhashedData));
            }
            else
            {
                throw new IOException("unknown version: " + version);
            }

            bcpgOut.Write(fingerprint);

            switch (keyAlgorithm)
            {
                case PgpPublicKeyAlgorithm.RsaGeneral:
                case PgpPublicKeyAlgorithm.RsaSign:
                    new MPInteger(signature).Encode(bcpgOut);
                    break;
                case PgpPublicKeyAlgorithm.Dsa:
                case PgpPublicKeyAlgorithm.ECDsa:
                case PgpPublicKeyAlgorithm.EdDsa:
                    int halfLength = signature.Length / 2;
                    new MPInteger(signature.AsSpan(0, halfLength)).Encode(bcpgOut);
                    new MPInteger(signature.AsSpan(halfLength)).Encode(bcpgOut);
                    break;
                default:
                    bcpgOut.Write(signature);
                    break;
            }
        }

        private static void EncodeLengthAndData(Stream pOut, byte[] data)
        {
            pOut.WriteByte((byte)(data.Length >> 8));
            pOut.WriteByte((byte)data.Length);
            pOut.Write(data);
        }

        private static byte[] GetEncodedSubpackets(SignatureSubpacket[] ps)
        {
            MemoryStream sOut = new MemoryStream();

            foreach (SignatureSubpacket p in ps)
            {
                p.Encode(sOut);
            }

            return sOut.ToArray();
        }
    }
}
