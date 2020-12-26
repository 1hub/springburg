using System;
using System.Collections.Generic;
using System.IO;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class SignaturePacket : ContainedPacket
    {
        private int version;
        private int signatureType;
        private DateTime creationTime;
        private long keyId;
        private PublicKeyAlgorithmTag keyAlgorithm;
        private HashAlgorithmTag hashAlgorithm;
        private MPInteger[] signature;
        private byte[] fingerprint;
        private SignatureSubpacket[] hashedData;
        private SignatureSubpacket[] unhashedData;
        private byte[] signatureEncoding;

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

                keyAlgorithm = (PublicKeyAlgorithmTag)bcpgIn.ReadByte();
                hashAlgorithm = (HashAlgorithmTag)bcpgIn.ReadByte();
            }
            else if (version == 4)
            {
                signatureType = bcpgIn.ReadByte();
                keyAlgorithm = (PublicKeyAlgorithmTag)bcpgIn.ReadByte();
                hashAlgorithm = (HashAlgorithmTag)bcpgIn.ReadByte();

                int hashedLength = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
                byte[] hashed = new byte[hashedLength];

                Streams.ReadFully(bcpgIn, hashed);

                //
                // read the signature sub packet data.
                //
                SignatureSubpacketsParser sIn = new SignatureSubpacketsParser(
                    new MemoryStream(hashed, false));

                IList<SignatureSubpacket> v = new List<SignatureSubpacket>();
                SignatureSubpacket sub;
                while ((sub = sIn.ReadPacket()) != null)
                {
                    v.Add(sub);
                }

                hashedData = new SignatureSubpacket[v.Count];

                for (int i = 0; i != hashedData.Length; i++)
                {
                    SignatureSubpacket p = (SignatureSubpacket)v[i];
                    if (p is IssuerKeyId)
                    {
                        keyId = ((IssuerKeyId)p).KeyId;
                    }
                    else if (p is SignatureCreationTime)
                    {
                        creationTime = ((SignatureCreationTime)p).Time;
                    }

                    hashedData[i] = p;
                }

                int unhashedLength = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
                byte[] unhashed = new byte[unhashedLength];

                Streams.ReadFully(bcpgIn, unhashed);

                sIn = new SignatureSubpacketsParser(new MemoryStream(unhashed, false));

                v.Clear();

                while ((sub = sIn.ReadPacket()) != null)
                {
                    v.Add(sub);
                }

                unhashedData = new SignatureSubpacket[v.Count];

                for (int i = 0; i != unhashedData.Length; i++)
                {
                    SignatureSubpacket p = (SignatureSubpacket)v[i];
                    if (p is IssuerKeyId)
                    {
                        keyId = ((IssuerKeyId)p).KeyId;
                    }

                    unhashedData[i] = p;
                }
            }
            else
            {
                throw new Exception("unsupported version: " + version);
            }

            fingerprint = new byte[2];
            Streams.ReadFully(bcpgIn, fingerprint);

            switch (keyAlgorithm)
            {
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.RsaSign:
                    MPInteger v = new MPInteger(bcpgIn);
                    signature = new MPInteger[] { v };
                    break;
                case PublicKeyAlgorithmTag.Dsa:
                case PublicKeyAlgorithmTag.ECDsa:
                case PublicKeyAlgorithmTag.EdDsa:
                    MPInteger r = new MPInteger(bcpgIn);
                    MPInteger s = new MPInteger(bcpgIn);
                    signature = new MPInteger[] { r, s };
                    break;
                default:
                    if ((keyAlgorithm >= PublicKeyAlgorithmTag.Experimental_1 && keyAlgorithm <= PublicKeyAlgorithmTag.Experimental_11) ||
                        keyAlgorithm == PublicKeyAlgorithmTag.ElGamalEncrypt ||
                        keyAlgorithm == PublicKeyAlgorithmTag.ElGamalGeneral)
                    {
                        signature = null;
                        MemoryStream bOut = new MemoryStream();
                        int ch;
                        while ((ch = bcpgIn.ReadByte()) >= 0)
                        {
                            bOut.WriteByte((byte)ch);
                        }
                        signatureEncoding = bOut.ToArray();
                    }
                    else
                    {
                        throw new IOException("unknown signature key algorithm: " + keyAlgorithm);
                    }
                    break;
            }
        }

        public SignaturePacket(
            int version,
            int signatureType,
            long keyId,
            PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm,
            DateTime creationTime,
            SignatureSubpacket[] hashedData,
            SignatureSubpacket[] unhashedData,
            byte[] fingerprint,
            MPInteger[] signature)
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

        public PublicKeyAlgorithmTag KeyAlgorithm => keyAlgorithm;

        public HashAlgorithmTag HashAlgorithm => hashAlgorithm;

        public MPInteger[] GetSignature() => signature;

        public byte[] GetSignatureBytes()
        {
            if (signatureEncoding != null)
            {
                return (byte[])signatureEncoding.Clone();
            }

            using MemoryStream bOut = new MemoryStream();

            foreach (MPInteger sigObj in signature)
            {
                sigObj.Encode(bOut);
            }

            return bOut.ToArray();
        }

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

                bcpgOut.Write(OpenPgp.PgpUtilities.KeyIdToBytes(keyId));

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

            if (signature != null)
            {
                foreach (var o in signature)
                {
                    o.Encode(bcpgOut);
                }
            }
            else
            {
                bcpgOut.Write(signatureEncoding);
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
