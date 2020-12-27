using InflatablePalace.IO;
using System;
using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    /// <summary>The string to key specifier class.</summary>
    public class S2k
    {
        private const int ExpBias = 6;

        public const int Simple = 0;
        public const int Salted = 1;
        public const int SaltedAndIterated = 3;
        public const int GnuDummyS2K = 101;
        public const int GnuProtectionModeNoPrivateKey = 1;
        public const int GnuProtectionModeDivertToCard = 2;

        internal int type;
        internal HashAlgorithmTag algorithm;
        internal byte[] iv;
        internal int itCount = -1;
        internal int protectionMode = -1;

        internal S2k(
            Stream inStr)
        {
            type = inStr.ReadByte();
            algorithm = (HashAlgorithmTag)inStr.ReadByte();

            //
            // if this happens we have a dummy-S2k packet.
            //
            if (type != GnuDummyS2K)
            {
                if (type != 0)
                {
                    iv = new byte[8];
                    if (inStr.ReadFully(iv) < iv.Length)
                        throw new EndOfStreamException();

                    if (type == 3)
                    {
                        itCount = inStr.ReadByte();
                    }
                }
            }
            else
            {
                inStr.ReadByte(); // G
                inStr.ReadByte(); // N
                inStr.ReadByte(); // U
                protectionMode = inStr.ReadByte(); // protection mode
            }
        }

        public S2k(
            HashAlgorithmTag algorithm)
        {
            this.type = 0;
            this.algorithm = algorithm;
        }

        public S2k(
            HashAlgorithmTag algorithm,
            byte[] iv)
        {
            this.type = 1;
            this.algorithm = algorithm;
            this.iv = iv;
        }

        public S2k(
            HashAlgorithmTag algorithm,
            byte[] iv,
            int itCount)
        {
            this.type = 3;
            this.algorithm = algorithm;
            this.iv = iv;
            this.itCount = itCount;
        }

        public int Type => type;

        /// <summary>The hash algorithm.</summary>
        public HashAlgorithmTag HashAlgorithm => algorithm;

        /// <summary>The IV for the key generation algorithm.</summary>
        public ReadOnlySpan<byte> GetIV() => iv;

        /// <summary>The iteration count</summary>
        public virtual long IterationCount => (16 + (itCount & 15)) << ((itCount >> 4) + ExpBias);

        /// <summary>The protection mode - only if GnuDummyS2K</summary>
        public int ProtectionMode => protectionMode;

        public void Encode(Stream bcpgOut)
        {
            bcpgOut.WriteByte((byte)type);
            bcpgOut.WriteByte((byte)algorithm);

            if (type != GnuDummyS2K)
            {
                if (type != 0)
                {
                    bcpgOut.Write(iv);
                }

                if (type == 3)
                {
                    bcpgOut.WriteByte((byte)itCount);
                }
            }
            else
            {
                bcpgOut.WriteByte((byte)'G');
                bcpgOut.WriteByte((byte)'N');
                bcpgOut.WriteByte((byte)'U');
                bcpgOut.WriteByte((byte)protectionMode);
            }
        }
    }
}
