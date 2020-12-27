using InflatablePalace.IO;
using System;
using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp.Packet
{
    /// <summary>A multiple precision integer</summary>
    class MPInteger
    {
        private readonly byte[] value;

        public MPInteger(Stream bcpgIn)
        {
            if (bcpgIn == null)
                throw new ArgumentNullException(nameof(bcpgIn));

            int bitLength = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
            byte[] bytes = new byte[(bitLength + 7) / 8];

            if (bcpgIn.ReadFully(bytes) < bytes.Length)
                throw new EndOfStreamException();

            this.value = bytes;
        }

        public MPInteger(ReadOnlySpan<byte> value)
        {
            int leadingZeros;
            for (leadingZeros = 0; leadingZeros < value.Length && value[leadingZeros] == 0; leadingZeros++)
                ;
            this.value = value.Slice(leadingZeros).ToArray();
        }

        public byte[] Value => value;


        public byte[] GetEncoded()
        {
            byte[] encodedValue = new byte[2 + value.Length];
            int length = value.Length * 8;
            for (int mask = 0x80; mask >= 0 && (value[0] & mask) == 0; mask >>= 1)
                length--;
            encodedValue[0] = (byte)(length >> 8);
            encodedValue[1] = (byte)length;
            Value.CopyTo(encodedValue, 2);
            return encodedValue;
        }

        public void Encode(Stream bcpgOut)
        {
            if (value.Length == 0)
            {
                bcpgOut.WriteByte(0);
                bcpgOut.WriteByte(0);
            }
            else
            {
                int length = value.Length * 8;
                for (int mask = 0x80; mask >= 0 && (value[0] & mask) == 0; mask >>= 1)
                    length--;
                bcpgOut.WriteByte((byte)(length >> 8));
                bcpgOut.WriteByte((byte)length);
                bcpgOut.Write(value);
            }
        }
    }
}
