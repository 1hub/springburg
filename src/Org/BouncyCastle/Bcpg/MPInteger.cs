using System;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>A multiple precision integer</summary>
    public class MPInteger : BcpgObject
    {
        private readonly byte[] value;

        public MPInteger(BcpgInputStream bcpgIn)
        {
            if (bcpgIn == null)
                throw new ArgumentNullException(nameof(bcpgIn));

            int bitLength = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
            byte[] bytes = new byte[(bitLength + 7) / 8];

            bcpgIn.ReadFully(bytes);

            this.value = bytes;
        }

        public MPInteger(byte[] value)
        {
            int leadingZeros;
            for (leadingZeros = 0; leadingZeros < value.Length && value[leadingZeros] == 0; leadingZeros++)
                ;
            if (leadingZeros == 0)
                this.value = value;
            else
                this.value = value.AsSpan(leadingZeros).ToArray();
        }

        public byte[] Value => value;

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            int length = value.Length * 8;
            for (int mask = 0x80; mask >= 0 && (value[0] & mask) == 0; mask >>= 1)
                length--;
            bcpgOut.WriteShort((short)length);
            bcpgOut.Write(value);
        }
    }
}
