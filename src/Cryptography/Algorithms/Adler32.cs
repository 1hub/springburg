using System.Security.Cryptography;

namespace InflatablePalace.Cryptography.Algorithms
{
    class Adler32 : HashAlgorithm
    {
        public uint checksum = 1;

        public override void Initialize()
        {
            checksum = 1;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int n;
            uint s1 = checksum & 0xFFFF;
            uint s2 = checksum >> 16;

            while (cbSize > 0)
            {
                n = (3800 > cbSize) ? cbSize : 3800;
                cbSize -= n;

                while (--n >= 0)
                {
                    s1 = s1 + (uint)(array[ibStart++] & 0xFF);
                    s2 = s2 + s1;
                }

                s1 %= 65521;
                s2 %= 65521;
            }

            checksum = (s2 << 16) | s1;
        }

        protected override byte[] HashFinal()
        {
            return new byte[] { (byte)(checksum >> 24), (byte)(checksum >> 16), (byte)(checksum >> 8), (byte)checksum };
        }

        public override int HashSize => 32;
    }
}
