using System.Security.Cryptography;

namespace InflatablePalace.Cryptography.Algorithms
{
    class Crc24 : HashAlgorithm
    {
        private const int Crc24Init = 0x0b704ce;
        private const int Crc24Poly = 0x1864cfb;

        private int crc = Crc24Init;

        public override void Initialize()
        {
            crc = Crc24Init;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (int j = 0; j < cbSize; j++)
            {
                crc ^= array[j + ibStart] << 16;
                for (int i = 0; i < 8; i++)
                {
                    crc <<= 1;
                    if ((crc & 0x1000000) != 0)
                    {
                        crc ^= Crc24Poly;
                    }
                }
            }
        }

        protected override byte[] HashFinal()
        {
            return new byte[] { (byte)(crc >> 16), (byte)(crc >> 8), (byte)crc };
        }

        public override int HashSize => 24;

        public void Reset() => Initialize();

        public void Update(int b) => HashCore(new byte[] { (byte)b }, 0, 1);

        public int Value => crc;
    }
}
