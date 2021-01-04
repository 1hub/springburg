using System;

namespace Springburg.Cryptography.Algorithms
{
    [Serializable]
    public struct ElGamalParameters
    {
        public byte[]? P;
        public byte[]? G;
        public byte[]? Y;
        public byte[]? X;
    }
}
