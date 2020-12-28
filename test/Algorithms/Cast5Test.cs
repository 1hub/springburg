using InflatablePalace.Cryptography.Algorithms;
using NUnit.Framework;

namespace InflatablePalace.Test.Algorithms
{
    [TestFixture]
    public class Cast5Test : SymmetricAlgorithmTest<CAST5>
    {
        public static object[] TestVectors => new object[]
        {
            new object[] { "0123456712345678234567893456789a", "0123456789abcdef", "238b4fe5847e44b2" },
        };
    }
}
