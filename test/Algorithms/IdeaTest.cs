using Springburg.Cryptography.Algorithms;
using NUnit.Framework;

namespace Springburg.Test.Algorithms
{
    [TestFixture]
    public class IdeaTest : SymmetricAlgorithmTest<IDEA>
    {
        public static object[] TestVectors => new object[]
        {
            new object[] { "80000000000000000000000000000000", "0000000000000000", "B1F5F7F87901370F" },
            new object[] { "40000000000000000000000000000000", "0000000000000000", "B3927DFFB6358626" },
            new object[] { "000102030405060708090A0B0C0D0E0F", "DB2D4A92AA68273F", "0011223344556677" },
        };
    }
}
