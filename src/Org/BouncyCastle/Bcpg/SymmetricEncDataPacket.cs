using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic type for a symmetric key encrypted packet.</remarks>
    public class SymmetricEncDataPacket
        : InputStreamPacket
    {
        internal SymmetricEncDataPacket(Stream bcpgIn)
            : base(bcpgIn)
        {
        }
    }
}
