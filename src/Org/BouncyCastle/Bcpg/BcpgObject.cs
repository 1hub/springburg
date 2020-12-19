using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for a PGP object.</summary>
    public abstract class BcpgObject
    {
        public abstract void Encode(Stream bcpgOut);
    }
}
