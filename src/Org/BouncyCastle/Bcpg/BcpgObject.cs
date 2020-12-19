using System;
namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for a PGP object.</summary>
    public abstract class BcpgObject
    {
        public abstract void Encode(BcpgOutputStream bcpgOut);
    }
}

