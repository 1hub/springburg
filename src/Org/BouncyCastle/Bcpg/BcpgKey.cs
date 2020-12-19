using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public abstract class BcpgKey
    {
        public abstract void Encode(Stream bcpgOut);
    }
}
