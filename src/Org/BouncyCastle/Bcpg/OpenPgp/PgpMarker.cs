using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// A PGP marker packet - in general these should be ignored other than where
    /// the idea is to preserve the original input stream.
    /// </summary>
    public class PgpMarker : PgpObject
    {
        private readonly MarkerPacket data;

        internal PgpMarker(MarkerPacket data)
        {
            this.data = data;
        }
    }
}
