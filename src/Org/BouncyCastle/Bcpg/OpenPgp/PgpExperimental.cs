using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpExperimental : PgpObject
    {
        private readonly ExperimentalPacket data;

        internal PgpExperimental(ExperimentalPacket data)
        {
            this.data = data;
        }
    }
}
