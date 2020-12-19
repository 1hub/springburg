using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
    public class Exportable : SignatureSubpacket
    {
        public Exportable(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.Exportable, critical, isLongLength, data)
        {
        }

        public Exportable(bool critical, bool isExportable)
            : base(SignatureSubpacketTag.Exportable, critical, false, new byte[] { isExportable ? 1 : 0 })
        {
        }

        public bool IsExportable => data[0] > 0;
    }
}
