using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>A list of PGP signatures - normally in the signature block after literal data.</summary>
    public class PgpSignatureList : IPgpObject
    {
        private PgpSignature[] sigs;

        public PgpSignatureList(PgpSignature[] sigs)
        {
            this.sigs = (PgpSignature[])sigs.Clone();
        }

        public PgpSignatureList(PgpSignature sig)
        {
            this.sigs = new PgpSignature[] { sig };
        }

        public PgpSignature this[int index] => sigs[index];

        public int Count => sigs.Length;

        public bool IsEmpty => sigs.Length == 0;
    }
}
