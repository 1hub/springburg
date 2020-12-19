using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Holder for a list of PgpOnePassSignature objects.</summary>
    public class PgpOnePassSignatureList : IPgpObject
    {
        private readonly PgpOnePassSignature[] sigs;

        public PgpOnePassSignatureList(PgpOnePassSignature[] sigs)
        {
            this.sigs = (PgpOnePassSignature[])sigs.Clone();
        }

        public PgpOnePassSignatureList(PgpOnePassSignature sig)
        {
            this.sigs = new PgpOnePassSignature[] { sig };
        }

        public PgpOnePassSignature this[int index] => sigs[index];

        public int Count => sigs.Length;

        public bool IsEmpty => sigs.Length == 0;
    }
}
