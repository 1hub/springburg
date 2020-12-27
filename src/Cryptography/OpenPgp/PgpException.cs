using System;

namespace InflatablePalace.Cryptography.OpenPgp
{
    /// <remarks>Generic exception class for PGP encoding/decoding problems.</remarks>
    [Serializable]
    public class PgpException
        : Exception
    {
        public PgpException() : base() { }
        public PgpException(string message) : base(message) { }
        public PgpException(string message, Exception exception) : base(message, exception) { }
    }
}
