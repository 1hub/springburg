using System;

namespace Springburg.Cryptography.OpenPgp
{
    /// <summary>
    /// Thrown if the key checksum is invalid.
    /// </summary>
    [Serializable]
    public class PgpKeyValidationException
        : PgpException
    {
        public PgpKeyValidationException() : base() { }
        public PgpKeyValidationException(string message) : base(message) { }
        public PgpKeyValidationException(string message, Exception exception) : base(message, exception) { }
    }
}
