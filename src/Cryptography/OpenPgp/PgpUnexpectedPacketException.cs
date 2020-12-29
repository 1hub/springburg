using System;

namespace Springburg.Cryptography.OpenPgp
{
    [Serializable]
    public class PgpUnexpectedPacketException : PgpException
    {
        public PgpUnexpectedPacketException() : base("Unexpected packet type in the stream") { }
        public PgpUnexpectedPacketException(string message) : base(message) { }
        public PgpUnexpectedPacketException(string message, Exception exception) : base(message, exception) { }
    }
}
