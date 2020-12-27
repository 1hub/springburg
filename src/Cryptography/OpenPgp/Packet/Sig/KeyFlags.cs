namespace InflatablePalace.Cryptography.OpenPgp.Packet.Sig
{
    class KeyFlags : SignatureSubpacket
    {
        public KeyFlags(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.KeyFlags, critical, isLongLength, data)
        {
        }

        public KeyFlags(bool critical, PgpKeyFlags flags)
            : base(SignatureSubpacketTag.KeyFlags, critical, false, CreateData((int)flags))
        {
        }

        private static byte[] CreateData(int v)
        {
            if (v > 0xffffff)
                return new[] { (byte)v, (byte)(v >> 8), (byte)(v >> 16), (byte)(v >> 24) };
            if (v > 0xffff)
                return new[] { (byte)v, (byte)(v >> 8), (byte)(v >> 16) };
            if (v > 0xff)
                return new[] { (byte)v, (byte)(v >> 8) };
            return new[] { (byte)v };
        }

        /// <summary>
        /// Return the flag values contained in the first 4 octets (note: at the moment
        /// the standard only uses the first two).
        /// </summary>
        public PgpKeyFlags Flags
        {
            get
            {
                int flags = 0;

                for (int i = 0; i != data.Length; i++)
                {
                    flags |= (data[i] & 0xff) << (i * 8);
                }

                return (PgpKeyFlags)flags;
            }
        }
    }
}
