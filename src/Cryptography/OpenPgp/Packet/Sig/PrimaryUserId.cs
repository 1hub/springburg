namespace InflatablePalace.Cryptography.OpenPgp.Packet.Sig
{
    /// <summary>
    /// Packet giving whether or not the signature is signed using the primary user ID for the key.
    /// </summary>
    class PrimaryUserId : SignatureSubpacket
    {
        public PrimaryUserId(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.PrimaryUserId, critical, isLongLength, data)
        {
        }

        public PrimaryUserId(bool critical, bool isPrimaryUserId)
            : base(SignatureSubpacketTag.PrimaryUserId, critical, false, new byte[] { isPrimaryUserId ? 1 : 0 })
        {
        }

        public bool IsPrimaryUserId => data[0] > 0;
    }
}
