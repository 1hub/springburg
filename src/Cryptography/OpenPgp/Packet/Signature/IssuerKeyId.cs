namespace Springburg.Cryptography.OpenPgp.Packet.Signature
{
    class IssuerKeyId : SignatureSubpacket
    {
        public IssuerKeyId(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.IssuerKeyId, critical, isLongLength, data)
        {
        }

        public IssuerKeyId(bool critical, long keyId)
            : base(SignatureSubpacketTag.IssuerKeyId, critical, false, PgpUtilities.KeyIdToBytes(keyId))
        {
        }

        public long KeyId
        {
            get
            {
                return
                    ((long)(data[0] & 0xff) << 56) |
                    ((long)(data[1] & 0xff) << 48) |
                    ((long)(data[2] & 0xff) << 40) |
                    ((long)(data[3] & 0xff) << 32) |
                    ((long)(data[4] & 0xff) << 24) |
                    ((long)(data[5] & 0xff) << 16) |
                    ((long)(data[6] & 0xff) << 8) |
                    ((long)data[7] & 0xff);
            }
        }
    }
}
