namespace Springburg.Cryptography.OpenPgp.Packet.Signature
{
    class EmbeddedSignature : SignatureSubpacket
    {
        public EmbeddedSignature(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.EmbeddedSignature, critical, isLongLength, data)
        {
        }
    }
}
