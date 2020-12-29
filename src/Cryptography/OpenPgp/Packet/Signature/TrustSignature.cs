using System;

namespace Springburg.Cryptography.OpenPgp.Packet.Signature
{
    class TrustSignature : SignatureSubpacket
    {
        public TrustSignature(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.TrustSignature, critical, isLongLength, data)
        {
        }

        public TrustSignature(bool critical, byte depth, byte trustAmount)
            : base(SignatureSubpacketTag.TrustSignature, critical, false, new byte[] { depth, trustAmount })
        {
        }

        public byte Depth => data[0];

        public byte TrustAmount => data[1];
    }
}
