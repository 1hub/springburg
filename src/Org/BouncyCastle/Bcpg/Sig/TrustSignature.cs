using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
    public class TrustSignature : SignatureSubpacket
    {
        public TrustSignature(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.TrustSig, critical, isLongLength, data)
        {
        }

        public TrustSignature(bool critical, byte depth, byte trustAmount)
            : base(SignatureSubpacketTag.TrustSig, critical, false, new byte[] { depth, trustAmount })
        {
        }

        public byte Depth => data[0];

        public byte TrustAmount => data[1];
    }
}
