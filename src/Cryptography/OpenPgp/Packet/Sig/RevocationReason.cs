using System;
using System.Text;

namespace InflatablePalace.Cryptography.OpenPgp.Packet.Sig
{
    /// <summary>
    /// Represents revocation reason OpenPGP signature sub packet.
    /// </summary>
    class RevocationReason : SignatureSubpacket
    {
        public RevocationReason(bool isCritical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.RevocationReason, isCritical, isLongLength, data)
        {
        }

        public RevocationReason(
            bool isCritical,
            RevocationReasonTag reason,
            string description)
            : base(SignatureSubpacketTag.RevocationReason, isCritical, false, CreateData(reason, description))
        {
        }

        private static byte[] CreateData(
            RevocationReasonTag reason,
            string description)
        {
            byte[] data = new byte[1 + Encoding.UTF8.GetByteCount(description)];
            data[0] = (byte)reason;
            Encoding.UTF8.GetBytes(description, data.AsSpan(1));
            return data;
        }

        public RevocationReasonTag Reason => (RevocationReasonTag)data[0];

        public string Description
        {
            get
            {
                if (data.Length == 1)
                    return string.Empty;
                return Encoding.UTF8.GetString(data.AsSpan(1));
            }
        }
    }
}
