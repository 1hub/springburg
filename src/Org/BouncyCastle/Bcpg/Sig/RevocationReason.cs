using System;
using System.Text;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Represents revocation reason OpenPGP signature sub packet.
    /// </summary>
    public class RevocationReason
        : SignatureSubpacket
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
            byte[] descriptionBytes = Encoding.UTF8.GetBytes(description);
            byte[] data = new byte[1 + descriptionBytes.Length];

            data[0] = (byte)reason;
            Array.Copy(descriptionBytes, 0, data, 1, descriptionBytes.Length);

            return data;
        }

        public virtual RevocationReasonTag GetRevocationReason()
        {
            return (RevocationReasonTag)GetData()[0];
        }

        public virtual string GetRevocationDescription()
        {
            byte[] data = GetData();
            if (data.Length == 1)
            {
                return string.Empty;
            }

            byte[] description = new byte[data.Length - 1];
            Array.Copy(data, 1, description, 0, description.Length);

            return Encoding.UTF8.GetString(description);
        }
    }
}
