using System;
using System.Text;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Represents revocation key OpenPGP signature sub packet.
    /// </summary>
    public class RevocationKey : SignatureSubpacket
    {
        public RevocationKey(bool isCritical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.RevocationKey, isCritical, isLongLength, data)
        {
        }

        public RevocationKey(bool isCritical, RevocationKeyTag signatureClass, PublicKeyAlgorithmTag keyAlgorithm, byte[] fingerprint)
            : base(SignatureSubpacketTag.RevocationKey, isCritical, false, CreateData(signatureClass, keyAlgorithm, fingerprint))
        {
        }

        private static byte[] CreateData(
            RevocationKeyTag signatureClass,
            PublicKeyAlgorithmTag keyAlgorithm,
            byte[] fingerprint)
        {
            // 1 octet of class, 
            // 1 octet of public-key algorithm ID, 
            // 20 octets of fingerprint
            byte[] data = new byte[2 + fingerprint.Length];
            data[0] = (byte)signatureClass;
            data[1] = (byte)keyAlgorithm;
            fingerprint.CopyTo(data, 2);
            return data;
        }

        public RevocationKeyTag SignatureClass => (RevocationKeyTag)data[0];

        public PublicKeyAlgorithmTag Algorithm => (PublicKeyAlgorithmTag)data[1];

        public ReadOnlySpan<byte> Fingerprint => data.AsSpan(2);
    }
}
