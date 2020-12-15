using System.Formats.Asn1;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public static class Rfc6637Utilities
    {
        // "Anonymous Sender    ", which is the octet sequence
        private static readonly byte[] ANONYMOUS_SENDER = new byte[] { 0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64, 0x65, 0x72, 0x20, 0x20, 0x20, 0x20 };

        public static int GetKeyLength(SymmetricKeyAlgorithmTag algID)
        {
            switch (algID)
            {
                case SymmetricKeyAlgorithmTag.Aes128: return 16;
                case SymmetricKeyAlgorithmTag.Aes192: return 24;
                case SymmetricKeyAlgorithmTag.Aes256: return 32;
                default:
                    throw new PgpException("unknown symmetric algorithm ID: " + algID);
            }
        }

        // RFC 6637 - Section 8
        // curve_OID_len = (byte)len(curve_OID);
        // Param = curve_OID_len || curve_OID || public_key_alg_ID || 03
        // || 01 || KDF_hash_ID || KEK_alg_ID for AESKeyWrap || "Anonymous
        // Sender    " || recipient_fingerprint;
        // Z_len = the key size for the KEK_alg_ID used with AESKeyWrap
        // Compute Z = KDF( S, Z_len, Param );
        public static byte[] CreateUserKeyingMaterial(PublicKeyPacket pubKeyData)
        {
            MemoryStream pOut = new MemoryStream();
            ECDHPublicBcpgKey ecKey = (ECDHPublicBcpgKey)pubKeyData.Key;

            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.WriteObjectIdentifier(ecKey.CurveOid.Value);
            byte[] encOid = writer.Encode();

            pOut.Write(encOid, 1, encOid.Length - 1);
            pOut.WriteByte((byte)pubKeyData.Algorithm);
            pOut.WriteByte(0x03);
            pOut.WriteByte(0x01);
            pOut.WriteByte((byte)ecKey.HashAlgorithm);
            pOut.WriteByte((byte)ecKey.SymmetricKeyAlgorithm);
            pOut.Write(ANONYMOUS_SENDER, 0, ANONYMOUS_SENDER.Length);

            byte[] fingerprint = PgpPublicKey.CalculateFingerprint(pubKeyData);
            pOut.Write(fingerprint, 0, fingerprint.Length);

            return pOut.ToArray();
        }
    }
}
