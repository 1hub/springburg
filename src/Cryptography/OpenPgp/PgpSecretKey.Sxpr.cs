using Springburg.Cryptography.Helpers;
using Springburg.Cryptography.OpenPgp.Packet;
using Springburg.Cryptography.OpenPgp.Keys;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Internal.Cryptography;
using System.Formats.Asn1;
using Springburg.Cryptography.Algorithms;

namespace Springburg.Cryptography.OpenPgp
{
    public partial class PgpSecretKey
    {
        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
        /// </summary>
        public static PgpSecretKey ParseSecretKeyFromSExpr(Stream inputStream, string passPhrase, PgpKey pubKey)
        {
            return DoParseSecretKeyFromSExpr(inputStream, Encoding.UTF8.GetBytes(passPhrase), pubKey);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
        /// </summary>
        public static PgpSecretKey ParseSecretKeyFromSExpr(Stream inputStream, byte[] rawPassPhrase, PgpKey pubKey)
        {
            return DoParseSecretKeyFromSExpr(inputStream, rawPassPhrase, pubKey);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys.
        /// </summary>
        public static PgpSecretKey ParseSecretKeyFromSExpr(Stream inputStream, string passPhrase)
        {
            return DoParseSecretKeyFromSExpr(inputStream, Encoding.UTF8.GetBytes(passPhrase), null);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys.
        /// </summary>
        public static PgpSecretKey ParseSecretKeyFromSExpr(Stream inputStream, byte[] rawPassPhrase)
        {
            return DoParseSecretKeyFromSExpr(inputStream, rawPassPhrase, null);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys.
        /// </summary>
        internal static PgpSecretKey DoParseSecretKeyFromSExpr(Stream inputStream, byte[] rawPassPhrase, PgpKey? pubKey)
        {
            SXprReader reader = new SXprReader(inputStream);

            reader.SkipOpenParenthesis();

            string type = reader.ReadString();
            if (type.Equals("protected-private-key", StringComparison.Ordinal))
            {
                reader.SkipOpenParenthesis();

                string curveName;
                Oid curveOid;

                string keyType = reader.ReadString();
                if (keyType.Equals("ecc", StringComparison.Ordinal))
                {
                    reader.SkipOpenParenthesis();

                    string curveID = reader.ReadString();
                    curveName = reader.ReadString();

                    switch (curveName)
                    {
                        case "NIST P-256": curveOid = new Oid("1.2.840.10045.3.1.7"); break;
                        case "NIST P-384": curveOid = new Oid("1.3.132.0.34"); break;
                        case "NIST P-521": curveOid = new Oid("1.3.132.0.35"); break;
                        case "brainpoolP256r1": curveOid = new Oid("1.3.36.3.3.2.8.1.1.7"); break;
                        case "brainpoolP384r1": curveOid = new Oid("1.3.36.3.3.2.8.1.1.11"); break;
                        case "brainpoolP512r1": curveOid = new Oid("1.3.36.3.3.2.8.1.1.13"); break;
                        case "Curve25519": curveOid = new Oid("1.3.6.1.4.1.3029.1.5.1"); break;
                        case "Ed25519": curveOid = new Oid("1.3.6.1.4.1.11591.15.1"); break;
                        default:
                            throw new PgpException("unknown curve algorithm");
                    }

                    reader.SkipCloseParenthesis();
                }
                else
                {
                    throw new PgpException("no curve details found");
                }

                byte[] qVal;
                string? flags = null;

                reader.SkipOpenParenthesis();

                type = reader.ReadString();
                if (type == "flags")
                {
                    // Skip over flags
                    flags = reader.ReadString();
                    reader.SkipCloseParenthesis();
                    reader.SkipOpenParenthesis();
                    type = reader.ReadString();
                }
                if (type.Equals("q", StringComparison.Ordinal))
                {
                    qVal = reader.ReadBytes();
                }
                else
                {
                    throw new PgpException("no q value found");
                }

                if (pubKey == null)
                {
                    var writer = new AsnWriter(AsnEncodingRules.DER);
                    writer.WriteObjectIdentifier(curveOid.Value!);

                    int expectedLength = writer.GetEncodedLength() + 2 + qVal.Length;
                    var destination = new byte[expectedLength];
                    writer.TryEncode(destination, out int oidBytesWritten);
                    Keys.MPInteger.TryWriteInteger(qVal, destination.AsSpan(oidBytesWritten), out int qBytesWritten);

                    var pubKeyBytes = destination.AsSpan(1, oidBytesWritten + qBytesWritten - 1).ToArray();

                    PublicKeyPacket pubPacket = new PublicKeyPacket(
                        flags == "eddsa" ? PgpPublicKeyAlgorithm.EdDsa : PgpPublicKeyAlgorithm.ECDsa, DateTime.UtcNow,
                        pubKeyBytes);
                    pubKey = new PgpPublicKey(pubPacket);
                }

                reader.SkipCloseParenthesis();

                byte[] dValue = GetDValue(reader, pubKey.KeyPacket, rawPassPhrase, curveName);

                var keyBytes = new byte[pubKey.KeyPacket.PublicKeyLength + 3 + dValue.Length];
                pubKey.KeyPacket.KeyBytes.AsSpan(0, pubKey.KeyPacket.PublicKeyLength).CopyTo(keyBytes);
                keyBytes[pubKey.KeyPacket.PublicKeyLength] = (byte)S2kUsageTag.None;
                Keys.MPInteger.TryWriteInteger(dValue, keyBytes.AsSpan(pubKey.KeyPacket.PublicKeyLength + 1), out var _);

                return new PgpSecretKey(new SecretKeyPacket(pubKey.Algorithm, pubKey.CreationTime, keyBytes), pubKey);
            }

            throw new PgpException("unknown key type found");
        }

        private static void WriteSExprPublicKey(SXprWriter writer, KeyPacket pubPacket, string curveName, string? protectedAt)
        {
            writer.StartList();
            switch (pubPacket.Algorithm)
            {
                case PgpPublicKeyAlgorithm.ECDsa:
                case PgpPublicKeyAlgorithm.EdDsa:
                    writer.WriteString("ecc");
                    writer.StartList();
                    writer.WriteString("curve");
                    writer.WriteString(curveName);
                    writer.EndList();
                    if (pubPacket.Algorithm == PgpPublicKeyAlgorithm.EdDsa)
                    {
                        writer.StartList();
                        writer.WriteString("flags");
                        writer.WriteString("eddsa");
                        writer.EndList();
                    }
                    writer.StartList();
                    writer.WriteString("q");
                    var keyBytes = pubPacket.KeyBytes.AsSpan(0, pubPacket.PublicKeyLength);
                    keyBytes = keyBytes.Slice(keyBytes[0] + 1 + 2); // Skip OID and encoded point length
                    writer.WriteBytes(keyBytes.ToArray());
                    writer.EndList();
                    break;

                /*case PgpPublicKeyAlgorithm.RsaEncrypt:
                case PgpPublicKeyAlgorithm.RsaSign:
                case PgpPublicKeyAlgorithm.RsaGeneral:
                    RsaPublicBcpgKey rsaK = (RsaPublicBcpgKey)pubPacket.Key;
                    writer.WriteString("rsa");
                    writer.StartList();
                    writer.WriteString("n");
                    writer.WriteBytes(rsaK.Modulus.Value);
                    writer.EndList();
                    writer.StartList();
                    writer.WriteString("e");
                    writer.WriteBytes(rsaK.PublicExponent.Value);
                    writer.EndList();
                    break;*/

                // TODO: DSA, etc.
                default:
                    throw new PgpException("unsupported algorithm in S expression");
            }

            if (protectedAt != null)
            {
                writer.StartList();
                writer.WriteString("protected-at");
                writer.WriteString(protectedAt);
                writer.EndList();
            }
            writer.EndList();
        }

        private static byte[] GetDValue(SXprReader reader, KeyPacket publicKey, byte[] rawPassPhrase, string curveName)
        {
            string type;
            reader.SkipOpenParenthesis();

            string protection;
            string? protectedAt = null;
            S2k s2k;
            byte[] iv;
            byte[] secKeyData;

            type = reader.ReadString();
            if (type.Equals("protected", StringComparison.Ordinal))
            {
                protection = reader.ReadString();

                reader.SkipOpenParenthesis();

                s2k = reader.ParseS2k();

                iv = reader.ReadBytes();

                reader.SkipCloseParenthesis();

                secKeyData = reader.ReadBytes();

                reader.SkipCloseParenthesis();

                reader.SkipOpenParenthesis();

                if (reader.ReadString().Equals("protected-at", StringComparison.Ordinal))
                {
                    protectedAt = reader.ReadString();
                }
            }
            else
            {
                throw new PgpException("protected block not found");
            }

            byte[] data;

            switch (protection)
            {
                case "openpgp-s2k3-sha1-aes256-cbc":
                case "openpgp-s2k3-sha1-aes-cbc":
                    PgpSymmetricKeyAlgorithm symmAlg =
                        protection.Equals("openpgp-s2k3-sha1-aes256-cbc", StringComparison.Ordinal) ?
                        PgpSymmetricKeyAlgorithm.Aes256 :
                        PgpSymmetricKeyAlgorithm.Aes128;
                    using (var c = PgpUtilities.GetSymmetricAlgorithm(symmAlg))
                    {
                        var keyBytes = new byte[c.KeySize / 8];
                        S2kBasedEncryption.MakeKey(rawPassPhrase, PgpHashAlgorithm.Sha1, s2k.GetIV(), s2k.IterationCount, keyBytes);
                        c.Key = keyBytes;
                        c.IV = iv;
                        c.Mode = CipherMode.CBC;
                        using var decryptor = new ZeroPaddedCryptoTransform(c.CreateDecryptor());
                        data = decryptor.TransformFinalBlock(secKeyData, 0, secKeyData.Length);
                        // TODO: check SHA-1 hash.
                    }
                    break;

                case "openpgp-s2k3-ocb-aes":
                    {
                        MemoryStream aad = new MemoryStream();
                        WriteSExprPublicKey(new SXprWriter(aad), publicKey, curveName, protectedAt);
                        var keyBytes = new byte[16];
                        S2kBasedEncryption.MakeKey(rawPassPhrase, PgpHashAlgorithm.Sha1, s2k.GetIV(), s2k.IterationCount, keyBytes);
                        using var aesOcb = new AesOcb(keyBytes);
                        data = new byte[secKeyData.Length - 16];
                        aesOcb.Decrypt(iv, secKeyData.AsSpan(0, secKeyData.Length - 16), secKeyData.AsSpan(secKeyData.Length - 16), data, aad.ToArray());
                    }
                    break;

                case "openpgp-native":
                default:
                    throw new PgpException(protection + " key format is not supported yet");
            }

            //
            // parse the secret key S-expr
            //
            Stream keyIn = new MemoryStream(data, false);

            reader = new SXprReader(keyIn);
            reader.SkipOpenParenthesis();
            reader.SkipOpenParenthesis();
            reader.SkipOpenParenthesis();
            String name = reader.ReadString();
            return reader.ReadBytes();
        }
    }
}
