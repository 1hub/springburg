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
using System.Net.Http.Headers;

namespace Springburg.Cryptography.OpenPgp
{
    /// <summary>General class to handle a PGP secret key object.</summary>
    public class PgpSecretKey : PgpEncodable, IPgpKey
    {
        private readonly SecretKeyPacket secret;
        private readonly PgpPublicKey pub;

        internal PgpSecretKey(
            SecretKeyPacket secret,
            PgpPublicKey pub)
        {
            this.secret = secret;
            this.pub = pub;
        }

        internal PgpSecretKey(
            PgpPrivateKey privKey,
            PgpPublicKey pubKey,
            PgpSymmetricKeyAlgorithm encAlgorithm,
            ReadOnlySpan<byte> rawPassPhrase,
            bool useSha1,
            bool isMasterKey)
        {
            this.pub = pubKey;

            var keyData = privKey.privateKey.ExportPrivateKey(
                rawPassPhrase,
                new S2kParameters { UsageTag = useSha1 ? S2kUsageTag.Sha1 : S2kUsageTag.Checksum, EncryptionAlgorithm = encAlgorithm });

            if (isMasterKey)
            {
                this.secret = new SecretKeyPacket(privKey.Algorithm, pub.CreationTime, keyData);
            }
            else
            {
                this.secret = new SecretSubkeyPacket(privKey.Algorithm, pub.CreationTime, keyData);
            }
        }

        public bool IsEncryptionKey => pub.IsEncryptionKey;

        public bool IsSigningKey => pub.IsSigningKey;

        public bool IsMasterKey => pub.IsMasterKey;

        /// <summary>Detect if the Secret Key's Private Key is empty or not</summary>
        public bool IsPrivateKeyEmpty
        {
            get
            {
                // FIXME: Move this elsewhere
                var s2k = secret.KeyBytes.AsSpan(secret.PublicKeyLength);
                if (s2k.Length < 3)
                    return true;
                if (s2k[0] == (byte)S2kUsageTag.Checksum || s2k[0] == (byte)S2kUsageTag.Sha1 /*|| s2k[0] == (byte)S2kUsageTag.Aead*/)
                {
                    if (s2k[2] == 101) // GNU private
                    {
                        // TODO: Check for GNU string
                        return true;
                    }
                }
                return false;
            }
        }

        /// <summary>The key ID of the public key associated with this key.</summary>
        public long KeyId => pub.KeyId;

        /// <summary>The public key associated with this key.</summary>
        public PgpPublicKey PublicKey => pub;

        /// <summary>Allows enumeration of any user IDs associated with the key.</summary>
        public IEnumerable<PgpUser> UserIds => pub.GetUserIds();

        /// <summary>Allows enumeration of any user attribute vectors associated with the key.</summary>
        public IEnumerable<PgpUser> UserAttributes => pub.GetUserAttributes();

        /// <summary>Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8 (Encoding.UTF8.GetBytes).
        /// </remarks>
        public PgpPrivateKey? ExtractPrivateKey(ReadOnlySpan<char> passPhrase)
        {
            byte[] rawPassPhrase = Array.Empty<byte>();
            try
            {
                rawPassPhrase = new byte[Encoding.UTF8.GetByteCount(passPhrase)];
                Encoding.UTF8.GetBytes(passPhrase, rawPassPhrase);
                return ExtractPrivateKey(rawPassPhrase);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(rawPassPhrase);
            }
        }

        /// <summary>Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public PgpPrivateKey? ExtractPrivateKey(ReadOnlySpan<byte> rawPassPhrase)
        {
            if (IsPrivateKeyEmpty)
                return null;

            if (secret.Version < 4)
            {
                Debug.Assert(secret.Algorithm == PgpPublicKeyAlgorithm.RsaGeneral || secret.Algorithm == PgpPublicKeyAlgorithm.RsaEncrypt || secret.Algorithm == PgpPublicKeyAlgorithm.RsaSign);
                var rsa = RsaKey.CreatePrivate(rawPassPhrase, secret.KeyBytes, out var _, version: 3);
                return new PgpPrivateKey(KeyId, rsa);
            }
            else if (secret.Version >= 4)
            {
                switch (secret.Algorithm)
                {
                    case PgpPublicKeyAlgorithm.RsaGeneral:
                    case PgpPublicKeyAlgorithm.RsaSign:
                    case PgpPublicKeyAlgorithm.RsaEncrypt:
                        var rsa = RsaKey.CreatePrivate(rawPassPhrase, secret.KeyBytes, out var _);
                        return new PgpPrivateKey(KeyId, rsa);

                    case PgpPublicKeyAlgorithm.Dsa:
                        var dsa = DsaKey.CreatePrivate(rawPassPhrase, secret.KeyBytes, out var _);
                        return new PgpPrivateKey(KeyId, dsa);

                    case PgpPublicKeyAlgorithm.ECDH:
                        var ecdh = ECDiffieHellmanKey.CreatePrivate(pub.Fingerprint, rawPassPhrase, secret.KeyBytes, out var _);
                        return new PgpPrivateKey(KeyId, ecdh);

                    case PgpPublicKeyAlgorithm.ECDsa:
                        var ecdsa = ECDsaKey.CreatePrivate(rawPassPhrase, secret.KeyBytes, out var _);
                        return new PgpPrivateKey(KeyId, ecdsa);

                    case PgpPublicKeyAlgorithm.EdDsa:
                        var eddsa = EdDsaKey.CreatePrivate(rawPassPhrase, secret.KeyBytes, out var _);
                        return new PgpPrivateKey(KeyId, eddsa);

                    case PgpPublicKeyAlgorithm.ElGamalEncrypt:
                    case PgpPublicKeyAlgorithm.ElGamalGeneral:
                        var elgamal = ElGamalKey.CreatePrivate(rawPassPhrase, secret.KeyBytes, out var _);
                        return new PgpPrivateKey(KeyId, elgamal);
                }
            }

            throw new PgpException("unknown public key version encountered");
        }

        public override void Encode(IPacketWriter packetWriter)
        {
            if (packetWriter == null)
                throw new ArgumentNullException(nameof(packetWriter));

            packetWriter.WritePacket(secret);
            if (pub.trustPk != null)
                packetWriter.WritePacket(pub.trustPk);
            foreach (var keySig in pub.keyCertifications)
                keySig.Signature.Encode(packetWriter);
            foreach (var user in pub.ids)
                user.Encode(packetWriter);
        }

        /// <summary>
        /// Return a copy of the passed in secret key, encrypted using a new password
        /// and the passed in algorithm.
        /// </summary>
        /// <param name="key">The PgpSecretKey to be copied.</param>
        /// <param name="oldPassPhrase">The current password for the key.</param>
        /// <param name="newPassPhrase">The new password for the key.</param>
        public static PgpSecretKey CopyWithNewPassword(
            PgpSecretKey key,
            ReadOnlySpan<char> oldPassPhrase,
            ReadOnlySpan<char> newPassPhrase)
        {
            int oldPassPhraseByteCount = Encoding.UTF8.GetByteCount(oldPassPhrase);
            int newPassPhraseByteCount = Encoding.UTF8.GetByteCount(newPassPhrase);
            byte[] passphraseBuffer = CryptoPool.Rent(oldPassPhraseByteCount + newPassPhraseByteCount);
            try
            {
                Encoding.UTF8.GetBytes(oldPassPhrase, passphraseBuffer);
                Encoding.UTF8.GetBytes(newPassPhrase, passphraseBuffer.AsSpan(oldPassPhraseByteCount));
                return CopyWithNewPassword(key, passphraseBuffer.AsSpan(0, oldPassPhraseByteCount), passphraseBuffer.AsSpan(oldPassPhraseByteCount, newPassPhraseByteCount));
            }
            finally
            {
                CryptoPool.Return(passphraseBuffer, oldPassPhraseByteCount + newPassPhraseByteCount);
            }
        }

        /// <summary>
        /// Return a copy of the passed in secret key, encrypted using a new password
        /// and the passed in algorithm.
        /// </summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        /// <param name="key">The PgpSecretKey to be copied.</param>
        /// <param name="rawOldPassPhrase">The current password for the key.</param>
        /// <param name="rawNewPassPhrase">The new password for the key.</param>
        public static PgpSecretKey CopyWithNewPassword(
            PgpSecretKey key,
            ReadOnlySpan<byte> rawOldPassPhrase,
            ReadOnlySpan<byte> rawNewPassPhrase)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.IsPrivateKeyEmpty)
                throw new PgpException("no private key in this SecretKey - public key present only.");

            byte[] rawKeyData = CryptoPool.Rent(key.secret.KeyBytes.Length - key.secret.PublicKeyLength + 0x20);
            try
            {
                S2kBasedEncryption.DecryptSecretKey(
                    rawOldPassPhrase,
                    key.secret.KeyBytes.AsSpan(key.secret.PublicKeyLength),
                    rawKeyData,
                    out int rawKeySize,
                    key.secret.Version);

                // Use the default S2K parameters
                var s2kParameters = new S2kParameters();

                var newKeyData = new byte[S2kBasedEncryption.GetEncryptedLength(s2kParameters, rawKeySize, key.secret.Version) + key.secret.PublicKeyLength];
                key.secret.KeyBytes.AsSpan(0, key.secret.PublicKeyLength).CopyTo(newKeyData);

                S2kBasedEncryption.EncryptSecretKey(
                    rawNewPassPhrase,
                    s2kParameters,
                    rawKeyData.AsSpan(0, rawKeySize),
                    newKeyData.AsSpan(key.secret.PublicKeyLength),
                    key.secret.Version);

                SecretKeyPacket secret;
                if (key.secret is SecretSubkeyPacket)
                {
                    secret = new SecretSubkeyPacket(key.PublicKey.Algorithm, key.PublicKey.CreationTime, newKeyData);
                }
                else
                {
                    secret = new SecretKeyPacket(key.PublicKey.Algorithm, key.PublicKey.CreationTime, newKeyData);
                }

                return new PgpSecretKey(secret, key.pub);
            }
            finally
            {
                CryptoPool.Return(rawKeyData);
            }
        }

        /// <summary>Replace the passed the public key on the passed in secret key.</summary>
        /// <param name="secretKey">Secret key to change.</param>
        /// <param name="publicKey">New public key.</param>
        /// <returns>A new secret key.</returns>
        /// <exception cref="ArgumentException">If KeyId's do not match.</exception>
        public static PgpSecretKey ReplacePublicKey(
            PgpSecretKey secretKey,
            PgpPublicKey publicKey)
        {
            if (secretKey == null)
                throw new ArgumentNullException(nameof(secretKey));
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            if (publicKey.KeyId != secretKey.KeyId)
                throw new ArgumentException("KeyId's do not match");

            return new PgpSecretKey(secretKey.secret, publicKey);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
        /// </summary>
        public static PgpSecretKey ParseSecretKeyFromSExpr(Stream inputStream, string passPhrase, PgpPublicKey pubKey)
        {
            return DoParseSecretKeyFromSExpr(inputStream, Encoding.UTF8.GetBytes(passPhrase), pubKey);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
        /// </summary>
        public static PgpSecretKey ParseSecretKeyFromSExpr(Stream inputStream, byte[] rawPassPhrase, PgpPublicKey pubKey)
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
        internal static PgpSecretKey DoParseSecretKeyFromSExpr(Stream inputStream, byte[] rawPassPhrase, PgpPublicKey? pubKey)
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

                byte[] dValue = GetDValue(reader, pubKey.PublicKeyPacket, rawPassPhrase, curveName);

                var keyBytes = new byte[pubKey.PublicKeyPacket.PublicKeyLength + 3 + dValue.Length];
                pubKey.PublicKeyPacket.KeyBytes.AsSpan(0, pubKey.PublicKeyPacket.PublicKeyLength).CopyTo(keyBytes);
                keyBytes[pubKey.PublicKeyPacket.PublicKeyLength] = (byte)S2kUsageTag.None;
                Keys.MPInteger.TryWriteInteger(dValue, keyBytes.AsSpan(pubKey.PublicKeyPacket.PublicKeyLength + 1), out var _);

                return new PgpSecretKey(new SecretKeyPacket(pubKey.Algorithm, pubKey.CreationTime, keyBytes), pubKey);
            }

            throw new PgpException("unknown key type found");
        }

        private static void WriteSExprPublicKey(SXprWriter writer, PublicKeyPacket pubPacket, string curveName, string? protectedAt)
        {
            throw new NotImplementedException();
            /*
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
                    writer.WriteBytes(((ECDsaPublicBcpgKey)pubPacket.Key).EncodedPoint.Value);
                    writer.EndList();
                    break;

                case PgpPublicKeyAlgorithm.RsaEncrypt:
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
                    break;

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
            writer.EndList();*/
        }

        private static byte[] GetDValue(SXprReader reader, PublicKeyPacket publicKey, byte[] rawPassPhrase, string curveName)
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
                    MemoryStream aad = new MemoryStream();
                    WriteSExprPublicKey(new SXprWriter(aad), publicKey, curveName, protectedAt);
                    //key = PgpUtilities.DoMakeKeyFromPassPhrase(PgpSymmetricKeyAlgorithm.Aes128, s2k, rawPassPhrase);
                    /*IBufferedCipher c = CipherUtilities.GetCipher("AES/OCB");
                    c.Init(false, new AeadParameters(key, 128, iv, aad.ToArray()));
                    data = c.DoFinal(secKeyData, 0, secKeyData.Length);*/
                    // TODO: AES/OCB support
                    throw new NotImplementedException();
                //break;

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
