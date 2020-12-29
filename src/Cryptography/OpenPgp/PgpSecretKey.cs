using Springburg.Cryptography.Algorithms;
using Springburg.Cryptography.Helpers;
using Springburg.Cryptography.OpenPgp.Packet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Ed25519Dsa = Springburg.Cryptography.Algorithms.Ed25519;

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
            byte[] rawPassPhrase,
            bool useSha1,
            bool isMasterKey)
        {
            BcpgKey secKey;

            this.pub = pubKey;

            switch (pubKey.Algorithm)
            {
                case PgpPublicKeyAlgorithm.RsaEncrypt:
                case PgpPublicKeyAlgorithm.RsaSign:
                case PgpPublicKeyAlgorithm.RsaGeneral:
                    RSA rsK = (RSA)privKey.Key;
                    var rsKParams = rsK.ExportParameters(true);
                    secKey = new RsaSecretBcpgKey(
                        new MPInteger(rsKParams.D),
                        new MPInteger(rsKParams.P),
                        new MPInteger(rsKParams.Q),
                        new MPInteger(rsKParams.InverseQ));
                    break;
                case PgpPublicKeyAlgorithm.Dsa:
                    DSA dsK = (DSA)privKey.Key;
                    var dsKParams = dsK.ExportParameters(true);
                    secKey = new DsaSecretBcpgKey(new MPInteger(dsKParams.X));
                    break;
                case PgpPublicKeyAlgorithm.ECDH:
                    ECDiffieHellman ecdhK = (ECDiffieHellman)privKey.Key;
                    var ecdhKParams = ecdhK.ExportParameters(true);
                    secKey = new ECSecretBcpgKey(new MPInteger(ecdhKParams.Curve.Oid.Value != "1.3.6.1.4.1.3029.1.5.1" ? ecdhKParams.D : ecdhKParams.D!.Reverse().ToArray()));
                    break;
                case PgpPublicKeyAlgorithm.ECDsa:
                case PgpPublicKeyAlgorithm.EdDsa:
                    ECDsa ecdsaK = (ECDsa)privKey.Key;
                    var ecdsaKParams = ecdsaK.ExportParameters(true);
                    secKey = new ECSecretBcpgKey(new MPInteger(ecdsaKParams.D));
                    break;
                case PgpPublicKeyAlgorithm.ElGamalEncrypt:
                case PgpPublicKeyAlgorithm.ElGamalGeneral:
                    ElGamal esK = (ElGamal)privKey.Key;
                    var esKParams = esK.ExportParameters(true);
                    secKey = new ElGamalSecretBcpgKey(new MPInteger(esKParams.X));
                    break;
                default:
                    throw new PgpException("unknown key class");
            }

            // FIXME: All this should be cleared out from memory
            byte[] keyData = Array.Empty<byte>();

            try
            {
                MemoryStream bOut = new MemoryStream();
                secKey.Encode(bOut);
                bOut.Write(Checksum(useSha1, bOut.GetBuffer(), (int)bOut.Length));
                keyData = bOut.ToArray();

                if (encAlgorithm == PgpSymmetricKeyAlgorithm.Null)
                {
                    if (isMasterKey)
                    {
                        this.secret = new SecretKeyPacket(pub.publicPk, encAlgorithm, null, null, keyData);
                    }
                    else
                    {
                        this.secret = new SecretSubkeyPacket(pub.publicPk, encAlgorithm, null, null, keyData);
                    }
                }
                else
                {
                    S2k? s2k;
                    byte[]? iv;
                    byte[] encData;

                    if (pub.Version >= 4)
                    {
                        encData = EncryptKeyDataV4(keyData, encAlgorithm, PgpHashAlgorithm.Sha1, rawPassPhrase, out s2k, out iv);
                    }
                    else
                    {
                        encData = EncryptKeyDataV3(keyData, encAlgorithm, rawPassPhrase, out s2k, out iv);
                    }

                    S2kUsageTag s2kUsage = useSha1 ? S2kUsageTag.Sha1 : S2kUsageTag.Checksum;

                    if (isMasterKey)
                    {
                        this.secret = new SecretKeyPacket(pub.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
                    }
                    else
                    {
                        this.secret = new SecretSubkeyPacket(pub.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
                    }
                }
            }
            finally
            {
                if (encAlgorithm != PgpSymmetricKeyAlgorithm.Null)
                {
                    CryptographicOperations.ZeroMemory(keyData);
                }
            }
        }

        /// <summary>
        /// Check if this key has an algorithm type that makes it suitable to use for signing.
        /// </summary>
        /// <remarks>
        /// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
        /// determining the preferred use of the key.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if this key algorithm is suitable for use with signing.
        /// </returns>
        public bool IsSigningKey
        {
            get
            {
                switch (pub.Algorithm)
                {
                    case PgpPublicKeyAlgorithm.RsaGeneral:
                    case PgpPublicKeyAlgorithm.RsaSign:
                    case PgpPublicKeyAlgorithm.Dsa:
                    case PgpPublicKeyAlgorithm.ECDsa:
                    case PgpPublicKeyAlgorithm.EdDsa:
                    case PgpPublicKeyAlgorithm.ElGamalGeneral:
                        return true;
                    default:
                        return false;
                }
            }
        }

        /// <summary>True, if this is a master key.</summary>
        public bool IsMasterKey
        {
            get { return pub.IsMasterKey; }
        }

        /// <summary>Detect if the Secret Key's Private Key is empty or not</summary>
        public bool IsPrivateKeyEmpty
        {
            get
            {
                byte[]? secKeyData = secret.GetSecretKeyData();
                return secKeyData == null || secKeyData.Length == 0;
            }
        }

        /// <summary>The algorithm the key is encrypted with.</summary>
        public PgpSymmetricKeyAlgorithm KeyEncryptionAlgorithm
        {
            get { return secret.EncAlgorithm; }
        }

        /// <summary>The key ID of the public key associated with this key.</summary>
        public long KeyId => pub.KeyId;

        /// <summary>The public key associated with this key.</summary>
        public PgpPublicKey PublicKey => pub;

        /// <summary>Allows enumeration of any user IDs associated with the key.</summary>
        public IEnumerable<PgpUser> UserIds => pub.GetUserIds();

        /// <summary>Allows enumeration of any user attribute vectors associated with the key.</summary>
        public IEnumerable<PgpUser> UserAttributes => pub.GetUserAttributes();

        private byte[] ExtractKeyData(byte[] rawPassPhrase)
        {
            PgpSymmetricKeyAlgorithm encAlgorithm = secret.EncAlgorithm;
            byte[] encData = secret.GetSecretKeyData() ?? Array.Empty<byte>();

            if (encAlgorithm == PgpSymmetricKeyAlgorithm.Null)
                // TODO Check checksum here?
                return encData;

            // TODO Factor this block out as 'decryptData'
            byte[] key = PgpUtilities.DoMakeKeyFromPassPhrase(secret.EncAlgorithm, secret.S2k, rawPassPhrase);
            byte[] iv = secret.GetIV().ToArray();
            byte[] data;

            if (secret.PublicKeyPacket.Version >= 4)
            {
                data = RecoverKeyData(encAlgorithm, CipherMode.CFB, key, iv, encData, 0, encData.Length);

                bool useSha1 = secret.S2kUsage == S2kUsageTag.Sha1;
                byte[] check = Checksum(useSha1, data, (useSha1) ? data.Length - 20 : data.Length - 2);

                for (int i = 0; i != check.Length; i++)
                {
                    if (check[i] != data[data.Length - check.Length + i])
                    {
                        throw new PgpException("Checksum mismatch at " + i + " of " + check.Length);
                    }
                }
            }
            else // version 2 or 3, RSA only.
            {
                data = new byte[encData.Length];

                iv = (byte[])iv.Clone();

                //
                // read in the four numbers
                //
                int pos = 0;

                for (int i = 0; i != 4; i++)
                {
                    int encLen = ((((encData[pos] & 0xff) << 8) | (encData[pos + 1] & 0xff)) + 7) / 8;

                    data[pos] = encData[pos];
                    data[pos + 1] = encData[pos + 1];
                    pos += 2;

                    if (encLen > (encData.Length - pos))
                        throw new PgpException("out of range encLen found in encData");

                    byte[] tmp = RecoverKeyData(encAlgorithm, CipherMode.CFB, key, iv, encData, pos, encLen);
                    Array.Copy(tmp, 0, data, pos, encLen);
                    pos += encLen;

                    if (i != 3)
                    {
                        Array.Copy(encData, pos - iv.Length, iv, 0, iv.Length);
                    }
                }

                //
                // verify and copy checksum
                //

                data[pos] = encData[pos];
                data[pos + 1] = encData[pos + 1];

                int cs = ((encData[pos] << 8) & 0xff00) | (encData[pos + 1] & 0xff);
                int calcCs = 0;
                for (int j = 0; j < pos; j++)
                {
                    calcCs += data[j] & 0xff;
                }

                calcCs &= 0xffff;
                if (calcCs != cs)
                {
                    throw new PgpException("Checksum mismatch: passphrase wrong, expected "
                        + cs.ToString("X")
                        + " found " + calcCs.ToString("X"));
                }
            }

            return data;
        }

        private static byte[] RecoverKeyData(PgpSymmetricKeyAlgorithm encAlgorithm, CipherMode cipherMode,
            byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
        {
            using var c = PgpUtilities.GetSymmetricAlgorithm(encAlgorithm);
            c.Mode = cipherMode;
            using var decryptor = new ZeroPaddedCryptoTransform(c.CreateDecryptor(key, iv.ToArray()));
            return decryptor.TransformFinalBlock(keyData, keyOff, keyLen);
        }

        /// <summary>Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8 (Encoding.UTF8.GetBytes).
        /// </remarks>
        public PgpPrivateKey? ExtractPrivateKey(string passPhrase)
        {
            return ExtractPrivateKey(Encoding.UTF8.GetBytes(passPhrase));
        }

        /// <summary>Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public PgpPrivateKey? ExtractPrivateKey(byte[] rawPassPhrase)
        {
            if (IsPrivateKeyEmpty)
                return null;

            PublicKeyPacket pubPk = secret.PublicKeyPacket;
            byte[] data = ExtractKeyData(rawPassPhrase);
            var bcpgIn = new MemoryStream(data, false);
            AsymmetricAlgorithm privateKey;
            switch (pubPk.Algorithm)
            {
                case PgpPublicKeyAlgorithm.RsaEncrypt:
                case PgpPublicKeyAlgorithm.RsaGeneral:
                case PgpPublicKeyAlgorithm.RsaSign:
                    RsaPublicBcpgKey rsaPub = (RsaPublicBcpgKey)pubPk.Key;
                    RsaSecretBcpgKey rsaPriv = new RsaSecretBcpgKey(bcpgIn);

                    // The modulus size determines the encoded output size of the CRT parameters.
                    byte[] n = rsaPub.Modulus.Value;
                    int halfModulusLength = (n.Length + 1) / 2;

                    var privateExponent = new BigInteger(rsaPriv.PrivateExponent.Value, isBigEndian: true, isUnsigned: true);
                    var P = new BigInteger(rsaPriv.PrimeP.Value, isBigEndian: true, isUnsigned: true);
                    var Q = new BigInteger(rsaPriv.PrimeQ.Value, isBigEndian: true, isUnsigned: true);
                    var DP = BigInteger.Remainder(privateExponent, P - BigInteger.One);
                    var DQ = BigInteger.Remainder(privateExponent, Q - BigInteger.One);
                    // Lot of the public keys in the test suite have this wrong (switched P/Q)
                    var InverseQ = BigInteger.ModPow(Q, P - BigInteger.One - BigInteger.One, P);

                    var rsaParameters = new RSAParameters
                    {
                        Modulus = n,
                        Exponent = rsaPub.PublicExponent.Value,
                        D = ExportKeyParameter(rsaPriv.PrivateExponent.Value, n.Length),
                        P = ExportKeyParameter(rsaPriv.PrimeP.Value, halfModulusLength),
                        Q = ExportKeyParameter(rsaPriv.PrimeQ.Value, halfModulusLength),
                        DP = ExportKeyParameter(DP, halfModulusLength),
                        DQ = ExportKeyParameter(DQ, halfModulusLength),
                        InverseQ = ExportKeyParameter(/*rsaPriv.InverseQ.Value*/InverseQ, halfModulusLength),
                    };
                    privateKey = RSA.Create(rsaParameters);
                    break;

                case PgpPublicKeyAlgorithm.Dsa:
                    DsaPublicBcpgKey dsaPub = (DsaPublicBcpgKey)pubPk.Key;
                    DsaSecretBcpgKey dsaPriv = new DsaSecretBcpgKey(bcpgIn);
                    int xqSize = Math.Max(dsaPriv.X.Value.Length, dsaPub.Q.Value.Length);
                    privateKey = DSA.Create(new DSAParameters
                    {
                        X = ExportKeyParameter(dsaPriv.X.Value, xqSize),
                        Y = dsaPub.Y.Value,
                        P = dsaPub.P.Value,
                        Q = ExportKeyParameter(dsaPub.Q.Value, xqSize),
                        G = dsaPub.G.Value,
                    });
                    break;

                case PgpPublicKeyAlgorithm.ECDH:
                case PgpPublicKeyAlgorithm.ECDsa:
                    ECPublicBcpgKey ecdsaPub = (ECPublicBcpgKey)secret.PublicKeyPacket.Key;
                    ECSecretBcpgKey ecdsaPriv = new ECSecretBcpgKey(bcpgIn);
                    var ecCurve = ECCurve.CreateFromOid(ecdsaPub.CurveOid);
                    var qPoint = PgpUtilities.DecodePoint(ecdsaPub.EncodedPoint);
                    var ecParams = new ECParameters
                    {
                        Curve = ecCurve,
                        D = ExportKeyParameter(ecCurve.Oid.Value != "1.3.6.1.4.1.3029.1.5.1" ? ecdsaPriv.X.Value : ecdsaPriv.X.Value.Reverse().ToArray(), qPoint.X!.Length),
                        Q = qPoint,
                    };
                    privateKey = pubPk.Algorithm == PgpPublicKeyAlgorithm.ECDH ? PgpUtilities.GetECDiffieHellman(ecParams) : ECDsa.Create(ecParams);
                    break;

                case PgpPublicKeyAlgorithm.EdDsa:
                    ECPublicBcpgKey eddsaPub = (ECPublicBcpgKey)secret.PublicKeyPacket.Key;
                    ECSecretBcpgKey eddsaPriv = new ECSecretBcpgKey(bcpgIn);
                    privateKey = new Ed25519Dsa(
                        eddsaPriv.X.Value,
                        eddsaPub.EncodedPoint.Value.AsSpan(1).ToArray());
                    break;

                case PgpPublicKeyAlgorithm.ElGamalEncrypt:
                case PgpPublicKeyAlgorithm.ElGamalGeneral:
                    ElGamalPublicBcpgKey elPub = (ElGamalPublicBcpgKey)pubPk.Key;
                    ElGamalSecretBcpgKey elPriv = new ElGamalSecretBcpgKey(bcpgIn);
                    ElGamalParameters elParams = new ElGamalParameters { P = elPub.P.Value, G = elPub.G.Value, Y = elPub.Y.Value, X = elPriv.X.Value };
                    privateKey = ElGamal.Create(elParams);
                    break;

                default:
                    throw new PgpException("unknown public key algorithm encountered");
            }

            return new PgpPrivateKey(KeyId, pubPk, privateKey);
        }

        private static byte[] ExportKeyParameter(byte[] value, int length)
        {
            if (value.Length < length)
            {
                byte[] target = new byte[length];
                value.CopyTo(target, length - value.Length);
                return target;
            }
            return value;
        }

        private static byte[] ExportKeyParameter(BigInteger value, int length)
        {
            byte[] target = new byte[length];

            if (value.TryWriteBytes(target, out int bytesWritten, isUnsigned: true, isBigEndian: true))
            {
                if (bytesWritten < length)
                {
                    Buffer.BlockCopy(target, 0, target, length - bytesWritten, bytesWritten);
                    target.AsSpan(0, length - bytesWritten).Clear();
                }

                return target;
            }

            throw new CryptographicException(); //SR.Cryptography_NotValidPublicOrPrivateKey);
        }

        private static byte[] Checksum(
            bool useSha1,
            byte[] bytes,
            int length)
        {
            if (useSha1)
            {
                using var sha1 = SHA1.Create();
                return sha1.ComputeHash(bytes, 0, length);
            }
            else
            {
                int Checksum = 0;
                for (int i = 0; i != length; i++)
                {
                    Checksum += bytes[i];
                }

                return new byte[] { (byte)(Checksum >> 8), (byte)Checksum };
            }
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
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        /// <param name="key">The PgpSecretKey to be copied.</param>
        /// <param name="oldPassPhrase">The current password for the key.</param>
        /// <param name="newPassPhrase">The new password for the key.</param>
        /// <param name="newEncAlgorithm">The algorithm to be used for the encryption.</param>
        public static PgpSecretKey CopyWithNewPassword(
            PgpSecretKey key,
            string oldPassPhrase,
            string newPassPhrase,
            PgpSymmetricKeyAlgorithm newEncAlgorithm)
        {
            return CopyWithNewPassword(key, Encoding.UTF8.GetBytes(oldPassPhrase), Encoding.UTF8.GetBytes(newPassPhrase), newEncAlgorithm);
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
        /// <param name="newEncAlgorithm">The algorithm to be used for the encryption.</param>
        /// <param name="rand">Source of randomness.</param>
        public static PgpSecretKey CopyWithNewPassword(
            PgpSecretKey key,
            byte[] rawOldPassPhrase,
            byte[] rawNewPassPhrase,
            PgpSymmetricKeyAlgorithm newEncAlgorithm)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.IsPrivateKeyEmpty)
                throw new PgpException("no private key in this SecretKey - public key present only.");

            byte[] rawKeyData = key.ExtractKeyData(rawOldPassPhrase);
            S2kUsageTag s2kUsage = key.secret.S2kUsage;
            byte[]? iv = null;
            S2k? s2k = null;
            byte[] keyData;
            PublicKeyPacket pubKeyPacket = key.secret.PublicKeyPacket;

            if (newEncAlgorithm == PgpSymmetricKeyAlgorithm.Null)
            {
                s2kUsage = S2kUsageTag.None;
                if (key.secret.S2kUsage == S2kUsageTag.Sha1)   // SHA-1 hash, need to rewrite Checksum
                {
                    keyData = new byte[rawKeyData.Length - 18];

                    Array.Copy(rawKeyData, 0, keyData, 0, keyData.Length - 2);

                    byte[] check = Checksum(false, keyData, keyData.Length - 2);

                    keyData[keyData.Length - 2] = check[0];
                    keyData[keyData.Length - 1] = check[1];
                }
                else
                {
                    keyData = rawKeyData;
                }
            }
            else
            {
                if (s2kUsage == S2kUsageTag.None)
                {
                    s2kUsage = S2kUsageTag.Checksum;
                }

                try
                {
                    if (pubKeyPacket.Version >= 4)
                    {
                        keyData = EncryptKeyDataV4(rawKeyData, newEncAlgorithm, PgpHashAlgorithm.Sha1, rawNewPassPhrase, out s2k, out iv);
                    }
                    else
                    {
                        keyData = EncryptKeyDataV3(rawKeyData, newEncAlgorithm, rawNewPassPhrase, out s2k, out iv);
                    }
                }
                catch (PgpException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new PgpException("Exception encrypting key", e);
                }
            }

            SecretKeyPacket secret;
            if (key.secret is SecretSubkeyPacket)
            {
                secret = new SecretSubkeyPacket(pubKeyPacket, newEncAlgorithm, s2kUsage, s2k, iv, keyData);
            }
            else
            {
                secret = new SecretKeyPacket(pubKeyPacket, newEncAlgorithm, s2kUsage, s2k, iv, keyData);
            }

            return new PgpSecretKey(secret, key.pub);
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

        private static byte[] EncryptKeyDataV3(
            byte[] rawKeyData,
            PgpSymmetricKeyAlgorithm encAlgorithm,
            byte[] rawPassPhrase,
            out S2k? s2k,
            out byte[]? iv)
        {
            // Version 2 or 3 - RSA Keys only

            s2k = null;

            byte[] keyData = new byte[rawKeyData.Length];

            //
            // process 4 numbers
            //
            int pos = 0;
            using var c = PgpUtilities.GetSymmetricAlgorithm(encAlgorithm);
            c.Key = PgpUtilities.DoMakeKeyFromPassPhrase(encAlgorithm, s2k, rawPassPhrase);
            c.GenerateIV();
            iv = c.IV;
            for (int i = 0; i != 4; i++)
            {
                int encLen = ((((rawKeyData[pos] & 0xff) << 8) | (rawKeyData[pos + 1] & 0xff)) + 7) / 8;

                keyData[pos] = rawKeyData[pos];
                keyData[pos + 1] = rawKeyData[pos + 1];

                if (encLen > (rawKeyData.Length - (pos + 2)))
                    throw new PgpException("out of range encLen found in rawKeyData");

                byte[] tmp;
                if (i != 0)
                {
                    c.IV = keyData.AsSpan(pos - iv.Length, iv.Length).ToArray();
                }
                using var encryptor = new ZeroPaddedCryptoTransform(c.CreateEncryptor());
                tmp = encryptor.TransformFinalBlock(rawKeyData, pos + 2, encLen);

                Array.Copy(tmp, 0, keyData, pos + 2, tmp.Length);
                pos += 2 + encLen;
            }

            //
            // copy in checksum.
            //
            keyData[pos] = rawKeyData[pos];
            keyData[pos + 1] = rawKeyData[pos + 1];

            return keyData;
        }

        private static byte[] EncryptKeyDataV4(
            byte[] rawKeyData,
            PgpSymmetricKeyAlgorithm encAlgorithm,
            PgpHashAlgorithm hashAlgorithm,
            byte[] rawPassPhrase,
            out S2k? s2k,
            out byte[]? iv)
        {
            using var c = PgpUtilities.GetSymmetricAlgorithm(encAlgorithm);
            c.GenerateIV();
            iv = c.IV;
            s2k = PgpUtilities.GenerateS2k(hashAlgorithm, 0x60);
            c.Key = PgpUtilities.DoMakeKeyFromPassPhrase(encAlgorithm, s2k, rawPassPhrase);
            using var encryptor = new ZeroPaddedCryptoTransform(c.CreateEncryptor());
            return encryptor.TransformFinalBlock(rawKeyData, 0, rawKeyData.Length);
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
                    PublicKeyPacket pubPacket = new PublicKeyPacket(
                        flags == "eddsa" ? PgpPublicKeyAlgorithm.EdDsa : PgpPublicKeyAlgorithm.ECDsa, DateTime.UtcNow,
                        new ECDsaPublicBcpgKey(curveOid, new MPInteger(qVal)));
                    pubKey = new PgpPublicKey(pubPacket);
                }

                reader.SkipCloseParenthesis();

                byte[] dValue = GetDValue(reader, pubKey.PublicKeyPacket, rawPassPhrase, curveName);

                return new PgpSecretKey(new SecretKeyPacket(pubKey.PublicKeyPacket, PgpSymmetricKeyAlgorithm.Null, null, null,
                    new MPInteger(dValue).GetEncoded()), pubKey);
            }

            throw new PgpException("unknown key type found");
        }

        private static void WriteSExprPublicKey(SXprWriter writer, PublicKeyPacket pubPacket, string curveName, string? protectedAt)
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
            writer.EndList();
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
            byte[] key;

            switch (protection)
            {
                case "openpgp-s2k3-sha1-aes256-cbc":
                case "openpgp-s2k3-sha1-aes-cbc":
                    PgpSymmetricKeyAlgorithm symmAlg =
                        protection.Equals("openpgp-s2k3-sha1-aes256-cbc", StringComparison.Ordinal) ?
                        PgpSymmetricKeyAlgorithm.Aes256 :
                        PgpSymmetricKeyAlgorithm.Aes128;
                    key = PgpUtilities.DoMakeKeyFromPassPhrase(symmAlg, s2k, rawPassPhrase);
                    data = RecoverKeyData(symmAlg, CipherMode.CBC, key, iv, secKeyData, 0, secKeyData.Length);
                    // TODO: check SHA-1 hash.
                    break;

                case "openpgp-s2k3-ocb-aes":
                    MemoryStream aad = new MemoryStream();
                    WriteSExprPublicKey(new SXprWriter(aad), publicKey, curveName, protectedAt);
                    key = PgpUtilities.DoMakeKeyFromPassPhrase(PgpSymmetricKeyAlgorithm.Aes128, s2k, rawPassPhrase);
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
