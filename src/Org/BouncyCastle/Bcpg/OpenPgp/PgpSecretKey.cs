using InflatablePalace.Cryptography.Algorithms;
using System;
using System.Collections;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using Ed25519Dsa = InflatablePalace.Cryptography.Algorithms.Ed25519;

namespace Org.BouncyCastle.Bcpg.OpenPgp
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
            SymmetricKeyAlgorithmTag encAlgorithm,
            byte[] rawPassPhrase,
            bool clearPassPhrase,
            bool useSha1,
            bool isMasterKey)
        {
            BcpgKey secKey;

            this.pub = pubKey;

            switch (pubKey.Algorithm)
            {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaSign:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    RSA rsK = (RSA)privKey.Key;
                    var rsKParams = rsK.ExportParameters(true);
                    secKey = new RsaSecretBcpgKey(
                        new MPInteger(rsKParams.D),
                        new MPInteger(rsKParams.P),
                        new MPInteger(rsKParams.Q),
                        new MPInteger(rsKParams.InverseQ));
                    break;
                case PublicKeyAlgorithmTag.Dsa:
                    DSA dsK = (DSA)privKey.Key;
                    var dsKParams = dsK.ExportParameters(true);
                    secKey = new DsaSecretBcpgKey(new MPInteger(dsKParams.X));
                    break;
                case PublicKeyAlgorithmTag.ECDH:
                    ECDiffieHellman ecdhK = (ECDiffieHellman)privKey.Key;
                    var ecdhKParams = ecdhK.ExportParameters(true);
                    secKey = new ECSecretBcpgKey(new MPInteger(ecdhKParams.Curve.Oid.Value != "1.3.6.1.4.1.3029.1.5.1" ? ecdhKParams.D : ecdhKParams.D.Reverse().ToArray()));
                    break;
                case PublicKeyAlgorithmTag.ECDsa:
                case PublicKeyAlgorithmTag.EdDsa:
                    ECDsa ecdsaK = (ECDsa)privKey.Key;
                    var ecdsaKParams = ecdsaK.ExportParameters(true);
                    secKey = new ECSecretBcpgKey(new MPInteger(ecdsaKParams.D));
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    ElGamal esK = (ElGamal)privKey.Key;
                    var esKParams = esK.ExportParameters(true);
                    secKey = new ElGamalSecretBcpgKey(new MPInteger(esKParams.X));
                    break;
                /*case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    ElGamalPrivateKeyParameters esK = (ElGamalPrivateKeyParameters)privKey.Key;
                    secKey = new ElGamalSecretBcpgKey(esK.X);
                    break;*/
                default:
                    throw new PgpException("unknown key class");
            }

            try
            {
                MemoryStream bOut = new MemoryStream();

                secKey.Encode(bOut);

                byte[] keyData = bOut.ToArray();
                byte[] checksumData = Checksum(useSha1, keyData, keyData.Length);

                keyData = keyData.Concat(checksumData).ToArray();

                if (encAlgorithm == SymmetricKeyAlgorithmTag.Null)
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
                    S2k s2k;
                    byte[] iv;

                    byte[] encData;
                    if (pub.Version >= 4)
                    {
                        encData = EncryptKeyDataV4(keyData, encAlgorithm, HashAlgorithmTag.Sha1, rawPassPhrase, clearPassPhrase, out s2k, out iv);
                    }
                    else
                    {
                        encData = EncryptKeyDataV3(keyData, encAlgorithm, rawPassPhrase, clearPassPhrase, out s2k, out iv);
                    }

                    int s2kUsage = useSha1
                        ? SecretKeyPacket.UsageSha1
                        : SecretKeyPacket.UsageChecksum;

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
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception encrypting key", e);
            }
        }

        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        [Obsolete("Use the constructor taking an explicit 'useSha1' parameter instead")]
        public PgpSecretKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets)
            : this(certificationLevel, keyPair, id, encAlgorithm, passPhrase, false, hashedPackets, unhashedPackets)
        {
        }

        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public PgpSecretKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets)
            : this(certificationLevel, keyPair, id, encAlgorithm, false, passPhrase, useSha1, hashedPackets, unhashedPackets)
        {
        }

        /// <remarks>
        /// If utf8PassPhrase is true, conversion of the passphrase to bytes uses Encoding.UTF8.GetBytes(), otherwise the conversion
        /// is performed using Convert.ToByte(), which is the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public PgpSecretKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            bool utf8PassPhrase,
            char[] passPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets)
            : this(certificationLevel, keyPair, id, encAlgorithm, PgpUtilities.EncodePassPhrase(passPhrase, utf8PassPhrase), true, useSha1, hashedPackets, unhashedPackets)
        {
        }

        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public PgpSecretKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            byte[] rawPassPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets)
            : this(certificationLevel, keyPair, id, encAlgorithm, rawPassPhrase, false, useSha1, hashedPackets, unhashedPackets)
        {
        }

        internal PgpSecretKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            byte[] rawPassPhrase,
            bool clearPassPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets)
            : this(keyPair.PrivateKey, CertifiedPublicKey(certificationLevel, keyPair, id, hashedPackets, unhashedPackets), encAlgorithm, rawPassPhrase, clearPassPhrase, useSha1, true)
        {
        }

        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public PgpSecretKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            HashAlgorithmTag hashAlgorithm,
            char[] passPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets)
            : this(certificationLevel, keyPair, id, encAlgorithm, hashAlgorithm, false, passPhrase, useSha1, hashedPackets, unhashedPackets)
        {
        }

        /// <remarks>
        /// If utf8PassPhrase is true, conversion of the passphrase to bytes uses Encoding.UTF8.GetBytes(), otherwise the conversion
        /// is performed using Convert.ToByte(), which is the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public PgpSecretKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            HashAlgorithmTag hashAlgorithm,
            bool utf8PassPhrase,
            char[] passPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets)
            : this(certificationLevel, keyPair, id, encAlgorithm, hashAlgorithm, PgpUtilities.EncodePassPhrase(passPhrase, utf8PassPhrase), true, useSha1, hashedPackets, unhashedPackets)
        {
        }

        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public PgpSecretKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            HashAlgorithmTag hashAlgorithm,
            byte[] rawPassPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets)
            : this(certificationLevel, keyPair, id, encAlgorithm, hashAlgorithm, rawPassPhrase, false, useSha1, hashedPackets, unhashedPackets)
        {
        }

        internal PgpSecretKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            HashAlgorithmTag hashAlgorithm,
            byte[] rawPassPhrase,
            bool clearPassPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets)
            : this(keyPair.PrivateKey, CertifiedPublicKey(certificationLevel, keyPair, id, hashedPackets, unhashedPackets, hashAlgorithm), encAlgorithm, rawPassPhrase, clearPassPhrase, useSha1, true)
        {
        }

        private static PgpPublicKey CertifiedPublicKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets)
        {
            PgpSignatureGenerator sGen = new PgpSignatureGenerator(HashAlgorithmTag.Sha1);

            //
            // Generate the certification
            //
            sGen.InitSign(certificationLevel, keyPair.PrivateKey);

            sGen.SetHashedSubpackets(hashedPackets);
            sGen.SetUnhashedSubpackets(unhashedPackets);

            try
            {
                PgpSignature certification = sGen.GenerateCertification(id, keyPair.PublicKey);
                return PgpPublicKey.AddCertification(keyPair.PublicKey, id, certification);
            }
            catch (Exception e)
            {
                throw new PgpException("Exception doing certification: " + e.Message, e);
            }
        }


        private static PgpPublicKey CertifiedPublicKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            HashAlgorithmTag hashAlgorithm)
        {
            PgpSignatureGenerator sGen = new PgpSignatureGenerator(hashAlgorithm);

            //
            // Generate the certification
            //
            sGen.InitSign(certificationLevel, keyPair.PrivateKey);

            sGen.SetHashedSubpackets(hashedPackets);
            sGen.SetUnhashedSubpackets(unhashedPackets);

            try
            {
                PgpSignature certification = sGen.GenerateCertification(id, keyPair.PublicKey);
                return PgpPublicKey.AddCertification(keyPair.PublicKey, id, certification);
            }
            catch (Exception e)
            {
                throw new PgpException("Exception doing certification: " + e.Message, e);
            }
        }

        public PgpSecretKey(
            int certificationLevel,
            AsymmetricAlgorithm keyPair,
            DateTime time,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets)
            : this(certificationLevel, new PgpKeyPair(keyPair, time), id, encAlgorithm, passPhrase, false, hashedPackets, unhashedPackets)
        {
        }

        public PgpSecretKey(
            int certificationLevel,
            AsymmetricAlgorithm keyPair,
            DateTime time,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets)
            : this(certificationLevel, new PgpKeyPair(keyPair, time), id, encAlgorithm, passPhrase, useSha1, hashedPackets, unhashedPackets)
        {
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
                    case PublicKeyAlgorithmTag.RsaGeneral:
                    case PublicKeyAlgorithmTag.RsaSign:
                    case PublicKeyAlgorithmTag.Dsa:
                    case PublicKeyAlgorithmTag.ECDsa:
                    case PublicKeyAlgorithmTag.EdDsa:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
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
                byte[] secKeyData = secret.GetSecretKeyData();

                return secKeyData == null || secKeyData.Length < 1;
            }
        }

        /// <summary>The algorithm the key is encrypted with.</summary>
        public SymmetricKeyAlgorithmTag KeyEncryptionAlgorithm
        {
            get { return secret.EncAlgorithm; }
        }

        /// <summary>The key ID of the public key associated with this key.</summary>
        public long KeyId
        {
            get { return pub.KeyId; }
        }

        /// <summary>Return the S2K usage associated with this key.</summary>
        public int S2kUsage
        {
            get { return secret.S2kUsage; }
        }

        /// <summary>Return the S2K used to process this key.</summary>
        public S2k S2k
        {
            get { return secret.S2k; }
        }

        /// <summary>The public key associated with this key.</summary>
        public PgpPublicKey PublicKey
        {
            get { return pub; }
        }

        /// <summary>Allows enumeration of any user IDs associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        public IEnumerable UserIds
        {
            get { return pub.GetUserIds(); }
        }

        /// <summary>Allows enumeration of any user attribute vectors associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        public IEnumerable UserAttributes
        {
            get { return pub.GetUserAttributes(); }
        }

        private byte[] ExtractKeyData(byte[] rawPassPhrase, bool clearPassPhrase)
        {
            SymmetricKeyAlgorithmTag encAlgorithm = secret.EncAlgorithm;
            byte[] encData = secret.GetSecretKeyData();

            if (encAlgorithm == SymmetricKeyAlgorithmTag.Null)
                // TODO Check checksum here?
                return encData;

            // TODO Factor this block out as 'decryptData'
            try
            {
                byte[] key = PgpUtilities.DoMakeKeyFromPassPhrase(secret.EncAlgorithm, secret.S2k, rawPassPhrase, clearPassPhrase);
                byte[] iv = secret.GetIV();
                byte[] data;

                if (secret.PublicKeyPacket.Version >= 4)
                {
                    data = RecoverKeyData(encAlgorithm, CipherMode.CFB, key, iv, encData, 0, encData.Length);

                    bool useSha1 = secret.S2kUsage == SecretKeyPacket.UsageSha1;
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
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception decrypting key", e);
            }
        }

        private static byte[] RecoverKeyData(SymmetricKeyAlgorithmTag encAlgorithm, CipherMode cipherMode,
            byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
        {
            var c = PgpUtilities.GetSymmetricAlgorithm(encAlgorithm);
            c.Mode = cipherMode;
            var decryptor = new ZeroPaddedCryptoTransformWrapper(c.CreateDecryptor(key, iv));
            return decryptor.TransformFinalBlock(keyData, keyOff, keyLen);
        }

        /// <summary>Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public PgpPrivateKey ExtractPrivateKey(char[] passPhrase)
        {
            return DoExtractPrivateKey(PgpUtilities.EncodePassPhrase(passPhrase, false), true);
        }

        /// <summary>Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8 (Encoding.UTF8.GetBytes).
        /// </remarks>
        public PgpPrivateKey ExtractPrivateKeyUtf8(char[] passPhrase)
        {
            return DoExtractPrivateKey(PgpUtilities.EncodePassPhrase(passPhrase, true), true);
        }

        /// <summary>Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public PgpPrivateKey ExtractPrivateKeyRaw(byte[] rawPassPhrase)
        {
            return DoExtractPrivateKey(rawPassPhrase, false);
        }

        internal PgpPrivateKey DoExtractPrivateKey(byte[] rawPassPhrase, bool clearPassPhrase)
        {
            if (IsPrivateKeyEmpty)
                return null;

            PublicKeyPacket pubPk = secret.PublicKeyPacket;
            try
            {
                byte[] data = ExtractKeyData(rawPassPhrase, clearPassPhrase);
                var bcpgIn = new MemoryStream(data, false);
                AsymmetricAlgorithm privateKey;
                switch (pubPk.Algorithm)
                {
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                    case PublicKeyAlgorithmTag.RsaSign:
                        RsaPublicBcpgKey rsaPub = (RsaPublicBcpgKey)pubPk.Key;
                        RsaSecretBcpgKey rsaPriv = new RsaSecretBcpgKey(bcpgIn);

                        // The modulus size determines the encoded output size of the CRT parameters.
                        byte[] n = rsaPub.Modulus.Value;
                        int halfModulusLength = (n.Length + 1) / 2;

                        var privateExponent = new BigInteger(rsaPriv.PrivateExponent.Value, isBigEndian: true, isUnsigned: true);
                        var DP = BigInteger.Remainder(privateExponent, new BigInteger(rsaPriv.PrimeP.Value, isBigEndian: true, isUnsigned: true) - BigInteger.One);
                        var DQ = BigInteger.Remainder(privateExponent, new BigInteger(rsaPriv.PrimeQ.Value, isBigEndian: true, isUnsigned: true) - BigInteger.One);

                        var rsaParameters = new RSAParameters
                        {
                            Modulus = n,
                            Exponent = rsaPub.PublicExponent.Value,
                            D = ExportKeyParameter(rsaPriv.PrivateExponent.Value, n.Length),
                            P = ExportKeyParameter(rsaPriv.PrimeP.Value, halfModulusLength),
                            Q = ExportKeyParameter(rsaPriv.PrimeQ.Value, halfModulusLength),
                            DP = ExportKeyParameter(DP, halfModulusLength),
                            DQ = ExportKeyParameter(DQ, halfModulusLength),
                            InverseQ = ExportKeyParameter(rsaPriv.InverseQ.Value, halfModulusLength),
                        };
                        privateKey = RSA.Create(rsaParameters);
                        break;
                    case PublicKeyAlgorithmTag.Dsa:
                        DsaPublicBcpgKey dsaPub = (DsaPublicBcpgKey)pubPk.Key;
                        DsaSecretBcpgKey dsaPriv = new DsaSecretBcpgKey(bcpgIn);
                        privateKey = DSA.Create(new DSAParameters
                        {
                            X = dsaPriv.X.Value,
                            Y = dsaPub.Y.Value,
                            P = dsaPub.P.Value,
                            Q = dsaPub.Q.Value,
                            G = dsaPub.G.Value,
                        });
                        break;
                    case PublicKeyAlgorithmTag.ECDH:
                    case PublicKeyAlgorithmTag.ECDsa:
                        ECPublicBcpgKey ecdsaPub = (ECPublicBcpgKey)secret.PublicKeyPacket.Key;
                        ECSecretBcpgKey ecdsaPriv = new ECSecretBcpgKey(bcpgIn);
                        var ecCurve = ECCurve.CreateFromOid(ecdsaPub.CurveOid);
                        var ecParams = new ECParameters
                        {
                            Curve = ecCurve,
                            D = ecCurve.Oid.Value != "1.3.6.1.4.1.3029.1.5.1" ? ecdsaPriv.X.Value : ecdsaPriv.X.Value.Reverse().ToArray(),
                            Q = PgpUtilities.DecodePoint(ecdsaPub.EncodedPoint),
                        };
                        privateKey = pubPk.Algorithm == PublicKeyAlgorithmTag.ECDH ? PgpUtilities.GetECDiffieHellman(ecParams) : ECDsa.Create(ecParams);
                        break;
                    case PublicKeyAlgorithmTag.EdDsa:
                        ECPublicBcpgKey eddsaPub = (ECPublicBcpgKey)secret.PublicKeyPacket.Key;
                        ECSecretBcpgKey eddsaPriv = new ECSecretBcpgKey(bcpgIn);
                        privateKey = new Ed25519Dsa(
                            eddsaPriv.X.Value,
                            eddsaPub.EncodedPoint.Value.AsSpan(1).ToArray());
                        break;
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        ElGamalPublicBcpgKey elPub = (ElGamalPublicBcpgKey)pubPk.Key;
                        ElGamalSecretBcpgKey elPriv = new ElGamalSecretBcpgKey(bcpgIn);
                        ElGamalParameters elParams = new ElGamalParameters { P = elPub.P.Value, G = elPub.G.Value, Y = elPub.Y.Value, X = elPriv.X.Value };
                        privateKey = ElGamal.Create(elParams);
                        break; 
                     /*
                     case PublicKeyAlgorithmTag.ElGamalEncrypt:
                     case PublicKeyAlgorithmTag.ElGamalGeneral:
                         ElGamalPublicBcpgKey elPub = (ElGamalPublicBcpgKey)pubPk.Key;
                         ElGamalSecretBcpgKey elPriv = new ElGamalSecretBcpgKey(bcpgIn);
                         ElGamalParameters elParams = new ElGamalParameters(elPub.P, elPub.G);
                         privateKey = new ElGamalPrivateKeyParameters(elPriv.X, elParams);
                         break;*/
                     default:
                        throw new PgpException("unknown public key algorithm encountered");
                }

                return new PgpPrivateKey(KeyId, pubPk, privateKey);
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception constructing key", e);
            }
        }

        private byte[] ExportKeyParameter(byte[] value, int length)
        {
            if (value.Length < length)
            {
                byte[] target = new byte[length];
                value.CopyTo(target, length - value.Length);
                return target;
            }
            return value;
        }

        private byte[] ExportKeyParameter(BigInteger value, int length)
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

        /*private ECPrivateKeyParameters GetECKey(string algorithm, BcpgInputStream bcpgIn)
         {
             ECPublicBcpgKey ecdsaPub = (ECPublicBcpgKey)secret.PublicKeyPacket.Key;
             ECSecretBcpgKey ecdsaPriv = new ECSecretBcpgKey(bcpgIn);
             return new ECPrivateKeyParameters(algorithm, ecdsaPriv.X, ecdsaPub.CurveOid);
         }*/

        private static byte[] Checksum(
            bool useSha1,
            byte[] bytes,
            int length)
        {
            if (useSha1)
            {
                return SHA1.Create().ComputeHash(bytes, 0, length);
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

        public override void Encode(PacketWriter outStr)
        {
            outStr.WritePacket(secret);

            if (pub.trustPk != null)
            {
                outStr.WritePacket(pub.trustPk);
            }

            if (pub.subSigs == null) // is not a sub key
            {
                foreach (PgpSignature keySig in pub.keySigs)
                {
                    keySig.Encode(outStr);
                }

                for (int i = 0; i != pub.ids.Count; i++)
                {
                    object pubID = pub.ids[i];
                    if (pubID is string)
                    {
                        string id = (string)pubID;
                        outStr.WritePacket(new UserIdPacket(id));
                    }
                    else
                    {
                        PgpUserAttributeSubpacketVector v = (PgpUserAttributeSubpacketVector)pubID;
                        outStr.WritePacket(new UserAttributePacket(v.ToSubpacketArray()));
                    }

                    if (pub.idTrusts[i] != null)
                    {
                        outStr.WritePacket(pub.idTrusts[i]);
                    }

                    foreach (PgpSignature sig in (IList)pub.idSigs[i])
                    {
                        sig.Encode(outStr);
                    }
                }
            }
            else
            {
                foreach (PgpSignature subSig in pub.subSigs)
                {
                    subSig.Encode(outStr);
                }
            }
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
        /// <param name="rand">Source of randomness.</param>
        public static PgpSecretKey CopyWithNewPassword(
            PgpSecretKey key,
            char[] oldPassPhrase,
            char[] newPassPhrase,
            SymmetricKeyAlgorithmTag newEncAlgorithm)
        {
            return DoCopyWithNewPassword(key, PgpUtilities.EncodePassPhrase(oldPassPhrase, false),
                PgpUtilities.EncodePassPhrase(newPassPhrase, false), true, newEncAlgorithm);
        }

        /// <summary>
        /// Return a copy of the passed in secret key, encrypted using a new password
        /// and the passed in algorithm.
        /// </summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8 (Encoding.UTF8.GetBytes).
        /// </remarks>
        /// <param name="key">The PgpSecretKey to be copied.</param>
        /// <param name="oldPassPhrase">The current password for the key.</param>
        /// <param name="newPassPhrase">The new password for the key.</param>
        /// <param name="newEncAlgorithm">The algorithm to be used for the encryption.</param>
        /// <param name="rand">Source of randomness.</param>
        public static PgpSecretKey CopyWithNewPasswordUtf8(
            PgpSecretKey key,
            char[] oldPassPhrase,
            char[] newPassPhrase,
            SymmetricKeyAlgorithmTag newEncAlgorithm)
        {
            return DoCopyWithNewPassword(key, PgpUtilities.EncodePassPhrase(oldPassPhrase, true),
                PgpUtilities.EncodePassPhrase(newPassPhrase, true), true, newEncAlgorithm);
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
        public static PgpSecretKey CopyWithNewPasswordRaw(
            PgpSecretKey key,
            byte[] rawOldPassPhrase,
            byte[] rawNewPassPhrase,
            SymmetricKeyAlgorithmTag newEncAlgorithm)
        {
            return DoCopyWithNewPassword(key, rawOldPassPhrase, rawNewPassPhrase, false, newEncAlgorithm);
        }

        internal static PgpSecretKey DoCopyWithNewPassword(
            PgpSecretKey key,
            byte[] rawOldPassPhrase,
            byte[] rawNewPassPhrase,
            bool clearPassPhrase,
            SymmetricKeyAlgorithmTag newEncAlgorithm)
        {
            if (key.IsPrivateKeyEmpty)
                throw new PgpException("no private key in this SecretKey - public key present only.");

            byte[] rawKeyData = key.ExtractKeyData(rawOldPassPhrase, clearPassPhrase);
            int s2kUsage = key.secret.S2kUsage;
            byte[] iv = null;
            S2k s2k = null;
            byte[] keyData;
            PublicKeyPacket pubKeyPacket = key.secret.PublicKeyPacket;

            if (newEncAlgorithm == SymmetricKeyAlgorithmTag.Null)
            {
                s2kUsage = SecretKeyPacket.UsageNone;
                if (key.secret.S2kUsage == SecretKeyPacket.UsageSha1)   // SHA-1 hash, need to rewrite Checksum
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
                if (s2kUsage == SecretKeyPacket.UsageNone)
                {
                    s2kUsage = SecretKeyPacket.UsageChecksum;
                }

                try
                {
                    if (pubKeyPacket.Version >= 4)
                    {
                        keyData = EncryptKeyDataV4(rawKeyData, newEncAlgorithm, HashAlgorithmTag.Sha1, rawNewPassPhrase, clearPassPhrase, out s2k, out iv);
                    }
                    else
                    {
                        keyData = EncryptKeyDataV3(rawKeyData, newEncAlgorithm, rawNewPassPhrase, clearPassPhrase, out s2k, out iv);
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
            if (publicKey.KeyId != secretKey.KeyId)
                throw new ArgumentException("KeyId's do not match");

            return new PgpSecretKey(secretKey.secret, publicKey);
        }

        private static byte[] EncryptKeyDataV3(
            byte[] rawKeyData,
            SymmetricKeyAlgorithmTag encAlgorithm,
            byte[] rawPassPhrase,
            bool clearPassPhrase,
            out S2k s2k,
            out byte[] iv)
        {
            // Version 2 or 3 - RSA Keys only

            s2k = null;
            iv = null;

            byte[] encKey = PgpUtilities.DoMakeKeyFromPassPhrase(encAlgorithm, s2k, rawPassPhrase, clearPassPhrase);

            byte[] keyData = new byte[rawKeyData.Length];

            //
            // process 4 numbers
            //
            int pos = 0;
            for (int i = 0; i != 4; i++)
            {
                int encLen = ((((rawKeyData[pos] & 0xff) << 8) | (rawKeyData[pos + 1] & 0xff)) + 7) / 8;

                keyData[pos] = rawKeyData[pos];
                keyData[pos + 1] = rawKeyData[pos + 1];

                if (encLen > (rawKeyData.Length - (pos + 2)))
                    throw new PgpException("out of range encLen found in rawKeyData");

                byte[] tmp;
                if (i == 0)
                {
                    tmp = EncryptData(encAlgorithm, encKey, rawKeyData, pos + 2, encLen, ref iv);
                }
                else
                {
                    byte[] tmpIv = keyData.AsSpan(pos - iv.Length, iv.Length).ToArray();
                    tmp = EncryptData(encAlgorithm, encKey, rawKeyData, pos + 2, encLen, ref tmpIv);
                }

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
            SymmetricKeyAlgorithmTag encAlgorithm,
            HashAlgorithmTag hashAlgorithm,
            byte[] rawPassPhrase,
            bool clearPassPhrase,
            out S2k s2k,
            out byte[] iv)
        {
            s2k = PgpUtilities.GenerateS2k(hashAlgorithm, 0x60);
            byte[] key = PgpUtilities.DoMakeKeyFromPassPhrase(encAlgorithm, s2k, rawPassPhrase, clearPassPhrase);
            iv = null;
            return EncryptData(encAlgorithm, key, rawKeyData, 0, rawKeyData.Length, ref iv);
        }

        private static byte[] EncryptData(
            SymmetricKeyAlgorithmTag encAlgorithm,
            byte[] key,
            byte[] data,
            int dataOff,
            int dataLen,
            ref byte[] iv)
        {
            var c = PgpUtilities.GetSymmetricAlgorithm(encAlgorithm);
            if (iv == null)
            {
                iv = PgpUtilities.GenerateIV((c.BlockSize + 7) / 8);
            }
            var encryptor = new ZeroPaddedCryptoTransformWrapper(c.CreateEncryptor(key, iv));
            return encryptor.TransformFinalBlock(data, dataOff, dataLen);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
        /// </summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public static PgpSecretKey ParseSecretKeyFromSExpr(Stream inputStream, char[] passPhrase, PgpPublicKey pubKey)
        {
            return DoParseSecretKeyFromSExpr(inputStream, PgpUtilities.EncodePassPhrase(passPhrase, false), true, pubKey);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
        /// </summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8 (Encoding.UTF8.GetBytes).
        /// </remarks>
        public static PgpSecretKey ParseSecretKeyFromSExprUtf8(Stream inputStream, char[] passPhrase, PgpPublicKey pubKey)
        {
            return DoParseSecretKeyFromSExpr(inputStream, PgpUtilities.EncodePassPhrase(passPhrase, true), true, pubKey);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
        /// </summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public static PgpSecretKey ParseSecretKeyFromSExprRaw(Stream inputStream, byte[] rawPassPhrase, PgpPublicKey pubKey)
        {
            return DoParseSecretKeyFromSExpr(inputStream, rawPassPhrase, false, pubKey);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys.
        /// </summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public static PgpSecretKey ParseSecretKeyFromSExpr(Stream inputStream, char[] passPhrase)
        {
            return DoParseSecretKeyFromSExpr(inputStream, PgpUtilities.EncodePassPhrase(passPhrase, false), true, null);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys.
        /// </summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8 (Encoding.UTF8.GetBytes).
        /// </remarks>
        public static PgpSecretKey ParseSecretKeyFromSExprUtf8(Stream inputStream, char[] passPhrase)
        {
            return DoParseSecretKeyFromSExpr(inputStream, PgpUtilities.EncodePassPhrase(passPhrase, true), true, null);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys.
        /// </summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public static PgpSecretKey ParseSecretKeyFromSExprRaw(Stream inputStream, byte[] rawPassPhrase)
        {
            return DoParseSecretKeyFromSExpr(inputStream, rawPassPhrase, false, null);
        }

        /// <summary>
        /// Parse a secret key from one of the GPG S expression keys.
        /// </summary>
        internal static PgpSecretKey DoParseSecretKeyFromSExpr(Stream inputStream, byte[] rawPassPhrase, bool clearPassPhrase, PgpPublicKey pubKey)
        {
            SXprReader reader = new SXprReader(inputStream);

            reader.SkipOpenParenthesis();

            string type = reader.ReadString();
            if (type.Equals("protected-private-key"))
            {
                reader.SkipOpenParenthesis();

                string curveName;
                Oid curveOid;

                string keyType = reader.ReadString();
                if (keyType.Equals("ecc"))
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
                string flags = null;

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
                if (type.Equals("q"))
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
                        flags == "eddsa" ? PublicKeyAlgorithmTag.EdDsa : PublicKeyAlgorithmTag.ECDsa, DateTime.UtcNow,
                        new ECDsaPublicBcpgKey(curveOid, new MPInteger(qVal)));
                    pubKey = new PgpPublicKey(pubPacket);
                }

                reader.SkipCloseParenthesis();

                byte[] dValue = GetDValue(reader, pubKey.PublicKeyPacket, rawPassPhrase, clearPassPhrase, curveName);

                return new PgpSecretKey(new SecretKeyPacket(pubKey.PublicKeyPacket, SymmetricKeyAlgorithmTag.Null, null, null,
                    new MPInteger(dValue).GetEncoded()), pubKey);
            }

            throw new PgpException("unknown key type found");
        }

        private static void WriteSExprPublicKey(SXprWriter writer, PublicKeyPacket pubPacket, string curveName, string protectedAt)
        {
            writer.StartList();
            switch (pubPacket.Algorithm)
            {
                case PublicKeyAlgorithmTag.ECDsa:
                case PublicKeyAlgorithmTag.EdDsa:
                    writer.WriteString("ecc");
                    writer.StartList();
                    writer.WriteString("curve");
                    writer.WriteString(curveName);
                    writer.EndList();
                    if (pubPacket.Algorithm == PublicKeyAlgorithmTag.EdDsa)
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

                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaSign:
                case PublicKeyAlgorithmTag.RsaGeneral:
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

        private static byte[] GetDValue(SXprReader reader, PublicKeyPacket publicKey, byte[] rawPassPhrase, bool clearPassPhrase, string curveName)
        {
            string type;
            reader.SkipOpenParenthesis();

            string protection;
            string protectedAt = null;
            S2k s2k;
            byte[] iv;
            byte[] secKeyData;

            type = reader.ReadString();
            if (type.Equals("protected"))
            {
                protection = reader.ReadString();

                reader.SkipOpenParenthesis();

                s2k = reader.ParseS2k();

                iv = reader.ReadBytes();

                reader.SkipCloseParenthesis();

                secKeyData = reader.ReadBytes();

                reader.SkipCloseParenthesis();

                reader.SkipOpenParenthesis();

                if (reader.ReadString().Equals("protected-at"))
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
                    SymmetricKeyAlgorithmTag symmAlg =
                        protection.Equals("openpgp-s2k3-sha1-aes256-cbc") ? SymmetricKeyAlgorithmTag.Aes256 : SymmetricKeyAlgorithmTag.Aes128;
                    key = PgpUtilities.DoMakeKeyFromPassPhrase(symmAlg, s2k, rawPassPhrase, clearPassPhrase);
                    data = RecoverKeyData(symmAlg, CipherMode.CBC, key, iv, secKeyData, 0, secKeyData.Length);
                    // TODO: check SHA-1 hash.
                    break;

                case "openpgp-s2k3-ocb-aes":
                    MemoryStream aad = new MemoryStream();
                    WriteSExprPublicKey(new SXprWriter(aad), publicKey, curveName, protectedAt);
                    key = PgpUtilities.DoMakeKeyFromPassPhrase(SymmetricKeyAlgorithmTag.Aes128, s2k, rawPassPhrase, clearPassPhrase);
                    /*IBufferedCipher c = CipherUtilities.GetCipher("AES/OCB");
                    c.Init(false, new AeadParameters(key, 128, iv, aad.ToArray()));
                    data = c.DoFinal(secKeyData, 0, secKeyData.Length);*/
                    // TODO: AES/OCB support
                    throw new NotImplementedException();
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
