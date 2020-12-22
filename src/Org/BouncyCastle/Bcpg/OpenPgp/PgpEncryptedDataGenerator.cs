using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using InflatablePalace.Cryptography.Algorithms;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Generator for encrypted objects.</summary>
    public class PgpEncryptedDataGenerator : IStreamGenerator
    {
        private Stream pOut;
        private CryptoStream cOut;
        private SymmetricAlgorithm c;
        private bool withIntegrityPacket;
        private CryptoStream digestOut;
        private HashAlgorithm digest;

        private abstract class EncMethod : ContainedPacket
        {
            public abstract void AddSessionInfo(byte[] si);
        }

        private class PbeMethod : EncMethod
        {
            private S2k s2k;
            private byte[] sessionInfo;
            private SymmetricKeyAlgorithmTag encAlgorithm;
            private byte[] key;

            internal PbeMethod(
                SymmetricKeyAlgorithmTag encAlgorithm,
                S2k s2k,
                byte[] key)
            {
                this.encAlgorithm = encAlgorithm;
                this.s2k = s2k;
                this.key = key;
            }

            public byte[] GetKey()
            {
                return key;
            }

            public override void AddSessionInfo(byte[] si)
            {
                using var symmetricAlgorithm = PgpUtilities.GetSymmetricAlgorithm(encAlgorithm);
                using var encryptor = new ZeroPaddedCryptoTransformWrapper(symmetricAlgorithm.CreateEncryptor(key, new byte[(symmetricAlgorithm.BlockSize + 7) / 8]));
                this.sessionInfo = encryptor.TransformFinalBlock(si, 0, si.Length - 2);
            }

            public override PacketTag Tag => PacketTag.SymmetricKeyEncryptedSessionKey;

            public override void Encode(Stream pOut)
            {
                SymmetricKeyEncSessionPacket pk = new SymmetricKeyEncSessionPacket(encAlgorithm, s2k, sessionInfo);
                pk.Encode(pOut);
            }
        }

        private class PubMethod : EncMethod
        {
            internal PgpPublicKey pubKey;
            internal bool sessionKeyObfuscation;
            internal byte[] data;

            internal PubMethod(PgpPublicKey pubKey, bool sessionKeyObfuscation)
            {
                this.pubKey = pubKey;
                this.sessionKeyObfuscation = sessionKeyObfuscation;
            }

            public override void AddSessionInfo(byte[] sessionInfo)
            {
                this.data = EncryptSessionInfo(sessionInfo);
            }

            private byte[] EncryptSessionInfo(byte[] sessionInfo)
            {
                if (pubKey.Algorithm == PublicKeyAlgorithmTag.RsaEncrypt || pubKey.Algorithm == PublicKeyAlgorithmTag.RsaGeneral)
                {
                    var asymmetricAlgorithm = pubKey.GetKey() as RSA;
                    return asymmetricAlgorithm.Encrypt(sessionInfo, RSAEncryptionPadding.Pkcs1);
                }

                if (pubKey.Algorithm == PublicKeyAlgorithmTag.ECDH)
                {
                    var otherPartyKey = pubKey.GetKey() as ECDiffieHellman;
                    ECDHPublicBcpgKey ecKey = (ECDHPublicBcpgKey)pubKey.PublicKeyPacket.Key;

                    // Generate the ephemeral key pair
                    var ecCurve = ECCurve.CreateFromOid(ecKey.CurveOid);
                    var ecdh = PgpUtilities.GetECDiffieHellman(ecCurve);
                    var derivedKey = ecdh.DeriveKeyFromHash(
                        otherPartyKey.PublicKey,
                        PgpUtilities.GetHashAlgorithmName(ecKey.HashAlgorithm),
                        new byte[] { 0, 0, 0, 1 },
                        Rfc6637Utilities.CreateUserKeyingMaterial(pubKey.PublicKeyPacket));

                    derivedKey = derivedKey.AsSpan(0, PgpUtilities.GetKeySize(ecKey.SymmetricKeyAlgorithm) / 8).ToArray();

                    byte[] paddedSessionData = PgpPad.PadSessionData(sessionInfo, sessionKeyObfuscation);
                    byte[] C = KeyWrapAlgorithm.WrapKey(derivedKey, paddedSessionData);
                    var ep = ecdh.PublicKey.ExportParameters();
                    byte[] VB = PgpUtilities.EncodePoint(ep.Q).GetEncoded();
                    byte[] rv = new byte[VB.Length + 1 + C.Length];
                    Array.Copy(VB, 0, rv, 0, VB.Length);
                    rv[VB.Length] = (byte)C.Length;
                    Array.Copy(C, 0, rv, VB.Length + 1, C.Length);

                    return rv;
                }

                if (pubKey.Algorithm == PublicKeyAlgorithmTag.ElGamalEncrypt || pubKey.Algorithm == PublicKeyAlgorithmTag.ElGamalGeneral)
                {
                    var asymmetricAlgorithm = pubKey.GetKey() as ElGamal;
                    return asymmetricAlgorithm.Encrypt(sessionInfo, RSAEncryptionPadding.Pkcs1).ToArray();
                }

                // TODO: ElGamal
                throw new NotImplementedException();
            }

            public override PacketTag Tag => PacketTag.PublicKeyEncryptedSession;

            public override void Encode(Stream pOut)
            {
                PublicKeyEncSessionPacket pk = new PublicKeyEncSessionPacket(pubKey.KeyId, pubKey.Algorithm, data);
                pk.Encode(pOut);
            }
        }

        private readonly IList<EncMethod> methods = new List<EncMethod>();
        private readonly SymmetricKeyAlgorithmTag defAlgorithm;

        /// <summary>Base constructor.</summary>
        /// <param name="encAlgorithm">The symmetric algorithm to use.</param>
        /// <param name="withIntegrityPacket">Use integrity packet.</param>
        public PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag encAlgorithm,
            bool withIntegrityPacket = false)
        {
            this.defAlgorithm = encAlgorithm;
            this.withIntegrityPacket = withIntegrityPacket;
        }

        /// <summary>
        /// Add a PBE encryption method to the encrypted object using the default algorithm (S2K_SHA1).
        /// </summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        [Obsolete("Use version that takes an explicit s2kDigest parameter")]
        public void AddMethod(char[] passPhrase)
        {
            AddMethod(passPhrase, HashAlgorithmTag.Sha1);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public void AddMethod(char[] passPhrase, HashAlgorithmTag s2kDigest)
        {
            DoAddMethod(PgpUtilities.EncodePassPhrase(passPhrase, false), true, s2kDigest);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8 (Encoding.UTF8.GetBytes).
        /// </remarks>
        public void AddMethodUtf8(char[] passPhrase, HashAlgorithmTag s2kDigest)
        {
            DoAddMethod(PgpUtilities.EncodePassPhrase(passPhrase, true), true, s2kDigest);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public void AddMethodRaw(byte[] rawPassPhrase, HashAlgorithmTag s2kDigest)
        {
            DoAddMethod(rawPassPhrase, false, s2kDigest);
        }

        internal void DoAddMethod(byte[] rawPassPhrase, bool clearPassPhrase, HashAlgorithmTag s2kDigest)
        {
            S2k s2k = PgpUtilities.GenerateS2k(s2kDigest, 0x60);
            methods.Add(new PbeMethod(defAlgorithm, s2k, PgpUtilities.DoMakeKeyFromPassPhrase(defAlgorithm, s2k, rawPassPhrase, clearPassPhrase)));
        }

        /// <summary>Add a public key encrypted session key to the encrypted object.</summary>
        public void AddMethod(PgpPublicKey key)
        {
            AddMethod(key, true);
        }

        public void AddMethod(PgpPublicKey key, bool sessionKeyObfuscation)
        {
            if (!key.IsEncryptionKey)
            {
                throw new ArgumentException("passed in key not an encryption key!");
            }

            methods.Add(new PubMethod(key, sessionKeyObfuscation));
        }

        private void AddCheckSum(
            byte[] sessionInfo)
        {
            Debug.Assert(sessionInfo != null);
            Debug.Assert(sessionInfo.Length >= 3);

            int check = 0;

            for (int i = 1; i < sessionInfo.Length - 2; i++)
            {
                check += sessionInfo[i];
            }

            sessionInfo[sessionInfo.Length - 2] = (byte)(check >> 8);
            sessionInfo[sessionInfo.Length - 1] = (byte)(check);
        }

        private byte[] CreateSessionInfo(
            SymmetricKeyAlgorithmTag algorithm,
            byte[] keyBytes)
        {
            byte[] sessionInfo = new byte[keyBytes.Length + 3];
            sessionInfo[0] = (byte)algorithm;
            keyBytes.CopyTo(sessionInfo, 1);
            AddCheckSum(sessionInfo);
            return sessionInfo;
        }

        /// <summary>
        /// Return an output stream which will encrypt the data as it is written to it.
        /// </summary>
        public IPacketWriter Open(IPacketWriter writer)
        {
            if (writer == null)
                throw new ArgumentNullException(nameof(writer));
            if (cOut != null)
                throw new InvalidOperationException("generator already in open state");
            if (methods.Count == 0)
                throw new InvalidOperationException("No encryption methods specified");

            c = PgpUtilities.GetSymmetricAlgorithm(defAlgorithm);

            if (methods.Count == 1)
            {
                if (methods[0] is PbeMethod)
                {
                    PbeMethod m = (PbeMethod)methods[0];
                    c.Key = m.GetKey();
                }
                else
                {
                    c.GenerateKey();

                    byte[] sessionInfo = CreateSessionInfo(defAlgorithm, c.Key);
                    PubMethod m = (PubMethod)methods[0];
                    m.AddSessionInfo(sessionInfo);
                }

                writer.WritePacket(methods[0]);
            }
            else // multiple methods
            {
                c.GenerateKey();
                byte[] sessionInfo = CreateSessionInfo(defAlgorithm, c.Key);

                foreach (EncMethod m in methods)
                {
                    m.AddSessionInfo(sessionInfo);
                    writer.WritePacket(m);
                }
            }

            try
            {
                // TODO Confirm the IV should be all zero bytes (not inLineIv - see below)
                c.IV = new byte[c.BlockSize / 8];

                if (withIntegrityPacket)
                {
                    pOut = writer.GetPacketStream(new SymmetricEncIntegrityPacket());
                }
                else
                {
                    pOut = writer.GetPacketStream(new SymmetricEncDataPacket());
                }

                int blockSize = c.BlockSize / 8;
                byte[] inLineIv = new byte[blockSize + 2];
                RandomNumberGenerator.Fill(inLineIv.AsSpan(0, blockSize));
                Array.Copy(inLineIv, inLineIv.Length - 4, inLineIv, inLineIv.Length - 2, 2);

                ICryptoTransform encryptor;
                if (withIntegrityPacket)
                {
                    encryptor = c.CreateEncryptor();
                }
                else
                {
                    c.Mode = CipherMode.ECB;
                    encryptor = new OpenPGPCFBTransformWrapper(c.CreateEncryptor(), c.IV, true);
                }

                Stream myOut = cOut = new CryptoStream(pOut, new ZeroPaddedCryptoTransformWrapper(encryptor), CryptoStreamMode.Write);

                if (withIntegrityPacket)
                {
                    digest = SHA1.Create();
                    myOut = digestOut = new CryptoStream(new FilterStream(myOut), digest, CryptoStreamMode.Write);
                }

                myOut.Write(inLineIv, 0, inLineIv.Length);

                return writer.CreateNestedWriter(new WrappedGeneratorStream(this, myOut));
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }
        }

        void IStreamGenerator.Close()
        {
            if (cOut != null)
            {
                // TODO Should this all be under the try/catch block?
                if (digestOut != null)
                {
                    // hand code a mod detection packet
                    digestOut.Write(new byte[] { 0xd3, 0x14 });
                    digestOut.FlushFinalBlock();

                    byte[] dig = digest.Hash;
                    cOut.Write(dig, 0, dig.Length);
                }

                cOut.FlushFinalBlock();
                cOut = null;

                pOut.Close();
                pOut = null;
            }
        }
    }
}
