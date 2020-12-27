using InflatablePalace.Cryptography.Algorithms;
using InflatablePalace.Cryptography.OpenPgp.Packet;
using InflatablePalace.IO;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace InflatablePalace.Cryptography.OpenPgp
{
    /// <summary>Generator for encrypted objects.</summary>
    public class PgpEncryptedMessageGenerator : PgpMessageGenerator
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
                return pubKey.EncryptSessionInfo(sessionInfo);
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
        public PgpEncryptedMessageGenerator(
            IPacketWriter packetWriter,
            SymmetricKeyAlgorithmTag encAlgorithm,
            bool withIntegrityPacket = false)
            : base(packetWriter)
        {
            this.defAlgorithm = encAlgorithm;
            this.withIntegrityPacket = withIntegrityPacket;
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        public void AddMethod(string passPhrase, HashAlgorithmTag s2kDigest)
        {
            AddMethod(Encoding.UTF8.GetBytes(passPhrase), s2kDigest);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        public void AddMethod(byte[] rawPassPhrase, HashAlgorithmTag s2kDigest)
        {
            S2k s2k = PgpUtilities.GenerateS2k(s2kDigest, 0x60);
            methods.Add(new PbeMethod(defAlgorithm, s2k, PgpUtilities.DoMakeKeyFromPassPhrase(defAlgorithm, s2k, rawPassPhrase)));
        }

        /// <summary>Add a public key encrypted session key to the encrypted object.</summary>
        public void AddMethod(PgpPublicKey key, bool sessionKeyObfuscation = true)
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
        protected override IPacketWriter Open()
        {
            var writer = base.Open();

            if (cOut != null)
                throw new InvalidOperationException("generator already in open state");
            if (methods.Count == 0)
                throw new InvalidOperationException("No encryption methods specified");

            c = PgpUtilities.GetSymmetricAlgorithm(defAlgorithm);

            if (methods.Count == 1 && methods[0] is PbeMethod)
            {
                PbeMethod m = (PbeMethod)methods[0];
                c.Key = m.GetKey();
                writer.WritePacket(methods[0]);
            }
            else
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
                if (withIntegrityPacket)
                {
                    pOut = writer.GetPacketStream(new SymmetricEncIntegrityPacket());
                }
                else
                {
                    pOut = writer.GetPacketStream(new SymmetricEncDataPacket());
                }

                int blockSize = (c.BlockSize + 7) / 8;
                byte[] inLineIv = new byte[blockSize * 2]; // Aligned to block size
                RandomNumberGenerator.Fill(inLineIv.AsSpan(0, blockSize));
                inLineIv[blockSize] = inLineIv[blockSize - 2];
                inLineIv[blockSize + 1] = inLineIv[blockSize - 1];

                ICryptoTransform encryptor;
                c.IV = new byte[blockSize];
                if (withIntegrityPacket)
                {
                    encryptor = c.CreateEncryptor();
                }
                else
                {
                    encryptor = c.CreateEncryptor();
                    var encryptedInlineIv = encryptor.TransformFinalBlock(inLineIv, 0, inLineIv.Length);
                    pOut.Write(encryptedInlineIv.AsSpan(0, blockSize + 2));
                    c.IV = encryptedInlineIv.AsSpan(2, blockSize).ToArray();
                    encryptor = c.CreateEncryptor();
                }

                Stream myOut = cOut = new CryptoStream(pOut, new ZeroPaddedCryptoTransformWrapper(encryptor), CryptoStreamMode.Write);

                if (withIntegrityPacket)
                {
                    digest = SHA1.Create();
                    myOut = digestOut = new CryptoStream(new FilterStream(myOut), digest, CryptoStreamMode.Write);
                    myOut.Write(inLineIv, 0, blockSize + 2);
                }

                return writer.CreateNestedWriter(new WrappedGeneratorStream(myOut, _ => Close()));
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }
        }

        void Close()
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
