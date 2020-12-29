using InflatablePalace.Cryptography.Helpers;
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
        private bool withIntegrityPacket;
        private Stream? pOut;
        private CryptoStream? cOut;
        private CryptoStream? digestOut;
        private HashAlgorithm? digest;

        private abstract class EncMethod
        {
            public abstract ContainedPacket GetSessionInfoPacket(byte[] sessionInfo);
        }

        private class PbeMethod : EncMethod
        {
            private S2k s2k;
            private PgpSymmetricKeyAlgorithm encAlgorithm;
            private byte[] key;

            public PbeMethod(
                PgpSymmetricKeyAlgorithm encAlgorithm,
                S2k s2k,
                byte[] key)
            {
                this.encAlgorithm = encAlgorithm;
                this.s2k = s2k;
                this.key = key;
            }

            public byte[] GetKey() => key;

            public SymmetricKeyEncSessionPacket GetSessionInfoPacket()
            {
                return new SymmetricKeyEncSessionPacket(encAlgorithm, s2k, null);
            }

            public override ContainedPacket GetSessionInfoPacket(byte[] sessionInfo)
            {
                using var symmetricAlgorithm = PgpUtilities.GetSymmetricAlgorithm(encAlgorithm);
                using var encryptor = new ZeroPaddedCryptoTransform(symmetricAlgorithm.CreateEncryptor(key, new byte[(symmetricAlgorithm.BlockSize + 7) / 8]));
                return new SymmetricKeyEncSessionPacket(encAlgorithm, s2k, encryptor.TransformFinalBlock(sessionInfo, 0, sessionInfo.Length - 2));
            }
        }

        private class PubMethod : EncMethod
        {
            private PgpPublicKey pubKey;

            public PubMethod(PgpPublicKey pubKey)
            {
                this.pubKey = pubKey;
            }

            public override ContainedPacket GetSessionInfoPacket(byte[] sessionInfo)
            {
                Debug.Assert(sessionInfo != null);
                return new PublicKeyEncSessionPacket(pubKey.KeyId, pubKey.Algorithm, pubKey.EncryptSessionInfo(sessionInfo));
            }
        }

        private readonly IList<EncMethod> methods = new List<EncMethod>();
        private readonly PgpSymmetricKeyAlgorithm defAlgorithm;

        /// <summary>Base constructor.</summary>
        /// <param name="encAlgorithm">The symmetric algorithm to use.</param>
        /// <param name="withIntegrityPacket">Use integrity packet.</param>
        public PgpEncryptedMessageGenerator(
            IPacketWriter packetWriter,
            PgpSymmetricKeyAlgorithm encAlgorithm,
            bool withIntegrityPacket = false)
            : base(packetWriter)
        {
            this.defAlgorithm = encAlgorithm;
            this.withIntegrityPacket = withIntegrityPacket;
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        public void AddMethod(string passPhrase, PgpHashAlgorithm s2kDigest)
        {
            AddMethod(Encoding.UTF8.GetBytes(passPhrase), s2kDigest);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        public void AddMethod(byte[] rawPassPhrase, PgpHashAlgorithm s2kDigest)
        {
            S2k s2k = PgpUtilities.GenerateS2k(s2kDigest, 0x60);
            methods.Add(new PbeMethod(defAlgorithm, s2k, PgpUtilities.DoMakeKeyFromPassPhrase(defAlgorithm, s2k, rawPassPhrase)));
        }

        /// <summary>Add a public key encrypted session key to the encrypted object.</summary>
        public void AddMethod(PgpPublicKey key)
        {
            if (!key.IsEncryptionKey)
            {
                throw new ArgumentException("passed in key not an encryption key!");
            }

            methods.Add(new PubMethod(key));
        }

        private static void AddCheckSum(
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

        private static byte[] CreateSessionInfo(
            PgpSymmetricKeyAlgorithm algorithm,
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
            // TODO: Do we want compatibility with old PGP? (IDEA + no password iirc)
            if (methods.Count == 0)
                throw new InvalidOperationException("No encryption methods specified");

            var c = PgpUtilities.GetSymmetricAlgorithm(defAlgorithm);

            if (methods.Count == 1 && methods[0] is PbeMethod)
            {
                PbeMethod m = (PbeMethod)methods[0];
                c.Key = m.GetKey();
                writer.WritePacket(m.GetSessionInfoPacket());
            }
            else
            {
                c.GenerateKey();
                byte[] sessionInfo = CreateSessionInfo(defAlgorithm, c.Key);

                foreach (EncMethod m in methods)
                {
                    writer.WritePacket(m.GetSessionInfoPacket(sessionInfo));
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

                Stream myOut = cOut = new CryptoStream(pOut, new ZeroPaddedCryptoTransform(encryptor), CryptoStreamMode.Write);

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
            Debug.Assert(cOut != null);
            Debug.Assert(pOut != null);

            // TODO Should this all be under the try/catch block?
            if (digestOut != null)
            {
                // hand code a mod detection packet
                digestOut.Write(new byte[] { 0xd3, 0x14 });
                digestOut.FlushFinalBlock();

                byte[] dig = digest!.Hash!;
                cOut.Write(dig, 0, dig.Length);
            }

            cOut.FlushFinalBlock();
            cOut = null;

            pOut.Close();
            pOut = null;
        }
    }
}
