using InflatablePalace.Cryptography.Algorithms;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpEncryptedMessage : PgpMessage
    {
        private List<PublicKeyEncSessionPacket> publicKeyEncSessionPackets;
        private List<SymmetricKeyEncSessionPacket> symmetricKeyEncSessionPackets;
        private InputStreamPacket encryptedPacket;
        private IPacketReader packetReader;
        private CryptoStream encStream;
        private HashAlgorithm hashAlgorithm;
        private TailEndCryptoTransform tailEndCryptoTransform;

        internal PgpEncryptedMessage(IPacketReader packetReader)
        {
            this.packetReader = packetReader;
            this.publicKeyEncSessionPackets = new List<PublicKeyEncSessionPacket>();
            this.symmetricKeyEncSessionPackets = new List<SymmetricKeyEncSessionPacket>();

            var packets = new List<Packet>();
            while (packetReader.NextPacketTag() == PacketTag.PublicKeyEncryptedSession ||
                   packetReader.NextPacketTag() == PacketTag.SymmetricKeyEncryptedSessionKey)
            {
                var keyPacket = packetReader.ReadPacket();
                if (keyPacket is SymmetricKeyEncSessionPacket symmetricKeyEncSessionPacket)
                {
                    symmetricKeyEncSessionPackets.Add(symmetricKeyEncSessionPacket);
                }
                else
                {
                    publicKeyEncSessionPackets.Add((PublicKeyEncSessionPacket)keyPacket);
                }
                packets.Add(keyPacket);
            }

            Packet packet = packetReader.ReadPacket();
            if (!(packet is SymmetricEncDataPacket) &&
                !(packet is SymmetricEncIntegrityPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            this.encryptedPacket = (InputStreamPacket)packet;
        }

        public IEnumerable<long> KeyIds => publicKeyEncSessionPackets.Select(pk => pk.KeyId);

        public PgpMessage DecryptMessage(PgpPrivateKey privateKey)
        {
            foreach (var keyData in publicKeyEncSessionPackets)
            {
                if (keyData.KeyId == privateKey.KeyId)
                {
                    byte[] sessionData = Array.Empty<byte>();
                    try
                    {
                        sessionData = GetSessionData(keyData, privateKey);

                        if (!ConfirmCheckSum(sessionData))
                        {
                            throw new PgpException("Checksum validation failed");
                        }

                        // Note: the oracle attack on the "quick check" bytes is deemed
                        // a security risk for typical public key encryption usages.
                        //return GetDataStream(symmAlg, sessionData.AsSpan(1, sessionData.Length - 3), verifyIntegrity: false);
                        return ReadMessage(packetReader.CreateNestedReader(GetDataStream(sessionData.AsSpan(0, sessionData.Length - 2), verifyIntegrity: false)));
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(sessionData.AsSpan());
                    }
                }
            }

            throw new PgpException("No matching key data found");
        }

        public PgpMessage DecryptMessage(string password)
        {
            return DecryptMessage(Encoding.UTF8.GetBytes(password));
        }

        public PgpMessage DecryptMessage(byte[] rawPassword)
        {
            foreach (var keyData in symmetricKeyEncSessionPackets)
            {
                byte[] sessionData = Array.Empty<byte>();
                try
                {
                    sessionData = GetSessionData(keyData, rawPassword);
                    return ReadMessage(packetReader.CreateNestedReader(GetDataStream(sessionData, verifyIntegrity: true)));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(sessionData.AsSpan());
                }
            }

            throw new PgpException("No PBE data found or password mismatch");
        }

        /// <summary>Return true if the message is integrity protected.</summary>
        /// <returns>True, if there is a modification detection code namespace associated
        /// with this stream.</returns>
        public bool IsIntegrityProtected => encryptedPacket is SymmetricEncIntegrityPacket;

        /// <summary>Verify the MDC packet, if present</summary>
        /// <remarks>Note: This can only be called after the message has been read.</remarks>
        /// <returns>True, if the message verifies, false otherwise</returns>
        public bool Verify()
        {
            if (!IsIntegrityProtected)
                return false;

            // Make sure we are at the end of the stream
            encStream.CopyTo(Stream.Null);

            // process the MDC packet
            var digest = hashAlgorithm.Hash;
            var streamDigest = tailEndCryptoTransform.TailEnd;

            return CryptographicOperations.FixedTimeEquals(digest, streamDigest);
        }

        private Stream GetDataStream(ReadOnlySpan<byte> sessionData, bool verifyIntegrity)
        {
            SymmetricKeyAlgorithmTag keyAlgorithm = (SymmetricKeyAlgorithmTag)sessionData[0];

            if (keyAlgorithm == SymmetricKeyAlgorithmTag.Null)
                return encryptedPacket.GetInputStream();

            var key = sessionData.Slice(1);
            SymmetricAlgorithm encryptionAlgorithm = PgpUtilities.GetSymmetricAlgorithm(keyAlgorithm);
            var iv = new byte[(encryptionAlgorithm.BlockSize + 7) / 8];
            byte[] keyArray = Array.Empty<byte>();
            ICryptoTransform decryptor;

            try
            {
                keyArray = key.ToArray();
                if (encryptedPacket is SymmetricEncIntegrityPacket)
                {
                    decryptor = encryptionAlgorithm.CreateDecryptor(keyArray, iv);
                }
                else
                {
                    encryptionAlgorithm.Mode = CipherMode.ECB;
                    decryptor = new OpenPGPCFBTransformWrapper(encryptionAlgorithm.CreateEncryptor(keyArray, null), iv, false);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyArray.AsSpan());
            }

            encStream = new CryptoStream(
                encryptedPacket.GetInputStream(),
                new ZeroPaddedCryptoTransformWrapper(decryptor),
                CryptoStreamMode.Read);
            if (encryptedPacket is SymmetricEncIntegrityPacket)
            {
                hashAlgorithm = SHA1.Create();
                tailEndCryptoTransform = new TailEndCryptoTransform(hashAlgorithm, hashAlgorithm.HashSize / 8);
                encStream = new CryptoStream(encStream, tailEndCryptoTransform, CryptoStreamMode.Read);
            }

            if (Streams.ReadFully(encStream, iv, 0, iv.Length) < iv.Length)
                throw new EndOfStreamException("unexpected end of stream.");

            int v1 = encStream.ReadByte();
            int v2 = encStream.ReadByte();

            if (v1 < 0 || v2 < 0)
                throw new EndOfStreamException("unexpected end of stream.");

            if (verifyIntegrity)
            {
                bool repeatCheckPassed = iv[iv.Length - 2] == (byte)v1 && iv[iv.Length - 1] == (byte)v2;

                // Note: some versions of PGP appear to produce 0 for the extra
                // bytes rather than repeating the two previous bytes
                bool zeroesCheckPassed = v1 == 0 && v2 == 0;

                if (!repeatCheckPassed && !zeroesCheckPassed)
                {
                    throw new PgpDataValidationException("quick check failed.");
                }

            }

            return encStream;
        }

        private bool ConfirmCheckSum(ReadOnlySpan<byte> sessionInfo)
        {
            int check = 0;
            for (int i = 1; i != sessionInfo.Length - 2; i++)
                check += sessionInfo[i];
            return sessionInfo[sessionInfo.Length - 2] == (byte)(check >> 8) && (sessionInfo[sessionInfo.Length - 1] == (byte)check);
        }

        /// <summary>Return the decrypted session data for the packet.</summary>
        private byte[] GetSessionData(SymmetricKeyEncSessionPacket keyData, byte[] rawPassword)
        {
            byte[] key = Array.Empty<byte>();
            try
            {
                key = PgpUtilities.DoMakeKeyFromPassPhrase(keyData.EncAlgorithm, keyData.S2k, rawPassword, false);
                if (keyData.SecKeyData?.Length > 0)
                {
                    using var keyCipher = PgpUtilities.GetSymmetricAlgorithm(keyData.EncAlgorithm);
                    using var keyDecryptor = new ZeroPaddedCryptoTransformWrapper(keyCipher.CreateDecryptor(key, new byte[(keyCipher.BlockSize + 7) / 8]));
                    return keyDecryptor.TransformFinalBlock(keyData.SecKeyData, 0, keyData.SecKeyData.Length);
                }
                else
                {
                    var sessionData = new byte[key.Length + 1];
                    sessionData[0] = (byte)keyData.EncAlgorithm;
                    key.CopyTo(sessionData, 1);
                    return sessionData;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        /// <summary>Return the decrypted session data for the packet.</summary>
        private byte[] GetSessionData(PublicKeyEncSessionPacket keyData, PgpPrivateKey privKey)
        {
            var secKeyData = keyData.SessionKey;
            var asymmetricAlgorithm = privKey.Key;

            if (asymmetricAlgorithm is RSA rsa)
            {
                return rsa.Decrypt(secKeyData, RSAEncryptionPadding.Pkcs1);
            }

            if (asymmetricAlgorithm is ECDiffieHellman ecdh)
            {
                ECDHPublicBcpgKey ecKey = (ECDHPublicBcpgKey)privKey.PublicKeyPacket.Key;

                byte[] enc = secKeyData;

                int pLen = ((((enc[0] & 0xff) << 8) + (enc[1] & 0xff)) + 7) / 8;
                if ((2 + pLen + 1) > enc.Length)
                    throw new PgpException("encoded length out of range");

                byte[] pEnc = new byte[pLen];
                Array.Copy(enc, 2, pEnc, 0, pLen);

                int keyLen = enc[pLen + 2];
                if ((2 + pLen + 1 + keyLen) > enc.Length)
                    throw new PgpException("encoded length out of range");

                byte[] keyEnc = new byte[keyLen];
                Array.Copy(enc, 2 + pLen + 1, keyEnc, 0, keyEnc.Length);

                var publicPoint = PgpUtilities.DecodePoint(new MPInteger(pEnc));
                var ecCurve = ECCurve.CreateFromOid(ecKey.CurveOid);
                var otherEcdh = PgpUtilities.GetECDiffieHellman(new ECParameters { Curve = ecCurve, Q = publicPoint });
                var derivedKey = ecdh.DeriveKeyFromHash(
                    otherEcdh.PublicKey,
                    PgpUtilities.GetHashAlgorithmName(ecKey.HashAlgorithm),
                    new byte[] { 0, 0, 0, 1 },
                    Rfc6637Utilities.CreateUserKeyingMaterial(privKey.PublicKeyPacket));

                derivedKey = derivedKey.AsSpan(0, PgpUtilities.GetKeySize(ecKey.SymmetricKeyAlgorithm) / 8).ToArray();

                var C = KeyWrapAlgorithm.UnwrapKey(derivedKey, keyEnc);
                return PgpPad.UnpadSessionData(C);
            }

            if (asymmetricAlgorithm is ElGamal elGamal)
            {
                return elGamal.Decrypt(secKeyData, RSAEncryptionPadding.Pkcs1).ToArray();
            }

            throw new NotImplementedException();
        }
    }
}
