﻿using InflatablePalace.Cryptography.Algorithms;
using InflatablePalace.Cryptography.Helpers;
using InflatablePalace.Cryptography.OpenPgp.Packet;
using InflatablePalace.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace InflatablePalace.Cryptography.OpenPgp
{
    public class PgpEncryptedMessage : PgpMessage
    {
        private List<PublicKeyEncSessionPacket> publicKeyEncSessionPackets;
        private List<SymmetricKeyEncSessionPacket> symmetricKeyEncSessionPackets;
        private StreamablePacket encryptedPacket;
        private Stream inputStream;
        private IPacketReader packetReader;
        private CryptoStream encStream;
        private HashAlgorithm hashAlgorithm;
        private TailEndCryptoTransform tailEndCryptoTransform;

        internal PgpEncryptedMessage(IPacketReader packetReader)
        {
            this.packetReader = packetReader;
            this.publicKeyEncSessionPackets = new List<PublicKeyEncSessionPacket>();
            this.symmetricKeyEncSessionPackets = new List<SymmetricKeyEncSessionPacket>();

            while (packetReader.NextPacketTag() == PacketTag.PublicKeyEncryptedSession ||
                   packetReader.NextPacketTag() == PacketTag.SymmetricKeyEncryptedSessionKey)
            {
                var keyPacket = packetReader.ReadContainedPacket();
                if (keyPacket is SymmetricKeyEncSessionPacket symmetricKeyEncSessionPacket)
                {
                    symmetricKeyEncSessionPackets.Add(symmetricKeyEncSessionPacket);
                }
                else
                {
                    publicKeyEncSessionPackets.Add((PublicKeyEncSessionPacket)keyPacket);
                }
            }

            var packet = packetReader.ReadStreamablePacket();
            if (!(packet.Packet is SymmetricEncDataPacket) &&
                !(packet.Packet is SymmetricEncIntegrityPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            this.encryptedPacket = packet.Packet;
            this.inputStream = packet.Stream;
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
                        sessionData = privateKey.DecryptSessionData(keyData.SessionKey);

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

        private void VerifyInlineIV(ReadOnlySpan<byte> inlineIv, ReadOnlySpan<byte> check)
        {
            bool repeatCheckPassed = inlineIv[inlineIv.Length - 2] == (byte)check[0] && inlineIv[inlineIv.Length - 1] == (byte)check[1];

            // Note: some versions of PGP appear to produce 0 for the extra
            // bytes rather than repeating the two previous bytes
            bool zeroesCheckPassed = check[0] == 0 && check[1] == 0;

            if (!repeatCheckPassed && !zeroesCheckPassed)
            {
                throw new PgpDataValidationException("quick check failed.");
            }
        }

        private Stream GetDataStream(ReadOnlySpan<byte> sessionData, bool verifyIntegrity)
        {
            SymmetricKeyAlgorithmTag keyAlgorithm = (SymmetricKeyAlgorithmTag)sessionData[0];

            if (keyAlgorithm == SymmetricKeyAlgorithmTag.Null)
                return inputStream;

            var key = sessionData.Slice(1);
            SymmetricAlgorithm encryptionAlgorithm = PgpUtilities.GetSymmetricAlgorithm(keyAlgorithm);
            var iv = new byte[(encryptionAlgorithm.BlockSize + 7) / 8];
            byte[] keyArray = Array.Empty<byte>();
            ICryptoTransform decryptor;
            var inlineIv = new byte[iv.Length * 2]; // Aligned to block size

            try
            {
                keyArray = key.ToArray();
                decryptor = encryptionAlgorithm.CreateDecryptor(keyArray, iv);
                if (encryptedPacket is SymmetricEncDataPacket)
                {
                    if (inputStream.ReadFully(inlineIv.AsSpan(0, iv.Length + 2)) < iv.Length + 2)
                        throw new EndOfStreamException();

                    var decryptedInlineIv = decryptor.TransformFinalBlock(inlineIv, 0, inlineIv.Length);
                    if (verifyIntegrity)
                        VerifyInlineIV(decryptedInlineIv.AsSpan(0, iv.Length), decryptedInlineIv.AsSpan(iv.Length, 2));

                    // Perform reset according to the OpenPGP CFB rules
                    decryptor = encryptionAlgorithm.CreateDecryptor(keyArray, inlineIv.AsSpan(2, iv.Length).ToArray());
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyArray.AsSpan());
            }

            encStream = new CryptoStream(
                inputStream,
                new ZeroPaddedCryptoTransform(decryptor),
                CryptoStreamMode.Read);
            if (encryptedPacket is SymmetricEncIntegrityPacket)
            {
                hashAlgorithm = SHA1.Create();
                tailEndCryptoTransform = new TailEndCryptoTransform(hashAlgorithm, hashAlgorithm.HashSize / 8);
                encStream = new CryptoStream(encStream, tailEndCryptoTransform, CryptoStreamMode.Read);

                if (encStream.ReadFully(inlineIv.AsSpan(0, iv.Length + 2)) < iv.Length + 2)
                    throw new EndOfStreamException();

                if (verifyIntegrity)
                    VerifyInlineIV(inlineIv.AsSpan(0, iv.Length), inlineIv.AsSpan(iv.Length, 2));
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
                key = PgpUtilities.DoMakeKeyFromPassPhrase(keyData.EncAlgorithm, keyData.S2k, rawPassword);
                if (keyData.SecKeyData?.Length > 0)
                {
                    using var keyCipher = PgpUtilities.GetSymmetricAlgorithm(keyData.EncAlgorithm);
                    using var keyDecryptor = new ZeroPaddedCryptoTransform(keyCipher.CreateDecryptor(key, new byte[(keyCipher.BlockSize + 7) / 8]));
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
    }
}
