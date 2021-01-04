using Internal.Cryptography;
using Springburg.Cryptography.Algorithms;
using Springburg.Cryptography.Helpers;
using Springburg.Cryptography.OpenPgp.Keys;
using Springburg.Cryptography.OpenPgp.Packet;
using Springburg.IO;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Springburg.Cryptography.OpenPgp
{
    public class PgpEncryptedMessage : PgpMessage
    {
        private List<PublicKeyEncSessionPacket> publicKeyEncSessionPackets;
        private List<SymmetricKeyEncSessionPacket> symmetricKeyEncSessionPackets;
        private StreamablePacket encryptedPacket;
        private Stream inputStream;
        private IPacketReader packetReader;
        private CryptoStream? encStream;
        private HashAlgorithm? hashAlgorithm;
        private TailEndCryptoTransform? tailEndCryptoTransform;

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
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));

            foreach (var keyData in publicKeyEncSessionPackets)
            {
                if (keyData.KeyId == privateKey.KeyId)
                {
                    byte[] sessionData = CryptoPool.Rent(keyData.SessionKey.Length);
                    try
                    {
                        privateKey.TryDecryptSessionInfo(keyData.SessionKey, sessionData, out int bytesWritten);

                        if (!ConfirmCheckSum(sessionData.AsSpan(0, bytesWritten)))
                        {
                            throw new PgpException("Checksum validation failed");
                        }

                        // Note: the oracle attack on the "quick check" bytes is deemed
                        // a security risk for typical public key encryption usages.
                        return ReadMessage(packetReader.CreateNestedReader(GetDataStream(sessionData.AsSpan(0, bytesWritten - 2), verifyIntegrity: false)));
                    }
                    finally
                    {
                        CryptoPool.Return(sessionData);
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
            if (encStream == null)
                throw new InvalidOperationException();
            if (!IsIntegrityProtected)
                return false;

            // Make sure we are at the end of the stream
            encStream.CopyTo(Stream.Null);

            // process the MDC packet
            Debug.Assert(hashAlgorithm != null);
            Debug.Assert(tailEndCryptoTransform != null);
            var digest = hashAlgorithm.Hash;
            var streamDigest = tailEndCryptoTransform.TailEnd;

            return CryptographicOperations.FixedTimeEquals(digest, streamDigest);
        }

        private static void VerifyInlineIV(ReadOnlySpan<byte> inlineIv, ReadOnlySpan<byte> check)
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
            PgpSymmetricKeyAlgorithm keyAlgorithm = (PgpSymmetricKeyAlgorithm)sessionData[0];

            if (keyAlgorithm == PgpSymmetricKeyAlgorithm.Null)
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

        private static bool ConfirmCheckSum(ReadOnlySpan<byte> sessionInfo)
        {
            int check = 0;
            for (int i = 1; i != sessionInfo.Length - 2; i++)
                check += sessionInfo[i];
            return sessionInfo[sessionInfo.Length - 2] == (byte)(check >> 8) && (sessionInfo[sessionInfo.Length - 1] == (byte)check);
        }

        /// <summary>Return the decrypted session data for the packet.</summary>
        private static byte[] GetSessionData(SymmetricKeyEncSessionPacket keyData, ReadOnlySpan<byte> rawPassword)
        {
            byte[] key = Array.Empty<byte>();
            try
            {
                key = new byte[PgpUtilities.GetKeySize(keyData.EncAlgorithm) / 8];
                S2kBasedEncryption.MakeKey(rawPassword, keyData.S2k.HashAlgorithm, keyData.S2k.GetIV(), keyData.S2k.IterationCount, key);
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
