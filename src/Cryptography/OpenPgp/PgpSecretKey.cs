using Internal.Cryptography;
using Springburg.Cryptography.OpenPgp.Keys;
using Springburg.Cryptography.OpenPgp.Packet;
using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Springburg.Cryptography.OpenPgp
{
    /// <summary>General class to handle a PGP secret key object.</summary>
    public partial class PgpSecretKey : PgpKey
    {
        internal PgpSecretKey(SecretKeyPacket keyPacket)
            : base(keyPacket)
        {
        }

        internal PgpSecretKey(SecretKeyPacket keyPacket, PgpKey secretOrPublicKey)
            : base(secretOrPublicKey)
        {
            this.keyPacket = keyPacket;
        }

        internal PgpSecretKey(IPacketReader packetReader, SecretKeyPacket secretKeyPacket, bool subKey)
            : base(packetReader, secretKeyPacket, subKey)
        {
        }

        public PgpSecretKey(
            PgpPublicKey pubKey,
            PgpPrivateKey privKey,
            ReadOnlySpan<byte> rawPassPhrase)
            : base(pubKey)
        {
            var keyData = privKey.privateKey.ExportPrivateKey(
                rawPassPhrase,
                new S2kParameters());

            if (pubKey.IsMasterKey)
            {
                this.keyPacket = new SecretKeyPacket(privKey.Algorithm, CreationTime, keyData);
            }
            else
            {
                this.keyPacket = new SecretSubkeyPacket(privKey.Algorithm, CreationTime, keyData);
            }
        }

        protected override PgpKey CreateMutableCopy() => new PgpSecretKey((SecretKeyPacket)this.KeyPacket, this);

        /// <summary>Detect if the Secret Key's Private Key is empty or not</summary>
        public bool IsPrivateKeyEmpty
        {
            get
            {
                // FIXME: Move this elsewhere
                var s2k = KeyPacket.KeyBytes.AsSpan(KeyPacket.PublicKeyLength);
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

            if (keyPacket.Version < 4)
            {
                Debug.Assert(keyPacket.Algorithm == PgpPublicKeyAlgorithm.RsaGeneral || keyPacket.Algorithm == PgpPublicKeyAlgorithm.RsaEncrypt || keyPacket.Algorithm == PgpPublicKeyAlgorithm.RsaSign);
                var rsa = RsaKey.CreatePrivate(rawPassPhrase, keyPacket.KeyBytes, out var _, version: 3);
                return new PgpPrivateKey(KeyId, rsa);
            }
            else if (keyPacket.Version >= 4)
            {
                switch (keyPacket.Algorithm)
                {
                    case PgpPublicKeyAlgorithm.RsaGeneral:
                    case PgpPublicKeyAlgorithm.RsaSign:
                    case PgpPublicKeyAlgorithm.RsaEncrypt:
                        var rsa = RsaKey.CreatePrivate(rawPassPhrase, keyPacket.KeyBytes, out var _);
                        return new PgpPrivateKey(KeyId, rsa);

                    case PgpPublicKeyAlgorithm.Dsa:
                        var dsa = DsaKey.CreatePrivate(rawPassPhrase, keyPacket.KeyBytes, out var _);
                        return new PgpPrivateKey(KeyId, dsa);

                    case PgpPublicKeyAlgorithm.ECDH:
                        var ecdh = ECDiffieHellmanKey.CreatePrivate(Fingerprint, rawPassPhrase, keyPacket.KeyBytes, out var _);
                        return new PgpPrivateKey(KeyId, ecdh);

                    case PgpPublicKeyAlgorithm.ECDsa:
                        var ecdsa = ECDsaKey.CreatePrivate(rawPassPhrase, keyPacket.KeyBytes, out var _);
                        return new PgpPrivateKey(KeyId, ecdsa);

                    case PgpPublicKeyAlgorithm.EdDsa:
                        var eddsa = EdDsaKey.CreatePrivate(rawPassPhrase, keyPacket.KeyBytes, out var _);
                        return new PgpPrivateKey(KeyId, eddsa);

                    case PgpPublicKeyAlgorithm.ElGamalEncrypt:
                    case PgpPublicKeyAlgorithm.ElGamalGeneral:
                        var elgamal = ElGamalKey.CreatePrivate(rawPassPhrase, keyPacket.KeyBytes, out var _);
                        return new PgpPrivateKey(KeyId, elgamal);
                }
            }

            throw new PgpException("unknown public key version encountered");
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

            byte[] rawKeyData = CryptoPool.Rent(key.keyPacket.KeyBytes.Length - key.keyPacket.PublicKeyLength + 0x20);
            try
            {
                S2kBasedEncryption.DecryptSecretKey(
                    rawOldPassPhrase,
                    key.keyPacket.KeyBytes.AsSpan(key.keyPacket.PublicKeyLength),
                    rawKeyData,
                    out int rawKeySize,
                    key.keyPacket.Version);

                // Use the default S2K parameters
                var s2kParameters = new S2kParameters();

                var newKeyData = new byte[S2kBasedEncryption.GetEncryptedLength(s2kParameters, rawKeySize, key.keyPacket.Version) + key.keyPacket.PublicKeyLength];
                key.keyPacket.KeyBytes.AsSpan(0, key.keyPacket.PublicKeyLength).CopyTo(newKeyData);

                S2kBasedEncryption.EncryptSecretKey(
                    rawNewPassPhrase,
                    s2kParameters,
                    rawKeyData.AsSpan(0, rawKeySize),
                    newKeyData.AsSpan(key.keyPacket.PublicKeyLength),
                    key.keyPacket.Version);

                SecretKeyPacket newKeyPacket;
                if (key.keyPacket is SecretSubkeyPacket)
                    newKeyPacket = new SecretSubkeyPacket(key.Algorithm, key.CreationTime, newKeyData);
                else
                    newKeyPacket = new SecretKeyPacket(key.Algorithm, key.CreationTime, newKeyData);

                return new PgpSecretKey(newKeyPacket, key);
            }
            finally
            {
                CryptoPool.Return(rawKeyData);
            }
        }
    }
}
