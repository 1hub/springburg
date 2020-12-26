using InflatablePalace.Cryptography.Algorithms;
using Internal.Cryptography;
using System;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>General class to contain a private key for use with other OpenPGP objects.</summary>
    public class PgpPrivateKey
    {
        private readonly long keyId;
        private readonly PublicKeyPacket publicKeyPacket;
        private readonly AsymmetricAlgorithm privateKey;

        /// <summary>
        /// Create a PgpPrivateKey from a keyID, the associated public data packet, and a regular private key.
        /// </summary>
        /// <param name="keyId">ID of the corresponding public key.</param>
        /// <param name="publicKeyPacket">the public key data packet to be associated with this private key.</param>
        /// <param name="privateKey">the private key data packet to be associated with this private key.</param>
        public PgpPrivateKey(
            long keyId,
            PublicKeyPacket publicKeyPacket,
            AsymmetricAlgorithm privateKey)
        {
            //if (!privateKey.IsPrivate)
            //    throw new ArgumentException("Expected a private key", "privateKey");

            this.keyId = keyId;
            this.publicKeyPacket = publicKeyPacket;
            this.privateKey = privateKey;
        }

        /// <summary>The keyId associated with the contained private key.</summary>
        public long KeyId => keyId;

        /// <summary>The public key packet associated with this private key, if available.</summary>
        public PublicKeyPacket PublicKeyPacket => publicKeyPacket;

        /// <summary>The contained private key.</summary>
        internal AsymmetricAlgorithm Key => privateKey;

        /// <summary>Return the decrypted session data for the packet.</summary>
        public byte[] DecryptSessionData(byte[] encryptedSessionData)
        {
            if (privateKey is RSA rsa)
            {
                return rsa.Decrypt(encryptedSessionData, RSAEncryptionPadding.Pkcs1);
            }

            if (privateKey is ECDiffieHellman ecdh)
            {
                ECDHPublicBcpgKey ecKey = (ECDHPublicBcpgKey)PublicKeyPacket.Key;

                int pLen = ((((encryptedSessionData[0] & 0xff) << 8) + (encryptedSessionData[1] & 0xff)) + 7) / 8;
                if ((2 + pLen + 1) > encryptedSessionData.Length)
                    throw new PgpException("encoded length out of range");

                byte[] pEnc = new byte[pLen];
                Array.Copy(encryptedSessionData, 2, pEnc, 0, pLen);

                int keyLen = encryptedSessionData[pLen + 2];
                if ((2 + pLen + 1 + keyLen) > encryptedSessionData.Length)
                    throw new PgpException("encoded length out of range");

                byte[] keyEnc = new byte[keyLen];
                Array.Copy(encryptedSessionData, 2 + pLen + 1, keyEnc, 0, keyEnc.Length);

                var publicPoint = PgpUtilities.DecodePoint(new MPInteger(pEnc));
                var ecCurve = ECCurve.CreateFromOid(ecKey.CurveOid);
                var otherEcdh = PgpUtilities.GetECDiffieHellman(new ECParameters { Curve = ecCurve, Q = publicPoint });
                var derivedKey = ecdh.DeriveKeyFromHash(
                    otherEcdh.PublicKey,
                    PgpUtilities.GetHashAlgorithmName(ecKey.HashAlgorithm),
                    new byte[] { 0, 0, 0, 1 },
                    Rfc6637Utilities.CreateUserKeyingMaterial(PublicKeyPacket));

                derivedKey = derivedKey.AsSpan(0, PgpUtilities.GetKeySize(ecKey.SymmetricKeyAlgorithm) / 8).ToArray();

                var C = SymmetricKeyWrap.AESKeyWrapDecrypt(derivedKey, keyEnc);
                return PgpPad.UnpadSessionData(C);
            }

            if (privateKey is ElGamal elGamal)
            {
                return elGamal.Decrypt(encryptedSessionData, RSAEncryptionPadding.Pkcs1).ToArray();
            }

            throw new NotImplementedException();
        }

        public byte[] Sign(byte[] hash, HashAlgorithmTag hashAlgorithm)
        {
            if (privateKey is RSA rsa)
                return rsa.SignHash(hash, PgpUtilities.GetHashAlgorithmName(hashAlgorithm), RSASignaturePadding.Pkcs1);
            else if (privateKey is DSA dsa)
                return dsa.CreateSignature(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            else if (privateKey is ECDsa ecdsa)
                return ecdsa.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            throw new NotImplementedException();
        }
    }
}
