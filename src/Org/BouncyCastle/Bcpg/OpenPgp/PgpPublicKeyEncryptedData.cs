using System;
using System.IO;
using System.Security.Cryptography;
using InflatablePalace.Cryptography.Algorithms;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>A public key encrypted data object.</summary>
    public class PgpPublicKeyEncryptedData : PgpEncryptedData
    {
        private PublicKeyEncSessionPacket keyData;

        internal PgpPublicKeyEncryptedData(
            PublicKeyEncSessionPacket keyData,
            InputStreamPacket encData)
            : base(encData)
        {
            this.keyData = keyData;
        }

        private bool ConfirmCheckSum(
            byte[] sessionInfo)
        {
            int check = 0;

            for (int i = 1; i != sessionInfo.Length - 2; i++)
            {
                check += sessionInfo[i] & 0xff;
            }

            return (sessionInfo[sessionInfo.Length - 2] == (byte)(check >> 8))
                && (sessionInfo[sessionInfo.Length - 1] == (byte)(check));
        }

        /// <summary>The key ID for the key used to encrypt the data.</summary>
        public long KeyId
        {
            get { return keyData.KeyId; }
        }

        /// <summary>
        /// Return the algorithm code for the symmetric algorithm used to encrypt the data.
        /// </summary>
        public SymmetricKeyAlgorithmTag GetSymmetricAlgorithm(PgpPrivateKey privKey)
        {
            byte[] sessionData = RecoverSessionData(privKey);
            return (SymmetricKeyAlgorithmTag)sessionData[0];
        }

        /// <summary>Return the decrypted data stream for the packet.</summary>
        public Stream GetDataStream(
            PgpPrivateKey privKey)
        {
            byte[] sessionData = RecoverSessionData(privKey);

            if (!ConfirmCheckSum(sessionData))
                throw new PgpKeyValidationException("key checksum failed");

            SymmetricKeyAlgorithmTag symmAlg = (SymmetricKeyAlgorithmTag)sessionData[0];
            if (symmAlg == SymmetricKeyAlgorithmTag.Null)
                return encData.GetInputStream();

            SymmetricAlgorithm encryptionAlgorithm = PgpUtilities.GetSymmetricAlgorithm(symmAlg);
            encryptionAlgorithm.Key = sessionData.AsSpan(1, sessionData.Length - 3).ToArray();
            encryptionAlgorithm.IV = new byte[(encryptionAlgorithm.BlockSize + 7) / 8];
            encryptionAlgorithm.Padding = PaddingMode.Zeros;


            ICryptoTransform decryptor;
            if (encData is SymmetricEncIntegrityPacket)
            {
                decryptor = encryptionAlgorithm.CreateDecryptor();
            }
            else
            {
                encryptionAlgorithm.Mode = CipherMode.ECB;
                decryptor = new OpenPGPCFBTransformWrapper(encryptionAlgorithm.CreateEncryptor(), encryptionAlgorithm.IV, false);
            }

            //encStream = new CryptoStream(encData.GetInputStream(), new ZeroPaddedCryptoTransformWrapper(decryptor), CryptoStreamMode.Read);

            try
            {
                byte[] iv = new byte[(encryptionAlgorithm.BlockSize + 7) / 8];

                encStream = new CryptoStream(
                    encData.GetInputStream(),
                    new ZeroPaddedCryptoTransformWrapper(decryptor),
                    CryptoStreamMode.Read);
                if (encData is SymmetricEncIntegrityPacket)
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

                // Note: the oracle attack on the "quick check" bytes is deemed
                // a security risk for typical public key encryption usages,
                // therefore we do not perform the check.

                return encStream;
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception starting decryption", e);
            }
        }

        private byte[] RecoverSessionData(PgpPrivateKey privKey)
        {
            byte[][] secKeyData = keyData.GetEncSessionKey();
            var asymmetricAlgorithm = privKey.Key;

            if (asymmetricAlgorithm is RSA rsa)
            {
                byte[] bi = secKeyData[0];
                return rsa.Decrypt(bi.AsSpan(2).ToArray(), RSAEncryptionPadding.Pkcs1);
            }

            if (asymmetricAlgorithm is ECDiffieHellman ecdh)
            {
                ECDHPublicBcpgKey ecKey = (ECDHPublicBcpgKey)privKey.PublicKeyPacket.Key;

                byte[] enc = secKeyData[0];

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
                int halfLength = Math.Max(secKeyData[0].Length, secKeyData[1].Length) - 2;
                var keyData = new byte[halfLength * 2];
                secKeyData[0].AsSpan(2).CopyTo(keyData.AsSpan(halfLength - (secKeyData[0].Length - 2)));
                secKeyData[1].AsSpan(2).CopyTo(keyData.AsSpan(halfLength + halfLength - (secKeyData[1].Length - 2)));
                return elGamal.Decrypt(keyData, RSAEncryptionPadding.Pkcs1).ToArray();
            }


            // TODO: ElGamal
            throw new NotImplementedException();
        }
    }
}
