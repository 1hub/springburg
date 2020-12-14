using System;
using System.IO;
using System.Numerics;
using System.Runtime;
using System.Security.Cryptography;
using InflatablePalace.Cryptography.Algorithms;
using InflatablePalace.OpenPGP;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A public key encrypted data object.</remarks>
    public class PgpPublicKeyEncryptedData
        : PgpEncryptedData
    {
        private PublicKeyEncSessionPacket keyData;

        internal PgpPublicKeyEncryptedData(
            PublicKeyEncSessionPacket keyData,
            InputStreamPacket encData)
            : base(encData)
        {
            this.keyData = keyData;
        }

        /*private static AsymmetricAlgorithm GetKeyCipher(
            PublicKeyAlgorithmTag algorithm)
        {
            try
            {
                switch (algorithm)
                {
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                        return CipherUtilities.GetCipher("RSA//PKCS1Padding");
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        return CipherUtilities.GetCipher("ElGamal/ECB/PKCS1Padding");
                    default:
                        throw new PgpException("unknown asymmetric algorithm: " + algorithm);
                }
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }
        }*/

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
        public SymmetricKeyAlgorithmTag GetSymmetricAlgorithm(
            PgpPrivateKey privKey)
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

            //var zeroPaddedStream = new ZeroPaddedStream(encData.GetInputStream(), encryptionAlgorithm.BlockSize / 8);
            /*encStream = 
                new OuterTrancateStream(new CryptoStream(zeroPaddedStream, encryptionAlgorithm.CreateDecryptor(), CryptoStreamMode.Read), zeroPaddedStream);*/
            encStream = new CryptoStream(encData.GetInputStream(), new ZeroPaddedCryptoTransformWrapper(encryptionAlgorithm.CreateDecryptor()), CryptoStreamMode.Read);


            /*IBufferedCipher cipher;
			string cipherName = PgpUtilities.GetSymmetricCipherName(symmAlg);
			string cName = cipherName;

            try
            {
                if (encData is SymmetricEncIntegrityPacket)
                {
					cName += "/CFB/NoPadding";
                }
                else
                {
					cName += "/OpenPGPCFB/NoPadding";
                }

                cipher = CipherUtilities.GetCipher(cName);
			}
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("exception creating cipher", e);
            }*/

            try
            {
                /*KeyParameter key = ParameterUtilities.CreateKeyParameter(
					cipherName, sessionData, 1, sessionData.Length - 3);

                byte[] iv = new byte[cipher.GetBlockSize()];

                cipher.Init(false, new ParametersWithIV(key, iv));

                encStream = BcpgInputStream.Wrap(new CipherStream(encData.GetInputStream(), cipher, null));*/

                //encryptionAlgorithm.Key = sessionData.AsSpan(1, sessionData.Length - 3).ToArray();

                byte[] iv = new byte[(encryptionAlgorithm.BlockSize + 7) / 8];

                if (encData is SymmetricEncIntegrityPacket)
                {
                    truncStream = new TruncatedStream(encStream);

                    /*string digestName = PgpUtilities.GetDigestName(HashAlgorithmTag.Sha1);
					IDigest digest = DigestUtilities.GetDigest(digestName);

					encStream = new DigestStream(truncStream, digest, null);*/
                    HashAlgorithm digest = SHA1.Create();
                    encStream = new CryptoStream(truncStream, digest, CryptoStreamMode.Read);
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

                //				bool repeatCheckPassed =
                //					iv[iv.Length - 2] == (byte)v1
                //					&&	iv[iv.Length - 1] == (byte)v2;
                //
                //				// Note: some versions of PGP appear to produce 0 for the extra
                //				// bytes rather than repeating the two previous bytes
                //				bool zeroesCheckPassed =
                //					v1 == 0
                //					&&	v2 == 0;
                //
                //				if (!repeatCheckPassed && !zeroesCheckPassed)
                //				{
                //					throw new PgpDataValidationException("quick check failed.");
                //				}

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
                //cipher.ProcessBytes(bi, 2, bi.Length - 2);
                return rsa.Decrypt(bi.AsSpan(2).ToArray(), RSAEncryptionPadding.Pkcs1);
            }
            if (asymmetricAlgorithm is ECDiffieHellman ecdh)
            {
                ECDHPublicBcpgKey ecKey = (ECDHPublicBcpgKey)privKey.PublicKeyPacket.Key;
                //X9ECParameters x9Params = ECKeyPairGenerator.FindECCurveByOid(ecKey.CurveOid);

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

                /*KeyParameter key;

                if (privKey.Key is X25519PrivateKeyParameters x25519privKeyParams)
                {
                    byte[] sharedKey = new byte[32];
                    byte[] reversedPrivateKey = new byte[32];
                    x25519privKeyParams.Encode(reversedPrivateKey, 0);
                    Array.Reverse((Array)reversedPrivateKey);
                    X25519.ScalarMult(reversedPrivateKey, 0, pEnc, 1, sharedKey, 0);
                    key = new KeyParameter(Rfc6637Utilities.CreateKey(privKey.PublicKeyPacket, sharedKey));
                }
                else
                {
                    ECPoint publicPoint = x9Params.Curve.DecodePoint(pEnc);
                    ECPrivateKeyParameters privKeyParams = (ECPrivateKeyParameters)privKey.Key;
                    ECPoint S = publicPoint.Multiply(privKeyParams.D).Normalize();
                    key = new KeyParameter(Rfc6637Utilities.CreateKey(privKey.PublicKeyPacket, S));
                }*/

                var publicPoint = PgpUtilities.DecodePoint(new MPInteger(pEnc));
                var ecCurve = ECCurve.CreateFromOid(ecKey.CurveOid);
                var otherEcdh = PgpUtilities.GetECDiffieHellman(new ECParameters { Curve = ecCurve, Q = publicPoint });
                var derivedKey = ecdh.DeriveKeyFromHash(
                    otherEcdh.PublicKey,
                    PgpUtilities.GetHashAlgorithmName(ecKey.HashAlgorithm),
                    new byte[] { 0, 0, 0, 1 },
                    Rfc6637Utilities.CreateUserKeyingMaterial(privKey.PublicKeyPacket));

                derivedKey = derivedKey.AsSpan(0, Rfc6637Utilities.GetKeyLength(ecKey.SymmetricKeyAlgorithm)).ToArray();

                var C = KeyWrapAlgorithm.UnwrapKey(derivedKey, keyEnc);
                return PgpPad.UnpadSessionData(C);
            }

            throw new NotImplementedException();
#if NOT


            if (keyData.Algorithm == PublicKeyAlgorithmTag.ECDH)
            {
                ECDHPublicBcpgKey ecKey = (ECDHPublicBcpgKey)privKey.PublicKeyPacket.Key;
                X9ECParameters x9Params = ECKeyPairGenerator.FindECCurveByOid(ecKey.CurveOid);

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

                KeyParameter key;

                if (privKey.Key is X25519PrivateKeyParameters x25519privKeyParams)
                {
                    byte[] sharedKey = new byte[32];
                    byte[] reversedPrivateKey = new byte[32];
                    x25519privKeyParams.Encode(reversedPrivateKey, 0);
                    Array.Reverse((Array)reversedPrivateKey);
                    X25519.ScalarMult(reversedPrivateKey, 0, pEnc, 1, sharedKey, 0);
                    key = new KeyParameter(Rfc6637Utilities.CreateKey(privKey.PublicKeyPacket, sharedKey));
                }
                else
                {
                    ECPoint publicPoint = x9Params.Curve.DecodePoint(pEnc);
                    ECPrivateKeyParameters privKeyParams = (ECPrivateKeyParameters)privKey.Key;
                    ECPoint S = publicPoint.Multiply(privKeyParams.D).Normalize();
                    key = new KeyParameter(Rfc6637Utilities.CreateKey(privKey.PublicKeyPacket, S));
                }

                IWrapper w = PgpUtilities.CreateWrapper(ecKey.SymmetricKeyAlgorithm);
                w.Init(false, key);

                return PgpPad.UnpadSessionData(w.Unwrap(keyEnc, 0, keyEnc.Length));
            }

            AsymmetricAlgorithm asymmetricAlgorithm;

            switch (keyData.Algorithm)
            {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    // FIXME: Parameters
                    asymmetricAlgorithm = RSA.Create(new RSAParameters());
                    break;
                /*case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    asymmetricAlgorithm = El*/
            }


            IBufferedCipher cipher = GetKeyCipher(keyData.Algorithm);

            try
			{
                cipher.Init(false, privKey.Key);
			}
			catch (InvalidKeyException e)
			{
				throw new PgpException("error setting asymmetric cipher", e);
			}

            if (keyData.Algorithm == PublicKeyAlgorithmTag.RsaEncrypt
				|| keyData.Algorithm == PublicKeyAlgorithmTag.RsaGeneral)
			{
                byte[] bi = secKeyData[0];

                cipher.ProcessBytes(bi, 2, bi.Length - 2);
			}
			else
			{
                throw new NotImplementedException();
				/*ElGamalPrivateKeyParameters k = (ElGamalPrivateKeyParameters)privKey.Key;
				int size = (k.Parameters.P.BitLength + 7) / 8;

                ProcessEncodedMpi(cipher, size, secKeyData[0]);
                ProcessEncodedMpi(cipher, size, secKeyData[1]);*/
			}

            try
			{
                return cipher.DoFinal();
			}
			catch (Exception e)
			{
				throw new PgpException("exception decrypting secret key", e);
			}
#endif
        }

        /*private static void ProcessEncodedMpi(IBufferedCipher cipher, int size, byte[] mpiEnc)
        {
            if (mpiEnc.Length - 2 > size)  // leading Zero? Shouldn't happen but...
            {
                cipher.ProcessBytes(mpiEnc, 3, mpiEnc.Length - 3);
            }
            else
            {
                byte[] tmp = new byte[size];
                Array.Copy(mpiEnc, 2, tmp, tmp.Length - (mpiEnc.Length - 2), mpiEnc.Length - 2);
                cipher.ProcessBytes(tmp, 0, tmp.Length);
            }
        }*/


    }
}
