using Internal.Cryptography;
using Springburg.Cryptography.Algorithms;
using System;
using System.Diagnostics;
using System.Formats.Asn1;
using System.IO;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp.Keys
{
    class ECDiffieHellmanKey : ECKey, IAsymmetricPrivateKey, IAsymmetricPublicKey
    {
        private ECDiffieHellman ecdh;
        private PgpHashAlgorithm hashAlgorithm;
        private PgpSymmetricKeyAlgorithm symmetricAlgorithm;
        private byte[] fingerprint;

        public PgpPublicKeyAlgorithm Algorithm => PgpPublicKeyAlgorithm.ECDH;

        public bool CanSign => false;

        public bool CanEncrypt => true;

        public ECDiffieHellmanKey(
            ECDiffieHellman ecdh,
            PgpHashAlgorithm hashAlgorithm,
            PgpSymmetricKeyAlgorithm symmetricAlgorithm,
            byte[] fingerprint)
        {
            if (fingerprint == null)
                throw new ArgumentNullException(nameof(fingerprint));

            this.ecdh = ecdh;
            this.hashAlgorithm = hashAlgorithm;
            this.symmetricAlgorithm = symmetricAlgorithm;
            this.fingerprint = fingerprint;

            VerifyHashAlgorithm();
            VerifySymmetricKeyAlgorithm();
        }

        public ECDiffieHellmanKey(
            ECDiffieHellman ecdh,
            byte[] kdfParameters,
            byte[] fingerprint)
            : this(ecdh, (PgpHashAlgorithm)kdfParameters[1], (PgpSymmetricKeyAlgorithm)kdfParameters[2], fingerprint)
        {
        }

         public static ECDiffieHellmanKey CreatePublic(
             byte[] fingerprint,
             ReadOnlySpan<byte> source,
             out int publicKeySize)
        {
            var ecParameters = ReadOpenPgpECParameters(source, out publicKeySize);
            // TODO: Validation
            byte kdfSize = source[publicKeySize];
            var kdfParameters = source.Slice(publicKeySize + 1, kdfSize).ToArray();
            return new ECDiffieHellmanKey(GetECDiffieHellman(ecParameters), kdfParameters, fingerprint);
        }

        public static ECDiffieHellmanKey CreatePrivate(
             ReadOnlySpan<byte> fingerprint,
             ReadOnlySpan<byte> password,
             ReadOnlySpan<byte> source,
             out int publicKeySize)
        {
            var ecParameters = ReadOpenPgpECParameters(source, out publicKeySize);
            // TODO: Validation
            byte kdfSize = source[publicKeySize];
            var kdfParameters = source.Slice(publicKeySize + 1, kdfSize).ToArray();

            byte[] paramsArray = new byte[source.Length - publicKeySize];
            try
            {
                S2kBasedEncryption.DecryptSecretKey(password, source.Slice(publicKeySize + kdfSize + 1), paramsArray, out int bytesWritten);
                Debug.Assert(bytesWritten != 0);
                ecParameters.D = MPInteger.ReadInteger(paramsArray, out int dConsumed).ToArray();
                return new ECDiffieHellmanKey(GetECDiffieHellman(ecParameters), kdfParameters, fingerprint.ToArray());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(paramsArray);
                CryptographicOperations.ZeroMemory(ecParameters.D);
            }
        }

        private void WriteKDFParameters(Span<byte> kdfParameters)
        {
            kdfParameters[0] = 3; // Length
            kdfParameters[1] = 0; // Reserved
            kdfParameters[2] = (byte)hashAlgorithm;
            kdfParameters[3] = (byte)symmetricAlgorithm;
        }

        public byte[] ExportPublicKey()
        {
            var ecParameters = ecdh.ExportParameters(false);
            int estimatedLength = 32 /* OID */ + MPInteger.GetMPEncodedLength(ecParameters.Q.X!, ecParameters.Q.Y!) + 1 /* EC Point type */ + 4 /* KDF Parameters */;
            var destination = new byte[estimatedLength];
            WriteOpenPgpECParameters(ecParameters, destination, out var bytesWritten);
            WriteKDFParameters(destination.AsSpan(bytesWritten));
            return destination.AsSpan(0, bytesWritten + 4).ToArray();
        }

        public byte[] ExportPrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            S2kParameters s2kParameters)
        {
            ECParameters ecParameters = new ECParameters();
            byte[] secretPart = Array.Empty<byte>();

            try
            {
                ecParameters = ecdh.ExportParameters(true);
                if (ecdh is X25519)
                    Array.Reverse(ecParameters.D!);

                int secretSize = MPInteger.GetMPEncodedLength(ecParameters.D!);
                secretPart = CryptoPool.Rent(secretSize);
                MPInteger.TryWriteInteger(ecParameters.D, secretPart, out var _);

                int encryptedSecretLength = S2kBasedEncryption.GetEncryptedLength(s2kParameters, secretSize);
                int estimatedLength =
                    32 /* OID */ +
                    MPInteger.GetMPEncodedLength(ecParameters.Q.X!, ecParameters.Q.Y!) + 1 /* EC Point type */ +
                    4 /* KDF Parameters */ +
                    encryptedSecretLength;
                var destination = new byte[estimatedLength];
                WriteOpenPgpECParameters(ecParameters, destination, out int bytesWritten);
                WriteKDFParameters(destination.AsSpan(bytesWritten));

                S2kBasedEncryption.EncryptSecretKey(passwordBytes, s2kParameters, secretPart.AsSpan(0, secretSize), destination.AsSpan(bytesWritten + 4));
                return destination.AsSpan(0, bytesWritten + 4 + encryptedSecretLength).ToArray();
            }
            finally
            {
                CryptoPool.Return(secretPart);
                if (ecParameters.D != null)
                    CryptographicOperations.ZeroMemory(ecParameters.D);
            }
        }

        public bool VerifySignature(
            ReadOnlySpan<byte> rgbHash,
            ReadOnlySpan<byte> rgbSignature,
            PgpHashAlgorithm hashAlgorithm) 
        {
            throw new NotSupportedException();
        }

        public byte[] CreateSignature(ReadOnlySpan<byte> rgbHash, PgpHashAlgorithm hashAlgorithm)
        {
            throw new NotSupportedException();
        }

        public bool TryDecryptSessionInfo(ReadOnlySpan<byte> encryptedSessionData, Span<byte> sessionData, out int bytesWritten)
        {
            var pEnc = MPInteger.ReadInteger(encryptedSessionData, out int pointBytesRead);
            encryptedSessionData = encryptedSessionData.Slice(pointBytesRead);
            int keyLen = encryptedSessionData[0];
            var keyEnc = encryptedSessionData.Slice(1, keyLen);

            var publicParams = ecdh.PublicKey.ExportParameters();

            var publicPoint = DecodePoint(pEnc);
            var otherEcdh = GetECDiffieHellman(new ECParameters { Curve = publicParams.Curve, Q = publicPoint });
            var derivedKey = ecdh.DeriveKeyFromHash(
                otherEcdh.PublicKey,
                PgpUtilities.GetHashAlgorithmName(this.hashAlgorithm),
                new byte[] { 0, 0, 0, 1 },
                CreateUserKeyingMaterial(publicParams.Curve.Oid));

            derivedKey = derivedKey.AsSpan(0, PgpUtilities.GetKeySize(this.symmetricAlgorithm) / 8).ToArray();

            var C = SymmetricKeyWrap.AESKeyWrapDecrypt(derivedKey, keyEnc.ToArray());
            var data = UnpadSessionData(C);
            if (sessionData.Length >= data.Length)
            {
                data.CopyTo(sessionData);
                bytesWritten = data.Length;
                return true;
            }
            bytesWritten = 0;
            return false;
        }

        public byte[] EncryptSessionInfo(ReadOnlySpan<byte> sessionInfo)
        {
            var publicKeyParams = ecdh.PublicKey.ExportParameters();

            // Generate the ephemeral key pair
            var ephemeralEcDh = GetECDiffieHellman(publicKeyParams.Curve);
            var derivedKey = ephemeralEcDh.DeriveKeyFromHash(
                ecdh.PublicKey,
                PgpUtilities.GetHashAlgorithmName(this.hashAlgorithm),
                new byte[] { 0, 0, 0, 1 },
                CreateUserKeyingMaterial(publicKeyParams.Curve.Oid));

            derivedKey = derivedKey.AsSpan(0, PgpUtilities.GetKeySize(symmetricAlgorithm) / 8).ToArray();

            byte[] paddedSessionData = PadSessionData(sessionInfo);
            byte[] C = SymmetricKeyWrap.AESKeyWrapEncrypt(derivedKey, paddedSessionData);
            var ep = ephemeralEcDh.PublicKey.ExportParameters();
            byte[] VB = EncodePoint(ep.Q, publicKeyParams.Curve.Oid);
            byte[] rv = new byte[VB.Length + 2 + 1 + C.Length];
            MPInteger.TryWriteInteger(VB, rv, out _);
            //Array.Copy(VB, 0, rv, 0, VB.Length);
            rv[VB.Length + 2] = (byte)C.Length;
            Array.Copy(C, 0, rv, VB.Length + 3, C.Length);

            return rv;
        }

        // "Anonymous Sender    ", which is the octet sequence
        private static readonly byte[] ANONYMOUS_SENDER = new byte[] { 0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64, 0x65, 0x72, 0x20, 0x20, 0x20, 0x20 };

        // RFC 4880bis - Section 13.5.
        // curve_OID_len = (byte)len(curve_OID);
        // Param = curve_OID_len || curve_OID || public_key_alg_ID || 03
        // || 01 || KDF_hash_ID || KEK_alg_ID for AESKeyWrap || "Anonymous
        // Sender    " || recipient_fingerprint;
        // Z_len = the key size for the KEK_alg_ID used with AESKeyWrap
        // Compute Z = KDF( S, Z_len, Param );
        private byte[] CreateUserKeyingMaterial(Oid curveOid)
        {
            MemoryStream pOut = new MemoryStream();

            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.WriteObjectIdentifier(curveOid.Value!);
            byte[] encOid = writer.Encode();

            pOut.Write(encOid, 1, encOid.Length - 1);
            pOut.WriteByte((byte)PgpPublicKeyAlgorithm.ECDH);
            pOut.WriteByte(0x03);
            pOut.WriteByte(0x01);
            pOut.WriteByte((byte)this.hashAlgorithm);
            pOut.WriteByte((byte)this.symmetricAlgorithm);
            pOut.Write(ANONYMOUS_SENDER, 0, ANONYMOUS_SENDER.Length);
            pOut.Write(fingerprint, 0, Math.Min(fingerprint.Length, 20));

            return pOut.ToArray();
        }

        private static byte[] PadSessionData(ReadOnlySpan<byte> sessionInfo)
        {
            int length = sessionInfo.Length;
            int paddedLength = ((length >> 3) + 1) << 3;

            paddedLength = Math.Max(40, paddedLength);

            int padCount = paddedLength - length;
            byte padByte = (byte)padCount;

            byte[] result = new byte[paddedLength];
            sessionInfo.CopyTo(result);
            for (int i = length; i < paddedLength; ++i)
            {
                result[i] = padByte;
            }
            return result;
        }

        private static byte[] UnpadSessionData(byte[] encoded)
        {
            int paddedLength = encoded.Length;
            byte padByte = encoded[paddedLength - 1];
            int padCount = padByte;
            int length = paddedLength - padCount;
            int last = length - 1;

            int diff = 0;
            for (int i = 0; i < paddedLength; ++i)
            {
                int mask = (last - i) >> 31;
                diff |= (padByte ^ encoded[i]) & mask;
            }

            diff |= paddedLength & 7;
            diff |= (40 - paddedLength) >> 31;

            if (diff != 0)
                throw new PgpException("bad padding found in session data");

            byte[] result = new byte[length];
            Array.Copy(encoded, 0, result, 0, length);
            return result;
        }

        static ECDiffieHellman GetECDiffieHellman(ECCurve curve)
        {
            if (curve.Oid.Value == "1.3.6.1.4.1.3029.1.5.1")
                return new X25519();
            return ECDiffieHellman.Create(curve);
        }

        static ECDiffieHellman GetECDiffieHellman(ECParameters parameters)
        {
            if (parameters.Curve.Oid.Value == "1.3.6.1.4.1.3029.1.5.1")
            {
                if (parameters.D != null)
                    Array.Reverse(parameters.D);
                return new X25519(parameters);
            }
            return ECDiffieHellman.Create(parameters);
        }

        private void VerifyHashAlgorithm()
        {
            switch (hashAlgorithm)
            {
                case PgpHashAlgorithm.Sha256:
                case PgpHashAlgorithm.Sha384:
                case PgpHashAlgorithm.Sha512:
                    break;
                default:
                    throw new InvalidOperationException(SR.Cryptography_OpenPgp_HashMustBeSHA256OrStronger);
            }
        }

        private void VerifySymmetricKeyAlgorithm()
        {
            switch (symmetricAlgorithm)
            {
                case PgpSymmetricKeyAlgorithm.Aes128:
                case PgpSymmetricKeyAlgorithm.Aes192:
                case PgpSymmetricKeyAlgorithm.Aes256:
                    break;
                default:
                    throw new InvalidOperationException(SR.Cryptography_OpenPgp_SymmetricKeyAlgorithmMustBeAES256OrStronger);
            }
        }
    }
}
