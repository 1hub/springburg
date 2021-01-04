using Internal.Cryptography;
using System;
using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp.Keys
{
    class RsaKey : IAsymmetricPublicKey, IAsymmetricPrivateKey
    {
        RSA rsa;

        public PgpPublicKeyAlgorithm Algorithm => PgpPublicKeyAlgorithm.RsaGeneral;

        public bool CanSign => true;

        public bool CanEncrypt => true;

        public RsaKey(RSA rsa)
        {
            this.rsa = rsa;
        }

        public static RsaKey CreatePublic(
             ReadOnlySpan<byte> source,
             out int publicKeyBytes)
        {
            var rsaParameters = ReadOpenPgpPublicKey(source, out publicKeyBytes);
            return new RsaKey(RSA.Create(rsaParameters));
        }

        public static RsaKey CreatePrivate(
             ReadOnlySpan<byte> password,
             ReadOnlySpan<byte> source,
             out int publicKeyBytes,
             int version = 4)
        {
            var rsaParameters = ReadOpenPgpPublicKey(source, out publicKeyBytes);
            byte[] paramsArray = new byte[source.Length - publicKeyBytes];

            try
            {
                S2kBasedEncryption.DecryptSecretKey(password, source.Slice(publicKeyBytes), paramsArray, out int bytesWritten, version);
                Debug.Assert(bytesWritten != 0);

                int halfModulusLength = (rsaParameters.Modulus!.Length + 1) / 2;
                rsaParameters.D = new byte[rsaParameters.Modulus.Length];
                rsaParameters.P = new byte[halfModulusLength];
                rsaParameters.Q = new byte[halfModulusLength];
                rsaParameters.DP = new byte[halfModulusLength];
                rsaParameters.DQ = new byte[halfModulusLength];
                rsaParameters.InverseQ = new byte[halfModulusLength];

                var privateSource = new ReadOnlySpan<byte>(paramsArray);
                var d = MPInteger.ReadInteger(privateSource, out int dConsumed);
                privateSource = privateSource.Slice(dConsumed);
                var p = MPInteger.ReadInteger(privateSource, out int pConsumed);
                privateSource = privateSource.Slice(pConsumed);
                var q = MPInteger.ReadInteger(privateSource, out int qConsumed);
                //source = source.Slice(qConsumed);
                // Technically InverseQ follows but it's often incorrect

                // FIXME: These BigIntegers cannot be cleared from memory
                var D = new BigInteger(d, isBigEndian: true, isUnsigned: true); 
                var P = new BigInteger(p, isBigEndian: true, isUnsigned: true);
                var Q = new BigInteger(q, isBigEndian: true, isUnsigned: true);
                var DP = BigInteger.Remainder(D, P - BigInteger.One);
                var DQ = BigInteger.Remainder(D, Q - BigInteger.One);
                // Lot of the public keys in the test suite have this wrong (switched P/Q)
                var InverseQ = BigInteger.ModPow(Q, P - BigInteger.One - BigInteger.One, P);

                d.CopyTo(rsaParameters.D.AsSpan(rsaParameters.D.Length - d.Length));
                p.CopyTo(rsaParameters.P.AsSpan(rsaParameters.P.Length - p.Length));
                q.CopyTo(rsaParameters.Q.AsSpan(rsaParameters.Q.Length - q.Length));

                DP.TryWriteBytes(rsaParameters.DP.AsSpan(rsaParameters.DP.Length - DP.GetByteCount(isUnsigned: true)), out var _, isBigEndian: true, isUnsigned: true);
                DQ.TryWriteBytes(rsaParameters.DQ.AsSpan(rsaParameters.DQ.Length - DQ.GetByteCount(isUnsigned: true)), out var _, isBigEndian: true, isUnsigned: true);
                InverseQ.TryWriteBytes(rsaParameters.InverseQ.AsSpan(rsaParameters.InverseQ.Length - InverseQ.GetByteCount(isUnsigned: true)), out var _, isBigEndian: true, isUnsigned: true);

                return new RsaKey(RSA.Create(rsaParameters));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(paramsArray);
                CryptographicOperations.ZeroMemory(rsaParameters.D);
                CryptographicOperations.ZeroMemory(rsaParameters.P);
                CryptographicOperations.ZeroMemory(rsaParameters.Q);
                CryptographicOperations.ZeroMemory(rsaParameters.DP);
                CryptographicOperations.ZeroMemory(rsaParameters.DQ);
                CryptographicOperations.ZeroMemory(rsaParameters.InverseQ);
            }
        }

        public static RSAParameters ReadOpenPgpPublicKey(ReadOnlySpan<byte> source, out int bytesRead)
        {
            var rsaParameters = new RSAParameters();
            rsaParameters.Modulus = MPInteger.ReadInteger(source, out int modulusConsumed).ToArray();
            source = source.Slice(modulusConsumed);
            rsaParameters.Exponent = MPInteger.ReadInteger(source, out int exponentConsumed).ToArray();
            bytesRead = modulusConsumed + exponentConsumed;
            return rsaParameters;
        }

        public byte[] ExportPublicKey()
        {
            var rsaParameters = rsa.ExportParameters(false);
            int expectedLength = MPInteger.GetMPEncodedLength(rsaParameters.Modulus!, rsaParameters.Exponent!);
            var destination = new byte[expectedLength];
            MPInteger.TryWriteInteger(rsaParameters.Modulus, destination, out int modulusWritten);
            MPInteger.TryWriteInteger(rsaParameters.Exponent, destination.AsSpan(modulusWritten), out int exponentWritten);
            return destination.AsSpan(0, modulusWritten + exponentWritten).ToArray();
        }

        public byte[] ExportPrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            S2kParameters s2kParameters)
        {
            RSAParameters rsaParameters = new RSAParameters();
            byte[] secretPart = Array.Empty<byte>();

            try
            {
                rsaParameters = rsa.ExportParameters(true);

                secretPart = CryptoPool.Rent(MPInteger.GetMPEncodedLength(rsaParameters.D!, rsaParameters.P!, rsaParameters.Q!, rsaParameters.InverseQ!));
                MPInteger.TryWriteInteger(rsaParameters.D, secretPart, out var dBytesWritten);
                MPInteger.TryWriteInteger(rsaParameters.P, secretPart.AsSpan(dBytesWritten), out var pBytesWritten);
                MPInteger.TryWriteInteger(rsaParameters.Q, secretPart.AsSpan(dBytesWritten + pBytesWritten), out var qBytesWritten);
                MPInteger.TryWriteInteger(rsaParameters.InverseQ, secretPart.AsSpan(dBytesWritten + pBytesWritten + qBytesWritten), out var iqBytesWritten);
                int secretSize = dBytesWritten + pBytesWritten + qBytesWritten + iqBytesWritten;

                int encryptedSecretSize = S2kBasedEncryption.GetEncryptedLength(s2kParameters, secretSize);
                int expectedLength =
                    MPInteger.GetMPEncodedLength(rsaParameters.Modulus!, rsaParameters.Exponent!) +
                    encryptedSecretSize;
                var destination = new byte[expectedLength];

                MPInteger.TryWriteInteger(rsaParameters.Modulus, destination, out int modulusWritten);
                MPInteger.TryWriteInteger(rsaParameters.Exponent, destination.AsSpan(modulusWritten), out int exponentWritten);

                S2kBasedEncryption.EncryptSecretKey(passwordBytes, s2kParameters, secretPart.AsSpan(0, secretSize), destination.AsSpan(modulusWritten + exponentWritten));

                return destination.AsSpan(0, modulusWritten + exponentWritten + encryptedSecretSize).ToArray();
            }
            finally
            {
                CryptoPool.Return(secretPart);
                CryptographicOperations.ZeroMemory(rsaParameters.D);
                CryptographicOperations.ZeroMemory(rsaParameters.P);
                CryptographicOperations.ZeroMemory(rsaParameters.Q);
                CryptographicOperations.ZeroMemory(rsaParameters.InverseQ);
                CryptographicOperations.ZeroMemory(rsaParameters.DP);
                CryptographicOperations.ZeroMemory(rsaParameters.DQ);
            }
        }

        public bool VerifySignature(
            ReadOnlySpan<byte> rgbHash,
            ReadOnlySpan<byte> rgbSignature,
            PgpHashAlgorithm hashAlgorithm)
        {
            var signature = MPInteger.ReadInteger(rgbSignature, out var _);
            return rsa.VerifyHash(rgbHash, signature, PgpUtilities.GetHashAlgorithmName(hashAlgorithm), RSASignaturePadding.Pkcs1);
        }

        public byte[] CreateSignature(
            ReadOnlySpan<byte> rgbHash,
            PgpHashAlgorithm hashAlgorithm)
        {
            var signature = rsa.SignHash(rgbHash.ToArray(), PgpUtilities.GetHashAlgorithmName(hashAlgorithm), RSASignaturePadding.Pkcs1);
            var signatureBytes = new byte[MPInteger.GetMPEncodedLength(signature)];
            MPInteger.TryWriteInteger(signature, signatureBytes, out var _);
            return signatureBytes;
        }

        public byte[] EncryptSessionInfo(ReadOnlySpan<byte> sessionInfo)
        {
            var encryptedSessionInfo = rsa.Encrypt(sessionInfo.ToArray(), RSAEncryptionPadding.Pkcs1);
            var mp = new byte[MPInteger.GetMPEncodedLength(encryptedSessionInfo)];
            MPInteger.TryWriteInteger(encryptedSessionInfo, mp, out var _);
            return mp;
        }

        public bool TryDecryptSessionInfo(ReadOnlySpan<byte> encryptedSessionData, Span<byte> sessionData, out int bytesWritten)
        {
            var mp = MPInteger.ReadInteger(encryptedSessionData, out var _);
            var data = rsa.Decrypt(mp.ToArray(), RSAEncryptionPadding.Pkcs1);
            if (sessionData.Length >= data.Length)
            {
                data.CopyTo(sessionData);
                bytesWritten = data.Length;
                return true;
            }
            bytesWritten = 0;
            return false;
        }
    }
}
