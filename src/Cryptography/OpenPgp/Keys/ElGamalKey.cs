using Internal.Cryptography;
using Springburg.Cryptography.Algorithms;
using System;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp.Keys
{
    class ElGamalKey : IAsymmetricPublicKey, IAsymmetricPrivateKey
    {
        ElGamal elGamal;

        public PgpPublicKeyAlgorithm Algorithm => PgpPublicKeyAlgorithm.ElGamalGeneral;

        public bool CanSign => false;

        public bool CanEncrypt => true;

        public ElGamalKey(ElGamal elGamal)
        {
            this.elGamal = elGamal;
        }

        public static ElGamalKey CreatePublic(
             ReadOnlySpan<byte> source,
             out int publicKeySize)
        {
            var elgamalParameters = ReadOpenPgpPublicKey(source, out publicKeySize);
            return new ElGamalKey(ElGamal.Create(elgamalParameters));
        }

        public static ElGamalKey CreatePrivate(
             ReadOnlySpan<byte> password,
             ReadOnlySpan<byte> source,
             out int bytesRead)
        {
            var elgamalParameters = ReadOpenPgpPublicKey(source, out bytesRead);
            byte[] xArray = new byte[source.Length - bytesRead];

            try
            {
                S2kBasedEncryption.DecryptSecretKey(password, source.Slice(bytesRead), xArray, out int bytesWritten);
                elgamalParameters.X = MPInteger.ReadInteger(xArray, out int xConsumed).ToArray();
                bytesRead = source.Length;
                return new ElGamalKey(ElGamal.Create(elgamalParameters));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(xArray);
                CryptographicOperations.ZeroMemory(elgamalParameters.X);
            }
        }

        private static ElGamalParameters ReadOpenPgpPublicKey(ReadOnlySpan<byte> source, out int bytesRead)
        {
            var elgamalParameters = new ElGamalParameters();
            elgamalParameters.P = MPInteger.ReadInteger(source, out int pConsumed).ToArray();
            source = source.Slice(pConsumed);
            elgamalParameters.G = MPInteger.ReadInteger(source, out int gConsumed).ToArray();
            source = source.Slice(gConsumed);
            elgamalParameters.Y = MPInteger.ReadInteger(source, out int yConsumed).ToArray();
            bytesRead = pConsumed + gConsumed + yConsumed;
            return elgamalParameters;
        }

        private static void WriteOpenPgpPublicKey(ElGamalParameters elgamalParameters, Span<byte> destination)
        {
            MPInteger.TryWriteInteger(elgamalParameters.P, destination, out int pWritten);
            MPInteger.TryWriteInteger(elgamalParameters.G, destination.Slice(pWritten), out int gWritten);
            MPInteger.TryWriteInteger(elgamalParameters.Y, destination.Slice(pWritten + gWritten), out int yWritten);
        }

        public byte[] ExportPublicKey()
        {
            var elgamalParameters = elGamal.ExportParameters(false);
            int expectedLength = MPInteger.GetMPEncodedLength(elgamalParameters.P!, elgamalParameters.G!, elgamalParameters.Y!);
            var destination = new byte[expectedLength];
            WriteOpenPgpPublicKey(elgamalParameters, destination);
            return destination;
        }

        public byte[] ExportPrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            S2kParameters s2kParameters)
        {
            ElGamalParameters elgamalParameters = new ElGamalParameters();
            byte[] secretPart = Array.Empty<byte>();

            try
            {
                elgamalParameters = elGamal.ExportParameters(true);
                secretPart = CryptoPool.Rent(MPInteger.GetMPEncodedLength(elgamalParameters.X!));
                MPInteger.TryWriteInteger(elgamalParameters.X, secretPart, out var secretSize);
                int publicKeySize = MPInteger.GetMPEncodedLength(elgamalParameters.P!, elgamalParameters.G!, elgamalParameters.Y!);
                int encryptedSecretSize = S2kBasedEncryption.GetEncryptedLength(s2kParameters, secretSize);
                int expectedLength = publicKeySize + encryptedSecretSize;
                var destination = new byte[expectedLength];
                WriteOpenPgpPublicKey(elgamalParameters, destination);
                S2kBasedEncryption.EncryptSecretKey(passwordBytes, s2kParameters, secretPart.AsSpan(0, secretSize), destination.AsSpan(publicKeySize));
                return destination;
            }
            finally
            {
                CryptoPool.Return(secretPart);
                CryptographicOperations.ZeroMemory(elgamalParameters.X);
            }
        }

        public bool VerifySignature(ReadOnlySpan<byte> rgbHash, ReadOnlySpan<byte> rgbSignature, PgpHashAlgorithm hashAlgorithm)
        {
            throw new NotSupportedException();
        }

        public byte[] CreateSignature(ReadOnlySpan<byte> rgbHash, PgpHashAlgorithm hashAlgorithm)
        {
            throw new NotSupportedException();
        }

        public byte[] EncryptSessionInfo(ReadOnlySpan<byte> sessionInfo)
        {
            var encryptedData = elGamal.Encrypt(sessionInfo, RSAEncryptionPadding.Pkcs1);
            var g = encryptedData.Slice(0, encryptedData.Length / 2);
            var p = encryptedData.Slice(encryptedData.Length / 2);
            var mp = new byte[MPInteger.GetMPEncodedLength(g) + MPInteger.GetMPEncodedLength(p)];
            MPInteger.TryWriteInteger(g, mp, out var gWritten);
            MPInteger.TryWriteInteger(p, mp.AsSpan(gWritten), out var _);
            return mp;
        }

        public bool TryDecryptSessionInfo(ReadOnlySpan<byte> encryptedSessionData, Span<byte> sessionData, out int bytesWritten)
        {
            var g = MPInteger.ReadInteger(encryptedSessionData, out var gBytesRead);
            var p = MPInteger.ReadInteger(encryptedSessionData.Slice(gBytesRead), out var _);
            var halfLength = Math.Max(g.Length, p.Length);
            var inputData = new byte[halfLength * 2];
            g.CopyTo(inputData.AsSpan(halfLength - g.Length));
            p.CopyTo(inputData.AsSpan(inputData.Length - p.Length));
            var data = elGamal.Decrypt(inputData, RSAEncryptionPadding.Pkcs1);
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
