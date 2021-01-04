using Internal.Cryptography;
using System;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp.Keys
{
    class DsaKey : IAsymmetricPrivateKey, IAsymmetricPublicKey
    {
        private DSA dsa;

        public PgpPublicKeyAlgorithm Algorithm => PgpPublicKeyAlgorithm.Dsa;

        public bool CanSign => true;

        public bool CanEncrypt => false;

        public DsaKey(DSA dsa)
        {
            this.dsa = dsa;
        }

        public static DsaKey CreatePublic(
             ReadOnlySpan<byte> source,
             out int publicKeySize)
        {
            var dsaParameters = ReadOpenPgpPublicKey(source, out publicKeySize);
            return new DsaKey(DSA.Create(dsaParameters));
        }


        public static DsaKey CreatePrivate(
             ReadOnlySpan<byte> password,
             ReadOnlySpan<byte> source,
             out int publicKeySize)
        {
            var dsaParameters = ReadOpenPgpPublicKey(source, out publicKeySize);
            byte[] xArray = new byte[source.Length - publicKeySize];

            try
            {
                S2kBasedEncryption.DecryptSecretKey(password, source.Slice(publicKeySize), xArray, out int bytesWritten);

                dsaParameters.X = MPInteger.ReadInteger(xArray, out int xConsumed).ToArray();

                // Make sure Q and X have the same length (DSA implementation on Windows requires it)
                if (dsaParameters.X.Length != dsaParameters.Q!.Length)
                {
                    int qxLength = Math.Max(dsaParameters.X.Length, dsaParameters.Q.Length);
                    if (dsaParameters.X.Length != qxLength)
                    {
                        var X = dsaParameters.X;
                        dsaParameters.X = new byte[qxLength];
                        X.CopyTo(dsaParameters.X, qxLength - X.Length);
                        CryptographicOperations.ZeroMemory(X);
                    }
                    if (dsaParameters.Q.Length != qxLength)
                    {
                        var Q = dsaParameters.Q;
                        dsaParameters.Q = new byte[qxLength];
                        Q.CopyTo(dsaParameters.Q, qxLength - Q.Length);
                        CryptographicOperations.ZeroMemory(Q);
                    }
                }

                return new DsaKey(DSA.Create(dsaParameters));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(xArray);
                CryptographicOperations.ZeroMemory(dsaParameters.X);
            }
        }

        private static DSAParameters ReadOpenPgpPublicKey(ReadOnlySpan<byte> source, out int bytesRead)
        {
            var dsaParameters = new DSAParameters();
            dsaParameters.P = MPInteger.ReadInteger(source, out int pConsumed).ToArray();
            source = source.Slice(pConsumed);
            dsaParameters.Q = MPInteger.ReadInteger(source, out int qConsumed).ToArray();
            source = source.Slice(qConsumed);
            dsaParameters.G = MPInteger.ReadInteger(source, out int gConsumed).ToArray();
            source = source.Slice(gConsumed);
            dsaParameters.Y = MPInteger.ReadInteger(source, out int yConsumed).ToArray();
            bytesRead = pConsumed + qConsumed + gConsumed + yConsumed;
            return dsaParameters;
        }

        private static void WriteOpenPgpPublicKey(DSAParameters dsaParameters, Span<byte> destination)
        {
            MPInteger.TryWriteInteger(dsaParameters.P, destination, out int pWritten);
            MPInteger.TryWriteInteger(dsaParameters.Q, destination.Slice(pWritten), out int qWritten);
            MPInteger.TryWriteInteger(dsaParameters.G, destination.Slice(pWritten + qWritten), out int gWritten);
            MPInteger.TryWriteInteger(dsaParameters.Y, destination.Slice(pWritten + qWritten + gWritten), out int yWritten);
        }

        public byte[] ExportPublicKey()
        {
            var dsaParameters = dsa.ExportParameters(false);
            int expectedLength = MPInteger.GetMPEncodedLength(dsaParameters.P!, dsaParameters.Q!, dsaParameters.G!, dsaParameters.Y!);
            var destination = new byte[expectedLength];
            WriteOpenPgpPublicKey(dsaParameters, destination);
            return destination;
        }

        public byte[] ExportPrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            S2kParameters s2kParameters)
        {
            DSAParameters dsaParameters = new DSAParameters();
            byte[] secretPart = Array.Empty<byte>();

            try
            {
                dsaParameters = dsa.ExportParameters(true);
                secretPart = CryptoPool.Rent(MPInteger.GetMPEncodedLength(dsaParameters.X!));
                MPInteger.TryWriteInteger(dsaParameters.X, secretPart, out var secretSize);
                int publicKeySize = MPInteger.GetMPEncodedLength(dsaParameters.P!, dsaParameters.Q!, dsaParameters.G!, dsaParameters.Y!);
                int encryptedSecretSize = S2kBasedEncryption.GetEncryptedLength(s2kParameters, secretSize);
                int expectedLength = publicKeySize + encryptedSecretSize;
                var destination = new byte[expectedLength];
                WriteOpenPgpPublicKey(dsaParameters, destination);
                S2kBasedEncryption.EncryptSecretKey(passwordBytes, s2kParameters, secretPart.AsSpan(0, secretSize), destination.AsSpan(publicKeySize));
                return destination;
            }
            finally
            {
                CryptoPool.Return(secretPart);
                CryptographicOperations.ZeroMemory(dsaParameters.X);
            }
        }

        public bool VerifySignature(
            ReadOnlySpan<byte> rgbHash,
            ReadOnlySpan<byte> rgbSignature,
            PgpHashAlgorithm hashAlgorithm)
        {
            var asnWriter = new AsnWriter(AsnEncodingRules.DER);
            using (var scope = asnWriter.PushSequence())
            {
                asnWriter.WriteIntegerUnsigned(MPInteger.ReadInteger(rgbSignature, out int rConsumed));
                asnWriter.WriteIntegerUnsigned(MPInteger.ReadInteger(rgbSignature.Slice(rConsumed), out var _));
            }
            return dsa.VerifySignature(rgbHash, asnWriter.Encode(), DSASignatureFormat.Rfc3279DerSequence);
        }

        public byte[] CreateSignature(ReadOnlySpan<byte> rgbHash, PgpHashAlgorithm hashAlgorithm)
        {
            byte[] ieeeSignature = dsa.CreateSignature(rgbHash.ToArray(), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            var r = ieeeSignature.AsSpan(0, ieeeSignature.Length / 2);
            var s = ieeeSignature.AsSpan(ieeeSignature.Length / 2);
            byte[] pgpSignature = new byte[MPInteger.GetMPEncodedLength(r) + MPInteger.GetMPEncodedLength(s)];
            MPInteger.TryWriteInteger(r, pgpSignature, out int rWritten);
            MPInteger.TryWriteInteger(s, pgpSignature.AsSpan(rWritten), out int _);
            return pgpSignature;
        }

        public bool TryDecryptSessionInfo(ReadOnlySpan<byte> encryptedSessionData, Span<byte> sessionData, out int bytesWritten)
        {
            throw new NotSupportedException();
        }

        public byte[] EncryptSessionInfo(ReadOnlySpan<byte> sessionInfo)
        {
            throw new NotSupportedException();
        }
    }
}
