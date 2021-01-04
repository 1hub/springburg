using Internal.Cryptography;
using Springburg.Cryptography.Algorithms;
using System;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp.Keys
{
    class ECDsaKey : ECKey, IAsymmetricPrivateKey, IAsymmetricPublicKey
    {
        private ECDsa ecdsa;

        public virtual PgpPublicKeyAlgorithm Algorithm => PgpPublicKeyAlgorithm.ECDsa;

        public bool CanSign => true;

        public bool CanEncrypt => false;

        public ECDsaKey(ECDsa ecdsa)
        {
            this.ecdsa = ecdsa;
        }

        public static ECDsaKey CreatePublic(
             ReadOnlySpan<byte> source,
             out int publicKeySize)
        {
            var ecParameters = ReadOpenPgpECParameters(source, out publicKeySize);
            return new ECDsaKey(CreateECDsa(ecParameters));
        }


        public static ECDsaKey CreatePrivate(
             ReadOnlySpan<byte> password,
             ReadOnlySpan<byte> source,
             out int publicKeySize)
        {
            var ecParameters = ReadOpenPgpECParameters(source, out publicKeySize);
            byte[] paramsArray = new byte[source.Length - publicKeySize];

            try
            {
                S2kBasedEncryption.DecryptSecretKey(password, source.Slice(publicKeySize), paramsArray, out int bytesWritten);
                Debug.Assert(bytesWritten != 0);
                ecParameters.D = MPInteger.ReadInteger(paramsArray, out int dConsumed).ToArray();
                return new ECDsaKey(CreateECDsa(ecParameters));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(paramsArray);
                CryptographicOperations.ZeroMemory(ecParameters.D);
            }
        }

        private static ECDsa CreateECDsa(ECParameters ecParameters)
        {
            switch (ecParameters.Curve.Oid.Value)
            {
                case "1.2.840.10045.3.1.7": // NIST P-256
                case "1.3.132.0.34": // NIST P-384
                case "1.3.132.0.35": // NIST P-521
                case "1.3.36.3.3.2.8.1.1.7": // brainpoolP256r1
                case "1.3.36.3.3.2.8.1.1.11": // brainpoolP384r1 (not in RFC 4880bis!)
                case "1.3.36.3.3.2.8.1.1.13": // brainpoolP512r1
                    return ECDsa.Create(ecParameters);
                default:
                    throw new CryptographicException(SR.Cryptography_OpenPgp_UnsupportedCurveOid, ecParameters.Curve.Oid.Value);
            }
        }

        public byte[] ExportPublicKey()
        {
            var ecParameters = ecdsa.ExportParameters(false);
            int estimatedLength = 32 /* OID */ + MPInteger.GetMPEncodedLength(ecParameters.Q.X!, ecParameters.Q.Y!) + 1 /* EC Point type */;
            var destination = new byte[estimatedLength];
            WriteOpenPgpECParameters(ecParameters, destination, out var bytesWritten);
            return destination.AsSpan(0, bytesWritten).ToArray();
        }

        public byte[] ExportPrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            S2kParameters s2kParameters)
        {
            ECParameters ecParameters = new ECParameters();
            byte[] secretPart = Array.Empty<byte>();

            try
            {
                ecParameters = ecdsa.ExportParameters(true);

                int secretSize = MPInteger.GetMPEncodedLength(ecParameters.D!);
                secretPart = CryptoPool.Rent(secretSize);
                MPInteger.TryWriteInteger(ecParameters.D, secretPart, out var _);

                int encryptedSecretLength = S2kBasedEncryption.GetEncryptedLength(s2kParameters, secretSize);
                int estimatedLength =
                    32 /* OID */ +
                    MPInteger.GetMPEncodedLength(ecParameters.Q.X!, ecParameters.Q.Y!) + 1 /* EC Point type */ +
                    encryptedSecretLength;
                var destination = new byte[estimatedLength];
                WriteOpenPgpECParameters(ecParameters, destination, out int bytesWritten);

                S2kBasedEncryption.EncryptSecretKey(passwordBytes, s2kParameters, secretPart.AsSpan(0, secretSize), destination.AsSpan(bytesWritten));
                return destination.AsSpan(0, bytesWritten + encryptedSecretLength).ToArray();
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
            var asnWriter = new AsnWriter(AsnEncodingRules.DER);
            using (var scope = asnWriter.PushSequence())
            {
                asnWriter.WriteIntegerUnsigned(MPInteger.ReadInteger(rgbSignature, out int rConsumed));
                asnWriter.WriteIntegerUnsigned(MPInteger.ReadInteger(rgbSignature.Slice(rConsumed), out var _));
            }
            return ecdsa.VerifyHash(rgbHash, asnWriter.Encode(), DSASignatureFormat.Rfc3279DerSequence);
        }

        public byte[] CreateSignature(ReadOnlySpan<byte> rgbHash, PgpHashAlgorithm hashAlgorithm)
        {
            byte[] ieeeSignature = ecdsa.SignHash(rgbHash.ToArray(), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            byte[] pgpSignature = new byte[ieeeSignature.Length + 4]; // Maximum possible length
            MPInteger.TryWriteInteger(ieeeSignature.AsSpan(0, ieeeSignature.Length / 2), pgpSignature, out int rWritten);
            MPInteger.TryWriteInteger(ieeeSignature.AsSpan(ieeeSignature.Length / 2), pgpSignature.AsSpan(rWritten), out int sWritten);
            return pgpSignature.AsSpan(0, rWritten + sWritten).ToArray();
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
