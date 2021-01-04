using Internal.Cryptography;
using Springburg.Cryptography.Algorithms;
using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp.Keys
{
    class EdDsaKey : ECDsaKey
    {
        public override PgpPublicKeyAlgorithm Algorithm => PgpPublicKeyAlgorithm.EdDsa;

        public EdDsaKey(ECDsa eddsa)
            : base(eddsa)
        {
            Debug.Assert(eddsa is Ed25519);
        }

        public new static EdDsaKey CreatePublic(
             ReadOnlySpan<byte> source,
             out int publicKeySize)
        {
            var ecParameters = ReadOpenPgpECParameters(source, out publicKeySize);
            return new EdDsaKey(CreateEdDsa(ecParameters));
        }


        public new static EdDsaKey CreatePrivate(
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
                return new EdDsaKey(CreateEdDsa(ecParameters));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(paramsArray);
                CryptographicOperations.ZeroMemory(ecParameters.D);
            }
        }

        private static ECDsa CreateEdDsa(ECParameters ecParameters)
        {
            switch (ecParameters.Curve.Oid.Value)
            {
                case "1.3.6.1.4.1.11591.15.1": // Ed25519
                    return new Ed25519(ecParameters);
                default:
                    throw new CryptographicException(SR.Cryptography_OpenPgp_UnsupportedCurveOid, ecParameters.Curve.Oid.Value);
            }
        }
    }
}
