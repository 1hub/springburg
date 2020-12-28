using Internal.Cryptography;
using NSec.Cryptography;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace InflatablePalace.Cryptography.Algorithms
{
    public class X25519 : ECDiffieHellman
    {
        Key? privateKey;
        PublicKey publicKey;

        public X25519()
        {
            this.privateKey = Key.Create(KeyAgreementAlgorithm.X25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            this.publicKey = this.privateKey.PublicKey;
        }

        public X25519(ECParameters parameters)
        {
            // TODO: Verify curve id
            if (parameters.D != null)
                this.privateKey = Key.Import(KeyAgreementAlgorithm.X25519, parameters.D, KeyBlobFormat.RawPrivateKey);
            this.publicKey = NSec.Cryptography.PublicKey.Import(KeyAgreementAlgorithm.X25519, parameters.Q.X, KeyBlobFormat.RawPublicKey);
        }

        // TODO: Implement other key derivation methods:
        // https://github.com/dotnet/runtime/blob/1d9e50cb4735df46d3de0cee5791e97295eaf588/src/libraries/Common/src/System/Security/Cryptography/ECDiffieHellmanDerivation.cs

        public override byte[] DeriveKeyFromHash(ECDiffieHellmanPublicKey otherPartyPublicKey, HashAlgorithmName hashAlgorithm, byte[]? secretPrepend, byte[]? secretAppend)
        {
            if (this.privateKey == null)
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, nameof(hashAlgorithm));

            using var sharedSecret = KeyAgreementAlgorithm.X25519.Agree(this.privateKey, ((X25519PublicKey)otherPartyPublicKey).publicKey);

            // NSec doesn't offer a way to export the shared secret. Unfortunately it also doesn't provide
            // the correct key derivation function so we have to resort to using the private API.
            var memoryHandle = (SafeHandle?)typeof(SharedSecret).GetProperty("Handle", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?.GetMethod?.Invoke(sharedSecret, null);
            Debug.Assert(memoryHandle != null);
            byte[] secretBytes = new byte[32];
            Marshal.Copy(memoryHandle.DangerousGetHandle(), secretBytes, 0, 32);

            using (var hash = System.Security.Cryptography.IncrementalHash.CreateHash(hashAlgorithm))
            {
                if (secretPrepend != null)
                    hash.AppendData(secretPrepend);
                hash.AppendData(secretBytes);
                if (secretAppend != null)
                    hash.AppendData(secretAppend);
                
                return hash.GetHashAndReset();
            }

            // Uses HMAC :/
            //if (hashAlgorithm == HashAlgorithmName.SHA256)
            //    return NSec.Cryptography.HkdfSha256.DeriveBytes(sharedSecret, secretAppend, secretAppend, 32);
        }

        public override ECParameters ExportParameters(bool includePrivateParameters)
        {
            if (this.privateKey == null && includePrivateParameters)
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);

            return new ECParameters
            {
                Curve = ECCurve.CreateFromOid(new Oid("1.3.6.1.4.1.3029.1.5.1")),
                D = includePrivateParameters ? privateKey!.Export(KeyBlobFormat.RawPrivateKey) : null,
                Q = new ECPoint { X = publicKey.Export(KeyBlobFormat.RawPublicKey), Y = new byte[32] }
            };
        }

        public override ECDiffieHellmanPublicKey PublicKey => new X25519PublicKey(publicKey);

        class X25519PublicKey : ECDiffieHellmanPublicKey
        {
            internal PublicKey publicKey;

            public X25519PublicKey(PublicKey publicKey)
            {
                this.publicKey = publicKey;
            }

            public override ECParameters ExportParameters()
            {
                return new ECParameters
                {
                    Curve = ECCurve.CreateFromOid(new Oid("1.3.6.1.4.1.3029.1.5.1")),
                    Q = new ECPoint { X = publicKey.Export(KeyBlobFormat.RawPublicKey), Y = new byte[32] }
                };
            }
        }
    }
}
