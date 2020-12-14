using NSec.Cryptography;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace InflatablePalace.Cryptography.Algorithms
{
    public class X25519 : ECDiffieHellman
    {
        Key privateKey;
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

        public override byte[] DeriveKeyFromHash(ECDiffieHellmanPublicKey otherPartyPublicKey, HashAlgorithmName hashAlgorithm, byte[] secretPrepend, byte[] secretAppend)
        {
            using var sharedSecret = KeyAgreementAlgorithm.X25519.Agree(this.privateKey, ((X25519PublicKey)otherPartyPublicKey).publicKey);

            // NSec doesn't offer a way to export the shared secret. Unfortunately it also doesn't provide
            // the correct key derivation function so we have to resort to using the private API.
            var memoryHandle = (SafeHandle)typeof(SharedSecret).GetProperty("Handle", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance).GetMethod.Invoke(sharedSecret, null);
            byte[] secretBytes = new byte[32];
            Marshal.Copy(memoryHandle.DangerousGetHandle(), secretBytes, 0, 32);

            var hashAlg = System.Security.Cryptography.HashAlgorithm.Create(hashAlgorithm.Name);
            if (secretPrepend != null)
                hashAlg.TransformBlock(secretPrepend, 0, secretPrepend.Length, null, 0);
            hashAlg.TransformBlock(secretBytes, 0, secretBytes.Length, null, 0);
            if (secretAppend != null)
                hashAlg.TransformBlock(secretAppend, 0, secretAppend.Length, null, 0);
            hashAlg.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

            return hashAlg.Hash;

            // Uses HMAC :/
            //if (hashAlgorithm == HashAlgorithmName.SHA256)
            //    return NSec.Cryptography.HkdfSha256.DeriveBytes(sharedSecret, secretAppend, secretAppend, 32);
        }

        public override ECParameters ExportParameters(bool includePrivateParameters)
        {
            return new ECParameters
            {
                Curve = ECCurve.CreateFromOid(new Oid("1.3.6.1.4.1.3029.1.5.1")),
                D = includePrivateParameters ? privateKey.Export(KeyBlobFormat.RawPrivateKey) : null,
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
