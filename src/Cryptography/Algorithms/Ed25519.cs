using Internal.Cryptography;
using NSec.Cryptography;
using System;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;

namespace Springburg.Cryptography.Algorithms
{
    public class Ed25519 : ECDsa
    {
        Key? privateKey;
        PublicKey? publicKey;

        public Ed25519()
        {
        }

        public Ed25519(ECParameters ecParameters)
        {
            ImportParameters(ecParameters);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                privateKey?.Dispose();
            }
            base.Dispose(disposing);
        }

        private void CreateKeys()
        {
            this.privateKey = Key.Create(NSec.Cryptography.SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            this.publicKey = this.privateKey.PublicKey;
        }

        protected override byte[] SignHashCore(ReadOnlySpan<byte> hash, DSASignatureFormat signatureFormat)
        {
            if (this.publicKey == null)
                CreateKeys();
            if (this.privateKey == null)
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);

            byte[] signature = NSec.Cryptography.SignatureAlgorithm.Ed25519.Sign(this.privateKey, hash).ToArray();

            if (signatureFormat == DSASignatureFormat.Rfc3279DerSequence)
            {
                var writer = new AsnWriter(AsnEncodingRules.DER);
                using (var sequence = writer.PushSequence())
                {
                    writer.WriteIntegerUnsigned(signature.AsSpan(0, 32));
                    writer.WriteIntegerUnsigned(signature.AsSpan(32));
                }
                signature = writer.Encode();
            }

            return signature;
        }

        protected override bool VerifyHashCore(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, DSASignatureFormat signatureFormat)
        {
            if (this.publicKey == null)
            {
                CreateKeys();
                Debug.Assert(this.publicKey != null);
            }

            if (signatureFormat == DSASignatureFormat.Rfc3279DerSequence)
            {
                var reader = new AsnReader(signature.ToArray(), AsnEncodingRules.DER);
                var sequence = reader.ReadSequence();
                var i1 = sequence.ReadInteger().ToByteArray(isUnsigned: true, isBigEndian: true);
                var i2 = sequence.ReadInteger().ToByteArray(isUnsigned: true, isBigEndian: true);
                var tempSignature = new byte[64];
                Array.Copy(i1, 0, tempSignature, 32 - i1.Length, i1.Length);
                Array.Copy(i2, 0, tempSignature, 64 - i2.Length, i2.Length);
                signature = tempSignature;
            }

            return NSec.Cryptography.SignatureAlgorithm.Ed25519.Verify(this.publicKey, hash, signature);
        }

        public override byte[] SignHash(byte[] hash)
        {
            return SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            return VerifyHash(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        public override void ImportParameters(ECParameters parameters)
        {
            privateKey?.Dispose();
            privateKey = null;
            publicKey = null;

            if (parameters.Q.X == null || parameters.Q.X?.Length != 32)
                throw new ArgumentException("Invalid public key parameters");
            if (parameters.D != null && parameters.D.Length != 32)
                throw new ArgumentException("Invalid private key parameters");

            this.publicKey = PublicKey.Import(NSec.Cryptography.SignatureAlgorithm.Ed25519, parameters.Q.X, KeyBlobFormat.RawPublicKey);
            if (parameters.D != null)
                this.privateKey = Key.Import(NSec.Cryptography.SignatureAlgorithm.Ed25519, parameters.D, KeyBlobFormat.RawPrivateKey);
        }

        public override ECParameters ExportParameters(bool includePrivateParameters)
        {
            if (this.publicKey == null)
                CreateKeys();
            if (this.privateKey == null && includePrivateParameters)
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);

            return new ECParameters
            {
                Curve = ECCurve.CreateFromOid(new Oid("1.3.6.1.4.1.11591.15.1")),
                D = includePrivateParameters ? privateKey!.Export(KeyBlobFormat.RawPrivateKey) : null,
                Q = new ECPoint { X = publicKey!.Export(KeyBlobFormat.RawPublicKey), Y = new byte[32] }
            };
        }
    }
}
