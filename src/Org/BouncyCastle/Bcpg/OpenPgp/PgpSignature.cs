using System;
using System.Formats.Asn1;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A PGP signature object.</remarks>
    public class PgpSignature
    {
        private static SignaturePacket Cast(Packet packet)
        {
            if (!(packet is SignaturePacket))
                throw new IOException("unexpected packet in stream: " + packet);

            return (SignaturePacket)packet;
        }

        public const int BinaryDocument = 0x00;
        public const int CanonicalTextDocument = 0x01;
        public const int StandAlone = 0x02;

        public const int DefaultCertification = 0x10;
        public const int NoCertification = 0x11;
        public const int CasualCertification = 0x12;
        public const int PositiveCertification = 0x13;

        public const int SubkeyBinding = 0x18;
        public const int PrimaryKeyBinding = 0x19;
        public const int DirectKey = 0x1f;
        public const int KeyRevocation = 0x20;
        public const int SubkeyRevocation = 0x28;
        public const int CertificationRevocation = 0x30;
        public const int Timestamp = 0x40;

        private readonly SignaturePacket sigPck;
        private readonly int signatureType;
        private readonly TrustPacket trustPck;

        private HashAlgorithm sig;
        private PgpPublicKey pubKey;
        private byte lastb; // Initial value anything but '\r'

        internal PgpSignature(
            BcpgInputStream bcpgInput)
            : this(Cast(bcpgInput.ReadPacket()))
        {
        }

        internal PgpSignature(
            SignaturePacket sigPacket)
            : this(sigPacket, null)
        {
        }

        internal PgpSignature(
            SignaturePacket sigPacket,
            TrustPacket trustPacket)
        {
            if (sigPacket == null)
                throw new ArgumentNullException("sigPacket");

            this.sigPck = sigPacket;
            this.signatureType = sigPck.SignatureType;
            this.trustPck = trustPacket;
        }

        /// <summary>The OpenPGP version number for this signature.</summary>
        public int Version
        {
            get { return sigPck.Version; }
        }

        /// <summary>The key algorithm associated with this signature.</summary>
        public PublicKeyAlgorithmTag KeyAlgorithm
        {
            get { return sigPck.KeyAlgorithm; }
        }

        /// <summary>The hash algorithm associated with this signature.</summary>
        public HashAlgorithmTag HashAlgorithm
        {
            get { return sigPck.HashAlgorithm; }
        }

        /// <summary>Return true if this signature represents a certification.</summary>
        public bool IsCertification()
        {
            return IsCertification(SignatureType);
        }

        public void InitVerify(
            PgpPublicKey pubKey)
        {
            lastb = 0;
            this.sig = PgpUtilities.GetHashAlgorithm(sigPck.HashAlgorithm);
            this.pubKey = pubKey;
            /*if (sig == null)
            {
                GetSig();
            }
            try
            {
                sig.Init(false, pubKey.GetKey());
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }*/
        }

        public void Update(
            byte b)
        {
            if (signatureType == CanonicalTextDocument)
            {
                doCanonicalUpdateByte(b);
            }
            else
            {
                sig.TransformBlock(new byte[] { b }, 0, 1, null, 0);
            }
        }

        private void doCanonicalUpdateByte(
            byte b)
        {
            if (b == '\r')
            {
                doUpdateCRLF();
            }
            else if (b == '\n')
            {
                if (lastb != '\r')
                {
                    doUpdateCRLF();
                }
            }
            else
            {
                sig.TransformBlock(new byte[] { b }, 0, 1, null, 0);
            }

            lastb = b;
        }

        private void doUpdateCRLF()
        {
            sig.TransformBlock(new byte[] { (byte)'\r', (byte)'\n' }, 0, 2, null, 0);
        }

        public void Update(
            params byte[] bytes)
        {
            Update(bytes, 0, bytes.Length);
        }

        public void Update(
            byte[] bytes,
            int off,
            int length)
        {
            if (signatureType == CanonicalTextDocument)
            {
                int finish = off + length;

                for (int i = off; i != finish; i++)
                {
                    doCanonicalUpdateByte(bytes[i]);
                }
            }
            else
            {
                sig.TransformBlock(bytes, off, length, null, 0);
            }
        }

        public bool Verify()
        {
            byte[] trailer = GetSignatureTrailer();
            sig.TransformFinalBlock(trailer, 0, trailer.Length);
            var hash = sig.Hash;
            var key = pubKey.GetKey();
            if (key is RSA rsa)
                return rsa.VerifyHash(hash, GetSignature(), PgpUtilities.GetHashAlgorithmName(sigPck.HashAlgorithm), RSASignaturePadding.Pkcs1);
            if (key is DSA dsa)
                return dsa.VerifySignature(hash, GetSignature(), DSASignatureFormat.Rfc3279DerSequence);
            if (key is ECDsa ecdsa)
                return ecdsa.VerifyHash(hash, GetSignature(), DSASignatureFormat.Rfc3279DerSequence);
            throw new NotImplementedException();
            //return sig.VerifySignature(GetSignature());
        }

        private void UpdateWithIdData(
            int header,
            byte[] idBytes)
        {
            this.Update(
                (byte)header,
                (byte)(idBytes.Length >> 24),
                (byte)(idBytes.Length >> 16),
                (byte)(idBytes.Length >> 8),
                (byte)(idBytes.Length));
            this.Update(idBytes);
        }

        private void UpdateWithPublicKey(
            PgpPublicKey key)
        {
            byte[] keyBytes = GetEncodedPublicKey(key);

            this.Update(
                (byte)0x99,
                (byte)(keyBytes.Length >> 8),
                (byte)(keyBytes.Length));
            this.Update(keyBytes);
        }

        /// <summary>
        /// Verify the signature as certifying the passed in public key as associated
        /// with the passed in user attributes.
        /// </summary>
        /// <param name="userAttributes">User attributes the key was stored under.</param>
        /// <param name="key">The key to be verified.</param>
        /// <returns>True, if the signature matches, false otherwise.</returns>
        public bool VerifyCertification(
            PgpUserAttributeSubpacketVector userAttributes,
            PgpPublicKey key)
        {
            UpdateWithPublicKey(key);

            //
            // hash in the userAttributes
            //
            try
            {
                MemoryStream bOut = new MemoryStream();
                foreach (UserAttributeSubpacket packet in userAttributes.ToSubpacketArray())
                {
                    packet.Encode(bOut);
                }
                UpdateWithIdData(0xd1, bOut.ToArray());
            }
            catch (IOException e)
            {
                throw new PgpException("cannot encode subpacket array", e);
            }

            return this.Verify();
            /*this.Update(sigPck.GetSignatureTrailer());

			return sig.VerifySignature(this.GetSignature());*/
        }

        /// <summary>
        /// Verify the signature as certifying the passed in public key as associated
        /// with the passed in ID.
        /// </summary>
        /// <param name="id">ID the key was stored under.</param>
        /// <param name="key">The key to be verified.</param>
        /// <returns>True, if the signature matches, false otherwise.</returns>
        public bool VerifyCertification(
            string id,
            PgpPublicKey key)
        {
            UpdateWithPublicKey(key);

            //
            // hash in the id
            //
            UpdateWithIdData(0xb4, Encoding.UTF8.GetBytes(id));

            return this.Verify();
            /*Update(sigPck.GetSignatureTrailer());

			return sig.VerifySignature(GetSignature());*/
        }

        /// <summary>Verify a certification for the passed in key against the passed in master key.</summary>
        /// <param name="masterKey">The key we are verifying against.</param>
        /// <param name="pubKey">The key we are verifying.</param>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        public bool VerifyCertification(
            PgpPublicKey masterKey,
            PgpPublicKey pubKey)
        {
            UpdateWithPublicKey(masterKey);
            UpdateWithPublicKey(pubKey);

            return this.Verify();
            /*Update(sigPck.GetSignatureTrailer());

			return sig.VerifySignature(GetSignature());*/
        }

        /// <summary>Verify a key certification, such as revocation, for the passed in key.</summary>
        /// <param name="pubKey">The key we are checking.</param>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        public bool VerifyCertification(
            PgpPublicKey pubKey)
        {
            if (SignatureType != KeyRevocation
                && SignatureType != SubkeyRevocation)
            {
                throw new InvalidOperationException("signature is not a key signature");
            }

            UpdateWithPublicKey(pubKey);

            return this.Verify();
            /*Update(sigPck.GetSignatureTrailer());

			return sig.VerifySignature(GetSignature());*/
        }

        public int SignatureType
        {
            get { return sigPck.SignatureType; }
        }

        /// <summary>The ID of the key that created the signature.</summary>
        public long KeyId
        {
            get { return sigPck.KeyId; }
        }

        [Obsolete("Use 'CreationTime' property instead")]
        public DateTime GetCreationTime()
        {
            return CreationTime;
        }

        /// <summary>The creation time of this signature.</summary>
        public DateTime CreationTime
        {
            get { return DateTimeOffset.FromUnixTimeSeconds(sigPck.CreationTime).DateTime; }
        }

        public byte[] GetSignatureTrailer()
        {
            return sigPck.GetSignatureTrailer();
        }

        /// <summary>
        /// Return true if the signature has either hashed or unhashed subpackets.
        /// </summary>
        public bool HasSubpackets
        {
            get
            {
                return sigPck.GetHashedSubPackets() != null
                    || sigPck.GetUnhashedSubPackets() != null;
            }
        }

        public PgpSignatureSubpacketVector GetHashedSubPackets()
        {
            return createSubpacketVector(sigPck.GetHashedSubPackets());
        }

        public PgpSignatureSubpacketVector GetUnhashedSubPackets()
        {
            return createSubpacketVector(sigPck.GetUnhashedSubPackets());
        }

        private PgpSignatureSubpacketVector createSubpacketVector(SignatureSubpacket[] pcks)
        {
            return pcks == null ? null : new PgpSignatureSubpacketVector(pcks);
        }

        public byte[] GetSignature()
        {
            MPInteger[] sigValues = sigPck.GetSignature();
            byte[] signature;

            if (sigValues != null)
            {
                if (sigValues.Length == 1)    // an RSA signature
                {
                    signature = sigValues[0].Value;
                }
                else
                {
                    var writer = new AsnWriter(AsnEncodingRules.DER);
                    using (var sequence = writer.PushSequence())
                    {
                        writer.WriteIntegerUnsigned(sigValues[0].Value);
                        writer.WriteIntegerUnsigned(sigValues[1].Value);
                    }
                    signature = writer.Encode();
                }
            }
            else
            {
                signature = sigPck.GetSignatureBytes();
            }

            return signature;
        }

        // TODO Handle the encoding stuff by subclassing BcpgObject?
        public byte[] GetEncoded()
        {
            MemoryStream bOut = new MemoryStream();

            Encode(bOut);

            return bOut.ToArray();
        }

        public void Encode(Stream outStream)
        {
            BcpgOutputStream bcpgOut = BcpgOutputStream.Wrap(outStream);

            bcpgOut.WritePacket(sigPck);

            if (trustPck != null)
            {
                bcpgOut.WritePacket(trustPck);
            }
        }

        private byte[] GetEncodedPublicKey(
            PgpPublicKey pubKey)
        {
            try
            {
                return pubKey.publicPk.GetEncodedContents();
            }
            catch (IOException e)
            {
                throw new PgpException("exception preparing key.", e);
            }
        }

        /// <summary>
        /// Return true if the passed in signature type represents a certification, false if the signature type is not.
        /// </summary>
        /// <param name="signatureType"></param>
        /// <returns>true if signatureType is a certification, false otherwise.</returns>
        public static bool IsCertification(int signatureType)
        {
            switch (signatureType)
            {
                case DefaultCertification:
                case NoCertification:
                case CasualCertification:
                case PositiveCertification:
                    return true;
                default:
                    return false;
            }
        }
    }
}
