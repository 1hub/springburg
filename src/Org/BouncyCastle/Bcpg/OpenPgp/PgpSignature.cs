using System;
using System.IO;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>A PGP signature object.</summary>
    public class PgpSignature : PgpEncodable
    {
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
        private readonly TrustPacket trustPck;

        private PgpSignatureHelper helper;
        private PgpPublicKey publicKey;

        internal PgpSignature(SignaturePacket sigPacket)
            : this(sigPacket, null)
        {
        }

        internal PgpSignature(SignaturePacket sigPacket, TrustPacket trustPacket)
        {
            if (sigPacket == null)
                throw new ArgumentNullException(nameof(sigPacket));

            this.sigPck = sigPacket;
            this.trustPck = trustPacket;
        }

        public PgpSignature(byte[] detachedSignature)
            : this(new MemoryStream(detachedSignature, false))
        {
        }

        public PgpSignature(Stream detachedSignature)
        {
            var packetReader = new PacketReader(detachedSignature);
            if (packetReader.NextPacketTag() != PacketTag.Signature)
                throw new PgpException("Not a signature");
            this.sigPck = (SignaturePacket)packetReader.ReadPacket();
        }

        /// <summary>The OpenPGP version number for this signature.</summary>
        public int Version => sigPck.Version;

        /// <summary>The key algorithm associated with this signature.</summary>
        public PublicKeyAlgorithmTag KeyAlgorithm => sigPck.KeyAlgorithm;

        /// <summary>The hash algorithm associated with this signature.</summary>
        public HashAlgorithmTag HashAlgorithm => sigPck.HashAlgorithm;

        /// <summary>Return true if this signature represents a certification.</summary>
        public bool IsCertification() => IsCertification(SignatureType);

        public void InitVerify(PgpPublicKey publicKey, bool ignoreTrailingWhitespace = false)
        {
            this.helper = new PgpSignatureHelper(SignatureType, HashAlgorithm);
            this.helper.IgnoreTrailingWhitespace = ignoreTrailingWhitespace;
            this.publicKey = publicKey;
        }

        public void Update(params byte[] bytes) => this.helper.Update(bytes);

        public void Update(byte[] bytes, int off, int length) => this.helper.Update(bytes, off, length);

        public bool Verify() => helper.Verify(sigPck.GetSignature(), GetSignatureTrailer(), this.publicKey.GetKey());

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
            this.helper.UpdateWithPublicKey(key);

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
                this.helper.UpdateWithIdData(0xd1, bOut.ToArray());
            }
            catch (IOException e)
            {
                throw new PgpException("cannot encode subpacket array", e);
            }

            return this.Verify();
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
            this.helper.UpdateWithPublicKey(key);

            //
            // hash in the id
            //
            this.helper.UpdateWithIdData(0xb4, Encoding.UTF8.GetBytes(id));

            return this.Verify();
        }

        /// <summary>Verify a certification for the passed in key against the passed in master key.</summary>
        /// <param name="masterKey">The key we are verifying against.</param>
        /// <param name="pubKey">The key we are verifying.</param>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        public bool VerifyCertification(
            PgpPublicKey masterKey,
            PgpPublicKey pubKey)
        {
            this.helper.UpdateWithPublicKey(masterKey);
            this.helper.UpdateWithPublicKey(pubKey);

            return this.Verify();
        }

        /// <summary>Verify a key certification, such as revocation, for the passed in key.</summary>
        /// <param name="pubKey">The key we are checking.</param>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        public bool VerifyCertification(
            PgpPublicKey pubKey)
        {
            if (SignatureType != KeyRevocation && SignatureType != SubkeyRevocation)
            {
                throw new InvalidOperationException("signature is not a key signature");
            }

            this.helper.UpdateWithPublicKey(pubKey);

            return this.Verify();
        }

        public int SignatureType => sigPck.SignatureType;

        /// <summary>The ID of the key that created the signature.</summary>
        public long KeyId => sigPck.KeyId;

        /// <summary>The creation time of this signature.</summary>
        public DateTime CreationTime => sigPck.CreationTime;

        public byte[] GetSignatureTrailer() => sigPck.GetSignatureTrailer();

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

        internal MPInteger[] GetDecodedSignature() => sigPck.GetSignature();

        public byte[] GetSignature() => sigPck.GetSignatureBytes();

        public override void Encode(IPacketWriter outStream)
        {
            outStream.WritePacket(sigPck);

            if (trustPck != null)
            {
                outStream.WritePacket(trustPck);
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
