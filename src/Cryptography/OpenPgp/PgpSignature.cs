using Springburg.Cryptography.OpenPgp.Packet;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp
{
    /// <summary>A PGP signature object.</summary>
    public class PgpSignature : PgpEncodable
    {
        private readonly SignaturePacket sigPck;
        private readonly TrustPacket? trustPck;

        private PgpSignatureAttributes? hashedAttributes;
        private PgpSignatureAttributes? unhashedAttributes;

        internal PgpSignature(SignaturePacket sigPacket)
            : this(sigPacket, null)
        {
        }

        internal PgpSignature(SignaturePacket sigPacket, TrustPacket? trustPacket)
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
            {
                throw new PgpUnexpectedPacketException();
            }
            this.sigPck = (SignaturePacket)packetReader.ReadContainedPacket();
        }

        /// <summary>The OpenPGP version number for this signature.</summary>
        public int Version => sigPck.Version;

        /// <summary>The key algorithm associated with this signature.</summary>
        public PgpPublicKeyAlgorithm KeyAlgorithm => sigPck.KeyAlgorithm;

        /// <summary>The hash algorithm associated with this signature.</summary>
        public PgpHashAlgorithm HashAlgorithm => sigPck.HashAlgorithm;

        public bool Verify(PgpPublicKey publicKey, Stream stream, bool ignoreTrailingWhitespace = false)
        {
            var helper = new PgpSignatureTransformation(SignatureType, HashAlgorithm, ignoreTrailingWhitespace);
            new CryptoStream(stream, helper, CryptoStreamMode.Read).CopyTo(Stream.Null);
            helper.Finish(sigPck.Version, sigPck.KeyAlgorithm, sigPck.CreationTime, sigPck.GetHashedSubPackets());
            return publicKey.Verify(helper.Hash!, sigPck.GetSignature(), helper.HashAlgorithm);
        }

        public PgpSignatureType SignatureType => sigPck.SignatureType;

        /// <summary>The ID of the key that created the signature.</summary>
        public long KeyId => sigPck.KeyId;

        /// <summary>The creation time of this signature.</summary>
        public DateTime CreationTime => sigPck.CreationTime;

        public PgpSignatureAttributes HashedAttributes => hashedAttributes ?? (hashedAttributes = new PgpSignatureAttributes(sigPck.GetHashedSubPackets() ?? Array.Empty<SignatureSubpacket>()));

        public PgpSignatureAttributes UnhashedAttributes => unhashedAttributes ?? (unhashedAttributes = new PgpSignatureAttributes(sigPck.GetUnhashedSubPackets() ?? Array.Empty<SignatureSubpacket>()));

        public byte[] GetSignature() => sigPck.GetSignature();

        public override void Encode(IPacketWriter outStream)
        {
            outStream.WritePacket(sigPck);

            if (trustPck != null)
            {
                outStream.WritePacket(trustPck);
            }
        }
    }
}
