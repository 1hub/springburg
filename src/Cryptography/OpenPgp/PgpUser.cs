using InflatablePalace.Cryptography.OpenPgp.Packet;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace InflatablePalace.Cryptography.OpenPgp
{
    /// <summary>
    /// Class that represents OpenPGP user id or user attribute and all its associated
    /// certification signatures.
    /// </summary>
    public class PgpUser : PgpEncodable
    {
        //readonly PgpPublicKey publicKey;
        readonly ContainedPacket userPacket;
        readonly TrustPacket? trustPacket;
        readonly List<PgpCertification> selfCertifications;
        readonly List<PgpCertification> otherCertifications;
        readonly List<PgpCertification> revocationSignatures;

        internal PgpUser(IPacketReader packetReader, PgpPublicKey publicKey)
        {
            Debug.Assert(packetReader.NextPacketTag() == PacketTag.UserId || packetReader.NextPacketTag() == PacketTag.UserAttribute);

            //this.publicKey = publicKey;
            this.userPacket = packetReader.ReadContainedPacket();
            this.trustPacket = packetReader.NextPacketTag() == PacketTag.Trust ? (TrustPacket)packetReader.ReadContainedPacket() : null;

            selfCertifications = new List<PgpCertification>();
            otherCertifications = new List<PgpCertification>();
            revocationSignatures = new List<PgpCertification>();

            while (packetReader.NextPacketTag() == PacketTag.Signature)
            {
                var signaturePacket = (SignaturePacket)packetReader.ReadContainedPacket();
                var signatureTrustPacket = packetReader.NextPacketTag() == PacketTag.Trust ? (TrustPacket)packetReader.ReadContainedPacket() : null;
                var signature = new PgpSignature(signaturePacket, signatureTrustPacket);
                AddCertification(publicKey, signature);
            }
        }

        internal PgpUser(PgpUser user, PgpPublicKey publicKey)
        {
            this.userPacket = user.userPacket;
            //this.publicKey = publicKey;
            this.selfCertifications = new List<PgpCertification>();
            this.otherCertifications = new List<PgpCertification>();
            this.revocationSignatures = new List<PgpCertification>();
            foreach (var certification in user.selfCertifications)
                this.selfCertifications.Add(new PgpCertification(certification.Signature, userPacket, publicKey));
            foreach (var certification in user.otherCertifications)
                this.otherCertifications.Add(new PgpCertification(certification.Signature, userPacket, publicKey));
            foreach (var certification in user.revocationSignatures)
                this.revocationSignatures.Add(new PgpCertification(certification.Signature, userPacket, publicKey));
        }

        internal PgpUser(ContainedPacket userPacket, PgpPublicKey publicKey, PgpSignature signature)
        {
            this.userPacket = userPacket;
            //this.publicKey = publicKey;
            this.selfCertifications = new List<PgpCertification>();
            this.otherCertifications = new List<PgpCertification>();
            this.revocationSignatures = new List<PgpCertification>();
            AddCertification(publicKey, signature);
        }

        public static PgpUser AddCertification(PgpUser user, PgpPublicKey publicKey, PgpSignature signature)
        {
            var newUser = new PgpUser(user, publicKey);
            newUser.AddCertification(publicKey, signature);
            return newUser;
        }

        public static PgpUser RemoveCertification(PgpUser user, PgpPublicKey publicKey, PgpCertification certification)
        {
            var newUser = new PgpUser(user, publicKey);
            newUser.selfCertifications.RemoveAll(c => Equals(c.Signature, certification.Signature));
            newUser.otherCertifications.RemoveAll(c => Equals(c.Signature, certification.Signature));
            newUser.revocationSignatures.RemoveAll(c => Equals(c.Signature, certification.Signature));
            return newUser;
        }

        private bool AddCertification(PgpPublicKey publicKey, PgpSignature signature)
        {
            var certification = new PgpCertification(signature, userPacket, publicKey);
            switch (signature.SignatureType)
            {
                case PgpSignature.CertificationRevocation:
                    revocationSignatures.Add(certification);
                    break;

                case PgpSignature.DefaultCertification:
                case PgpSignature.NoCertification:
                case PgpSignature.CasualCertification:
                case PgpSignature.PositiveCertification:
                    if (signature.KeyId == publicKey.KeyId)
                        selfCertifications.Add(certification);
                    else
                        otherCertifications.Add(certification);
                    break;

                case PgpSignature.BinaryDocument:
                default:
                    return false;
            }

            return true;
        }

        public string? UserId => (userPacket as UserIdPacket)?.GetId();

        public PgpUserAttributes? UserAttributes => userPacket is UserAttributePacket userAttributePacket ? new PgpUserAttributes(userAttributePacket.GetSubpackets()) : null;

        internal object UserIdOrAttributes => ((object)UserId! ?? UserAttributes)!;

        internal ContainedPacket UserPacket => userPacket;

        //internal PgpPublicKey PublicKey => publicKey;

        public IList<PgpCertification> SelfCertifications => selfCertifications.AsReadOnly();

        public IList<PgpCertification> OtherCertifications => otherCertifications.AsReadOnly();

        public IList<PgpCertification> RevocationSignatures => revocationSignatures.AsReadOnly();

        public override void Encode(IPacketWriter packetWriter)
        {
            if (packetWriter == null)
                throw new ArgumentNullException(nameof(packetWriter));

            packetWriter.WritePacket(userPacket);
            if (trustPacket != null)
                packetWriter.WritePacket(trustPacket);
            foreach (PgpCertification sig in SelfCertifications)
                sig.Signature.Encode(packetWriter);
            foreach (PgpCertification sig in OtherCertifications)
                sig.Signature.Encode(packetWriter);
            foreach (PgpCertification sig in RevocationSignatures)
                sig.Signature.Encode(packetWriter);
        }
    }
}
