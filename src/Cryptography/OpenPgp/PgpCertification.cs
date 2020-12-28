using InflatablePalace.Cryptography.OpenPgp.Packet;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace InflatablePalace.Cryptography.OpenPgp
{
    public class PgpCertification
    {
        PgpSignature signature;
        ContainedPacket? userPacket;
        PgpPublicKey publicKey;

        internal PgpCertification(
            PgpSignature signature,
            ContainedPacket? userPacket,
            PgpPublicKey publicKey)
        {
            this.signature = signature;
            this.userPacket = userPacket;
            this.publicKey = publicKey;
        }

        public long KeyId => signature.KeyId;

        public PgpSignatureAttributes HashedAttributes => signature.HashedAttributes;

        public PgpSignatureAttributes UnhashedAttributes => signature.UnhashedAttributes;

        public PgpSignature Signature => signature;

        private static MemoryStream GenerateCertificationData(
            PgpPublicKey? signingKey,
            ContainedPacket? userPacket,
            PgpPublicKey publicKey)
        {
            var data = new MemoryStream();

            // FIXME: Use Equals or fingerprint?
            if (signingKey.KeyId != publicKey.KeyId && userPacket == null)
            {
                byte[] signingKeyBytes = signingKey.PublicKeyPacket.GetEncodedContents();
                data.Write(new[] {
                (byte)0x99,
                (byte)(signingKeyBytes.Length >> 8),
                (byte)(signingKeyBytes.Length) });
                data.Write(signingKeyBytes);
            }

            byte[] keyBytes = publicKey.PublicKeyPacket.GetEncodedContents();
            data.Write(new[] {
                (byte)0x99,
                (byte)(keyBytes.Length >> 8),
                (byte)(keyBytes.Length) });
            data.Write(keyBytes);

            byte idType = 0;
            byte[]? idBytes = null;

            if (userPacket is UserAttributePacket userAttributePacket)
            {
                MemoryStream bOut = new MemoryStream();
                foreach (UserAttributeSubpacket packet in userAttributePacket.GetSubpackets())
                {
                    packet.Encode(bOut);
                }
                idType = 0xd1;
                idBytes = bOut.ToArray();
            }
            else if (userPacket is UserIdPacket userIdPacket)
            {
                idType = 0xb4;
                idBytes = Encoding.UTF8.GetBytes(userIdPacket.GetId());
            }

            if (idBytes != null)
            {
                data.Write(new[] {
                    (byte)idType,
                    (byte)(idBytes.Length >> 24),
                    (byte)(idBytes.Length >> 16),
                    (byte)(idBytes.Length >> 8),
                    (byte)(idBytes.Length) });
                data.Write(idBytes);
            }

            data.Position = 0;

            return data;
        }

        /// <summary>
        /// Verify the signature as certifying by the passed in public key.
        /// </summary>
        /// <returns>True, if the signature matches, false otherwise.</returns>
        public bool Verify(PgpPublicKey signingKey)
        {
            Debug.Assert(signingKey.KeyId == KeyId);
            return signature.Verify(signingKey, GenerateCertificationData(signingKey, userPacket, publicKey));
        }

        /// <summary>Verify a key certification, such as self-certifcation or revocation.</summary>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        public bool Verify()
        {
            return Verify(publicKey);
        }
    }
}
