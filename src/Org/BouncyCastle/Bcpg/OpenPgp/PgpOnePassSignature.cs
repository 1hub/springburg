using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A one pass signature object.</remarks>
    public class PgpOnePassSignature : PgpEncodable
    {
        private readonly OnePassSignaturePacket sigPack;

        internal PgpOnePassSignature(OnePassSignaturePacket sigPack)
        {
            this.sigPack = sigPack;
        }

        public long KeyId => sigPack.KeyId;

        public int SignatureType => sigPack.SignatureType;

        public HashAlgorithmTag HashAlgorithm => sigPack.HashAlgorithm;

        public PublicKeyAlgorithmTag KeyAlgorithm => sigPack.KeyAlgorithm;

        public PgpSignatureCalculator GetSignatureCalculator(PgpPublicKey publicKey)
        {
            return new PgpSignatureCalculator(new PgpSignatureHelper(SignatureType, HashAlgorithm), publicKey);
        }

        public override void Encode(IPacketWriter writer)
        {
            writer.WritePacket(sigPack);
        }
    }
}
