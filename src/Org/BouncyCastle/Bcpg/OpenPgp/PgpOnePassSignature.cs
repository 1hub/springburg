using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A one pass signature object.</remarks>
    public class PgpOnePassSignature : PgpEncodable
    {
        private readonly OnePassSignaturePacket sigPack;

        private PgpSignatureHelper helper;
        private PgpPublicKey publicKey;

        internal PgpOnePassSignature(OnePassSignaturePacket sigPack)
        {
            this.sigPack = sigPack;
        }

        public long KeyId => sigPack.KeyId;

        public int SignatureType => sigPack.SignatureType;

        public HashAlgorithmTag HashAlgorithm => sigPack.HashAlgorithm;

        public PublicKeyAlgorithmTag KeyAlgorithm => sigPack.KeyAlgorithm;

        public void InitVerify(PgpPublicKey publicKey)
        {
            this.helper = new PgpSignatureHelper(SignatureType, HashAlgorithm);
            this.publicKey = publicKey;
        }


        public void Update(byte b) => this.helper.Update(b);

        public void Update(params byte[] bytes) => this.helper.Update(bytes);

        public void Update(byte[] bytes, int off, int length) => this.helper.Update(bytes, off, length);

        /// <summary>Verify the calculated signature against the passed in PgpSignature.</summary>
        public bool Verify(PgpSignature pgpSig) => helper.Verify(pgpSig.GetDecodedSignature(), pgpSig.GetSignatureTrailer(), this.publicKey.GetKey());

        public override void Encode(PacketWriter writer)
        {
            writer.WritePacket(sigPack);
        }
    }
}
