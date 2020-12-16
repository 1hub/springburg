using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A one pass signature object.</remarks>
    public class PgpOnePassSignature : PgpSignatureBase
    {
        private readonly OnePassSignaturePacket sigPack;
        private PgpPublicKey publicKey;

        internal PgpOnePassSignature(OnePassSignaturePacket sigPack)
        {
            this.sigPack = sigPack;
        }

        public long KeyId => sigPack.KeyId;

        public int SignatureType => sigPack.SignatureType;

        public override HashAlgorithmTag HashAlgorithm => sigPack.HashAlgorithm;

        public PublicKeyAlgorithmTag KeyAlgorithm => sigPack.KeyAlgorithm;

        public void InitVerify(PgpPublicKey publicKey)
        {
            this.publicKey = publicKey;
            Init(SignatureType);
        }

        /// <summary>Verify the calculated signature against the passed in PgpSignature.</summary>
        public bool Verify(PgpSignature pgpSig) => Verify(pgpSig.GetDecodedSignature(), pgpSig.GetSignatureTrailer(), this.publicKey.GetKey());

        public byte[] GetEncoded()
        {
            MemoryStream bOut = new MemoryStream();
            Encode(bOut);
            return bOut.ToArray();
        }

        public void Encode(Stream outStr)
        {
            BcpgOutputStream.Wrap(outStr).WritePacket(sigPack);
        }
    }
}
