using System.IO;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpSignatureCalculator
    {
        internal PgpSignatureHelper helper;
        internal PgpPublicKey publicKey;

        internal PgpSignatureCalculator(PgpSignatureHelper helper, PgpPublicKey publicKey)
        {
            this.helper = helper;
            this.publicKey = publicKey;
        }

        /// <summary>
        /// Wrap a readable stream of literal data and hash any contents read from it
        /// </summary>
        /// <param name="stream">Input stream of literal data</param>
        /// <returns>Wrapped stream</returns>
        public Stream WrapReadStream(Stream stream)
        {
            return new CryptoStream(stream, helper, CryptoStreamMode.Read);
        }

        public Stream WrapWriteStream(Stream stream)
        {
            return new CryptoStream(stream, helper, CryptoStreamMode.Write);
        }

        public void Update(byte b) => this.helper.Update(b);

        public void Update(params byte[] bytes) => this.helper.Update(bytes);

        public void Update(byte[] bytes, int off, int length) => this.helper.Update(bytes, off, length);
    }
}
