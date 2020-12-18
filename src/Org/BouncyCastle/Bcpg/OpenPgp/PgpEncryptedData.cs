using InflatablePalace.Cryptography.Algorithms;
using System.IO;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public abstract partial class PgpEncryptedData
    {
        protected InputStreamPacket encData;
        protected CryptoStream encStream;
        protected HashAlgorithm hashAlgorithm;
        private protected TailEndCryptoTransform tailEndCryptoTransform;

        internal PgpEncryptedData(InputStreamPacket encData)
        {
            this.encData = encData;
        }

        /// <summary>Return the raw input stream for the data stream.</summary>
        public virtual Stream GetInputStream()
        {
            return encData.GetInputStream();
        }

        /// <summary>Return true if the message is integrity protected.</summary>
        /// <returns>True, if there is a modification detection code namespace associated
        /// with this stream.</returns>
        public bool IsIntegrityProtected()
        {
            return encData is SymmetricEncIntegrityPacket;
        }

        /// <summary>Note: This can only be called after the message has been read.</summary>
        /// <returns>True, if the message verifies, false otherwise</returns>
        public bool Verify()
        {
            if (!IsIntegrityProtected())
                throw new PgpException("data not integrity protected.");

            //
            // make sure we are at the end.
            //
            while (encStream.ReadByte() >= 0)
            {
                // do nothing
            }

            //
            // process the MDC packet
            //
            var digest = hashAlgorithm.Hash;
            var streamDigest = tailEndCryptoTransform.TailEnd;

            return CryptographicOperations.FixedTimeEquals(digest, streamDigest);
        }
    }
}
