using System.IO;
using System.IO.Compression;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>Compressed data objects</remarks>
    public class PgpCompressedData
        : PgpObject
    {
        private readonly CompressedDataPacket data;

        public PgpCompressedData(
            BcpgInputStream bcpgInput)
        {
            Packet packet = bcpgInput.ReadPacket();
            if (!(packet is CompressedDataPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            this.data = (CompressedDataPacket)packet;
        }

        /// <summary>The algorithm used for compression</summary>
        public CompressionAlgorithmTag Algorithm
        {
            get { return data.Algorithm; }
        }

        /// <summary>Get the raw input stream contained in the object.</summary>
        public Stream GetInputStream()
        {
            return data.GetInputStream();
        }

        /// <summary>Return an uncompressed input stream which allows reading of the compressed data.</summary>
        public Stream GetDataStream()
        {
            switch (Algorithm)
            {
                case CompressionAlgorithmTag.Uncompressed:
                    return GetInputStream();
                case CompressionAlgorithmTag.Zip:
                    return new DeflateStream(GetInputStream(), CompressionMode.Decompress);
                case CompressionAlgorithmTag.ZLib:
                    var inputStream = GetInputStream();
                    var cmf = inputStream.ReadByte();
                    var flg = inputStream.ReadByte();
                    // FIXME: Check CMF and FLG values, skip FDICT, skip Adler32 at the end
                    return new DeflateStream(inputStream, CompressionMode.Decompress);
                // FIXME
                //case CompressionAlgorithmTag.BZip2:
                //   return new CBZip2InputStream(GetInputStream());
                default:
                    throw new PgpException("can't recognise compression algorithm: " + Algorithm);
            }
        }
    }
}
