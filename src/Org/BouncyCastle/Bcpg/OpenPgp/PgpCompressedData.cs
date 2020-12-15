using System.IO;
using System.IO.Compression;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Compressed data objects</summary>
    public class PgpCompressedData : PgpObject
    {
        private readonly CompressedDataPacket data;

        internal PgpCompressedData(CompressedDataPacket data)
        {
            this.data = data;
        }

        /// <summary>The algorithm used for compression</summary>
        public CompressionAlgorithmTag Algorithm => data.Algorithm;

        /// <summary>Get the raw input stream contained in the object.</summary>
        public Stream GetInputStream() => data.GetInputStream();

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
                    if ((flg & 0x20) != 0)
                    {
                        // Skip FDICT
                        inputStream.ReadByte();
                        inputStream.ReadByte();
                        inputStream.ReadByte();
                        inputStream.ReadByte();
                    }
                    // FIXME: Truncate Adler32 at the end
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
