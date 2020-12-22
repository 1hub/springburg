using InflatablePalace.Cryptography.Algorithms;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpCompressedMessage : PgpMessage
    {
        private CompressedDataPacket compressedDataPacket;
        private Stream inputStream;
        private IPacketReader packetReader;
        
        internal PgpCompressedMessage(IPacketReader packetReader)
        {
            var packet = packetReader.ReadStreamablePacket();
            this.compressedDataPacket = (CompressedDataPacket)packet.Packet;
            this.inputStream = packet.Stream;
            this.packetReader = packetReader;
        }

        private Stream GetDataStream()
        {
            switch (this.compressedDataPacket.Algorithm)
            {
                case CompressionAlgorithmTag.Uncompressed:
                    return inputStream;

                case CompressionAlgorithmTag.Zip:
                    return new DeflateStream(inputStream, CompressionMode.Decompress);

                case CompressionAlgorithmTag.ZLib:
                    var cmf = inputStream.ReadByte();
                    var flg = inputStream.ReadByte();
                    if ((flg & 0x20) != 0)
                    {
                        // Skip FDICT, to be tested
                        inputStream.ReadByte();
                        inputStream.ReadByte();
                        inputStream.ReadByte();
                        inputStream.ReadByte();
                    }
                    // Truncate the Adler32 hash
                    var adler32 = new Adler32();
                    var truncatedStream = new CryptoStream(inputStream, new TailEndCryptoTransform(adler32, adler32.HashSize / 8), CryptoStreamMode.Read);
                    return new DeflateStream(truncatedStream, CompressionMode.Decompress);

                // FIXME
                //case CompressionAlgorithmTag.BZip2:
                //   return new CBZip2InputStream(GetInputStream());
                default:
                    throw new PgpException("can't recognise compression algorithm: " + this.compressedDataPacket.Algorithm);
            }
        }

        public PgpMessage ReadMessage()
        {
            return ReadMessage(packetReader.CreateNestedReader(GetDataStream()));
        }
    }
}
