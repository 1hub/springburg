using InflatablePalace.Cryptography.Algorithms;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Class for producing compressed data packets.</summary>
    public class PgpCompressedMessageGenerator
        : IStreamGenerator
    {
        private readonly CompressionAlgorithmTag algorithm;
        private readonly CompressionLevel compression;

        private Stream dOut;
        private Stream pkOut;
        private Adler32 checksum;

        public PgpCompressedMessageGenerator(
            CompressionAlgorithmTag algorithm)
            : this(algorithm, CompressionLevel.Optimal)
        {
        }

        public PgpCompressedMessageGenerator(
            CompressionAlgorithmTag algorithm,
            CompressionLevel compression)
        {
            switch (algorithm)
            {
                case CompressionAlgorithmTag.Uncompressed:
                case CompressionAlgorithmTag.Zip:
                case CompressionAlgorithmTag.ZLib:
                //case CompressionAlgorithmTag.BZip2:
                    break;
                default:
                    throw new ArgumentException("unknown compression algorithm", "algorithm");
            }

            this.algorithm = algorithm;
            this.compression = compression;
        }

        /// <summary>
        /// Return an output stream which will save the data being written to
        /// the compressed object.
        /// </summary>
        /// <param name="writer">Writer to be used for output.</param>
        /// <returns>A Stream for output of the compressed data.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="IOException"></exception>
        public IPacketWriter Open(IPacketWriter writer)
        {
            if (writer == null)
                throw new ArgumentNullException(nameof(writer));
            if (dOut != null)
                throw new InvalidOperationException("generator already in open state");

            var packet = new CompressedDataPacket(algorithm);

            this.pkOut = writer.GetPacketStream(packet);

            switch (algorithm)
            {
                case CompressionAlgorithmTag.Uncompressed:
                    dOut = pkOut;
                    break;
                case CompressionAlgorithmTag.Zip:
                    dOut = new DeflateStream(pkOut, compression, leaveOpen: true);
                    break;
                case CompressionAlgorithmTag.ZLib:
                    checksum = new Adler32();
                    byte cmf = 0x78; // Deflate, 32K window size
                    byte flg = 0; // Fastest compression level
                    // Checksum
                    flg |= (byte)(31 - ((cmf << 8) + flg) % 31);
                    Debug.Assert(((cmf << 8) + flg) % 31 == 0);
                    pkOut.WriteByte(cmf);
                    pkOut.WriteByte(flg);
                    dOut =
                        new CryptoStream(
                            new DeflateStream(pkOut, compression, leaveOpen: true),
                            checksum,
                            CryptoStreamMode.Write);
                    break;
                /*case CompressionAlgorithmTag.BZip2:
                    dOut = new SafeCBZip2OutputStream(pkOut);
                    break;*/
                default:
                    // Constructor should guard against this possibility
                    throw new InvalidOperationException();
            }

            return writer.CreateNestedWriter(new WrappedGeneratorStream(this, dOut));
        }

        /// <summary>Close the compressed object.</summary>summary>
        void IStreamGenerator.Close()
        {
            if (dOut != null)
            {
                if (dOut != pkOut)
                {
                    dOut.Close();
                }
                dOut = null;

                if (checksum != null)
                {
                    pkOut.Write(checksum.Hash);
                    checksum = null;
                }

                pkOut.Close();
                pkOut = null;
            }
        }
    }
}
