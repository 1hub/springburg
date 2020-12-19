using InflatablePalace.Cryptography.Algorithms;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Class for producing compressed data packets.</summary>
    public class PgpCompressedDataGenerator
        : IStreamGenerator
    {
        private readonly CompressionAlgorithmTag algorithm;
        private readonly CompressionLevel compression;

        private Stream dOut;
        private BcpgOutputStream pkOut;
        private Adler32 checksum;

        public PgpCompressedDataGenerator(
            CompressionAlgorithmTag algorithm)
            : this(algorithm, CompressionLevel.Optimal)
        {
        }

        public PgpCompressedDataGenerator(
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
        /// <p>
        /// Return an output stream which will save the data being written to
        /// the compressed object.
        /// </p>
        /// <p>
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </p>
        /// </summary>
        /// <param name="outStr">Stream to be used for output.</param>
        /// <returns>A Stream for output of the compressed data.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="IOException"></exception>
        public Stream Open(Stream outStr)
        {
            if (dOut != null)
                throw new InvalidOperationException("generator already in open state");
            if (outStr == null)
                throw new ArgumentNullException("outStr");

            this.pkOut = new BcpgOutputStream(outStr, PacketTag.CompressedData);

            doOpen();

            return new WrappedGeneratorStream(this, dOut);
        }

        /// <summary>
        /// <p>
        /// Return an output stream which will compress the data as it is written to it.
        /// The stream will be written out in chunks according to the size of the passed in buffer.
        /// </p>
        /// <p>
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </p>
        /// <p>
        /// <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2
        /// bytes worth of the buffer will be used.
        /// </p>
        /// <p>
        /// <b>Note</b>: using this may break compatibility with RFC 1991 compliant tools.
        /// Only recent OpenPGP implementations are capable of accepting these streams.
        /// </p>
        /// </summary>
        /// <param name="outStr">Stream to be used for output.</param>
        /// <param name="buffer">The buffer to use.</param>
        /// <returns>A Stream for output of the compressed data.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="IOException"></exception>
        /// <exception cref="PgpException"></exception>
        public Stream Open(Stream outStr, byte[] buffer)
        {
            if (dOut != null)
                throw new InvalidOperationException("generator already in open state");
            if (outStr == null)
                throw new ArgumentNullException("outStr");
            if (buffer == null)
                throw new ArgumentNullException("buffer");

            this.pkOut = new BcpgOutputStream(outStr, PacketTag.CompressedData, buffer);

            doOpen();

            return new WrappedGeneratorStream(this, dOut);
        }

        private void doOpen()
        {
            pkOut.WriteByte((byte)algorithm);

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
