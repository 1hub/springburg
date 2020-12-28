using InflatablePalace.Cryptography.Algorithms;
using InflatablePalace.Cryptography.OpenPgp.Packet;
using InflatablePalace.IO;
using InflatablePalace.IO.Checksum;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace InflatablePalace.Cryptography.OpenPgp
{
    /// <summary>Class for producing compressed data packets.</summary>
    class PgpCompressedMessageGenerator : PgpMessageGenerator
    {
        private readonly PgpCompressionAlgorithm algorithm;
        private readonly CompressionLevel compressionLevel;

        private Stream? dOut;
        private Stream? pkOut;
        private Adler32? checksum;

        public PgpCompressedMessageGenerator(
            IPacketWriter packetWriter,
            PgpCompressionAlgorithm algorithm,
            CompressionLevel compressionLevel = CompressionLevel.Optimal)
            : base(packetWriter)
        {
            switch (algorithm)
            {
                case PgpCompressionAlgorithm.Uncompressed:
                case PgpCompressionAlgorithm.Zip:
                case PgpCompressionAlgorithm.ZLib:
                //case CompressionAlgorithmTag.BZip2:
                    break;
                default:
                    throw new ArgumentException("unknown compression algorithm", nameof(algorithm));
            }

            this.algorithm = algorithm;
            this.compressionLevel = compressionLevel;
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
        protected override IPacketWriter Open()
        {
            var writer = base.Open();

            var packet = new CompressedDataPacket(algorithm);

            this.pkOut = writer.GetPacketStream(packet);

            switch (algorithm)
            {
                case PgpCompressionAlgorithm.Uncompressed:
                    dOut = pkOut;
                    break;
                case PgpCompressionAlgorithm.Zip:
                    dOut = new DeflateStream(pkOut, compressionLevel, leaveOpen: true);
                    break;
                case PgpCompressionAlgorithm.ZLib:
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
                            new DeflateStream(pkOut, compressionLevel, leaveOpen: true),
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

            return writer.CreateNestedWriter(new WrappedGeneratorStream(dOut, _ => Close()));
        }

        /// <summary>Close the compressed object.</summary>
        void Close()
        {
            Debug.Assert(pkOut != null);

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
