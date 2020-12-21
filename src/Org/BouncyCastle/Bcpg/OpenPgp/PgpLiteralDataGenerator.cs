using System;
using System.IO;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Class for producing literal data packets.</summary>
    public class PgpLiteralDataGenerator
        : IStreamGenerator
    {
        public const char Binary = PgpLiteralData.Binary;
        public const char Text = PgpLiteralData.Text;
        public const char Utf8 = PgpLiteralData.Utf8;

        /// <summary>The special name indicating a "for your eyes only" packet.</summary>
        public const string Console = PgpLiteralData.Console;

        private Stream pkOut;

        /// <summary>
        /// Generates literal data objects in the old format.
        /// This is important if you need compatibility with PGP 2.6.x.
        /// </summary>
        /// <param name="oldFormat">If true, uses old format.</param>
        public PgpLiteralDataGenerator()
        {
        }

        /// <summary>
        /// Open a literal data packet, returning a stream to store the data inside the packet.
        /// </summary>
        /// <param name="writer">The writer we want the packet in.</param>
        /// <param name="format">The format we are using.</param>
        /// <param name="name">The name of the 'file'.</param>
        /// <param name="modificationTime">The time of last modification we want stored.</param>
        public Stream Open(
            IPacketWriter writer,
            char format,
            string name,
            DateTime modificationTime)
        {
            if (writer == null)
                throw new ArgumentNullException(nameof(writer));
            if (pkOut != null)
                throw new InvalidOperationException("generator already in open state");

            var packet = new LiteralDataPacket(format, name, modificationTime);
            pkOut = writer.GetPacketStream(packet);
            return new WrappedGeneratorStream(this, pkOut);
        }

        /// <summary>
        /// Open a literal data packet for the passed in <c>FileInfo</c> object, returning
        /// an output stream for saving the file contents.
        /// </summary>
        /// <param name="writer">The writer we want the packet in.</param>
        /// <param name="format">The format we are using.</param>
        /// <param name="file">The <c>FileInfo</c> object containg the packet details.</param>
        public Stream Open(
            IPacketWriter writer,
            char format,
            FileInfo file)
        {
            return Open(writer, format, file.Name, file.LastWriteTime);
        }

        /// <summary>
        /// Close the literal data packet - this is equivalent to calling Close()
        /// on the stream returned by the Open() method.
        /// </summary>
        void IStreamGenerator.Close()
        {
            if (pkOut != null)
            {
                pkOut.Close();
                pkOut = null;
            }
        }
    }
}
