using System;
using System.IO;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Class for producing literal data packets.</summary>
    class PgpLiteralMessageGenerator : IStreamGenerator
    {
        public const char Binary = PgpLiteralData.Binary;
        public const char Text = PgpLiteralData.Text;
        public const char Utf8 = PgpLiteralData.Utf8;

        /// <summary>The special name indicating a "for your eyes only" packet.</summary>
        public const string Console = PgpLiteralData.Console;

        private IPacketWriter writer;
        private Stream outputStream;

        /// <summary>
        /// Open a literal data packet.
        /// </summary>
        /// <param name="writer">The writer we want the packet in.</param>
        /// <param name="format">The format we are using.</param>
        /// <param name="name">The name of the 'file'.</param>
        /// <param name="modificationTime">The time of last modification we want stored.</param>
        public PgpLiteralMessageGenerator(
            IPacketWriter writer,
            char format,
            string name,
            DateTime modificationTime)
        {
            if (writer == null)
                throw new ArgumentNullException(nameof(writer));

            var packet = new LiteralDataPacket(format, name, modificationTime);
            this.outputStream = writer.GetPacketStream(packet);
            this.writer = writer;
        }

        /// <summary>
        /// Open a literal data packet for the passed in FileInfo object.
        /// </summary>
        /// <param name="writer">The writer we want the packet in.</param>
        /// <param name="format">The format we are using.</param>
        /// <param name="fileInfo">The FileInfo object containg the packet details.</param>
        public PgpLiteralMessageGenerator(
            IPacketWriter writer,
            char format,
            FileInfo fileInfo)
            : this(writer, format, fileInfo.Name, fileInfo.LastWriteTime)
        {
        }

        public Stream GetStream() => new WrappedGeneratorStream(this, this.outputStream);

        void IStreamGenerator.Close()
        {
            if (this.outputStream != null)
            {
                this.outputStream.Close();
                this.outputStream = null;
            }
            if (this.writer != null)
            {
                this.writer.Dispose();
                this.writer = null;
            }
        }
    }
}
