using Springburg.Cryptography.OpenPgp.Packet;
using Springburg.IO;
using System;
using System.IO;
namespace Springburg.Cryptography.OpenPgp
{
    /// <summary>Class for producing literal data packets.</summary>
    class PgpLiteralMessageGenerator
    {
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
            PgpDataFormat format,
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
            PgpDataFormat format,
            FileInfo fileInfo)
            : this(writer, format, fileInfo.Name, fileInfo.LastWriteTime)
        {
        }

        public Stream GetStream() => new WrappedGeneratorStream(this.outputStream, _ => Close());

        void Close()
        {
            this.outputStream.Close();
            this.writer.Dispose();
        }
    }
}
