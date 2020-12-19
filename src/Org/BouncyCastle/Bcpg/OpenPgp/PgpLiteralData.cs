using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Class for processing literal data objects.</summary>
    public class PgpLiteralData : IPgpObject
    {
        public const char Binary = 'b';
        public const char Text = 't';
        public const char Utf8 = 'u';

        /// <summary>The special name indicating a "for your eyes only" packet.</summary>
        public const string Console = "_CONSOLE";

        private readonly LiteralDataPacket data;

        internal PgpLiteralData(LiteralDataPacket data)
        {
            this.data = data;
        }

        /// <summary>The format of the data stream - Binary or Text</summary>
        public int Format => data.Format;

        /// <summary>The file name that's associated with the data stream.</summary>
        public string FileName => data.FileName;

        /// <summary>Return the file name as an unintrepreted byte array.</summary>
        public byte[] GetRawFileName() => data.GetRawFileName();

        /// <summary>The modification time for the file.</summary>
        public DateTime ModificationTime => DateTimeOffset.FromUnixTimeSeconds(data.ModificationTime).UtcDateTime;

        /// <summary>The raw input stream for the data stream.</summary>
        public Stream GetInputStream() => data.GetInputStream();

        /// <summary>The input stream representing the data stream.</summary>
        public Stream GetDataStream() => data.GetInputStream();
    }
}
