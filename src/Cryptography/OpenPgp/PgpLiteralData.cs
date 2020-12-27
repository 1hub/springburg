using System;
using System.IO;

namespace InflatablePalace.Cryptography.OpenPgp
{
    /// <summary>Class for processing literal data objects.</summary>
    public static class PgpLiteralData
    {
        public const char Binary = 'b';
        public const char Text = 't';
        public const char Utf8 = 'u';

        /// <summary>The special name indicating a "for your eyes only" packet.</summary>
        public const string Console = "_CONSOLE";
    }
}
