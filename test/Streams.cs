using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    public sealed class Streams
    {
        public static byte[] ReadAll(Stream inStr)
        {
            MemoryStream buf = new MemoryStream();
            inStr.CopyTo(buf);
            return buf.ToArray();
        }

        public static int ReadFully(Stream inStr, byte[] buf)
        {
            return ReadFully(inStr, buf, 0, buf.Length);
        }

        public static int ReadFully(Stream inStr, byte[] buf, int off, int len)
        {
            int totalRead = 0;
            while (totalRead < len)
            {
                int numRead = inStr.Read(buf, off + totalRead, len - totalRead);
                if (numRead < 1)
                    break;
                totalRead += numRead;
            }
            return totalRead;
        }
    }
}
