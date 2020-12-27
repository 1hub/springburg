using System;
using System.IO;

namespace InflatablePalace.IO
{
    static class StreamExtensions
    {
        public static byte[] ReadAll(this Stream inputStream)
        {
            MemoryStream buf = new MemoryStream();
            inputStream.CopyTo(buf);
            return buf.ToArray();
        }

        public static int ReadFully(this Stream inputStream, Span<byte> buffer)
        {
            int totalRead = 0;
            while (buffer.Length > 0)
            {
                int numRead = inputStream.Read(buffer);
                if (numRead <= 0)
                    break;
                totalRead += numRead;
                buffer = buffer.Slice(numRead);
            }
            return totalRead;
        }
    }
}
