using System;
using System.Diagnostics;
using System.IO;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    class TruncatedStream : BaseInputStream
    {
        private readonly int lookAheadSize;
        private readonly int lookAheadBufLimit;
        private readonly Stream inStr;
        private readonly byte[] lookAhead;
        private int bufStart, bufEnd;

        internal TruncatedStream(Stream inStr, int lookAheadSize)
        {
            this.lookAheadSize = lookAheadSize;
            this.lookAhead = new byte[Math.Max(512, 128 + lookAheadSize)];
            this.lookAheadBufLimit = this.lookAhead.Length - lookAheadSize;

            int numRead = Streams.ReadFully(inStr, lookAhead, 0, lookAhead.Length);

            if (numRead < lookAheadSize)
                throw new EndOfStreamException();

            this.inStr = inStr;
            this.bufStart = 0;
            this.bufEnd = numRead - lookAheadSize;
        }

        private int FillBuffer()
        {
            if (bufEnd < lookAheadBufLimit)
                return 0;

            Debug.Assert(bufStart == lookAheadBufLimit);
            Debug.Assert(bufEnd == lookAheadBufLimit);

            Array.Copy(lookAhead, lookAheadBufLimit, lookAhead, 0, lookAheadSize);
            bufEnd = Streams.ReadFully(inStr, lookAhead, lookAheadSize, lookAheadBufLimit);
            bufStart = 0;
            return bufEnd;
        }

        public override int ReadByte()
        {
            if (bufStart < bufEnd)
                return lookAhead[bufStart++];

            if (FillBuffer() < 1)
                return -1;

            return lookAhead[bufStart++];
        }

        public override int Read(byte[] buf, int off, int len)
        {
            int avail = bufEnd - bufStart;

            int pos = off;
            while (len > avail)
            {
                Array.Copy(lookAhead, bufStart, buf, pos, avail);

                bufStart += avail;
                pos += avail;
                len -= avail;

                if ((avail = FillBuffer()) < 1)
                    return pos - off;
            }

            Array.Copy(lookAhead, bufStart, buf, pos, len);
            bufStart += len;

            return pos + len - off;
        }

        public ReadOnlySpan<byte> GetLookAhead()
        {
            return lookAhead.AsSpan(bufStart, lookAheadSize);
        }
    }
}
