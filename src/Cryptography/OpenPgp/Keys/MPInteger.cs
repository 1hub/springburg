using Internal.Cryptography;
using System;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp.Keys
{
    class MPInteger
    {
        public static ReadOnlySpan<byte> ReadInteger(ReadOnlySpan<byte> source, out int bytesConsumed)
        {
            if (source.Length < 2)
                throw new CryptographicException(SR.Cryptography_OpenPgp_InvalidMPInteger);
            int bitCount = (source[0] << 8) + source[1];
            int byteCount = (bitCount + 7) / 8;
            if (source.Length < 2 + byteCount)
                throw new CryptographicException(SR.Cryptography_OpenPgp_InvalidMPInteger);
            bytesConsumed = byteCount + 2;
            return source.Slice(2, byteCount);
        }

        public static bool TryWriteInteger(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten)
        {
            int leadingZeros;
            for (leadingZeros = 0; leadingZeros < source.Length && source[leadingZeros] == 0; leadingZeros++)
                ;
            source = source.Slice(leadingZeros);

            if (destination.Length < 2 + source.Length)
            {
                bytesWritten = 0;
                return false;
            }

            int bitSize = source.Length * 8;
            if (bitSize != 0)
            {
                for (int mask = 0x80; mask >= 0 && (source[0] & mask) == 0; mask >>= 1)
                    bitSize--;
            }

            destination[0] = (byte)(bitSize >> 8);
            destination[1] = (byte)bitSize;
            source.CopyTo(destination.Slice(2));
            bytesWritten = source.Length + 2;
            return true;
        }

        public static int GetMPEncodedLength(ReadOnlySpan<byte> source)
        {
            int leadingZeros;
            for (leadingZeros = 0; leadingZeros < source.Length && source[leadingZeros] == 0; leadingZeros++)
                ;
            return source.Length - leadingZeros + 2;
        }

        public static int GetMPEncodedLength(params byte[][] sources)
        {
            int totalSize = 0;
            foreach (byte[] source in sources)
                totalSize += GetMPEncodedLength(new ReadOnlySpan<byte>(source));
            return totalSize;
        }
    }
}
