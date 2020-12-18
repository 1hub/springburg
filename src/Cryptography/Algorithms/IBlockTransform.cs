using System;

namespace InflatablePalace.Cryptography.Algorithms
{
    interface IBlockTransform : IDisposable
    {
        int BlockSizeInBytes { get; }

        int Transform(ReadOnlySpan<byte> input, Span<byte> output);
    }
}
