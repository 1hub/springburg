using System;

namespace Springburg.Cryptography.Algorithms
{
    interface IBlockTransform : IDisposable
    {
        int BlockSizeInBytes { get; }

        int Transform(ReadOnlySpan<byte> input, Span<byte> output);
    }
}
