using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace InflatablePalace.Cryptography.Algorithms
{
    interface IBlockTransform
    {
        int BlockSizeInBytes { get; }

        int Transform(ReadOnlySpan<byte> input, Span<byte> output);
    }
}
