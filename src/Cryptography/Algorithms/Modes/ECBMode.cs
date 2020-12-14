using Internal.Cryptography;
using System;

namespace InflatablePalace.Cryptography.Algorithms.Modes
{
    sealed class ECBMode : BasicSymmetricCipher
    {
        private IBlockTransform blockTransform;

        public ECBMode(IBlockTransform blockTransform, int paddingSizeInBytes)
            : base(Array.Empty<byte>(), blockTransform.BlockSizeInBytes, paddingSizeInBytes)
        {
            this.blockTransform = blockTransform;
        }

        public override int Transform(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int outputCount = 0;
            int blockSize = blockTransform.BlockSizeInBytes;
            while (input.Length > blockSize)
            {
                blockTransform.Transform(input.Slice(0, blockSize), output.Slice(0, blockSize));
                outputCount += blockSize;
                input = input.Slice(blockSize);
                output = output.Slice(blockSize);
            }
            return outputCount;
        }

        public override int TransformFinal(ReadOnlySpan<byte> input, Span<byte> output)
        {
            return Transform(input, output);
        }
    }
}
