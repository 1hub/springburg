using Internal.Cryptography;
using System;
using System.Security.Cryptography;

namespace InflatablePalace.Cryptography.Algorithms.Modes
{
    sealed class CFBMode : BasicSymmetricCipher
    {
        private IBlockTransform blockTransform;
        private bool encryption;
        private byte[] FR;
        private byte[] FRE;

        public CFBMode(byte[] iv, IBlockTransform blockTransform, bool encryption, int paddingSizeInBytes)
            : base(iv, blockTransform.BlockSizeInBytes, paddingSizeInBytes)
        {
            if (iv == null)
                throw new ArgumentNullException(nameof(iv));
            if (iv.Length != blockTransform.BlockSizeInBytes)
                throw new ArgumentOutOfRangeException(nameof(iv));

            this.FR = CryptoPool.Rent(iv.Length);
            this.FRE = CryptoPool.Rent(iv.Length);
            iv.CopyTo(this.FR, 0);

            this.blockTransform = blockTransform;
            this.encryption = encryption;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                CryptoPool.Return(FR);
                FR = null;
                CryptoPool.Return(FRE);
                FRE = null;
            }
            base.Dispose(disposing);
        }

        public override int Transform(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int outputCount = 0;
            int blockSize = BlockSizeInBytes;

            while (input.Length > 0)
            {
                blockTransform.Transform(FR, FRE);
                // TODO: Vectorize
                for (int i = 0; i < blockSize; i++)
                    FRE[i] ^= input[i];
                if (encryption)
                    FRE.AsSpan(0, blockSize).CopyTo(FR.AsSpan());
                else
                    input.Slice(0, blockSize).CopyTo(FR.AsSpan());
                FRE.AsSpan(0, blockSize).CopyTo(output);
                input = input.Slice(blockSize);
                output = output.Slice(blockSize);
                outputCount += blockSize;
            }

            return outputCount;
        }

        public override int TransformFinal(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int outputSize = 0;
            int blockSize = BlockSizeInBytes;

            if (input.Length >= blockSize)
            {
                int alignedLength = input.Length - (input.Length % blockSize);
                outputSize += Transform(input.Slice(0, alignedLength), output.Slice(0, alignedLength));
                input = input.Slice(alignedLength);
                output = output.Slice(alignedLength);
            }

            if (input.Length > 0)
            {
                blockTransform.Transform(FR, FRE);
                // TODO: Vectorize
                for (int i = 0; i < input.Length; i++)
                    FRE[i] ^= input[i];
                FRE.AsSpan(0, output.Length).CopyTo(output);
                outputSize += output.Length;
            }

            // Reset vectors
            IV.CopyTo(FR.AsSpan());
            CryptographicOperations.ZeroMemory(FRE);

            return outputSize;
        }
    }
}
