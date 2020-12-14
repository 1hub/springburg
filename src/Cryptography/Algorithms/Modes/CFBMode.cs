using Internal.Cryptography;
using System;
using System.Security.Cryptography;

namespace InflatablePalace.Cryptography.Algorithms.Modes
{
    sealed class CFBMode : BasicSymmetricCipher
    {
        private IBlockTransform blockTransform;
        private bool encryption;
        private byte[] current;
        private byte[] temp;

        public CFBMode(byte[] iv, IBlockTransform blockTransform, bool encryption, int paddingSizeInBytes)
            : base(iv, blockTransform.BlockSizeInBytes, paddingSizeInBytes)
        {
            if (iv == null)
                throw new ArgumentNullException(nameof(iv));
            if (iv.Length != blockTransform.BlockSizeInBytes)
                throw new ArgumentOutOfRangeException(nameof(iv));

            this.current = CryptoPool.Rent(iv.Length);
            this.temp = CryptoPool.Rent(iv.Length);
            Array.Copy(iv, this.current, iv.Length);

            this.blockTransform = blockTransform;
            this.encryption = encryption;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                CryptoPool.Return(current);
                current = null;
                CryptoPool.Return(temp);
                temp = null;
            }
            base.Dispose(disposing);
        }

        public override int Transform(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int outputCount = 0;
            int blockSize = BlockSizeInBytes;

            while (input.Length > 0)
            {
                blockTransform.Transform(current, temp);
                // TODO: Vectorize
                for (int i = 0; i < blockSize; i++)
                    temp[i] ^= input[i];
                if (encryption)
                    temp.AsSpan(0, blockSize).CopyTo(current.AsSpan());
                else
                    input.Slice(0, blockSize).CopyTo(current.AsSpan());
                temp.AsSpan(0, blockSize).CopyTo(output);
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
                blockTransform.Transform(current, temp);
                // TODO: Vectorize
                for (int i = 0; i < input.Length; i++)
                    temp[i] ^= input[i];
                temp.AsSpan(0, output.Length).CopyTo(output);
                outputSize += output.Length;
            }

            // Reset vectors
            IV.CopyTo(current.AsSpan());
            CryptographicOperations.ZeroMemory(temp);

            return outputSize;
        }
    }
}
