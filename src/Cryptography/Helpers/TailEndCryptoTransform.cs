using Internal.Cryptography;
using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace InflatablePalace.Cryptography.Helpers
{
    class TailEndCryptoTransform : ICryptoTransform
    {
        ICryptoTransform innerTransform;
        ArraySegment<byte> rollingBuffer;
        int rollingBufferOffset;
        int tailEndSize;

        public TailEndCryptoTransform(ICryptoTransform innerTransform, int tailEndSize)
        {
            int rollingBufferSize = 
                innerTransform.CanTransformMultipleBlocks ?
                128 * innerTransform.InputBlockSize :
                innerTransform.InputBlockSize +
                tailEndSize;
            this.innerTransform = innerTransform;
            this.tailEndSize = tailEndSize;
            this.rollingBuffer = new ArraySegment<byte>(CryptoPool.Rent(rollingBufferSize), 0, rollingBufferSize);
            this.rollingBufferOffset = 0;
        }

        public bool CanReuseTransform => innerTransform.CanReuseTransform;

        public bool CanTransformMultipleBlocks => true;

        public int InputBlockSize => innerTransform.InputBlockSize;

        public int OutputBlockSize => innerTransform.OutputBlockSize;

        public void Dispose()
        {
            CryptoPool.Return(rollingBuffer);
            rollingBuffer = null;
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            int outputCount = 0;
            while (inputCount > 0)
            {
                int numBytesToConsume = Math.Min(inputCount, this.rollingBuffer.Count - rollingBufferOffset);
                inputBuffer.AsSpan(inputOffset, numBytesToConsume).CopyTo(rollingBuffer.AsSpan(rollingBufferOffset));
                rollingBufferOffset += numBytesToConsume;
                if (rollingBufferOffset == rollingBuffer.Count)
                {
                    int blockSize = innerTransform.TransformBlock(rollingBuffer.Array, 0, rollingBuffer.Count - tailEndSize, outputBuffer, outputOffset);
                    outputOffset += blockSize;
                    outputCount += blockSize;
                    rollingBuffer.AsSpan(rollingBuffer.Count - tailEndSize, tailEndSize).CopyTo(rollingBuffer);
                    rollingBufferOffset = tailEndSize;
                }
                inputCount -= numBytesToConsume;
                inputOffset += numBytesToConsume;
            }

            if (rollingBufferOffset - tailEndSize >= InputBlockSize)
            {
                int bytesToConsume = rollingBufferOffset - tailEndSize;
                int reminder = bytesToConsume % InputBlockSize;
                bytesToConsume -= reminder;
                int blockSize = innerTransform.TransformBlock(rollingBuffer.Array, 0, bytesToConsume, outputBuffer, outputOffset);
                outputCount += blockSize;
                rollingBuffer.AsSpan(rollingBufferOffset - reminder - tailEndSize, reminder + tailEndSize).CopyTo(rollingBuffer);
                rollingBufferOffset = reminder + tailEndSize;
            }

            return outputCount;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            Debug.Assert(inputCount + rollingBufferOffset >= tailEndSize);

            int outputCount = 0;
            byte[] outputBuffer = new byte[inputCount + rollingBufferOffset - tailEndSize];
            int outputOffset = 0;
            while (inputCount > 0)
            {
                int numBytesToConsume = Math.Min(inputCount, this.rollingBuffer.Count - rollingBufferOffset);
                inputBuffer.AsSpan(inputOffset, numBytesToConsume).CopyTo(rollingBuffer.AsSpan(rollingBufferOffset));
                rollingBufferOffset += numBytesToConsume;
                if (rollingBufferOffset == rollingBuffer.Count)
                {
                    int blockSize = innerTransform.TransformBlock(rollingBuffer.Array, 0, rollingBuffer.Count - tailEndSize, outputBuffer, outputOffset);
                    outputOffset += blockSize;
                    outputCount += blockSize;
                    rollingBuffer.AsSpan(rollingBuffer.Count - tailEndSize, tailEndSize).CopyTo(rollingBuffer);
                    rollingBufferOffset = tailEndSize;
                }
                inputCount -= numBytesToConsume;
                inputOffset += numBytesToConsume;
            }

            Debug.Assert(rollingBufferOffset >= tailEndSize);
            byte[] finalBlock = innerTransform.TransformFinalBlock(rollingBuffer.Array, 0, rollingBufferOffset - tailEndSize);
            Debug.Assert(finalBlock.Length == outputBuffer.Length - outputOffset);
            finalBlock.CopyTo(outputBuffer, outputOffset);
            outputCount += finalBlock.Length;

            Debug.Assert(outputCount == outputBuffer.Length);

            return outputBuffer;
        }

        public ReadOnlySpan<byte> TailEnd => rollingBuffer.AsSpan(rollingBufferOffset - tailEndSize, tailEndSize);
    }
}
