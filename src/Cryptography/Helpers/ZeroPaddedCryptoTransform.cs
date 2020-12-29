using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Springburg.Cryptography.Helpers
{
    /// <summary>
    /// Wrapper around cryptography transformations that generates and
    /// truncated zero padding around the last block.
    /// </summary>
    class ZeroPaddedCryptoTransform : ICryptoTransform
    {
        ICryptoTransform transform;

        public ZeroPaddedCryptoTransform(ICryptoTransform transform)
        {
            this.transform = transform;
            Debug.Assert(transform.InputBlockSize == transform.OutputBlockSize);
        }

        public bool CanReuseTransform => transform.CanReuseTransform;

        public bool CanTransformMultipleBlocks => transform.CanTransformMultipleBlocks;

        public int InputBlockSize => transform.InputBlockSize;

        public int OutputBlockSize => transform.OutputBlockSize;

        public void Dispose()
        {
            transform.Dispose();
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            return transform.TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputCount % InputBlockSize != 0)
            {
                byte[] tempBuffer = new byte[inputCount + InputBlockSize - (inputCount % InputBlockSize)];
                Array.Copy(inputBuffer, inputOffset, tempBuffer, 0, inputCount);
                byte[] output = transform.TransformFinalBlock(tempBuffer, 0, tempBuffer.Length);
                return output.AsSpan(0, inputCount).ToArray();
            }
            return transform.TransformFinalBlock(inputBuffer, inputOffset, inputCount);
        }
    }
}
