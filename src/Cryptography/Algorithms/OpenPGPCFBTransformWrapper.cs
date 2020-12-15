using Internal.Cryptography;
using System;
using System.Security.Cryptography;

namespace InflatablePalace.Cryptography.Algorithms
{
    class OpenPGPCFBTransformWrapper : ICryptoTransform
    {
        private ICryptoTransform ecbTransform;
        private long count;
        private bool encryption;
        private byte[] FR;
        private byte[] FRE;

        public OpenPGPCFBTransformWrapper(ICryptoTransform ecbTransform, byte[] iv, bool encryption)
        {
            this.ecbTransform = ecbTransform;
            this.count = 0;
            this.encryption = encryption;

            this.FR = CryptoPool.Rent(iv.Length);
            this.FRE = CryptoPool.Rent(iv.Length);
            iv.CopyTo(this.FR, 0);
        }

        public bool CanReuseTransform
        {
            get { return true; }
        }

        public bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        public int InputBlockSize
        {
            get { return this.ecbTransform.InputBlockSize; }
        }

        public int OutputBlockSize
        {
            get { return this.ecbTransform.OutputBlockSize; }
        }

        public void Dispose()
        {
            CryptoPool.Return(FR);
            FR = null;
            CryptoPool.Return(FRE);
            FRE = null;
            this.ecbTransform.Dispose();
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            int blockSize = InputBlockSize;

            if (inputBuffer == null)
                throw new ArgumentNullException(nameof(inputBuffer));
            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException(nameof(inputOffset));
            if (inputOffset > inputBuffer.Length)
                throw new ArgumentOutOfRangeException(nameof(inputOffset));
            if (inputCount <= 0)
                throw new ArgumentOutOfRangeException(nameof(inputCount));
            if (inputCount % blockSize != 0)
                throw new ArgumentOutOfRangeException(nameof(inputCount), SR.Cryptography_MustTransformWholeBlock);
            if (inputCount > inputBuffer.Length - inputOffset)
                throw new ArgumentOutOfRangeException(nameof(inputCount), SR.Cryptography_TransformBeyondEndOfBuffer);
            if (outputBuffer == null)
                throw new ArgumentNullException(nameof(outputBuffer));
            if (outputOffset > outputBuffer.Length)
                throw new ArgumentOutOfRangeException(nameof(outputOffset));
            if (inputCount > outputBuffer.Length - outputOffset)
                throw new ArgumentOutOfRangeException(nameof(outputOffset), SR.Cryptography_TransformBeyondEndOfBuffer);

            var input = inputBuffer.AsSpan(inputOffset, inputCount);
            var output = outputBuffer.AsSpan(outputOffset);
            int outputCount = 0;
            while (input.Length >= blockSize)
            {
                if (count == 0)
                {
                    this.ecbTransform.TransformBlock(FR, 0, blockSize, FRE, 0);
                    // TODO: Vectorize
                    for (int i = 0; i < blockSize; i++)
                        FRE[i] ^= input[i];
                    if (encryption)
                        FRE.AsSpan(0, blockSize).CopyTo(FR.AsSpan());
                    else
                        input.Slice(0, blockSize).CopyTo(FR.AsSpan());
                    FRE.AsSpan(0, blockSize).CopyTo(output);
                }
                else if (count == blockSize)
                {
                    // Two more bytes in CFB mode, then resynchronize
                    this.ecbTransform.TransformBlock(FR, 0, blockSize, FRE, 0);
                    output[0] = (byte)(FRE[0] ^ input[0]);
                    output[1] = (byte)(FRE[1] ^ input[1]);
                    FR.AsSpan(2).CopyTo(FR);
                    if (!encryption)
                    {
                        FR[blockSize - 2] = input[0];
                        FR[blockSize - 1] = input[1];
                        this.ecbTransform.TransformBlock(FR, 0, blockSize, FRE, 0);
                        for (int n = 2; n < blockSize; n++)
                        {
                            FR[n - 2] = input[n];
                            output[n] = (byte)(input[n] ^ FRE[n - 2]);
                        }
                    }
                    else
                    {
                        FR[blockSize - 2] = output[0];
                        FR[blockSize - 1] = output[1];
                        this.ecbTransform.TransformBlock(FR, 0, blockSize, FRE, 0);
                        for (int n = 2; n < blockSize; n++)
                        {
                            FR[n - 2] = output[n] = (byte)(input[n] ^ FRE[n - 2]);
                        }
                    }
                }
                else
                {
                    if (!encryption)
                    {
                        FR[blockSize - 2] = input[0];
                        output[0] = (byte)(input[0] ^ FRE[blockSize - 2]);
                        FR[blockSize - 1] = input[1];
                        output[1] = (byte)(input[1] ^ FRE[blockSize - 1]);
                        this.ecbTransform.TransformBlock(FR, 0, blockSize, FRE, 0);
                        for (int n = 2; n < blockSize; n++)
                        {
                            FR[n - 2] = input[n];
                            output[n] = (byte)(input[n] ^ FRE[n - 2]);
                        }
                    }
                    else
                    {
                        FR[blockSize - 2] = output[0] = (byte)(input[0] ^ FRE[blockSize - 2]);
                        FR[blockSize - 1] = output[1] = (byte)(input[1] ^ FRE[blockSize - 1]);
                        this.ecbTransform.TransformBlock(FR, 0, blockSize, FRE, 0);
                        for (int n = 2; n < blockSize; n++)
                        {
                            FR[n - 2] = output[n] = (byte)(input[n] ^ FRE[n - 2]);
                        }
                    }
                }
                input = input.Slice(blockSize);
                output = output.Slice(blockSize);
                outputCount += blockSize;
                count += blockSize;
            }
            return outputCount;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputCount < 0)
                throw new ArgumentOutOfRangeException(nameof(inputCount));

            if (inputCount > 0)
            {
                var output = new byte[inputCount];
                TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
                return output;
            }

            return Array.Empty<byte>();
        }
    }
}
