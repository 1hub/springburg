using System;
using System.Diagnostics;
using System.Security.Cryptography;
using Internal.Cryptography;

namespace Springburg.Cryptography.Primitives
{
    public class CMAC : KeyedHashAlgorithm
    {
        private readonly SymmetricAlgorithm cipher;
        private ICryptoTransform? encryptor;
  
        private readonly byte[] buffer;
        private int bufferPosition;
 
        private readonly byte[] lu1;
        private readonly byte[] lu2;
 
        public CMAC(SymmetricAlgorithm cipher)
            : this(cipher, null)
        {
        }
 
        public CMAC(SymmetricAlgorithm cipher, byte[]? key)
        {
            if (cipher == null)
                throw new ArgumentNullException(nameof(cipher));
            if (cipher.BlockSize != 64 && cipher.BlockSize != 128)
                throw new ArgumentException(SR.Cryptography_CMAC_UnsupportedBlockSize);
 
            this.cipher = cipher;
 
            buffer = new byte[cipher.BlockSize / 8];
            lu1 = new byte[cipher.BlockSize / 8];
            lu2 = new byte[cipher.BlockSize / 8];
 
            HashSizeValue = cipher.BlockSize;
            if (key != null)
                Key = key;
        }
 
        public override byte[] Key
        {
            set => cipher.Key = value;
            get => cipher.Key;
        }

        private static void ApplyU(byte[] source, byte[] dest)
        {
            for (int i = 0; ; )            
            {
                dest[i] = (byte)(source[i] << 1);
 
                if (++i >= source.Length)
                    break;
 
                if ((source[i] & 0x80) != 0)
                    dest[i - 1] |= 0x1;
            }
 
            if ((source[0] & 0x80) != 0)
            {
                if (dest.Length == 8)
                    dest[7] ^= 0x1B;
                else
                    dest[15] ^= 0x87;
            }
        }
 
        public override void Initialize()
        {
            cipher.Mode = CipherMode.ECB;
            cipher.Padding = PaddingMode.None;
            encryptor = cipher.CreateEncryptor();
            CryptographicOperations.ZeroMemory(buffer);
            encryptor.TransformBlock(buffer, 0, buffer.Length, buffer, 0);
            ApplyU(buffer, lu1);
            ApplyU(lu1, lu2);
            CryptographicOperations.ZeroMemory(buffer);
            bufferPosition = 0;
        }

        protected override void HashCore(ReadOnlySpan<byte> source)
        {
            if (encryptor == null)
            {
                Initialize();
                Debug.Assert(encryptor != null);
            }

            while (true)
            {
                int count = Math.Min(source.Length, buffer.Length - bufferPosition);
 
                for (int i = 0; i < count; i++)
                    buffer[bufferPosition++] ^= source[i];
 
                source = source.Slice(count);
                if (source.Length == 0)
                    break;
 
                encryptor.TransformBlock(buffer, 0, buffer.Length, buffer, 0);
 
                bufferPosition = 0;
            }
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            HashCore(array.AsSpan(ibStart, cbSize));
        }
 
        protected override byte[] HashFinal()
        {
            if (encryptor == null)
            {
                Initialize();
                Debug.Assert(encryptor != null);
            }

            if (bufferPosition < buffer.Length)
            {
                buffer[bufferPosition] ^= 0x80;
 
                for (int i = 0; i < buffer.Length; i++)
                    buffer[i] ^= lu2[i];
            }
            else
            {
                for (int i = 0; i < buffer.Length; i++)
                    buffer[i] ^= lu1[i];
            }
 
            byte[] ret = new byte[buffer.Length];
            encryptor.TransformBlock(buffer, 0, buffer.Length, ret, 0);
            return ret;
        }
 
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                encryptor?.Dispose();
                encryptor = null;
                cipher?.Clear();
                CryptographicOperations.ZeroMemory(buffer);
                CryptographicOperations.ZeroMemory(lu1);
                CryptographicOperations.ZeroMemory(lu2);
            }
            base.Dispose(disposing);
        }
    }
}