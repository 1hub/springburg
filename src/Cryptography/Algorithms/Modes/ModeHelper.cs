using Internal.Cryptography;
using System;
using System.Security.Cryptography;

namespace InflatablePalace.Cryptography.Algorithms.Modes
{
    static class ModeHelper
    {

        public static ICryptoTransform CreateEncryptor(CipherMode mode, PaddingMode padding, byte[] key, byte[] iv, Func<byte[], bool, IBlockTransform> createTransform)
        {
            switch (mode)
            {
                case CipherMode.ECB:
                    return new UniversalCryptoEncryptor(padding, new ECBMode(createTransform(key, true), 0));
                case CipherMode.CFB:
                    return new UniversalCryptoEncryptor(padding, new CFBMode(iv, createTransform(key, true), true, 0));
                default:
                    throw new CryptographicException(string.Format(SR.Cryptography_CipherModeNotSupported, mode));
            }
        }

        public static ICryptoTransform CreateDecryptor(CipherMode mode, PaddingMode padding, byte[] key, byte[] iv, Func<byte[], bool, IBlockTransform> createTransform)
        {
            switch (mode)
            {
                case CipherMode.ECB:
                    return new UniversalCryptoDecryptor(padding, new ECBMode(createTransform(key, false), 0));
                case CipherMode.CFB:
                    return new UniversalCryptoDecryptor(padding, new CFBMode(iv, createTransform(key, true), false, 0));
                default:
                    throw new CryptographicException(string.Format(SR.Cryptography_CipherModeNotSupported, mode));
            }
        }

        public static void ThrowOnUnsupportedMode(CipherMode mode)
        {
            switch (mode)
            {
                case CipherMode.ECB:
                case CipherMode.CFB:
                    break;
                default:
                    throw new CryptographicException(string.Format(SR.Cryptography_CipherModeNotSupported, mode));
            }
        }
    }
}
