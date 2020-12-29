using Internal.Cryptography;
using System;
using System.Security.Cryptography;

namespace Springburg.Cryptography.Algorithms.Modes
{
    static class ModeHelper
    {

        public static ICryptoTransform CreateEncryptor(CipherMode mode, PaddingMode padding, byte[] rgbKey, byte[]? rgbIV, Func<byte[], bool, IBlockTransform> createTransform)
        {
            switch (mode)
            {
                case CipherMode.ECB:
                    return new UniversalCryptoEncryptor(padding, new ECBMode(createTransform(rgbKey, true), 0));
                case CipherMode.CFB:
                    if (rgbIV == null)
                        throw new ArgumentNullException(nameof(rgbIV));
                    return new UniversalCryptoEncryptor(padding, new CFBMode(rgbIV, createTransform(rgbKey, true), true, 0));
                default:
                    throw new CryptographicException(string.Format(SR.Cryptography_CipherModeNotSupported, mode));
            }
        }

        public static ICryptoTransform CreateDecryptor(CipherMode mode, PaddingMode padding, byte[] key, byte[]? iv, Func<byte[], bool, IBlockTransform> createTransform)
        {
            switch (mode)
            {
                case CipherMode.ECB:
                    return new UniversalCryptoDecryptor(padding, new ECBMode(createTransform(key, false), 0));
                case CipherMode.CFB:
                    if (iv == null)
                        throw new ArgumentNullException(nameof(iv));
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
