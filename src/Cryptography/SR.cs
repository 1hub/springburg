namespace Internal.Cryptography
{
    class SR
    {
        public static string Cryptography_PartialBlock = "The input data is not a complete block.";
        public static string Cryptography_UnknownPaddingMode = "Unknown padding mode used.";
        public static string Cryptography_InvalidPadding = "Padding is invalid and cannot be removed.";
        public static string Cryptography_MustTransformWholeBlock = "TransformBlock may only process bytes in block sized increments.";
        public static string Cryptography_TransformBeyondEndOfBuffer = "Attempt to transform beyond end of buffer.";
        public static string Cryptography_CipherModeNotSupported = "The specified CipherMode '{0}' is not supported.";
        public static string Cryptography_Xml_KW_BadKeySize = "The length of the encrypted data in Key Wrap is either 32, 40 or 48 bytes.";
        public static string Cryptography_Xml_BadWrappedKeySize = "Bad wrapped key size.";
        public static string Argument_DestinationTooShort = "Destination is too short.";
    }
}
