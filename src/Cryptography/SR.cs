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
        public static string Cryptography_CSP_NoPrivateKey = "Object contains only the public half of a key pair.A private key must also be provided.";
        public static string Cryptography_HashAlgorithmNameNullOrEmpty = "The hash algorithm name cannot be null or empty.";
        public static string Cryptography_TlsRequires64ByteSeed = "The TLS key derivation function requires a seed value of exactly 64 bytes.";

        public static string Argument_DestinationTooShort = "Destination is too short.";

        public static string Cryptography_OpenPgp_InvalidMPInteger = "Invalid encoding of MP integer in signature or key.";
        public static string Cryptography_OpenPgp_UnsupportedECPoint = "Unsupported EC point format.";
        public static string Cryptography_OpenPgp_HashMustBeSHA256OrStronger = "Hash algorithm must be SHA-256 or stronger.";
        public static string Cryptography_OpenPgp_SymmetricKeyAlgorithmMustBeAES256OrStronger = "Symmetric key algorithm must be AES-128 or stronger.";
        public static string Cryptography_OpenPgp_UnsupportedCurveOid = "Unsupported curve: {0}.";
        public static string Cryptography_OpenPgp_SigningKeyIdMismatch = "Key id of signing key and private key don't match.";
    }
}
