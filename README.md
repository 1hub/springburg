# Inflatable Palace

This library takes OpenPGP implementation from BouncyCastle and updates it to work on top of .NET cryptography classes instead of BouncyCastle ones. It also updates the API to use generics and latest C# features. Where deemed reasonable it also tries to avoid mistakes that were present in the original BouncyCastle design like  passing in parameters that are already implied by other means and where mismatch would only result in error.

At the moment this is not a production ready code and some features of the original API are missing or not working:
- Bzip2 compression and decompression, Zlib compression (RFC 1950)
- ElGamal ciphers
- SHA224 hash algorithm
- DSA with large keys or 224-bit Q value

Unlike BouncyCastle 1.8.9 which this code is forked from it adds support for X25519 key exchange algorithm and Ed25519 signature algorithm. Both are currently implemented as wrappers around the NSec security library since .NET lacks cross platform implementation.

Implementations of legacy algorithms (IDEA, CAST5, TwoFish) are provided for compatibility but generally don't meet the code quality required for cryptographic code.

Just as BouncyCastle the library is licensed under MIT license.
