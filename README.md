# Springburg

This is an experimental OpenPGP library for .NET. At the moment the API is unstable, bugs are all around the place and it is not ready for production use.

The library uses parts of the OpenPGP implementation from [Bouncy Castle](https://github.com/bcgit/bc-csharp/) but it's heavily rewritten. It updates the API to use generics, latest C# features and offer more fool proof type-safe API for building OpenPGP applications. Where deemed reasonable it also tries to avoid mistakes that were present in the original BouncyCastle design like passing in parameters that are already implied by other means and where mismatch would only result in error.

Where possible the .NET cryptography APIs are used under the hood (RSA, DSA, ECDsa, ECDiffieHellman, AES, 3DES, etc.). X25519 and Ed25519 algorithms are implemented using the [NSec library](https://nsec.rocks/). Few more algorithms are implemented in managed code to offer legacy compatibility (ElGamal encryption and Twofish, IDEA and CAST5 symmetric ciphers). The eventual goal is to offer an option to drop these legacy algorithm where compatibility is not a concern. They are not requirement of the OpenPGP specification but older versions of PGP and GnuPG software are known to use some of these algorithms as default. The impementations were used to bootstrap some of the ported Bouncy Castle unit tests.

The following features of the original API are missing or not working properly:
- Bzip2 compression and decompression
- SHA224 hash algorithm
- DSA with large keys or 224-bit Q value

Just as Bouncy Castle the library is licensed under MIT license.
