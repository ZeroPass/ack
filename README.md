# AntelopeIO Cryptography Kits
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![build](https://github.com/ZeroPass/antelope.ck/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/ZeroPass/antelope.ck/actions/workflows/build.yml)
[![tests](https://github.com/ZeroPass/antelope.ck/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/ZeroPass/antelope.ck/actions/workflows/tests.yml)

[AntelopeIO](https://github.com/antelopeIO) Cryptography Library is a header-only library designed for use in smart contracts. The library includes implementations of ECC primitives and ECDSA verification algorithms, as well as RSA PKCS v1.5 & RSASSA-PSS signature verification algorithms and Keccak hash algorithms: SHA3-256, SHA3-384, SHA3-512, SHAKE-128, and SHAKE-256.

One of the key features of the library is its optimization of algorithm execution by minimizing heap allocations. The library achieves this by allocating most of the data on the stack and passing it around by pointers and references using `std::span`. Data structures are designed in a way that utilizes static polymorphism to minimize v-table emissions and runtime overhead. This design choice ensures that the library operates as efficiently as possible, making it well-suited for use in resource-constrained environments.

It should be noted that some parts of the underlying algorithm implementations, such as software modular exponentiation, are taken from other libraries and were not developed by the authors of this library.

# Algorithms
## ECC
The library implements core elliptic curve primitives, such as curve and point, and supports basic EC arithmetic operations (addition, subtraction, and multiplication) for curves over a prime finite field GF(p). Points can be represented in both affine and homogeneous coordinate systems, providing flexibility for various use cases and applications. Furthermore, the library pre-defines two elliptic curves: `secp256k1` and `secp256r1`. 

In addition to the core EC primitives, the library also provides implementation for the ECDSA signature verification algorithm. This implementation follows the [NIST FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) standard and has been cross-checked against the [SECG SEC1 v2.0](https://www.secg.org/sec1-v2.pdf) standard and the [BSI TR-03111 v2.10](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-1_pdf.pdf) standard.

### Elliptic Curve Primitives
The [ack/ec.hpp](include/ack/ec.hpp) header file defines the following elliptic curve primitives:
- `ec_point_fp` - represents a point in affine coordinate system for a curve over GF(p)
- `ec_point_fp_proj` - represents a point in homogeneous coordinate system for a curve over GF(p)
- `ec_curve_fp` - represents an elliptic curve over GF(p)

### Pre-defined Elliptic Curves
The [ack/ec_curve.hpp](include/ack/ec_curve.hpp) header file contains definitions for pre-defined elliptic curves.

### ECDSA Signature Verification Functions
The [ack/ecdsa.hpp](include/ack/ecdsa.hpp) header file defines the following ECDSA signature verification functions:
- `ecdsa_verify` - checks if an ECDSA signature is valid for the provided message.
- `assert_ecdsa` - fails transaction if an ECDSA signature is not valid for the provided message.

## RSA PKCS#1 v1.5 & RSASSA-PSS signature verification
The implementation of RSA PKCS#1 v1.5 and RSASSA-PSS signature verification algorithms is following the *RFC 8017* [https://www.rfc-editor.org/rfc/rfc8017](https://www.rfc-editor.org/rfc/rfc8017). For RSASSA-PSS only MGF1 mask generation function is supported. The underlying implementation for *modular exponentiation* math was borrowed from [U-Boot](https://github.com/u-boot/u-boot) C implementation. This implementation uses *Montgomery multiplication* which speeds up the computation of *modular exponentiation*. See [powm.h](include/ack/c/powm.h).

The [ack/rsa.hpp](include/ack/rsa.hpp) header file defines the RSA PKCS v1.5 signature verification functions for *SHA-1*, *SHA-256* and *SHA-512*:
- `verify_rsa_sha1` - checks if RSA signature is valid for the provided SHA-1 hash.
- `assert_rsa_sha1` - fails transaction if RSA signature is not valid for the provided SHA-1 hash.
- `verify_rsa_sha256` - checks if RSA signature is valid for the provided SHA-256 hash.
- `assert_rsa_sha256` - fails transaction if RSA signature is not valid for the provided SHA-256 hash.
- `verify_rsa_sha512` - checks if RSA signature is valid for the provided SHA-512 hash.
- `assert_rsa_sha512` - fails transaction if RSA signature is not valid for the provided SHA-512 hash.

the RSASSA-PSS signature verification functions for *SHA-1*, *SHA-256* and *SHA-512*:
- `verify_rsa_pss_sha1` - checks if RSASSA-PSS MGF1 signature is valid for the provided SHA-1 hash.
- `assert_rsa_pss_sha1` - fails transaction if RSASSA-PSS MGF1 signature is not valid for the provided SHA-1 hash.
- `verify_rsa_pss_sha256` - checks if RSASSA-PSS MGF1 signature is valid for the provided SHA-256 hash.
- `assert_rsa_pss_sha256` - fails transaction if RSASSA-PSS MGF1 signature is not valid for the provided SHA-256 hash.
- `verify_rsa_pss_sha512` - checks if RSASSA-PSS MGF1 signature is valid for the provided SHA-512 hash.
- `assert_rsa_pss_sha512` - fails transaction if RSASSA-PSS MGF1 signature is not valid for the provided SHA-512 hash.

and modular exponentiation function:
- `powm` - computes modular exponentiation for base and exponent over modulus.  
   By default `eosio::mod_exp` intrinsic is used if macro `ACK_NO_INTRINSICS=1` is not defined.

## Keccak hash algorithms
Library implements 4 Keccak hashing algorithms: SHA3-256, SHA3-512, SHAKE-128 and SHAKE-256. The underlying base implementation was copied from the original authors. The code is hosted at [https://github.com/XKCP/XKCP](https://github.com/XKCP/XKCP)

The [ack/keccak.hpp](include/ack/keccak.hpp) header file defines those 4 hash algorithms:
- `sha3_256` - computes SHA3-256 hash
- `sha3_384` - computes SHA3-384 hash
- `sha3_512` - computes SHA3-512 hash
- `shake128_fixed` - computes fixed size  SHAKE-128 hash
- `shake128` - computes var-long SHAKE-128 hash
- `shake256_fixed` - computes fixed size SHAKE-256 hash
- `shake256` - computes var-long SHAKE-256 hash

# Algorithm testing
The validity of algorithms was tested with FIPS 186-3 & 186-4 and FIPS 202 test vectors from the US National Institute of Standards and Technology - NIST. In addition, the RSA and ECDSA signature verification algorithms were tested using test vectors from Google's Wycheproof project. The tests can be found in [tests](tests/include/ack/tests/) folder. To compile the tests, configuring `cmake` with `-DACK_BUILD_TESTS=ON` (enabled by default).

FIPS 186-4: [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures)
<br>Project Wycheproof: [https://github.com/google/wycheproof](https://github.com/google/wycheproof)
<br>Keccak SHA-3 FIPS 202: [https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#sha3vsha3vss]( https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#sha3vsha3vss)

# Use in project
To use antelope.ck library in your project, it is recommended to use  [CMake](https://cmake.org/) and configure your project to use the external `ack` project. E.g.: using [FetchContent](https://cmake.org/cmake/help/latest/module/FetchContent.html) or copy the library folder to your project and point cmake to it with [add_subdirectory](https://cmake.org/cmake/help/latest/command/add_subdirectory.html).
If only pure WASM implementation is desired configure your CMake project with `ACK_NO_INTRINSICS=ON` option before including ack library. This will exclude specialized intrinsics such as `eosio::mod_exp` from being used by the library, and instead, a software implementation will be used.

If configured correctly, you should be able to add the antelope.ck library to your [CMake](https://cmake.org/) project using command `add_library(<your_project> ack)` and include it in your code using the header file: `#include <ack/ack.hpp>`.  


**Example:**
```cpp
  #include <ack/ack.hpp>

  // Calculate sum of 2 EC points on secp256k1 curve using affine coordinates
  const auto p1 = ack::ec_curve::secp256k1.make_point( p1_x, p1_y );
  const auto p2 = ack::ec_curve::secp256k1.generate_point( "85d0c2e48955214783ecf50a4f041" );
  const auto p3 = p1 + p2;

  // Triple the p3 point
  const auto p4 = p3 * 3;

  // Multiply the inverse of p4 by integer 0x73c5f6a67456ae48209b5a32d1b8
  const auto p5 = -p4 * "73c5f6a67456ae48209b5a32d1b8";
  
  // Generate 2 EC points on secp256r1 curve using Jacobi coordinates representation
  using secp256r1_t     = decltype( ack::ec_curve::secp256r1 );
  using point_r1_jacobi = ack::ec_point_fp_jacobi<secp256r1_t>;
  
  const auto p1         = ack::ec_curve::secp256k1.generate_point<point_r1_jacobi>( "5d0c2e48955214783ecf50a4f041" );
  const auto p2_affine  = ack::ec_curve::secp256k1.make_point( p2_x, p2_y );
  const auto p2         = point_r1_jacobi( p2_affine );
  
  // Calculate sum of 2 EC points on secp256r1 curve in Jacobi coordinates
  const auto p3 = p1 + p2;

  // Double point p3 
  const auto p4 = p3 * 2; // or p3.doubled();
  
  // Verify point p4 is not identity and lies on the curve
  eosio::check( !p4.is_identity(), "invalid point" );
  eosio::check( p4.is_on_curve() , "invalid point" );
  eosio::check( p4.is_valid()    , "invalid point" );
  
  // Convert point p4 to affine coordinates
  const auto p4_affine = p4.to_affine();

  // Verify secp256k1 ECDSA-SHA256 signature
  auto pub_point = ack::ec_curve::secp256k1.make_point( pubkey_x, pubkey_y );

  // Optionally, verify public key
  eosio::check( pub_point.is_valid(), "invalid public key" );

  auto md = eosio::sha256( msg, msg_len );
  ack::assert_ecdsa( pub_point, md, sig_r, sig_s,
      "failed to verify secp256k1 ECDSA-SHA256 signature"
  );

  // Verify secp256r1 ECDSA-SHA256 signature
  auto pub_point = ack::ec_curve::secp256r1.make_point( pubkey_x, pubkey_y );

  // Optionally, verify public key
  eosio::check( pub_point.is_valid(), "invalid public key" );

  const bool valid = ack::ecdsa_verify( pub_point, md_bytes, sig_r, sig_s );
  if ( !valid ) {
    // Do something...
  }

  // Verify RSA PKCS#1 v1.5 SHA-512 signature
  auto pubkey = ack::rsa_public_key( ras_modulus, rsa_exponent ); // or ack::rsa_public_key_view(...)
  auto md     = eosio::sha512( msg, msg_len );
  ack::assert_rsa_sha512( pubkey, md, rsa_sig,
      "failed to verify RSA PKCS#1 v1.5 SHA-512 signature"
  );

  // or with verify function
  if ( !ack::verify_rsa_sha512( pubkey, md, rsa_sig ) ) {
    // Do something...
  }

  // Verify RSASSA-PSS MGF1 SHA-256 signature
  auto pubkey = ack::rsa_pss_public_key( ras_modulus, rsa_exponent, pss_salt_len ); // or ack::rsa_pss_public_key_view(...)
  auto md     = eosio::sha256( msg, msg_len );
  ack::assert_rsa_pss_sha256( pubkey, md, rsapss_sig,
      "Failed to verify RSASSA-PSS MGF1 SHA-256 signature"
  );

  // or with verify function
  if ( !ack::verify_rsa_pss_sha256( pubkey, md, rsapss_sig ) ) {
    // Do something...
  }

  // Calculate SHA384
  hash384 mdsh384 = ack::sha384( byte_data );

  // Calculate SHA3-384
  hash384 mdsh3 = ack::sha3_384( byte_data );

  // Calculate fixed size SHAKE-128 hash
  hash160 mdshk128 = ack::shake128_fixed<20>( byte_data );

  // calculate var-long SHAKE-256 hash
  bytes mdshk256 = ack::shake256( byte_data, /*hash_len=*/16 );
```

# Building tests & examples
The library includes tests and an example [helloack](examples/helloack) smart contract. To configure `CMake` to build the example contract, define `-DACK_BUILD_EXAMPLES=ON`. To build the te configure `CMake` with `-DACK_BUILD_TESTS=ON`. Both options are enabled by default.

**Example config & build:**
```
1.) mkdir build
2.) cd build
3.) cmake -DACK_BUILD_EXAMPLES=ON -DACK_BUILD_TESTS=OFF ../
4.) make -j 4
```
## Testnet
The [examples/helloack](examples/helloack) smart contract is uploaded to the [Jungle 4](https://jungle4.eosq.eosnation.io/account/helloeosiock) testnet under the account `helloeosiock`.

# Disclaimer
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
