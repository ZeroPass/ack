# Antelope Cryptography Kits
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![build](https://github.com/ZeroPass/antelope.ck/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/ZeroPass/antelope.ck/actions/workflows/build.yml)
[![tests](https://github.com/ZeroPass/antelope.ck/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/ZeroPass/antelope.ck/actions/workflows/tests.yml)

Header only cryptography library for [Antelope](https://github.com/antelopeIO)  smart contracts.
At the moment library implements RSA PKCS v1.5 signature verification algorithm and the Keccak hash algorithms: SHA3-256, SHA3-512, SHAKE-128 and SHAKE-256.

Library tries to optimize the execution of algorithms by minimizing the heap allocations to bare minimum. This is achieved by allocating most of the data on the stack and pass it around by pointers and references using `std::span`. Note that some parts of the underlying algorithm implementations are taken from other libraries and was not built by the authors of this library.

# Algorithms
## RSA PKCS#1 v1.5 & RSASSA-PSS signature verification
The implementation of RSA PKCS#1 v1.5 and RSASSA-PSS signature verification algorithms is following the *RFC 8017* [https://www.rfc-editor.org/rfc/rfc8017](https://www.rfc-editor.org/rfc/rfc8017). For RSASSA-PSS only MGF1 mask generation function is supported. The underlying implementation for *modular exponentiation* math was borrowed from [U-Boot](https://github.com/u-boot/u-boot) C implementation. This implementation uses *Montgomery multiplication* which speeds up the computation of *modular exponentiation*. See [powm.h](include/eosiock/c/powm.h).

The [eosiock/rsa.hpp](include/eosiock/rsa.hpp) header file defines the RSA PKCS v1.5 signature verification functions for *SHA-1*, *SHA-256* and *SHA-512*:
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
- `powm` - computes modular exponentiation for base and exponent over modulus

## Keccak hash algorithms
Library implements 4 Keccak hashing algorithms: SHA3-256, SHA3-512, SHAKE-128 and SHAKE-256. The underlying base implementation was copied from the original authors. The code is hosted at [https://github.com/XKCP/XKCP](https://github.com/XKCP/XKCP)
<br>The [eosiock/keccak.hpp](include/eosiock/keccak.hpp) header file defines those 4 hash algorithms:
- `sha3_256` - computes SHA3-256 hash
- `sha3_512` - computes SHA3-512 hash
- `shake128_fixed` - computes fixed size  SHAKE-128 hash
- `shake128` - computes var-long SHAKE-128 hash
- `shake256_fixed` - computes fixed size SHAKE-256 hash
- `shake256` - computes var-long SHAKE-256 hash

# Algorithm testing
The validity of algorithms was tested with some of FIPS 186-3 and FIPS 202 test vectors from the US National Institute of Standards and Technology - NIST. Additionally, validity of RSA signature verification algorithms was tested with testvectors from Google's project Wycheproof.
<br>The tests can be found in [tests/rsa_test.hpp](tests/rsa_test.hpp) and [tests/keccak_test.hpp](tests/keccak_test.hpp) for Keccak algorithms. Tests can be compiled by configuring `cmake` with `-DEOSIO_CK_BUILD_TESTS=ON` (on by default).
<br><br>RSA FIPS 186-3: [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures)
<br>Project Wycheproof: [https://github.com/google/wycheproof](https://github.com/google/wycheproof)
<br>Keccak SHA-3 FIPS 202: [https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#sha3vsha3vss]( https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#sha3vsha3vss)

# Use in project
To use antelope.ck library in your project it's best to use [CMake](https://cmake.org/), and configure the project to use the external `eosio.ck` project. e.g.: via [FetchContent](https://cmake.org/cmake/help/latest/module/FetchContent.html) or copy the library folder to your project and point cmake to it with [add_subdirectory](https://cmake.org/cmake/help/latest/command/add_subdirectory.html). <br>If configured correctly you should be able to add in your [CMake](https://cmake.org/) project `add_library(<your_project> eosio.ck)` and include the `antelope.ck` library in your code: `#include <eosiock/eosiock.hpp>`.

**Example:**
```cpp
  #include <eosiock/eosiock.hpp>

  // Verify RSA PKCS#1 v1.5 SHA-512 signature
  auto pubkey = rsa_public_key( ras_modulus, rsa_exponent ); // or rsa_public_key_view(...)
  auto md     = eosio::sha512( msg, msg_len );
  assert_rsa_sha512( pubkey, md, rsa_sig,
      "failed to verify RSA PKCS#1 v1.5 SHA-512 signature"
  );

  // or with verify function
  if ( !verify_rsa_sha512( pubkey, md, rsa_sig ) ) {
    // Do something...
  }

  // Verify RSASSA-PSS MGF1 SHA-256 signature
  auto pubkey = rsa_public_key( ras_modulus, rsa_exponent, pss_salt_len ); // or rsa_public_key_view(...)
  auto md     = eosio::sha256( msg, msg_len );
  assert_rsa_pss_sha256( pubkey, md, rsapss_sig,
      "Failed to verify RSASSA-PSS MGF1 SHA-256 signature"
  );

  // or with verify function
  if ( !verify_rsa_pss_sha256( pubkey, md, rsapss_sig ) ) {
    // Do something...
  }

  // Calculate SHA3-256
  eosio::checksum256 mdsh3 = sha3_256( byte_data );

  // Calculate fixed size SHAKE-128 hash
  eosio::checksum160 mdshk128 = shake128_fixed<20>( byte_data );

  // calculate var-long SHAKE-256 hash
  bytes mdshk256 = shake256( byte_data, /*hash_len=*/16 );
```

# Building tests & examples
The library includes tests and example [examples/helloeosiock](examples/helloeosiock) smart contract. To configure `cmake` to build example contract, define `-DEOSIO_CK_BUILD_EXAMPLES=ON`. For building tests configure `cmake` with `-DEOSIO_CK_BUILD_TESTS=ON`. Both options are enabled by default.

**Example config & build:**
```
1.) mkdir build
2.) cd build
3.) cmake -DEOSIO_CK_BUILD_EXAMPLES=ON -DEOSIO_CK_BUILD_TESTS=OFF ../
4.) make -j 4
```
## Testnet
The [examples/helloeosiock](examples/helloeosiock) smart contract is uploaded to the [Jungle 3](https://jungle3.bloks.io/account/helloeosiock) testnet, [Jungle 4](https://jungle4.eosq.eosnation.io/account/helloeosiock) and [CryptoKylin](https://kylin.eosq.eosnation.io/account/helloeosiock) testnet under the account `helloeosiock`.

# Disclaimer
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
