# EOSIO Cryptography Kits
Header only cryptography library for EOSIO smart contracts.
At the moment library implements RSA PKCS v1.5 signature verification algorithm and the Keccak hash algorithms: SHA3-256, SHA3-512, SHAKE-128 and SHAKE-256.

Library tries to optimize the execution of algorithms by minimizing the heap allocations to bare minimum. This is achieved by allocating most of the data on the stack and pass it around by pointers and references using [span](include/eosiock/span.hpp). Note that some parts of the underlying algorithm implementations are taken from other libraries and was not build by the authors of this library.

# Algorithms
## RSA PKCS v1.5 signature verification
The RSA PKCS v1.5 signature verification implementation tries to follow the *RFC 3447* [https://tools.ietf.org/html/rfc3447](https://tools.ietf.org/html/rfc3447). The underlying implementation for *modular exponentiation* math was borrowed from [U-Boot](https://github.com/u-boot/u-boot) C implementation. This implementation uses *Montgomery multiplication* which speeds up the computation of *modular exponentiation*. See [powm.h](include/eosiock/c/powm.h).

The [eosiock/rsa.hpp](include/eosiock/rsa.hpp) header file defines the RSA PKCS v1.5 signature verification functions for *SHA-1*, *SHA-256* and *SHA-512*:
- `verify_rsa_sha1` - checks if RSA signature is valid for the provided SHA-1 hash.
- `assert_rsa_sha1_signature` - fails transaction if RSA signature is not valid for the provided SHA-1 hash.
- `verify_rsa_sha256` - checks if RSA signature is valid for the provided SHA-256 hash.
- `assert_rsa_sha256_signature` - fails transaction if RSA signature is not valid for the provided SHA-256 hash.
- `verify_rsa_sha512` - checks if RSA signature is valid for the provided SHA-512 hash.
- `assert_rsa_sha512_signature` - fails transaction if RSA signature is not valid for the provided SHA-512 hash.

- `powm` - computes modular exponentiation

## Keccak hash algorithms
Library implements 4 Keccak hashing algorithms: SHA3-256, SHA3-512, SHAKE-128 and SHAKE-256. The underlying base implementation was copied from the original authors. The code is hosted at [https://github.com/XKCP/XKCP](https://github.com/XKCP/XKCP)
<br>The [eosiock/keccak.hpp](include/eosiock/keccak.hpp) header file defines those 4 hash algorithms:
- `sha3_256` - computes SHA3-256 hash
- `sha3_512` - computes SHA3-512 hash
- `sha3_512` - computes SHA3-512 hash
- `shake128_fixed` - computes SHAKE-128 hash of fixed size
- `shake128` - computes SHAKE-128 var-long hash
- `shake256_fixed` - computes SHAKE-256 hash of fixed size
- `shake256` - computes SHAKE-256 var-long hash

# Algorithm testing
The validity of algorithms was tested with some of FIPS 186-3 and FIPS 202 test vectors from the US National Institute of Standards and Technology - NIST.
<br>The tests can be found in [tests/rsa_test.hpp](tests/rsa_test.hpp) and [tests/keccak_test.hpp](tests/keccak_test.hpp) for Keccak algorithms. Tests can be compiled by configuring `cmake` with `-DEOSIO_CK_BUILD_TESTS=ON` (on by default).
<br><br>RSA FIPS 186-3: [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures)
<br>Keccak SHA-3 FIPS 202: [https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#sha3vsha3vss]( https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#sha3vsha3vss)

# Use in project
To use eosio.ck library in project it's best to make your project with [CMake](https://cmake.org/), and configure the project file to use external project. e.g.: via [FetchContent](https://cmake.org/cmake/help/latest/module/FetchContent.html) or copy the library folder to your project and point cmake to it with [add_subdirectory](https://cmake.org/cmake/help/latest/command/add_subdirectory.html). <br>If configured correctly you should be able to add `add_library(<your_project> eosio.ck)` to your cmake project and include the `eosio.ck` library in your code directly by stating: `#include <eosiock/eosiock.hpp>`.

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
The [examples/helloeosiock](examples/helloeosiock) smart contract is uploaded to the [Jungle 3](https://jungle3.bloks.io/account/helloeosiock) testnet and [CryptoKylin](https://kylin.eosq.eosnation.io/account/helloeosiock) testnet under the account `helloeosiock`.

# Disclaimer
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
