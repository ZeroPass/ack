#include <eosio/eosio.hpp>
#include <eosiock/rsa.hpp>

using namespace eosiock;

struct [[eosio::contract]] helloeosiock : public eosio::contract {
    using eosio::contract::contract;

    /**
     * Action verifies RSA PKCS v1.5 SHA-1 signature.
     * Action fails if signature is invalid
     * @param rsa_pubkey - RSA public key
     * @param msg        - signed message
     * @param sig        - signature
    */
    [[eosio::action("rsasha1"), eosio::read_only]]
    void check_rsa_sha1(rsa_public_key_view rsa_pubkey, bytes_view msg, bytes_view sig);

    /**
     * Action verifies RSA PKCS v1.5 SHA-256 signature.
     * Action fails if signature is invalid
     * @param rsa_pubkey - RSA public key
     * @param msg        - signed message
     * @param sig        - signature
    */
    [[eosio::action("rsasha2"), eosio::read_only]]
    void check_rsa_sha256(rsa_public_key_view rsa_pubkey, bytes_view msg, bytes_view sig);

    /**
     * Action verifies RSA PKCS v1.5 SHA-512 signature.
     * Action fails if signature is invalid
     * @param rsa_pubkey - RSA public key
     * @param msg        - signed message
     * @param sig        - signature
    */
    [[eosio::action("rsasha512"), eosio::read_only]]
    void check_rsa_sha512(rsa_public_key_view rsa_pubkey, bytes_view msg, bytes_view sig);

    /**
     * Benchmark action for testing verification of 1 RSA 1024 PKCS v1.5 SHA-1 signature.
     */
    [[eosio::action("btrsa1ksha1"), eosio::read_only]]
    void bt_rsa_1024_sha1();

    /**
     * Benchmark action for testing verification of 1 RSA 2048 PKCS v1.5 SHA-1 signature.
     */
    [[eosio::action("btrsa2ksha1"), eosio::read_only]]
    void bt_rsa_2048_sha1();

    /**
     * Benchmark action for testing verification of 1 RSA 1024 PKCS v1.5 SHA-256 signature.
     */
    [[eosio::action("btrsa1ksha2"), eosio::read_only]]
    void bt_rsa_1024_sha256();

    /**
     * Benchmark action for testing verification of 1 RSA 2048 PKCS v1.5 SHA-256 signature.
     */
    [[eosio::action("btrsa2ksha2"), eosio::read_only]]
    void bt_rsa_2048_sha256();

    /**
     * Benchmark action for testing verification of 1 RSA 4096 PKCS v1.5 SHA-256 signature.
     */
    [[eosio::action("btrsa4ksha2"), eosio::read_only]]
    void bt_rsa_4096_sha256();

    /**
     * Benchmark action for testing verification of 1 RSA 1024 PKCS v1.5 SHA-512 signature.
     */
    [[eosio::action("btrsa1ksha512"), eosio::read_only]]
    void bt_rsa_1024_sha512();

    /**
     * Benchmark action for testing verification of 1 RSA 2048 PKCS v1.5 SHA-512 signature.
     */
    [[eosio::action("btrsa2ksha512"), eosio::read_only]]
    void bt_rsa_2048_sha512();
};
