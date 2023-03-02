#include <eosio/eosio.hpp>
#include <ack/ack.hpp>

using namespace ack;

struct [[eosio::contract]] helloack : public eosio::contract {
    using eosio::contract::contract;

    /**
     * Action verifies RSA PKCS v1.5 SHA-1 signature.
     * Action fails if signature is invalid
     * @param pubkey - RSA public key
     * @param msg    - signed message
     * @param sig    - RSA PKCS v1.5 SHA-1 signature
    */
    [[eosio::action("rsasha1"), eosio::read_only]]
    void check_rsa_sha1(rsa_public_key_view pubkey, bytes_view msg, bytes_view sig);

    /**
     * Action verifies RSA PSS MGF1 SHA-1 signature.
     * Action fails if signature is invalid
     * @param pubkey - RSA-PSS public key
     * @param msg    - signed message
     * @param sig    - RSA-PSS MGF1 SHA-1 signature
    */
    [[eosio::action("rsapsssha1"), eosio::read_only]]
    void check_rsa_pss_sha1(rsa_pss_public_key_view pubkey, bytes_view msg, bytes_view sig);

    /**
     * Action verifies RSA PKCS v1.5 SHA-256 signature.
     * Action fails if signature is invalid
     * @param pubkey - RSA public key
     * @param msg    - signed message
     * @param sig    - RSA PKCS v1.5 SHA-256 signature
    */
    [[eosio::action("rsasha2"), eosio::read_only]]
    void check_rsa_sha256(rsa_public_key_view pubkey, bytes_view msg, bytes_view sig);

    /**
     * Action verifies RSA PSS MGF1 SHA-256 signature.
     * Action fails if signature is invalid
     * @param pubkey - RSA-PSS public key
     * @param msg    - signed message
     * @param sig    - RSA-PSS MGF1 SHA-256 signature
    */
    [[eosio::action("rsapsssha2"), eosio::read_only]]
    void check_rsa_pss_sha256(rsa_pss_public_key_view pubkey, bytes_view msg, bytes_view sig);

    /**
     * Action verifies RSA PKCS v1.5 SHA-512 signature.
     * Action fails if signature is invalid
     * @param pubkey - RSA public key
     * @param msg    - signed message
     * @param sig    - RSA PKCS v1.5 SHA-512 signature
    */
    [[eosio::action("rsasha512"), eosio::read_only]]
    void check_rsa_sha512(rsa_public_key_view pubkey, bytes_view msg, bytes_view sig);

    /**
     * Action verifies RSA PSS MGF1 SHA-512 signature.
     * Action fails if signature is invalid
     * @param pubkey - RSA-PSS public key
     * @param msg    - signed message
     * @param sig    - RSA PSS MGF1 SHA-512 signature
    */
    [[eosio::action("rsapsssha512"), eosio::read_only]]
    void check_rsa_pss_sha512(rsa_pss_public_key_view pubkey, bytes_view msg, bytes_view sig);

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
     * Benchmark action for testing verification of 1 RSA 2048 PSS MGF1 SHA-256 signature.
     */
    [[eosio::action("btrsapss2sha2"), eosio::read_only]]
    void bt_rsa_pss_2048_sha256();

    /**
     * Benchmark action for testing verification of 1 RSA 4096 PKCS v1.5 SHA-256 signature.
     */
    [[eosio::action("btrsa4ksha2"), eosio::read_only]]
    void bt_rsa_4096_sha256();

    /**
     * Benchmark action for testing verification of 1 RSA 4096 PSS MGF1 SHA-256 signature.
     */
    [[eosio::action("btrsapss4sha2"), eosio::read_only]]
    void bt_rsa_pss_4096_sha256();

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

    /**
     * Benchmark action for testing verification of 1 secp256k1 ECDSA signature.
     */
    [[eosio::action("btecck1"), eosio::read_only]]
    void bt_ecc_secp256k1_sha256();

    /**
     * Benchmark action for testing verification of 1 secp256r1 ECDSA signature.
     */
    [[eosio::action("bteccr1"), eosio::read_only]]
    void bt_ecc_secp256r1_sha256();
};
