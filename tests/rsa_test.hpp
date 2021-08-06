#pragma once
#include <eosio/crypto.hpp>
#include <eosio/tester.hpp>

#include <eosiock/rsa.hpp>
#include <eosiock/utils.hpp>

#include "utils.hpp"

namespace eosiock::test {
    EOSIO_TEST_BEGIN(rsa_pkcs_1_5_sha1_test)
        // NIST FIPS 186-4 test vectors
        // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
        // CAVS 11.0
        // "SigVer PKCS#1 Ver 1.5" information
        // Combinations selected: Mod Size 1024 with SHA-1; Mod Size 2048 with SHA-1 ; Mod Size 3072 with SHA-1

        //[mod = 1024]
        auto n = "dd07f43534adefb5407cc163aacc7abe9f93cb749643eaec22a3ef16e77813d77df20e84a755088872fde21d3d3192f9a78d726ef3d0daa9d6bc19daf6822eb834fbf837ed03d0f84a7fc7709be382e880e77ba3ce3d91ca1cbf567fc2e62169843489188a128ec853079e7942e6590508ea2faab1cf87b860b21b9546442455"_hex;
        auto e = "fe3fa1"_hex;
        auto m = "98245960c6d4da684d9da2e78cf59d2a63ca53ac39740c9f44e837c9042e0c911115715a17251a0f1fd5f5ff10fec5ec75900c5e80842f3d4f11d59f6f2390df9f09bfefd66db3ef878a10fe23997650e08c6180b9ff4e28b56c20b06d9ec163c8680cc80a96eb2f0d24bc8acdaefa7e2b2819baeacfb188fe5fdfa10687e946"_hex;
        auto s = "1ea751e8c5329879a9003f529eba19514c153ee0bdd8caac9c94fbbf95a41ebdb9ad54a976bc1218a94b53e69cf3362b0472a8781b8df4af3e9aa584099c71f9622a6fcc3fd3935b033f68c1c970676eb6d2184056f1b524acec26c51df6dbe9bf3b4e1fc144b8edf563a03f28ad78d457485b4a57ed0ce81e409245f5ce1014"_hex;
        auto r = false; // Result = F
        auto d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA-1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA-1 signature verification failed"
            );
        })

        e = "fe3fa1"_hex;
        m = "d7eabc57c2803382d1deb56a146767ac80c89183382e01990bb5aa1d3d2391168ad6eaf768fb7d738d014f92b14d7f0595306eb7441622a49800edee0134492d82320707fceba902af2e0c95fe634a85727bde6f022709a09248752db9a71941c7e75cb107b87dd6414d329b830f8fd521932ad3fbc97d36fe778b03eee6c7f7"_hex;
        s = "9dac630d264a6a53cb81a6901ac0baabfb24d73b60ad3a4ed3a0eb98a2118a573c3cfe294178fbee63da7c27c5826fa5e6d1682eb254da53a961ba4473672f57a27aec22d4b205f79819ab4cb18b0f3842684bbdeca71cfcbc30d1866d22c9f1fa9dbe9e1a2f5f6f68fd4fff6909fd2c1a9904204a3cfa30da4c87de35a769a9"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "fe3fa1"_hex;
        m = "73ef115a1dec6d91e1aa51c5e11708ead45b2419fb0313d9565ff39e1928a78f5a662b8c0c91247030f7bc934a5dac9412e99a556d40a6469beb40e7b2ff3c884bfd28537bf7dd8d05f45419cd96bb3e90fac8aad3e04eb6190c0eeb59eccfc5af7ab1b85264be71c66ac25e53085c70b5565620152c32b0388905b3f73689cf"_hex;
        s = "25493b7d70cc07e9269a248632c2c89c8514fe8298ed84319ec664f01db980e24bbb59eea5867316792fec36cbe9ee9d3c69346b992377f35c08d19de0d6dd37482074cf5d3c5cd2b54d09a3ed296187f4ee5b30926a7aa794c88a2c0f9d09f721436e5a9bd4fef62e20e43095faee7f5f1e6ce87705c27aa5cdb08d50bd2cf0"_hex;
        r = true; // Result = P
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA1 signature" );

        e = "fe3fa1"_hex;
        m = "de4dc041a283c488187ef9b75e701ab0a25d6ab6e5cf9cc702ccf02cec05a04e37507acbda58cec933938a8b4b75a4425ce4b82590ebf3c30cb22f982dae5fdf11152ea85a95e32a2e45885a82dc4bbd9921247ac7a2b8b37ba97e157d6c20ae738424ffaaa0cb53137b394f8c0bd7c961fcf6de135cb53e589824cb62a7a963"_hex;
        s = "1cbd45327f5bb1f7a86758ec9125d28cfbcc235fe18269442ea9bb9491241088c20b2652c00dfb08ed0f0002b7c6eabd5299174bcd42f96171cec53d9cee01fb52ebfee08089feaa4fc6e1da5dcf57d123da6a964f6d610e37af8a57ad31857eda5ebbbadafc6e02bf8f326fc4f853734b25cd56fed04ff647d50c3127fa35ed"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "d20835"_hex;
        m = "c2721310ab955a702b78c23fe70032172922593c30ec9fc4cbc55bfb26f54605e36830c56caef1fe8847a3b82d1e0ee696536445943d2f8729b087b1537b88c2263503951d3a7408b2f0345e2c4ff0e2b9a05acdbc841e6a683918788e19c4d0b363f648663ecbd6d1fbdff98d9bc054bb91a39c50c956b5b0e876187fd6e278"_hex;
        s = "4efb676a7f2214898257240803890a42c5b2e746928bcded262af27b68cf38d364ed7d5989ea93bfa8b5194d53708120864bd78367cb14dd76e2f983ee9190fca55468922cb3a7bfea38dffb704e81cb9bfba6a2b1b6c5af6814a812ac53befffa170a1e3f70e969078a9fe9bec58cc4c2d7891171949ce8c7cf20478b4ac1f0"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "fe3fa1"_hex;
        m = "43226431830fd187e5fd0ff94bd3b4d1ab40074e12ac1d3ee96e42cf783f9ba3a8ee09220d564f14238e786fd85f736d4bfb01e2d4ebd1cd444ae82d6e314716e672c80308894a6e3ccf0d9e79f15fc108a1793a8b8ba43c3d8ba0987b1d45d384156b7c7d9008bcb82a982f3571c2f2699a38fe3f73dfb45d9930b8a8ebde03"_hex;
        s = "34ba929fd60fa28dbe9f60c08d6b55cce37e888ac2adc9b714e5796a7a600e95449e70bac5814e3f6826df7b23512d17e343e62881c1a96970b254bf26503b0853ae509e39421c94ff844cb65683f84200acac3e759f191fdee7d65969b72873c77d1e13ffb13153940120ce5cbe2076675e844d6f7588a9ac129cbbcfaff3a3"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        n = "931a92071b310602a55840b8c0aea51e3562513e81010e1b93374cf4bbc50cdd94fa1dcb8d8b609e5dbea182c052e06d2a1c454755d9a279092221dc52d132e55ebe7234728a7692763636845a122e8752a319c5cf5065fb7c576460996bfe1e1b4fd319ed11400df2e6a18461f1a39c83996fe6886ed41be89cbcde6c764fe9"_hex;
        e = "a71a21"_hex;
        m = "85254daa44d5ba337cf350e0679f416ed930168fd179ea484d4cd698633dac5a8ea8e86c46f6e311d31b4a946263cf2f596f1e2ae87a1347e0e22a5ec9e337452fa557f23c7926e48c5f32bf3ccdb03644ab6e2d07a2091f299660bea17148da0f2382844fe7ea734ec7f0a71c624c4b43edeee058783498cf726000137049e2"_hex;
        s = "6f47d4d0ef70bbc71de2d6a88e044c6920dd81b030e8cb2e422a25101997e4186d00ca17bb6520b6d92075c7ab58ab84c7f4658bd955de37327817e18c3142ea6222b240b260489ea4008227de13b0c078f83909dd65852bfaa01bc9dc7e64ce80f35503fa9badde585652c9cd0fab0e73066d83ff9f343d4137778e3c09a58e"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "a71a21"_hex;
        m = "be5e8dae6e3a61370324e23ba572996d4c0d6288d32c21355162b12fa6db1da554e313e091a795259a40f2dd49edf5f3eaa05c7e4bbd8ba0121e82ad535a0d9062473a6be6bd107e2f9d7e4aca1292f65217ecf1883a71d9a69f449cf147f2dd8e92ec9996033b0a6d446fcb4f6ad83e2b79f92bb52b3aa9b7eddd42a72b3352"_hex;
        s = "206f738f2df12a70b0a1f5670be0c9c0341a1931d8fdd9491268a08bb42ca8dee88571f140bb7d4abc60f82fd284319e06b44aa9e384ba4c38b9a427e44013a2eed009e196a840f357cafd47485a978b7050342a46df3c4840ee4c56b2dbe605e555a3e7f6045d163f0641b6dd1da51a48c1e497d24db15f3b1a959438e18fd5"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "a71a21"_hex;
        m = "544c1e697305e865ac0c00da5c17d1d369449101d55c741993581f7799245f0736a41b65a6f58743e4f59b0cbf05c4c6300dd93debc1505e3423b2e1f4494c2b0c612872e9f23b225865e07f9cc3858cbfc0a42c25f9f688677ae3b05e833c857d8c2cd664866cc9b364b77d1cda7eedbd64dc18ac8bcc5fd3649a2efe5997de"_hex;
        s = "73d0492938b07e39e4f611ee7f50d4558537dab9ede3f44b49448d88e447ae07790f969ad8f15c327b540486135cdb6e0a9725eaab5e343b64700233edd13c43cdb25cbc2f5311558152af4b2818be52ccb8cd0ed4ec475e7ff75dc7d56dc999b3d15b319d76c5dc6f690ff977407c1789e9531941062881b6ecfebb6dbfad2b"_hex;
        r = true; // Result = P
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA1 signature" );

        e = "597bdf"_hex;
        m = "c18b5b1847b7e397c39a6f90402aefc1d727f11418f31f17aca308ac3956230286c510c3e01c228fbc091baa9d1236f1382b6b13d688eefdfbb0f99645d3cbad965df12f76cbc49eb2bd33be494dc29289a0d38676ba24ee6b979aaf04773d3c3a7983c5d06bd1abefe13f360d849c8a13adb2d7be33cad1458173603deb8098"_hex;
        s = "0e68bca9c9d1332ece050f6ca2cf697b7b00a3aef4f3925dcc34449be05ea7a732165abfbf808e0431d6266d4d24595b94b3921c877105c6dbea351de2047b8e7373f775958ca0e09a7da0fc0c74638d3d2b42a5fdf557d47039a0d3092304627fd2537f907876180a8ac3b4d6182fc8b515b3a12f3601ba002ec59ea0072115"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "a71a21"_hex;
        m = "992fe15e5f63f165df61ba064f593894c4db4fbc489974682d6fabe4a1a0b13f82637af5739edeca2ff18ff91df64e8e25c75e11c3c13964598883eeca4b3cfa444a39595d95d54f6216e4adebd1e83ab36b8857a7e93de33dbb4f5d07f9004888ec06d446d03fba20d8a168e273705e17ceb3d81f9ae8ad810ff777823165f4"_hex;
        s = "233ae74861a1c0db26a07165eef66954400a4aaf2f12a4f0b66ba5ac0549669c6688d5b35f1e5b1f8ee054dcfb87d3ffcf55ee5c3df6753f1cf838a109370f1709b1c77f6a8a5189c0eed565f930c01a6630dd35130cffd12ec4a02848d77f5a8661f42e087277382a36e504293492dfa8a689ff35d95343effe0baa9a9a090d"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "a71a21"_hex;
        m = "ae004a585df79c01bff18adc7fffb88ff91c020e9e0208119a43eac4b59450c0776cae3a90cec67a77626e8f50cb934213357e48eb2d56bcdcb6e6cca999a1b2f5fce3e6a8367a9194e265455932dbec858790ff003e33f9a8cc3b0a380de30f6ed973c26dd9c22e6098f96760dd99779839c09ba6dca8b045ac70e829991fc1"_hex;
        s = "3d954f484b59c38ef3103aa65ef334c81d8f4619f55148c2d95f5d23730cf6764accdac01405ab16ac53db30c4c00d62b2a34bd6fdb480b05e72ab02fe0bffb2d67d17f99275cb9ff17d87a1a78ee3531cd5221af5052e3e67b01e9c28e52bd99460ff28a40f618f3c7da8452f3c8172886b7350435dfe64e399e5483c540156"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        n = "eb3b1cbf5b0e88bd44b8575e6b40b618103dcb9a51d36e83baf5bf1ab6c0e4261c12664bc1a4d2216820e2dba9ff7c98b23b58ee86e738e0633dc916477e94be2fb8acf19f532842dbb2eb7911f8f7d884ce022395967e4442396e3618f875c856c73f6b89127646df29ff9971c0358fbda0a7673cc08c3f3f26d71411712a53"_hex;
        e = "6ff82f"_hex;
        m = "caa67650963439fbee5e64bb2f5f5a34f7a9d110ddcb2bfe609803fa1e8606d0475404db50f04613ec972347383ecea6353172847cfa815b2d8449102980c8788108c11b2e820f3802c83a09de86484726e3d5f17263664a860bfb2185c7e354610ad49796b43b721838d18989fe6f20b00623de27cf83d1537741b39923006c"_hex;
        s = "dec7ad8721af589e22dda67098a77fc1b5dd0216dfb77caa5d71bfd6ae256b49dcd20066694d6c4f7b20b355d8eabcaa92a8d91e077fb0241a62be5e34bc1e577a5fea84af6903dfe94fef4d626709ce5d7abe4b1ce420312f928e00c0f62a4f99409ee3f11efcdd5e390ff2b69af600c9b5738915beae3b7f6d3cce8af4bad0"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "6ff82f"_hex;
        m = "1ac33b15b4837e06f6be09f4c0e066cf9766f1154cf1988edb99e0399383288677b632c5e52adfdf75223a4424bcb824b2c7bfe248d464c65e9079f2dc51c7977fee98687fd4794f6f563d5f6445450b59c1ff95d24eadc9c02b68eaa5df64edf81475e5cba8d2bfab021a2fc8a294ea56fcbb163287fafec911b40b365587f0"_hex;
        s = "1ea5f7437790531ab98e5bc93bffd187c1d5a25ec93cb35c02ac5f96b188483fb593ccbb27a4bd9c335657aaf4d5bcaac7c10c7943e4bb4aa66776d35bba92307564cfc7709049b7c9b59e4cce3c6c6cddcbd28d14a0d91afe6439cedc65bca893e6d4347100296cf5b37b889eeb0512121dcdc0ccdc8c10d9215260028be3c4"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "6ff82f"_hex;
        m = "0c5b2ceeb622c694a8e3feba0d6a802b19713107f7c2c20b029b8612375680dcea49c10fb9ecf17bbf392ba20a590e784e7c1067da091696ccf7426b817a0c4f50e395b178c1374d564d61aedc05a2f13e9603cdeeff9ad0cbf45ceb96803331a5ef51dcdbebc391d7e549e56cb7651f5187b23f1aee774067597c9b5cb01c0c"_hex;
        s = "cb554ca80e9c492edd709f35092850a63ee94cd42740397a19cbeadc30306169d47db14b8225e0115437b25c2e2194af74636888a6995d4fbd574c3f3e0ac5896e9864c702019d5f19ae4bf1a5dd3d0f23ba9b0a40b7ab49bf95779cbde4533f81469ee9da651e913bdb62e75c1f166a61a45712d2210cf1267444558710c8d2"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "6ff82f"_hex;
        m = "cc8e2868722310fb117ca3a52e1839eb85d308b8aa00ed0bf0b76aec8a70eba4f0d14d2d85c5a0e876ce2c8ee59cb36947def6c40a587aa07b368ca8e8a08367018e45b984de0d7f1aa46b977cc18c0cd9b7bb897cbb2814aa0ce8f8c9843e03c86c19f2ba95dd2ac4a466a93aae4b3b05055ff148517ecf43e286c57744a3e1"_hex;
        s = "44263cea7850a2bd4204388df7a14cabbd0bc9f600c3a166d5ab003fc934963165dcb890c90c59eee6893f89fa98b4e162650ce853724e240ff642b68631fc2372a76dd72babe88954bacb6279fd3c92e63115869fcc6e7b6bd95116f9452878508b441227342d99f108dcb8b3408c0f2c49636ebf96e49d7a5b89ce84565243"_hex;
        r = true; // Result = P
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA1 signature" );

        e = "6ff82f"_hex;
        m = "f2f47bb35772361b88df3595fb27bd1c4bc66da330e8d159afcf332a8e76b4890b749c6dce22ef991b0041214c55ca2a7f16bdf18c09d60f3a2a32fbb24e64d03306c55008c60b29b7471e787c29278cf5dde9ec1fc2549b818e579aa7f0f7afd2749e65eea6b554c47a74a271ebf9ca17e3989cd25b7386eec34a1157a494ae"_hex;
        s = "c57b082915a8946942059dff585c079a5574f665aa7962eb6c51b8abbc78aaabc40904586bababfa5a9e98030f46db40e7b06320cbb924a16e886b963222c7ace2bec5dfce87964f22e07150124166e58f62e53cba5f6466c6e56caa71be4b5039cf16a43d414e40a56007e86ec995d923db42fb9ec1054cc1f1e4deae73ea81"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "8aebdf"_hex;
        m = "032daa37ba23c04da51121e7e470f7d21c1c377e0ea0d75f6fb43b93f304f0c5ac339c51922035a9636872f7ad2c7f042814f5584a9309a3166d045b3577f3a7479e9f7c7b2bbf055d466d49f0b8d708fdf537e5aa5905cb4eb26a8984fff9bf7f779afe9dcdc62b3eb3fa24d69d65a641c7e46f5779319fc18a58640b236ad6"_hex;
        s = "cc71562cb955efc4a5bd0239f688e8828d2268278cd8763761b1274386f7520cd54d229e1ca4799d7efcb6c3e908307ea9233198b148c3e4ece724b9a769abdbe26685238c6ee88299b24c52337eb8c4753d0af63d3163d17093e4da9caa4181f22f1ca36063f8aaf82ea2735fb7d9f0ac161a33e64a7fc89f68c29fcd3a8c89"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        //[mod = 2048]
        n = "ddc1676352ca011a235db9b4bb41eab81a9f3447a34c3626a531e3319665edd9c9e269788323ac7f2db36b9106f4b2148b7c7a309a0b7482ff08cc97c792bf8e2319f42aa51078a29a4ff90c0e29563059a8608e8809a04bf45f1334b23631d99253ba230dc640ffc3a70c27ce5fc7ebd1adfe68e4462790007b39f5d5b47dd9bd04d0d08ac3b586fd6cc8e178d52ecbc09434d4b89d83cadef6c53cce17788e87b551aa0b507893f308e23da919a4aa01183ddc831a99a3e3c4e5bffdc7e8c8b6800699abdf11569ba66e5892b2e55c6f8578a12f5e304dc28ffbd5ee2dfd2bafabac77ba67031f588e73cf7ba344396d166f5392ad36187b45e15916aaf5b7"_hex;
        e = "748d77"_hex;
        m = "9e7d8a94561c95facc082974fcdbcb813e1b37fdcbb1013a7d9c7c53d6e6dbbd44d7961fa36a106404fd760ead4ceacd61a0e150e144c95bb239f01a212aa1b585a29024c47d7745189d022b13dee9b9e14b5b70ce92a38607b50638a503ea61e7473e4abf3f15c4914f947437770f6f48836f079a81d7e4057887566a5700e9"_hex;
        s = "cd0a22729f6a2eb4c7bd6c1ebcb9510ba1aa6e8921109d7c1fff6f7cfc36691b69e89656b9d7cead82356efd740faeddb0e3cba5a98656b841f2e98d296b995b758074fbd97af3baa4b28e9df89e9246eed76ae3eca1bd213a81b5d15411dff648b887a8835fa2f7bb2f78be5c4be8dfb1ef0d6b08319685edc437e56da3c8a532ec8c7382f74859530eef7adffa68ede91e3fe4bd29f43bc8ff813fec7d0a15aee6de202e4f32fbce4621807cfab47bc395ac10368d931bd73a86d40a38cfa898668cf76f0f4eff32223c0e452132c36b2c16f228286abe0f3fd4f0eb73e5ad989ca19872097948c6152320daed43bc2a98c3468a610d13ca086bd8ea89bbce"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "748d77"_hex;
        m = "2dc3fc128057e1c291f9b55ace78d9473dcd3560a7ac7d1bfc59b301f3bdee5ff1b9593f2cba7e96108ec5bfe2763728a37c884c370655e1c6acaa526347c76feb4a24643056b2e7570864b67f16ee41a49acda3c2ad87d73d38342980073deae41f6468d452041e30109a27ee8085f907cf0a4f91c99b6728a6596e9326d739"_hex;
        s = "bb75bbdbaea3269a01bd9b5e492178b7ec11abfb59d417cd5cdabb8a4b922b0f21ae69e9da7a9f628c9cf396bfeb75c836bf734561e68e91fbefeaf0f57f261c936bef741527187a5315dbf584f332fe3ed8a44367688e28998675c31f2b1cc3fa87faa4abcadff5fc64025c9589149e41c45a5037fe1c27d320d5a40ab6119b639ba052ad1d8a0339fd3a03f1356bcbc056c4f604862df36b66685feccfe5f93f2fe0c957a02e8d41a574ab0e56d8672d338de761fc9e9a1b801ac5dbd56c1592efa77f782d1dce3531efa5c7f569ddc313f5dce62466ddf269bd5b780f7c7c68b5232e1f77f7b4a8eef8a978eeb56d691c3e4a95965867c61d3c8e7badda1f"_hex;
        r = true; // Result = P
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA1 signature" );

        e = "748d77"_hex;
        m = "02e74a1d1d61bc6c856a20fecdd64c6a011542b3e7629c1c843e2d3ee21de557115ff5e56c8134741d95c1b4e4efeace14224df8de2b3d48d1eb68c5a2dbb6c429fb7472ad0bb1ad61fee8182eace06eb3c7d1168b10c8f8ceca4c90da6f424053a30eeb6866fbbf588ddd523573f5f1e9ec1435767a03d682c423c412435174"_hex;
        s = "7aaab14a1a89468ab4b583a8ad03df515e5d34b0c36eeabff6c4532385d448ce99e4ba35c927751cd499fe3080e004a903afe833667965fbd2d97f8a4b617f805ec88bba1133c5c304e2183797887db331a597d1e5f673264f6fcce750b504ed24fc066af248833d42cee935779bcfa02b73dcd29254b4dcbe831b70c289f6998884bd216f320e4615fec8181d17654b7201b62e8610e69dbd8cbad6de1a5cc1b4619b2680e7ddc27c02a9b8dde6efecf0f6c4551bd38b46f10e78692887bfae9cde1cca4e33733797144c6cded6b58cde54c5b877e5d10d4775200c0f4eff5ccde7a42788ac22f762411da48826b670297f2b07435d61a31e063ec1a2791a32"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "748d77"_hex;
        m = "4b4f319b5c8c53e7a4749c4ee58b0b25365a96da57721b2044af994c0abaa0ffdad106065ccbdc7e4556a03c2c84b46c9a860f7760b7332b2ddc5f165fa905321a887ec89797fd8ebfefc212f92c905c402a60cf780c57510283f6ac8e4d913330fb02a8b7f89e5d3ac7689af38c853f50cef0aa487b6fdbec2cc6d63eab2a49"_hex;
        s = "1ee9549fc8cf651a593e8c4516cb1b3d58099e6334b2b35c5da1e1c549e4a7769e92d51b52f622d5da43f8778c0e0f860f7e3a02268ab7a64523c0eddfd7db7941896a67bb33895d577be6c8c86af72d4e2feb5968eb2f04e462a2ed9e648c36c2d6667832a640d393fc11494a7379fb4fd6f0bff27718d8c9cfe0c9f2dd82472dbb6b751a5398be3f9aa67919461efa7bac3c6d5fc42b2149acdf29f8a30a98ac89a6a48833a3b2658111094372616986479256617247e60d95bf797b503d0dfc61b6336beed318d36e9f3575454cae1df787ff7f163f40598694ac891e09f743e02f442a1ab5ce1148cb66fde982ccb8ec945e59c57cfd5747cd5de5f3bf12"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "8ffac3"_hex;
        m = "f62e0e07bb71ca7f93736ce1d2c29a4fe7a5c8769955a364916ab09a19943063238b48648d495e73a376c6ade6249ec20cbcf69447383501ca93b7fc8a7ebbe341557d0cb9519fa247ffcdaf95f1a179a5b3c4121300572b9b369129da08a97b5973f62ac7f355b186f6cb106a916b1cbd727a198616d28a0a3c84489499c1d2"_hex;
        s = "66b378c5fa44c443f0ec885d55dc877612246703342fc8ef38a98c26325e52b9772f30d29f4a23b67153cdab1f84a615208ef809d84be83c57cce32ec9f9dd07a64af14f964c73d5a8f9fbafc07a68dd046cfed8e1c54c6fed3a4bb7c9ec153b64bb6c1591f1f78f834c44153da1dafbaaa9d44b8406108d70577ea8497b33aa09c5f2b63906949f1ac098d34c82a80a37d2f4164ea88bcaa30ead54f3b0391485a8eba084de3be452de37dc52d278d757c70c1b75bc1ce7c1441b0cfed2ec5e045bd77e732715c593e2a3b21ad81f7f92b6eb9ab23f84cfbdadfc89c75dd4474e752bcf479805f2b4fc5b953e2aa82b72044fb865cc93124096c14e0a645947"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "748d77"_hex;
        m = "60c3a8bb6b10b30395cb1a4b8faf39cabe5cc3b79057b769115390bdb9afbdb8883f506d564ffa2164e537ae3647c625a5bd5cb7309899d693733b979bb9925b386834aed414f16fe32e0932bb869de2a60f64ab36e29f16d9864f76ad6fa58496c4ba468d6680353b2df99ec675a649ebd943594d3eb1730c1434229ad8de7a"_hex;
        s = "5d36b5e092060e763963b87b41b027a1356a1d5068c8ddee205f0b012c27d6906e75ec2fa93cb840d69ff3c149653802659ef116c7d740afd3c4050193cb488493a9bf1025ff3918ffdb073e5b2f705eb771e1e7c91dbb9a9e18b1a36951d60671e25e4042776ca265bbba032b1dd5aae000737c49583450e072c4571ece1b5af9403bec0ee4eeb1e14165c8df6d2eeb93f10ba3dbcb9ff92abc2773d044560fa162e9e5b7f6915184e6ff3548df75ef7fdc8f2c869edbcb1b4a6598fd1acaa394f501eefc3fe5e6945f4143509d6cf8b4c8418e4f26f53400fc50d00cc4491ad16b58785fcc6f123d52b482764225f66998b3abc3b3e2d5e8741f3170ecc574"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        n = "8cff9858fa12773ef90c10e8f142f69c0350772f999ff10ba2a5ec71cbee037f3a78a1c46028150a0004fd0198bb8175fa30fd9765a4e2c679124ded055cd37d4102b5e695d91b58bbb44e72c136c5e3da43b4e6d5604edc36774c353a729bb1647f4a33d74ccb70f7b003617bab798887b8f65cbe11aa8349dbfc0f5036042d6cd4c49b10634fdd9d9cbf61d9f85c94ae98cbf77172c61696434ebc2ac6ae8f678f0e4029eacc8fb1699916bdce026cd94780de58a707659ff650dae7599b6b1b6337323832b45a4ede37fba87051658e79248fcebde7c36009954919c87f836a2084d88f5237f72f4d208412e91ff6f3252574df7c00334a0fcf8fcc7ecc2b"_hex;
        e = "0b8f69"_hex;
        m = "3ac87eafcf45920e233638ed4caa54765db4b801dd143ad978130943f5af41bc68f8bc83a9ba2c57045c668232080116880d20776f818c19142a068b619fdbb52baab85eadf1c0f135d5dc801d9b5209fdc99af81fd36dee33f71ec144662dc4eba41a48c33177621c6941eff4a970d623b3cd8dd55404df3d44faec884d6071"_hex;
        s = "80ab1f8e28c9f939a7a15a6f81b41547e8497b5ba2dd08333243352e9d7aa347dcde6200a5e1cfc8136d3c59999ee571347c8a48d91e185d0b08ca31c8ea83d578f0fea6ad38c820d68b10221d493ea93e065fd846340ae09b94c6dcb78cffc79b958540689455734a9adebbbe50bed6e998e957079d11812bc2b4b497f9b9fc1496a639e021337d86c4df2bae4a065fe69e517655a571369a4454a1e29370689f8866375fad63075ef189f0ec3b686b5f3f02ae84c99ea67701d6906ad867d0dabef4f210e533d7daceda12ee0ad2a6826178503ae472f278b7f25d51c1fe8ef4b3d61da0928f4d7315abb27e570ec36fbdfbb4e3158e29b4605e1b082e56ef"_hex;
        r = true; // Result = P
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA1 signature" );

        e = "0b8f69"_hex;
        m = "e88292f68268095c2d1059d6c671ee2cc3bc8734748f97a2896ceb22d56b8ea4512beaf7640e2f9a61a6f9cf526a2df0f4ae230602d20b98b6b989c18e7ca3854c60dd654006a231c9e2e61e1aee0a193aa0005a4e19af3b1b9f994bc74dbb9edf09b4689fb72aca6dac6aeca6664e4c9d7a6456e1cd4c34bf0762e708459e97"_hex;
        s = "4b40e154df4538c2de6fc13cd93522acb23305b40890ae9e9ef33df58d0d1ada511346126fcd55fca4206bf3bf988c2967ade215538b818303596ffc33d4ae05ffb321ff303fa9a2b87b5467723dd1e036633398e15d9abe62d9f7528b1f31f3ad6ab70fd5af6029da4a961d006d7ff0f6b7e2f9181fdc47ed5fe0f74802e9d63249bd394bd6b570187dadb42a1ebb38bf1c78ba5b57c0a97ae29a6c9f8680b493a44c4909790143aaf12152d56df38864a36231f558c624077a00ef3619c58f7ebad4cdf706c4b2a47c6525c76b78f5473b57a0802432dcc67230fce82c87e41282b7e8f9855bf72f0770dd6be3f7fd260a435d51c1f2323257b507f97a7c38"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "d0d14f"_hex;
        m = "3853cd6d1384358712da7c1c583afee73fea00ee4aaf41be5c32d2f827a8280ce6b270454f822206c340d953c9ac6292ba041293be285dcff6fca5edfb0e508b88791d3a7309b8cae29f8cc9bbd7d8465ce905da8dcd37eab2a3222646511f55846e7e55675f1e5dd5bf3c861705898a8d607fcba0e6f497f7eef0aaeebabcf4"_hex;
        s = "55dd7641ead751bc1b160724dd86e89497764119a998d5f800f97defe942aedc5cd2c8413918ac107a705dab99bdb182037f051b61932fd4d41f0a890f6db996cf99d210084536e3711653ab4ee5ce5b066a569306983c2f5b6c00c51fa49774f33c13565b95e832588ad2c004b81887c3df340096920908979e6f168c8818062cb04391f5649869e35efe762628f49d6751b7a3e0b184e9f935f591e4f2a1db158cb78f8e256c74c294ff424bc2efd3145cb234af88c623afa67b3eae68b91dc16a99ca36fca81653aa3ea47338c5a5a2a5b2340cff80672767f6e9549c6adebe6a84a4232560ad431a5f42a3ded809fda302ea7ce944ea3e7be7853704e1ea"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "0b8f69"_hex;
        m = "fefde998a5de015f63b0a75ce7f79f4dc681d18dc298aae64b7cbfa74610b3f70ed35b69b81221d19c5ca6551037acc7771132327b79e0b2968fa689d7b9a170e3983e2b3a3ba160bb9248a96b25ebe87205a7db66035cf0cc21545adc4625648536d805b1c04ab5ca3ad3807d2a2659be4678b00c9fe547f6190f41de1e087c"_hex;
        s = "17a01e1254dc902e8c6d607226175416c17ea28d28696b20706790dbac60f73732c804b6756df87ce6b1baceb22d582a6e24bf3d1754ccf1ca57e06150e6da60bcb8b116b3b8a31a715e0872b6047c6a4d7f6817ef5f12d13356b2b50fd71f5d9a38a0c35072ca38beed29ba541557b0525fd3d6639661037b5b61bee51aaf4e6c6bf5c577f9dee4811319d671911138050c54bc273db9eed5a7bde3281e65942cbddbf909e87587c58c8d40c081c81950f73a33d80bea61a56ee4a8930ac3b954d4a0706aaf3c753efd304946f90f33a20cfde65e388c266bad024cb1aea8879c78fd0d9bfddaceeb84f10ab66cfce1aa4f0651d7b1f0b4ee808a2e1f490ead"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "0b8f69"_hex;
        m = "c0b2621f30115b296d84c7d4e015981a24435e1877a660cc6cd6ec1de088eb1b2efab889a79233993cc211f67e2e7607c911c573bbdcb7e0eb21aa01d8b03ccf20001916f3d01134c60d6e1d4cf784a3a28089f5caf4a7655adf506e752cd2f5fb8a2bcffd141e847430865232b7eb75185753a68a365ae220d8856c9e43d415"_hex;
        s = "368416eab883a2643e5288ad1d97887941e6a42a54a44336f12336cab4038e693f98ebe3df7378fd501ec9c7f267d6f8fafebc5340744a436d99647b19df668169849032b852df30da848e4605015aa0a9ce39c9ae25368c0575e7957273639d957b392e3556742bc5d0214c4cb82e3d342d3a73f72b7184b72b2ae2225ee830b1ddc528460046d83526c6d07b2bb89d4593b459f248eec995442e4aaad368dc0d3a10907ee779eb23c8a60df52fa461ea99e47e8cea7b761a02bdf81d43e4a7a44992d1317211607e099141de07ea034e95995ae52ebbccd38d0964e3fb4756dd6d57fb01dcc44b6d89852bcc605dabe36398e53029f4397dffef3ece22b939"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "0b8f69"_hex;
        m = "84ada4599f0bc0a41db787310f53a1588282b8669ba82e89e7f20fecec974422045d0ac86b5ea366960c4b97c6736e6adebe180771fdad962025da5c2358cb2725679fed559619b0ba9f98a4c6f949942f599b82fa7af38ed91aa219b645142990d5490f863a8948317754a2376d999f1d5c281e5da76838b9d74d69cee385f0"_hex;
        s = "8286a2139ece519ecdf8aebc2db2427c207100212008dd27b1058bf46db2a477ff55bde9f0d02cbc3d93b6a97361bcbb3aad990ee9d255c58a96bd7108311d3d9276247f274d5a0dc9e6e411ff389de34cb693b273b5da7bcaafa101a5fb6ef42fdd6288ff6b6868291ca914f564c75fcad55d7c2ca3bb5da2abe02a3d589686f79c4bbf24876cdba03ffabaab32395245d72051c4aef965c0c18ee7ae1d19d8c179086f6c0495df64c44b618d5e9d07f20e051ac360fd6a84e87f7f7a777059d0ea3eb21a11de8cbc22724944c71cef002b612278ade389530486df058cc5459c20dfd4e9695c04bce91dac8a1ec79f43f80c0d691a1cfd1a7204af2a7a1a96"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        n = "ca1d2f73de2f586157f15beb1ab7c3cf7b8d99ed818cb89eedd10ce20fa3cdf12c41bf04ed06769b7f78fe493a2d17acd5fee9c147d4944c9df3a6a99e5b4cd0d4e6392733806998a05f546a046a6767d79f23e627dbada0404f2b7dff2e17a5bc537bd8efbe0b87e50f5a4645e4a0dea8a2799d48dc110daaeef895db6d6244627d45cb382bfe394d94cd122f8ad73d3c0ec0946669938c1204f940dafc4cbaa95a91d55ae84264390590dbce3b9bf7a6a085444906c774877ae3a67b1a6d19ce37936adb50cc510018dcbe3ecc964583ada6dbd22b0eb4a89571d98238894b1033764b0c4726fe8511f4207568aa4489cf7a57e84b9c5ff26bdab9b660f91d"_hex;
        e = "1e5e25"_hex;
        m = "014bd8a7ccd4c3924208a8a6021bb7df5f238021062ab5e1e18131223c583aa4278c03581bc07516e0af2f92adc0cc8d92dc6448137c553e16064312ff595dc719a6e22f3883e4a69c3a4d0019671fbf75c200891239f5dacc426ef7256f8323a0427d146a4498a83f5107d58c3639ded17e5bcd4a881e1dceddbab7f7c13320"_hex;
        s = "400994dcf90a8391d448059aa51ef3ef10ac64df165d5b6b22fb745bbfec307bfed443dd912414bde19bddff653f6460d6c2e1be6db883132981bc05d66827540a0f5fdb883645511173dc3b3c900daf1c0c2da808ef4a86061777f0c6f3ef738813f3cbce89cc8daddf6d178d1a45c83da92b3cc0cb68be6de5f5d56e5aad6db077f23979648253a8b1758e6478605646981882445f46738c955c900d74c60771528b91a83c69ced1ec3159be138b7d3872aef5ffd2f58c02b50bebb5dc3164bfdab96e6f325f9d4293a6b41d3f9f53535681454051778b98655849174748b1ef1a3841532b5aacc6a4b68a0cf994993643549ca0df2eba94718b11b73d6c9c"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "1e5e25"_hex;
        m = "26dfc6c8d3f37c12edf9b1e176ba99ea602fd989a3453eaa8eddafe95a1760f805d049415e69d7cd5ccae165b3a7ddf7a902543b26f293950ba2a43ec59c7c9f224876fd63af005b9285949c1667ebe984616d52b8b3ebb825d590ea69b8150e244f35430b4e61843832b4cfc481298798530c188011aed9827d5d366df2930e"_hex;
        s = "8b9416808240350eab81f1468367cdb6c2b770b7dd9d88fcca8786db9407179b9401c5f074bf9d7a85c5fe26859e8e3bfd26502175bd1a759d1a6bd79149c043b25d9fa70d80f163696ca4153a3df857c63e709f0c00bfcd47e66467110dc6aa8da6411586101eaf99068585962ff994e8e51b30319561648994f2533bbd8b8adc2dff2126cd753ed8b8abc5913c0cf984e78128e2c18fc1f9d8017c60d2c4dd642633dfd412cc00a0c32569b25e328f242d691d75cd2ae22f8359426548b04e36f15bfb9fd561b1e3f3196296823a3828bb791f19bcb75e172f7c06e30cb2e9576bc83a7b59c67b821fc8c1d4d9775ef0f2b33a44c19d3aad04abfa17b8ac71"_hex;
        r = true; // Result = P
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA1 signature" );

        e = "1e5e25"_hex;
        m = "59e84c0d700305007789dd765f33fc014241ef0fa4b406befcbdfaf27175d3a4e1ce097d27caeaa39eeb3bd3e1ea22b0d5ac445aea712a439d4fe93e42df02d9003687ed1d167f737b668c9963e0cb16820afcba3167e349faeeed8957bb179abc050c86d8508d1919e316f36e7dbfdb5044605603fef878198350fb3972db8e"_hex;
        s = "39daab754cc68ccadaf33a057d76aacccc30ad5341dfad503b33f29243e57636a68453323d81cede8ba0959bb980905f4a464ac21880842cf26eb8e8801c105ebda3a866d0d3e8597d234a21c46adb5dff49174df3c36f7c3deb693362418520af227195d609a548836378f4885af1ef95d2d9373c53ed811884cc534b7d88449281b2155938553205d5b51e39439904757a50d6c877d686b32906dd50049a620c3c3489c9007633a04882ef0186af29c71518ae8ed96f307d68eb33ce40793de205caea711cf9bea7fee8b751cd764f4e4e616c50be2456a868803969d692ff8b8b15a4f0d4ead24f610e231d5012a31247b46a582f1d3fea404a5d29691f7e"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "1e5e25"_hex;
        m = "73e48a5d845d55944fe63aa61db36d80724b2809ecdeaa106dd880827db603e1e91822f1b01861b520db22993d6523f162b249a22b029c1f9174929857d6906ea6bcaee9f4cfbb2d2a68816a055e4954bc1ca2d3e4f65ffb91bddf3ebf9091e0f0f6b6ac162a69e6b2b6dd803e43e790c9b0bc02e161fb8ab5daeedd7b8c0d21"_hex;
        s = "5f566d4ad20bec081e05f610df9b972a69afbb71e2a345f3b4fe8b5e2243cdc6a68044e46996ee9bbdd90e6bc7354238566fd7535e6ef04b7d0ea8eb3cb287b23e2492f1f16c799150bfef616467f1ae535667fe76ad5f6ec16aa0f0491c3ee7afebc6da5d6e4ebcc0194e90fd0bc944b0279c9973e269a7452b87a1a317c3d8131804ba4ab2b7a48a8241fa20506d9dd4d1ad74051d28c32c0e1c7bc4099e25c6056a359132c3f0d8d1f2725fffaec815eb91d9bb902aa8d024b797da8035c024539514ff3346067bd583aae8fe5f2a54be488f053407827445a27faaf635e97a7888246d817e7b291d9ae5939e0ebd0cd4a6cefcdf4bc5a637e294a368ab29"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "60e097"_hex;
        m = "da4c0bf959ae81004fed9e58752e03f486906288f30fd891d7a77e952dbc3bac41b9dc3f64f86610e4e2aa7a3b571bfb8750ddef3ac21e9e13c6a9794df8b8a1161c0aa94208369d41be3f434ed868a0ea294abe89a123ad8b7171c86d70c03941bdc0c05ba69ab04ec9843a177994ed9764d17e477290c527f0fe09f7edf97d"_hex;
        s = "8b31638425af6493fdf969789f33b2f44bb0d84923347cf03cdc72ad9f139fad79096d100e567caa8099ae15c2ff5c74a3ddb8b40f5fa5a23da10b6b39d985d2d2219d129a39587983660fc9d51f43b1cefc1ae1a102c6d9634b4748d3a2688197fd445a635bfe40dba7da006e7016b9f1a77c2be92f1f50181c025b22224785d4c9c7062429506ba2a1b18bd719ef72892029df3098e707bf1858f81dee73827f9e1d1f9fb1055d969ed45a513f39870250c2b8a507605468d75f0d3ddf1dd1ac3a8bd245101dcf1eae32822dd208b0dea4ef5722d22518de07712192178f57c523175fe4ba17fdaf7e604efc6ad5e2215e1f327abe9ec2004bf7b70505e492"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "1e5e25"_hex;
        m = "f0d6d7e7eedfec55dbb2e7506ebad1c99ba7ed0a5b1f9b01afb07cdce20ad7d70f6b3b52e45a6627a598663a7454fe52cf9e4b275a1ea7bcdf06ceee9345404d9bfee62cce38f7f4bdd71dbef0cbd4207387134692b42f45e027fcad7e11355d99761e9c35e16765295554016b861bdc8e498e91894af947bafd4e402bd77faf"_hex;
        s = "c6141f88f387f4250ea16d2bc2b438fdfdaf3f3eff539a4f0573d249502d08c4a57333c511dac0b1d0e85cc3ff3bcd9ede0bddab2e4141157e41003dec0dd494cce39e4e9e4d77e89ab266e74579382fe4c829a090ffe40ae17b53da2653876112acb2b1575613570f4ccb219ae51ddd950078c0554cdb7394906c54ca960fc56bedacf7d62e25b72d5e727d18b9cd378f8131b9de088216929f42420404d75b4e960a257927f82ff353217042b61a45ecb45457a581dd82c57a76f7160273de2be85b594db977a29e92813f74feb1678e35a339c42dc66eaec11c8531869ee64c8f6fdd4bc2d918ac29e8995a35f06edc7fb1ec494a86b04dccadd448620ad2"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        //[mod = 3072]
        n = "d8196d0e7875a3d396365b446f520f6706695a8046976fdf7917157e8747a58e5d30d83620703e743271b17f3c9763514c38c6808b49ea42ed3c9ad2514bfe059e095c2f17624b5bc1aa5060c320ca14da57d65024b7f1c09c1611b56a3d62fb104c4e458b18f6760d85c53cdcf0b83ff25b48b046d46c0110f8093f9b4873e99b81756232ab077c7195f711c86ae44de848011e028e666ce8f264ea34cd82193cce9fb055a09cf7d12d1e3cdc57f7efbf48237722e1f1bf499572a7b942a74e634751a1808f475806aa5233d122f7220f3f694b91990a45740d547b62582390ec43417037b05a82b0f72fcdae476f04128f2a3b3cf769c8e8d441db469f29da612ae4de490787eef11127a38510073a127ddf279e5132dd6db07275efac083104cbfa39acc224ac1755dfa8299ad4be9ec44b57d83837c583bd35ed8e857e6369281c41c0227283f137df0b29aa6940d126bcc46ee37c3774ba88cf60e5af2678adc8e1eb5e9b3b96c9e8ab2f6c7e69a2360df666544c5b266ff09d21b373ed"_hex;
        e = "edc8a7"_hex;
        m = "af09df21babe776fcecbb5c5dfa352c790ab27b9a5e74242bbd23970368dbefd7c3c74d161ae01c7e13c65b415f38aa660f51b69ea1c9a504fe1ad31987cb9b26a4db2c37d7b326c50dbc8c91b13925306ff0e6098532dee7282a99c3ddf99f9e1024301f76e31e58271870bd94b9356e892a6a798d422a48c7fd5b80efe855a"_hex;
        s = "8005d3a1f6bc9e5b25e4bfe751a511b741d622eddab691d10911019f2589475c2432ab9a90627020ab3117042e468f1847a70d8fc392b09092bfca421292c5d4ecc0540957dedf526914490ce8338de9451cbc1c9c25dbba91d8c3d447dc7d044d9654022c8a21c08ecbadac1e44b0fe2ab462037cb409a8e37f617bc723ff4969e4553f46a8532cdc9429c0a03b8c34cb41812816904c98ea31eefb0d9a5a8f0c182e7d889d13704ba616ef1e91df911ea868df5d03b39d30624f310bff100d404fe6e86fe5986abd597babba200a28bc961d6d8054887a2f44ff269129e9b085891840e926244281cc312282e6da6ff5e70fb44cff6b2a2c48951601b1db25b4f70aabbcddb7e1c33e0521442e81df7835dde8a2852d410b45705e8763b5bbdae5dbf4d84dfe782ae862366ccf37adcbc8e51c9769fd516bab1f1572d8ebcd80ae9d052b1b102a2c13a7ed44465d9c535e6cf202c981c302e4117b74475f1b129d719280facc628fec3c28285bfccdccb67d75a71ae7908aacff6adf55d0ff"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "edc8a7"_hex;
        m = "5fa7b357c3630bec6d6e119f4266ff9465391acc638a87a7ad565fa84cd70679d0a8b82f892b64cefa28be108bb690627e5f5030247ff86251ed12270ddd12f18c05e9c161ffd7a4eeef817d1f6543065885c712ab65d7154fb66fe54da717c27d066f95b1a80c75300c826f663bc287d9f2a7fa5f03cbc68ff99f6c75fbbbf5"_hex;
        s = "1e84e79b2c46ca8d7a0e35503e4713f556eeac5b86116ded6c9ae1c14343c4c0c241424fa4ade7f76d93e6f845c62f0f2039e3cfda2d364cda93006199ba774842a7f0a99fc72bb21d583ab440a7ea37c371211c8a99f49772edbf14a18b8c1d112fe78af270c8dd3eafad00c004ba22bd521f3767b2d05a4f4ad87a850c4cd444126c6ecf50487053dab17dd624f9daa9a921d31ccfbe77a56787c13522eec9a7948626e560413cf210e438b61475f0fe3b53c29c038e8962781886eb2bf407b74ef7169a8302113cba712488fb9f2e27743d3a48033ae9b6fb76b768ac7014d73df1f4740721a5da04257c5cd72c0bb3de9e734f800e8db60b5b56e7dd58dbcb02b48e837f0264c2aa8b2543162533081cd579c1651b8ee4cd5981a7b27b7c77450e6d4bf3576e541409c2ebd09975d92ba4c35ffde2a7b2bbfb9628795de7c49805ce553bd632ceeda8e626fef36e5fb118dc0708f785680a5888096046832121d5427d7239e123733ca606fb991cae95f1ffc23ab0457599abf92732a87d"_hex;
        r = true; // Result = P
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA1 signature" );

        e = "9fbb4f"_hex;
        m = "e4bc017c194430d1ae0798c2a122b56aedab0dc4f68cb81c27911fc3dabf040778e8c362e17cd7f20ea29f29f58762c6acf69204d22a4d112be029c18ab03184f49c2b9602ea1d75872f0f9873ad115ef7de8045ea51865c6cb5e0fbc934e4b1a002c27e44350a4262d76e76e439ca1a168b61ee07aa69e53339cbd75ef32476"_hex;
        s = "2e6b315e6ae71c573f396ac918df88f2254b6c29d552dff65d30f37e07fbee166459ad9b21969e19adf0ef493d368ef4e889e002f636eab345a1bcd373904d8137262e7828f50c3a5b0be2d89f5cf0217a5a593bb4b58b93cd59870e3e61e682f8f2778cb907cae1e9650280748011d08cb9b1e437ee26099a876d414e7ed5a1f31aacc632f2503ce38d4a15cdc9b5d8c9a01a379e5cc6315b6d81bf657c4b5d876752e8682177a799c9ae4687b58ca5182d6fcf06c3048b2410285d5d4f98cf94b71d3af8f7328450fb0cd8189a3d354c29b425ab75c33c9a29aacc602bfd0955e57214f1b4def30dc2f06b8abdbd9d609e126699c7994d34312bfdfeda87b23c484a097e614508bbd9f0daf2e0e71ef7c20ae14a943499b82a294ba90787b26df264fd8ce25b88d14b636c6a5b587cff9c80370162859df1ef2bec3a946997f84a5c8c577ea8329f3cdcc97214e6071badf226851ab3b5c7c1c9bfee3feec017393c3a054adf70a58e8596fcd47af32ca062567cdd87c5a53dae3780ba13ee"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "edc8a7"_hex;
        m = "b6ce2cd484adf679c884c35b885757bd48a50241733f215bfd5ae70547e25eb44311a88bd8418bcf88fe2d9c50601bd6cf979061abc8f5953118a4ec3b06f1fe57fd6bb025295fa8018b9e04e248804b824729a3c0fa0b45427cac2f5eddaa183bbafca933107aea7c51a0fb08b88f04a9da546e797f6d5479af8934781090eb"_hex;
        s = "01a0e831fbe4cba0309731c0bff9f3348e919fedca607b59d306e5f691879692ad2eda3a7e911da2dfcc2c1ece81873e8741ebec79dc58cf2884f638f393ad044d18c5147801d3c2238f10bce526f82d8fda18abf635e4c4593b44d4d1b9d390a62a9c3bdb662a0b5346e128c1841bf65780133cbb7ec1efa67f94a2ee8d503fcab70a0d9fa50c0ebbfb94910b0565efc6f0d79f1ea29ffdb0898a21c919ce9aae3d7349b2090a8c09f98e953a4cccfc8b0d19a8cd7a8a34c0dd5adc2f383b7dc2b5bfd7d9aed1a47aaecc54b5998c0c8e735b6f6ae7f737a68ef79d38fdf0756cee89089ceafc9cbefa2a02a0d02a7935c10a7826ecb6aa17a4d34b1c77d6942889457984e8197144907d3ac2a3e65ebe9d974bf522aada84f45bba806ca4b0534cad5b460d1bf5571a1e050e5494138f4c8bfcb4334968b50d9cb50b32c52aba4598fa47603de7d358f85b68e13432fd85b247c3759ff7e24dc1934d01ddd60a0156d4fe9d314681d3fd69f071bdfcc5b3a5b2df626f34eb95043bf160eb0a"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "edc8a7"_hex;
        m = "79d92d0766310a0011b4398c59543062ef8dceec5e5386e64949c028f4337cc007ae39448e1f156743e935c910e36714d009064456711f46b081d1c5ac60fa419caa106157684c8a803f0eb00be77d6cfcdf6d4f725f8777e58fa35facf679fbc2357905c9f5f7924f1e8be85149b893fd79cbb6bc0506a070d9fe9ffadf4219"_hex;
        s = "1fd91927e15056b040794544ad1bd99a077f3151d9d705ced12c9a6c41483dc1e1b94bc549e06c91a35816ce9016a9f56b9b95f8ce2c9e4a33b445f701abae9c6301bc9581ae89ea2e83b725431d01a3ce1e266ad3b8cd29b217b27e1db105887423d25dd5c6e0c02b3800df9fbcb9f306b86ecbca65366542da71b03955d4063512998924a30283592516037e51e24ee8e8c6bba339e5cc6a3b64375a7dd96e7efc00d410fc0a63d0833dfc8ef518c74c2dc13f79cacbafc3fdc2253c50cf7a1f79ffc185a96a1602e5b7416123d874b5e4c4b4b35b3523309895113d7d2aa71cd895feed0eb9174ecb5b8dec252c53890e28648e71c87a8528be9c7b23de20550675b0b5072fe52cb1de14c5e1be13896dac73220726adb1e8102fcdce01b92251497a553d74f938c96fd9e5936392f0f5c5efe15a7574e01342cedc17cf4f750825424c7b939d0328d2c5a0a8f744826ed9f8dd4479a40da051b7924a29e81c13e929e4815474bb4a825d564cee8f22ce451d094c19d9661dc413e070c5a6"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "edc8a7"_hex;
        m = "569b513e3a2f031a0fb2b3a2f3d51c321ffdde7dc9997f8248b2afbc79c3d09961ccb52e14a2aa29d589b5077e041c8723ec275ef2c0272c5d3cb7af7c2d4236ac83c6597da8d7e8cb10e6212a12c32688f661ae0d4fdafa468bb20b83c860127de90a283ce9913f3870cd58bfa41af7964213d4e3ed9dd44ac62837573c3113"_hex;
        s = "0202f80676900c6ebdaad6750b5e0600af5caee8b03480b8acfecf719fb3508b41ebc57e7625ee0303675478f17de92710db1855557ef3ad3e29353a53794df804db4ea20e8cc4a9c9ddb78b4be6f2475833fc13d9810de1bb338bc45bd88e76d8bba7b08beec647f3e084a15848591592b0fa7ccadf033a958ff643e8741fac68e7f8e7f6597ddbfe0e696fb68811d910ae817a017e136d100d50e2de6f9f8569593a5a88b535d44466e97baa7f9270334c299a7684059fdf5dc519ddceb050678501637b48ef27614b042365900a060e438ab6f16e3624795d47f448c0e91661c8aae15e46ceb37aa58ba8c413b6a6a812dedd263f2d8de3cd6f7f3b396334248ecc3f4dc5484a4218e33de1359798dda01affcafe7567633076ae95b847b2afcc1919e296cb77c8b00ed4aba717bd8c79b4320adae92bac470019ea631cc2efde91d5e465394c4c616faab83f5875fbb67b6c6ceca73c891ef4288750b02bbf478d532517bc6f76f0fd48dc2c0971888dc94854017c8e5551f0fda68e681a"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        n = "da3428fb42c2bd8b0a954bb132f3334b804b163913398188d6b7a8433fc66249a300eb5e7ed2b20b7e22e21caef328071993af0200040247c651a57d37160bf41db0af7840aa731be37c3daca590388ab93ca935b9ed94962f3837bf7df344855b2ce7eb4c68485c8455a16bae782d606a246a1a66229be6a4e3fa9b534c5e1c1100b5a15551fb0a70e78612eb2116f1a38fd694028cd2172bc7699105cd6e4c14b5c9da61819048c42b10e31c3019f8c97825f7f70312ee3e6348a38e0b4fe9d567e1a4087cf260944f57cdde56dfd9cd781c846ec73b523bda1539130c1750f24cf0b6d0d160f4492ee38d31bc44d4ca299effb4427e2bd4fff80f7d19042d988713a84d470fdb692a296e6e14c68d561addd58863496aba014ccc423cdaebe43874c90ba0981404398250a062266e372a9ab7f29c236225769f0baea54aa436705f0dad5dce1d608ce27cb34d22ec913c99c5a2d28103b0a88c8cbc3b9b37525ac45bb39d26d0615fb0af055911bcad4d724c208e1cde40259578df24ba3b"_hex;
        e = "8a381f"_hex;
        m = "8bd0e9c0054beaa7d19e08483fa541fa551ee71421af980d4b2b71e2f1117fb8ae5576c3fc63a666bd622a9c14b5639679c8a5a60d092f5b2a3461ee3fd429dcdb07bfd5078192d5d9d3829146ed4f1438e251aae0ec6afd4eb03a7e3fc39106366c2abdceac963c4e7b76ee7e55edbcb9f555e94461313ade26635b98e5a07e"_hex;
        s = "4197ec722775cc065adfcecce1af88d2556161466124f358563c84c52eb4ff711b9afa9a6c0bab52ea08f7a6f434ea5a6b4dabd3554baae2330b1de68e62d83c2d6217781c6e38376f142971e13c8806e0bf467089e3dae47b80f9f93e8677209f29d0b20b474ac815a2e2388b9d34b838373401b72a33e30914cc0ce9e1357d00f55d9736107d3db204bb13d77923566d35715a9c986f199d5d185f02aed6481dbd116e3fbc81c3bd4e3438928d3c93f63d9566b4af39bdc6361783286611a0bee9f326ac1678ffd9ef517ea0a6908cc38d3b153e68ce79bcde3c2f33d240cec3066d8c05af6d38008239979dacc67c2bcc14212909f4e2f92b654f7dea995cf006088be930061798d5fd0e4851c65d5a23b9440a83aacca0837059e85f32d16f390b02a57b910c6a9109f8d69af07d7a8a44beb4ddef724bdc475369ad34510b8edb5c2b36c9f9cfc775d1f1840d2406943048ba339d94f7f226763c17425543fc5d2c4f0d9fb0f4ca98e100be9c2917c13ebeb90a9e4fd235671cfca89769"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "8a381f"_hex;
        m = "b8012a53d58a2db0cfa9e680b24a6327a01873cc7493650ea46213f26cea2020291f7d50039a32ffceed5b66323370ac0aebca5b0b066311a63ede782faac7773e8f1baa567a0b10c48bfd04ca14d46ffd63713becdb790b024a5929ae7688bfc0f90c4b174f404d792ed442c21515d641286f565f3b3064812d8eee3077ec61"_hex;
        s = "584351aa09ff6cd9da1771735e122bea891e20c6c3e297966885f7c7768a395c455768a8c6066018cce86d2effd909a719bd7d712072efa0aa530b9ed6a1a24c4c4f589a006c077ffb013f4fd9dc0a9e13b516a3234d09f79ff76e8d46a8c5f1e41f229805d9ffcea507277511b5f8e71d13568574d01759cd851e2b6cdb6a7fca280ee10d7a62ae15db9069c0438ccfdce2b8d83dbc7e5abe6ddb1813ce1b7aafad383455b50da544bdec9dce0d93894927940d17159f1f82bf44dcd8e69631125695b7cbed538ff467d0f53258d815b8a817e79fa238eef0a26e53202ff5e2d57b547831eba68f71ee81b1d4a5af42de2c5c4e9a8e4d3f53d6e9832e71de9590851a5be5e18b381c94536313185db54f9f03d362971b13a8612d3456cd8d3f15644fbeb33f8fb2b9b6b60522f49b6c6bc5d6c3701371f66dd115f95eaf5889893e27df3975ea90ee3e8b9438e7dc26ecee1dd9fdc34843e3188cb020778b4ffb8b52339405f17278be0e6d9a227292363829cce7cc3ac2ba1ff90cf8c09dbc"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "8a381f"_hex;
        m = "0803aa22e7bfadb1ae48bdc6dea805f2951c23650d81d2056509c6c2a432d823fbf963254a4aee46e6bc0bdd9a7b7eaceb85a2b8a01a0959826d638d61a0a19157ef5ab3512c6d62ca6be887dafe281870a442e9dbfda2c69041f2c027323ec4a64f5572024b722be3bd1b6ca8194a5babdfcba0c612e57616ec3c02fed0f6e3"_hex;
        s = "bf3adfd66bd872ad41c1b2465bee7befb88bb46c36d1a113ee3df6e0d2547f771fa7e72b7ba22d86673912d70b8ca1bb61e6835da82f6a272ee25b4d603bed423d6febc079a13f9140cfd22fe2aa9994125310b8f4268b3ebd68ec0ec781bd129d921502ee93fad8d96d006996e44d662ddca2932d8c06f088cff205e5826104b7f2860beb589a5161e8c0d5454fa7c522e395e843f025e6b99af27951ce577894adf63516b7fc78a6bebf17c287d199888e5237a17a88a765f929618c53b87a7e4660507dc7fa3e4ffdac8eee8963a960eb34f0f974d83fcac38223f24c79f818fb46e767cb3a807a77d6fdaa4d1b072f9d20ef025329da3f2933ab694b838996b0e6710cee35339f4e1cb7a145e3feac23847049977a6afd55038b8fd9449bee3875ca23708932d693657167ee577fa56d790dbd98537857a5d67bfa5c998c39af621c43c5ebc3976a0de1dc09890929ac3384abcfc22ed1c965254245bb2c6f68399ad3b9c4e6499d1f09ae800a5d6fe871dc7adc98293fd86930aa566523"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "7e024d"_hex;
        m = "66617eec7cb213d31a231ddbd0d4cebf80f32ac36d81bb979559877f416e3fb1da54b9fefe02a0b5d3d66bc59bd98b218945e969d3448fc609fba516a5c7a049e3c6b60ad39a95a2ac69541a6328aaa07c1a5e2d2193fe647102d4bc1a2e16e12ac05d58220258624ce6c2244f4a9104017a71567cf770387477fbbac82c0943"_hex;
        s = "72d24f9b4b3642043b7080ce66d5c2bed95b1a710776ede03cbfef3806760a6ee640def72c6b04477342dc3d1109d06d58a1880bcb8b3ffd8ea15c2e66de6815419c684962f79dd0c0645b2b22cbcea29c7ae85bb5e689ead0f07350a3cc8dd872698daaafea95b014e12132df28b50e63f7c011a9e6a7184376223730119b201e8ac5d61b6bf9e7c2896fff600a119300bfb034a985330de944ffebf67f720a33115fa680e02bca71eed92d0160c83a037be1bc4383c26ada8e1298dd92d0db9d7d918a59baf2c2b2b88e7996f630d5f88675b8cf80be841973e3c1efd0a156ac9f5570eb2797ddd32cd4575fba8c3ed5c39236af3845bfd95020463ffb983b9a0ae24bd244f20a5ada496f58c80fa5b16dd2a8010abc86c7a8474621d4ebee2849ea96e0e94956614ea0818c425c0ccbbff20a62cb7d218573f5aeba6920f75a7fb26ebcf5debc473d4a8daed02e1eab16212ed268caf07c2df497d1ef6700f47287b80c6635edab668c3665ab333617daa98aac9c1f71f749bc1dc2bb2428"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "8a381f"_hex;
        m = "1c7965099677664f23eeec41046865633a36ef29f6116ebd5101dbfc3d7edfc1bbd5a0674fcedb89b18c330cc6b4c860ced20c02dff8d24692a8a853fcf3676fe0e3087d2217b9c37fad30f17c65405f9c02aa97d6f4351346350148237118e3f1694652f8992b86f4188ef70ec1f4e90b9071eec44ebfadd6718de19a3e19a5"_hex;
        s = "8b7a7e94dd13ad803b61a100b66075f011b9c52d8d443c49560f99256f0eef53a699d24dbd8aceaf85c2fc0eaedb6e34f1bb4e5a58a171b5f08170ff865cda853e599dd6f7b88c32678733198e1ee4eb586cb360f3ef8aa3c034557c49cc39bf02a5bb8b4f17aaf7a736b83d2965c4ae8bbf9cc81f3f7943dcfb74caf216b745f6fa6b941e6dc5d535feb5862864d4ab4d4258d7bd1f93ae81219f88d3b8790cd40e2c222b074a1d396a92f75bee8e088e0e71daa7120256c5842dc4abaf04d9784d25dc6374c0c33126055c4367d841809fb21f3a3cdbbee5aad204bd89b3b7aa4995154b4f2ff3896c936a1b8f41a95db16ffbb733d6abc23889ea2ddb07498a3bb270e259276d4bfbdccb94683a7860de3786c93b19e285685f4397594d1b18c1dafb09e614e8e59760968e14992f9b1b7bfadd283c3493ad5035b79630846b349e3cd294e93952b40cf4580e4fc24fdfbe77aeb92f8c6afe03624be13862880f1f939c21cc895e62fa4c78a3b95341092a6abe7d21b5bf5528b2383c20e6"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "8a381f"_hex;
        m = "d02569c471a2139f9265920ec395fd1803fe857d1e1063e03a2b0f2bac1ab33010dddf8c98ab7ed1a43709e49333faa3d91284cb52138119d77bacb00e2110bb8630c0530329c9a31627654af16771007a07217d9e0ef397e8ade1aa52c5db3c5ba874e15924dc5d11be0e09853b4a780d65c659a90ba19f964a18e01f0bfcfb"_hex;
        s = "40bb34f18580db4e1af934834953321a7fda886fb8831041909abfc08db1aedaf64115791699180c18b14584457933033e9cd0347b3e25dfde4c77bf5983f8f1635cadecaf7b109f399ef891604d4ef0b8bdc49d24011e7b1e4af79c34d0616aec06da2fe4a88847dca5f739bbd8c4dd6e4b196d8117f666534538ba180f703bd5cd87a9de0a50cdf2ed4b9e542d4ea9c2eba109754c55bd4432f37dba8708bd528a244e2b8aba7e8e56facb218391ca9dd29d8c1a58d7bf749f047829ff52998649f52ac76cf540ced9bc63c5fbb8e470a91fa0aba01bdd1fb899bac38c7b9e6c5f69591f63af213c2b543078ff3e29d02327aad6242511e6c91b37074a94ead1753546d0db25048fe2f3d10dccad0624495a3e1efd1687c9d0854fccbaf13e1e4892ebaecf2d1336681ee4f3888922a75424ee61d229f2f85984d187c9955ae51e6707bda528586b7e373267834dbf5a31332e640b611be64058e79f02fc4fa02e2e238eaa4cb725c471e9c0e5a48bbcd6efb9fb851cac9617a4da16e17166"_hex;
        r = true; // Result = P
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA1 signature" );

        n = "d7a6b5b175afa3bb18fffeaee645a096d8ff28cf96e13dce6d753d3eef4c0cf605dd06f0d25d208da216eba09b3e7e59b304210e63118c5fbc3185f1b845d18bdbf113c4d65ad2880bb2a5eb5b4e7210df30296a4ed6cbc637595318e72e2a6439e4d244d63defad0d2a7d5c06518b0981fef4c916c533f3495c098b40254724fc5a44b0f1d23c3a275466100eb39de3dff6dd48e8322ac2251f3b1f09ae8e6a6136645acbf358e7baa89bc515a12e78cf0f6c9e257b816be1e7a3098b9c1d3b47a4c955b390dc576cca2f9b391b61af5e0eeba21addbe728c58eceb8e018573962ae069f91c538e3161e5765db7e15b352ba3978edbab3071104353d122024e1f3e31f6337dddaae90a2a646074b5691b95b7d82429192c897598a00d67639c326922407002d49432b3cdf84c095c021c4dbe53f7fbe80a497f75991d195122fdb672c67fc973626583202c8230a506f251600ab46435acf51ef6461bd55d0c14a76bb4f1c0b7e3c1affdf21dc8e514c2e8732779e62c3f1fd8626c4b80c683"_hex;
        e = "2fda05"_hex;
        m = "711cb316a158e229d3c4d2f5d6c7e5aa29b4ade40e95a188df2715eea5256946e7c98034c09173be343f8768c4235d9d409c6951dddda5e588ed874b79f1306a0aaee6c4ca4ac456cd52b0bf47028ea559c0b3552be99da93bd0e12ff504648783d2ce0de60b3cb94608364386eae08a1c2674362042ef9ca2d90be341e56e65"_hex;
        s = "d3c03e8891632b8fd169dbd4ef4a51f207ef89b50dffbc23fa2d941491d8e185f3c743684677df40b18b0d8cc712ae61a3027ad5be4725d6a8e7b242b2139494bbc5c59a0122b26e0f9afb8df76db8dfdce8e9d2c38818bb0140a41f9060bf23e6ae364220eb56e3a62eaf966873c14dd82bec57876d43d1e07197da109fc009ab8b45e48ddb7cb1ff34ef3fdb3f4226eea8597c5c59ac573d15183489ee52db3af1c13feddc9357722978e4172a3bb26bf2b2b537f121295c00151e1629e28cbddd7957a595cf5effa365dba30698d8049d4701a4dcf03e9bf53e4ad449a7aed4abb6cf65ebd33cbf763fef760c1fe178f5d748fe37292cef145d61cee1dc02bf1655516a5de3168dfbbf4136e6351d3b8313ece067edbe34b1678ea34387636506192384489556efbd133a9912d51780d7fed8662ced97a6dd49e423da4b0019fac0b83e96862eb302910284ff2eb190ac61dd2159ee24e0b233eb38d383b4ff6633bdba58d85cb81abccb072ad716eda8b33b6c8ea9de43e8bc184f1882b9"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "2fda05"_hex;
        m = "1b51ee87dd2a4715ad8de13b9dd8f46243d37bae04e392d39380232ab4e8c1044615d43e80edf7157bba9e3cf0d9fc2c44b624bcc1f86ef127f81c1763783d109e92d2ed79ee30bb9738a59f5dd15e26f5c588d699feb6090eb783fb6e3378212bae30bc5194b9af0bf13e8d6928e3f760e9f125135d33c250a3a0fd5e8039dd"_hex;
        s = "397e6e6a04b3fcb3f0379fe1f9b9e5cf5c6d433e383b688cced0a6ddebc740b8ec0266aa5c7e89d5ca77c9a020716dbce12dc044c00b3b1b23fe3419630bbd8bde5c9883a6d26232fee11a81ced86ccb338dfe46faa3fd58720b80f305d40f1966c268c56d92af05c4f1bf66e6d1c5c810fedff5b316f3b61089c8ab9a4f2b4d7a46bab1868008ff3c0bba9800634c5781cfd7711a9b51f41b517ea428a9b63eb36609c763cef555df2cfcd25e16b8b3c631fcc12ed78904111188908a21253544a8f9fb0615570b3f2453a3214ecfdbf44f403d1baf0fba84d17527e7cc23e15cfe047f4fffd89bbfecae01cd3ebec787c3dc54d9511af93a3b37924ef9d6d5fc6e147dd9e91a39bfe101e3e55004f096b9b889e95b4f1fcd561ea76ee6b19276e8a26aa3aa3eda99de7ee48ad1b1c907cc302e909e89f5e3dce32657ebcdeef78722b7ac95a87930facd56e9cc976b501edda38b663d98c9993b0139032dc95fdbe4a17a9eb0e82c40402365fb84c1195b039246cd424233c88fef251ff77c"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "6ce901"_hex;
        m = "45d9c631cf0813fe85c7715860bc3a3b38f2a41a8688a12e6ea6030dfdb5e47eafd0458c3475f5d97381b535d05b996faa6fb16b28dee97536732ed5cadad2a46c0c32def50e96b897db58331d9f49f1742550476b935495b7555cd23a57f56b8577d54e9b3abd41f7bda479d1ef11689efec9d6d60faa33f932d72cd495157c"_hex;
        s = "c7958952aae21c256809e83d7f1833e9819d3b4e4cf562ec71bc0effe7a797d62e71d1937a79361d1cdc9cd5726207daaa9def6249a0fd3da6a23683fc8b084871325e07223a3317868efdad20f52a0330f369a0ba51f0fc098afde7d2b72b7f2faab6782cb663c4701fc07bd82fa6d4ea77205a7ee8473a9c8336a781fb64c03632c52e6c1451c3ace7674d5fc9f26e8613c12137977511484487d9a8b928666bbe23cf0eefc849d9e0d0c125cc2ac42f342cb658d164ae57ab3d5606b8096fd4b4c81d54c9db79c5db70106cc474bc64ca73b713385dd9539329260899054bf6f74a45fd5363f78de558484a124a113ac2d2bc6fb8ed19730dc746748b62818e6e62f558d5d9fcbd2c6f4fcc70db6c7fc5c22524a89f04229def949379074e7220cb4717d6407364062095b615464e9ce9c50f53c4358d9f80ffbfe70c15cfd2d9d5f0b451979412f3cdc8f9619e189bf23e71116eb3c620c8f0740b890bfbe961f6cf8854ac6b2dc4fbfd62b6be3bfd1824070cd46b1002b61c1e572437af"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "2fda05"_hex;
        m = "c58629fdf3aaed600121e5a109ec1f62b360ab46abcbaeb1535ab2d0b53a40dabbfeb195a241411bac8c65de157a5fea49190f6a54940c6e9a0ff3ebc8d3ff030aabda877f8db3bbea7d9159aaafe7d8ecec68ed1f361c53a8afb4c8d7b71b581a554ddd71d86cc722be1119aed4e0b4039f5fd8f3fb08e8e5029c6dcb2fbb5e"_hex;
        s = "40ea4940619e7611473537ef5b108f9e1216e2ab9bb7fd45cfffe15e70621af6590eb571f9be970d30e5df0dbe527b9a9ea70e259b964e496735177d417de3291d16e0b055cc9b8f4dd5498bb7a78d8882bfba624580d81ff0b76f6a82f9a15d2c28cbeaa0e6c02807901838500e36cb403acadd6e431196c794c0bbae65fa6b7ef2ab4c58c0fc7f3d27bbc14dd7699d7b0fc42a3dd30504f7c7e71d8504c23fe08a05e76c8061337687241d27a0ba2411619d2befd66a00d894f302bbdc4f3ae7a562307f21cc43c377b084d8521e2f3d27315b5c8b494b5178dab25fb3a8ade194cf3f909e9f29d888f15a75d26d427e7a17edf63f7f5dd814c67433ae7e15f668637579a3b1d59c73f153e094029e74b8966a9a4b72efe0d5d0e7d9c44c63de6d0dbf00e76d459c3ded35165eac8a76883ced93359c34fdfa94ba74bb58464770051537e9b71f16f615d5615a7b8d380b4bb9ec2499b255ec17131d2161d10709c357687728de9758cf5a166e81fbc086a2e20dae9b99c4f4f83c5edc0ad6"_hex;
        r = true; // Result = P
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA1 signature" );

        e = "2fda05"_hex;
        m = "f7653ea73a08384cd5dc0f14daf59160b94ee19eb76b83109f3db3cfb446fb0febfe04a45774adc6e5385a1149798ecf386bbd7ad8eb5b7d7566393b75f711528ecf602136da73885ba0c5ee5569888919a482d9af891a76e6feb30c46b738a446a2f825bf82b51aa1d9f7b5e50ca614c2c2d8c4248de8845accc84b0ed0988c"_hex;
        s = "4ba672add725521df81acde1e1efd18d169ce4e04cb55d39fdb2c6598250e0c7953867dbe189c327f76bb6afeac0e013853e75829eb50635622c26667d55cf3bf81bcbbb94e5c0fffbd853e2d7d536659b1ca9105b777d6fdacf3000c7c287e484933d38e2c52b301e01a3fd196b4960b4d8a983466ec376ec1d70bd26e1d4dc707a87ccb32a4e12f56d00d1a8f9dc20794a59a437e93fe5c79a1ecd16dbc0191589b14c30e5187e626a0038b6f2396bb30c9b4c73a5b21db2128ffe67c6bcf81b0ccbc68a6fafb94296e334cbd28603a4f44da05a4c5d243e30160cd44f08aaaef7135632dd50830010bcf4b5282cc55e070478e51bdc87ed68534b8133876222986d525ec26624ad87e4a6910c6e3caac92e32e2fbf0945f8f1b201de5ef522aa4e84e06633ff3c092f8f095783da7f929013844458e3978f5e7679b633152a94880b6ccb064e5093a126ccd0435381908df6b4c84e47875edf323742429b7428bccdd889d602085d6b40ac2c05c705a91b41a9081586439cd178edfe7f909"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })

        e = "2fda05"_hex;
        m = "0ad50e46eb42d8f201ee505c91168bd00494cc1945b402f86b4491ce98ea559c20bbe42dee081492247bbecf0263c1d4094d49af60d451ff76ba66ace937aed5a7902a0a53ec38bcea645cf1a6593f3c220af8edc0658b85481eaf6dd1ffd5e7e57f6544e0954b5899ceb22b449e0ff197f3623c2c10b9712799f57818ead0b8"_hex;
        s = "d4abfe9247a4fbd27668d0ed8473bb4d40eb5d5ccab3fa2dc7662d52dd613c12335fd0f13bc99c34d6966aeae422a7e3c9a2389d80480c9120eeabacb884ddb2906ea80511641747229e0a07c2ca082b354a0a52debfb93e1ffa19787134c8d7b8f81c0a07be5cf421fbcbca0084ae5b2410771f06c4bca56a920139ee50009ef879631609f0478b21e6548446752ff85905d0c5a80414afe6021a3ab737f061134f8fb390b030b1e6a1a016b8ec34b0cf3b38cd1b023ee7dd6840d459ff83fb2c6b703abf646478fdd64cf0347b9b55c78f2c731cf7b0242de2a6f247932a5cfe1391d7d19480a7945a105e3088c3ac5b72c8e422991b0b36e3ecad0904fdcb42a64271840dcdb1625760361ce81f4f68bab447390b691bc63829f60af23a77edc2cf97c071f58cf8a7c414ce5fdbfa7a6725203cd54c3386c4c85cdf17f770aea7e79de4d8368fc68b6f6c024bdb4ef9c346e0d78494f7134b0e9c651540dd2cf8edb5812a5f8d9943622fac67d5ad8fecef405bcfb16ec1fbecef8bc1c787"_hex;
        r = false; // Result = F
        d = eosio::sha1( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha1( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA1 signature verification failed", [&]() {
            assert_rsa_sha1_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA1 signature verification failed"
            );
        })
    EOSIO_TEST_END

    EOSIO_TEST_BEGIN(rsa_pkcs_1_5_sha256_test)
        // NIST FIPS 186-4 test vectors
        // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
        // CAVS 11.0
        // "SigVer PKCS#1 Ver 1.5" information
        // Combinations selected: Mod Size 1024 with SHA-256; Mod Size 2048 with SHA-256 ; Mod Size 3072 with SHA-256

        //[mod = 1024]
        auto n = "8592b5850b9ba96e7faecbdd67e50ed5fb2018fda0bc6a09ab6345910fc445ac6bdb0e7a4c6b72c9441649c9e78109bbaa1d79f9fafb8794a1a06cb638bd8f3c3416d44c43cf862b8ac1d5006310b05a7760d341d07077ae775f1695061d3c7297dd3ab8fc5d03d09ed1602a1bb69891bb377fd0aad6cd90f8b207467db36279"_hex;
        auto e = "eef211"_hex;
        auto m = "23d29062797ec367d664542872324b63a72305caed23d04b0834b594801095d7521078cae54c21f33f04e622793fbe3f70b19c45bee2fb8fe98dba53d9462b6c9060675c150ee491b1c849e75ef1806f7db60d6fc7399fa986efe5e00546a399458c051ff10c33c9947a257f0a91b97b35fa034df170e4224922de45eb5826e6"_hex;
        auto s = "02d07177f91c0db0b74e34b532aa18673d27fdee370b7aa9094ef765c9a8278b7128f1bd24fd3992e6376f83bdea9e505be10de15163286a7c9d9873bdbcffe0535f9f8cb0dd99ba34e24ec462e4ad03618258b66894daeac9415545e030bd963f2beb8d089183ec7ff1be67e6f94e6871d42fb7d7c694682a9f4af599bfdf81"_hex;
        auto r = false; // Result = F
        auto d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA-256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA-256 signature verification failed"
            );
        })

        e = "eef211"_hex;
        m = "1e422f898ff258a99bc53648541709b3a3bba5828d36d070b42bec6a2117d6e6403f0d762ce6179d2dc220e180b1e52156a9d0291eed64840787dc91c1f20fda841797a0547b32bb83b668a177276fc4aee64b21fefa391522cc4e7372dc5cd5f2b3152f8e1973aaa48757afc3df7041b35b5e91b5c317cc0be48a38bb3d837f"_hex;
        s = "2e37c8221597f7e2b1970c40a50db5fefde31b1dff1e9b9d6a70b023acb014971580eddf1d67f15d9fbbddfcdf49cda14ccb7516c33b787a3a3fd43d005d02de10f93ffc99585ae5dfaa766c0f1f5bfa62e50e76a059a4a1e814c1ee9836e01595731dce48f94aa1ae36d9c5165a3eb28013fac271e091f7018fe96ec26009c1"_hex;
        r = true; // Result = P
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA256 signature" );

        e = "eef211"_hex;
        m = "084e3b56d68ea7c99068489e2c8080b9d3eb5ffea1e67eaea9c82af33935c5b960956ac0aec4d0ef3b0b71ecea50ebe9ef89a6c18f77b743279004cd703da91e01459b6516898b9d8ff30e1d3ca9fa6b5786135252cae734d410f6a1fe811627f248166c9645a27b9506665ca7f377e713c8eed97249d628b5314894696bd47f"_hex;
        s = "1b7dfda3e6da9e67ee9f207a9e03559fb5d7ec88f0310ac051e1e0612119214bcb11d1003bb5fbea088354c2a9c3318baa0264f67f0860f17528bfa63ee35f22908caf0e8e57c0ce63b334b747cc1a31ff90cdd550b27a34b05695a39d48e900a5e1ab4ce3f5030d903315a5dadbdbb0ffae04134a74cde2b99b8f8b5305759c"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "990d05"_hex;
        m = "c65f67c4843110ad555134fa8b9ec51dd9c93ff9ad5d96febffd6c95eaed88be3cd584f749c1c561c46bb11e50bd1bfd939202598cbd7c3e274cedce0f0e7ce3c452c8f6edf2d640ef904f1ebe20e8baf4a621e82041324e606942c83275db0b87609b8819cc2c93ff4776c47ece129d238f026e0ef3a07691dcd54bfa2c8b7c"_hex;
        s = "116b58e45693d6c80065cef13ab2f33ed6c4d3b6c5048ca2fac4c793b962c1d8315f6a76e379a0b4daa8e1ffe096291aa9c18b9a182d6f4c5b5bb6ed02b4a0fd39388e4ca5772165538aad34313696fa2a303ff024e25a301997f94860080783d87c7fd24f4eb7791a3b6be09c3f3ad0221ef8268444c40fd845617416119761"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "eef211"_hex;
        m = "edf40a32aed24e14439d8db48e80d92c4c11035dedd30d90a4ffde5dba8439cd274cf0bb63c155807a90f2cf5fac7add8297ffc5a4dd642ceae1162031dbf746a2229b3586a7b71d5bc2d6ac27324e320c5f73031de10a1d7046010a74105d0885fe7368be8d5b340fbda2148f183f7213f1c8ddffeae6ab5cb907e32b2b525a"_hex;
        s = "4e6e6482b8f163fb3c32ff454703a037b9882eec1f82dbd675c94accd79a476e12a347d2e9b4745d30164ce8484635aeddf1116df40b516e6b2af497d27f2194cceb801922aa6d55c935ad166bc477c8e54ab29c07f432b0aa3808e17d28254a0431fd0267e389a6b852f10df0f9a2f317c6a6e762c7395e743b38341828ac10"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "eef211"_hex;
        m = "b1bd4eedcbef7c57ecab2aed92cbd60052ddeb201181969a7713d53fa18ad16716a06d36fd341f1e8decffa5c41e1d695cf11861fbbfec65aabe0cf188e0b126bff77111b81d13308b53a232ba68c0ff1e1d3df82186e8802eb3a5bb6690c095950a810764730196d0283b1cda7166ca80a8836eed9e32f2ed3ac925a363a7bf"_hex;
        s = "7a0225a29a5f3e4592843c5c4d543d14ac544a3eeee9dd5e795ffa87c4e16dabaf07ef75363d773d89ca712df7c32010d3ca024ed84a954ff9625390e498d04e2c676f3c51ebf0a46fe22ccbffa53c52f9a292886e6a8b64efe5717c527dfaed41d2290c79c18ab28a96ab5afd2f071689653550a64be24fdb5f90a8014df659"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        n = "8f705d5529b5bf74600abc485bc4bb76deb9627088e51fdd26dd0f37bb3b98a9da4094d275d55011a844884122daf8b4abe99d43d918eb50d9642436647f60577c5f60fb9b810147a910dd7dd610318392dffa3fcc41f89f461bb5be85bf885b672cecf00da3af4d7d90074c4c0144c4bcd2d49145f8097648ec7230747f7033"_hex;
        e = "d90b53"_hex;
        m = "10c21d2d4afdf3502dac1a791216d0c240b6b12061e0cf3033a7043380fd8756501cbe385d2553a6c7078aa909a3d2c22c2e9a743bd66503f6a8217ccab1b4f50163d916373b2ad80da17d8d211074213d76509fcede06f6984c95fea9e896b68b5f15d0be879f6f65429c2f40a4e066da587ca9043fda92815b09c103ec5521"_hex;
        s = "0411589c7d0860d41c7d4fef4d604b4dca0b160529209e762d5fc73df911e7bfdbe16feb0def70993e64eeb66888e47b3613256dfe04e75142ff2b325fd86b8e02eb01e4cd05b05cc788f014c170d584d092b7220a66133d4f0e949457eddc567eda792abe49b8a8fdfe177c6b6e0d7ac4262e95fa87c1277c46a759f9723cc6"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "09ffbd"_hex;
        m = "393f6cd3c89e67def9579e586c945fe97d567bae23c54a2e18c5f0903bc9df0b32ec9d9d533ec800c55b57dae2432234e065a52db1fd00ef27a043e35c15e9215167a22bd53856daa9586698e19735d08dd7e7a3996568ddf289b027ea5b467eded903e316371954ec7654fc31389fa7ccd3c978a4a489dec1a6c0c4ae42ff08"_hex;
        s = "327269d1d4d871a8be4ee49be39c5a51482fbe89d522c0d6cfb0ea6bf0c6f0b343a94222ef65058e27f5107e4f8d0ce20a064f19ac39189f221c5e62ad4fd7006eb1de620052bd35c268d5c1c6ee0f81e8b3f7f2977d2449167caaee2ca54d458108645268749651de6f7acaff09591d19ac99dc17d480ef3531ed4c14eb85bf"_hex;
        r = true; // Result = P
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA256 signature" );

        e = "09ffbd"_hex;
        m = "036f62daacf68776f409d0595509a596a544b085ec7649687390324e1db78538fa90ea7b1abb0d659f9d50231663bde208433e35cb0510b79ec375f1f6eda97e128f186cd5d7cee6d5d22f10b076e8339fe5251a4df005bce9da4a1b795f566b72f553778652b141be2ed5e8c84a0fcf92b1cdfc183e0fbe7a5e1b9351177248"_hex;
        s = "56c4af89728a322066b8c291b4f03da5a038e4a44ffd9b49be9ee5d1a800da1c58e7a852218eaee853f9695dd308e1a5fd95b41a441c2a6bd124088868fa26f384c9ce87849b2eb5edac55cb95d5dcda7bfffea621b3fa66e6b200ce755b947e778fbae07490410509f5036a07280f943b7300562926cdca3b20097f1ffc24e2"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "09ffbd"_hex;
        m = "8c25bd2bed75a33ac134f9c1d445245fd8e580d6148fae11591c2b65382f271772d0941eb0577d2b748c99e7500c207b56efdd56cfa7852a302b47384956a4cec089810ebe987af0e8e47a8b91c488902d2ae4170983539e3adeb74ed451e2815c98ac827f0043930384c335ff3507a347dfbea02be9c172617da42f3fe98a37"_hex;
        s = "56254367f71f6f1fc6944ebd29f8a5592095ebc73ff5222bd815da17bac7f12290f747deaeb29b98c98d31a3ea32508d7683a67d449c59a0d6c16b4855aaa7d6f170c02c5cef61c9b6889207ad021017094d24246c4c90a0de055f02a5984efb67481684667eea36ad6373c36712625fa18d3ed41b1dec22f3bfb0d534e52da6"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "09ffbd"_hex;
        m = "2cb9740e0c1b8867866aa81c64122295854ed681e8eceabf0651bf7a65bc23996acfc8566f4bf42c151b7bf7db94eb57f0fb065546477549e829bafb8d4a67086dd48d87533378edf41d992e7fcfc425759a9c36bb9f4b32eed7767af6566f68ded0adeae25c7a70ca78ec09774d16c8bc357f6d6f7bd441bf62d942c768a580"_hex;
        s = "156747b263be659661e5e35e363d0523303ded9eec1e751575ab3a43156773a056acfd0daaa68625b1cc068458ff9e40ae167594bac846cca2b98bf6e5a4a01e961adfcd70206c05d66e3903a64b61afcbd17391ad0db529944fc2d0d7be3a4da8091cb75910f670d9515ee4f8ff3d62307eb54657e03a330e3cb0661e6fb796"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "09ffbd"_hex;
        m = "127498bf44b97a4a4ed7ad4bbc7c3781e2f83a53149fc95c1a6efa27def23d376866ec4b0c1c23e0e21ed1f677140f17c268b1965aa91b15e62d5749d4fb64024ee7d06569ff897ca026f0f282ff2f17a70dcc2ae8187fd8cfd241004dbaa6b9ab416c96c32b5429703930c543053e88782db49928b39cafc0a4e2d3b1f8ac66"_hex;
        s = "1976fe18cf82bf6ba851626bf94509348f56866930c771c82a6e12c30735c283694a0eeac9337e407525e0a831ba7eff77299c6896a85050b960718a40d5e34b7bf71eae4cdfad0d91d8fa6dfe37f30679ef444ccd360971ddc47e038123b7eceb3072f370796122aaf0b9427563280222328fc0068ae1dbd39a033740789536"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        n = "a16c7fcbb8d6fc602277e9cebb1790bd14999ef7670400c0bd0ea6116fc72e29b868c8b62ada0e7b4cd351b5a76c177f158b4f724f1d287d66df114eabd68e3e8d12409b69f96e334c0daff79392d184b9102ea5c4ec13052bfc509d9ae76851e8557a417b86e9d37687d243cf48812ce621c5f39404cd6b22a60beef744a42f"_hex;
        e = "681201"_hex;
        m = "e24695128cc0f0e9905a6dcc1c54e481ef431c0426a13e2a51888984ccbb48864de601e8b927f04d3cccb323985f47cabde033f89b51035c3478f881f5e0fef64621deac6061b59f5e1ba5b8971fcaf22cda70bdddd883a021874621753e48e9f47d95242877292720cdaa55c29d564363bb3a1a953ea43d403fdc2cf5dd0fa9"_hex;
        s = "88b9604e95ccc993514a258d5a6785836b3c0ceda1f9a8359b1ec9592100c9b47572fb17d2c24dbd6b99ab46c408b7bd4b8094a44d05c2cde1145ab516b36926358f980ce1eb2e92793f65f34f09a4053f8deb77025052e12922e3f14823859d7e49aa54b7a7f0b20c1672e1a278ec631f955b4c19da05dd9c1f4487a0e08f31"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "681201"_hex;
        m = "820e27d35ad139ca305e9eb26c128ff59dcac86f05522e7e5721b458bf437fa22396493ea93903647942bef4c4afcb0a05a021d386c300a0260fd4395bb55c7473530b061f6baf983115501ea5f05b64de5e00e933f1d8f1aa20cbd6033f319ff9ae37d3c4508490e23e1dd717bd862ab36e2b5913c5fe996abc60d6c2c945"_hex;
        s = "519c717e336e7a28d648acf178931f6cb958684979b23e1d53ad32aa242e327699ca1a1f294feeb8b6ad8668b75a3e42ca4ce08a91c3fcae06c7974e6d9e23e622363cae4cdcd1914d31f38f95002b1a6da863e70c244411cb1be90ffea30ca4e345429e58eb751f676ea7ebee4363c552aa5bda5d57908fd5a87142db8d9821"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "681201"_hex;
        m = "d8330fa49a0a75f27470a2898ec1134666515fb467ad6b74be23dde26984d3f59028d467193307167717a2abc25aa6790d9acaa8f4ceb49274ce6f6d00161a2bd0c6dd9e7dee22e0cb0901f2c5c7fba31010ecb379453b39d0c95442f9c058bb40161291edc32e16184ea5a7bf907c8c16bbae1f1e9b6730791b72a97d0af56e"_hex;
        s = "5a692ebff6a43c5e63602018577fcac17415fcec4087e4c41065da33dbd7d87862de2e0c003bef2ebd0a411884811c7fbfa893590ea885acfb023857b904b0aff0e5061f2fe3376be5ae4de0510b2c34be6e0192722e63dd6f3fa9a7f8a191b7160997c463d7f7d46577e6cce534da08d1e5245b3a03b780f8144070cb66e6ff"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "681201"_hex;
        m = "243db9a1c203c792db3204bbfb3cea400d6e5efec0c935092f0df759c016e3c04c6b331f8115a1da85ad2989dcb911f18c3927327f7c4a4128382b996ada552eb51b6ba372d4b1bca113ce16c06ed116ef97711f53319908b8e224cd7aaae584a573ea935be90121768b7cca6f0232977fb2c62d03902c442533685bb92d99aa"_hex;
        s = "8d1a40fbd8186e3cd1dfbb529e1ee9ab13a6c8e6cf04e663a4de2349c05334f0ab3c694ea89397ca3e70a2a1957ac75a6544842af88cbe3ebf641f68cbce75638da1c953c3f594f8ee8b3825ab4aaafb9fb152f05bb7dcc07e3b666ca8626e69bb262bc240398007b871b7790eca96512d64f3ff94470224fa075ce3164cb1e1"_hex;
        r = true; // Result = P
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA256 signature" );

        e = "eefc9f"_hex;
        m = "186594f37c9ff1fe3ef55bbb511dfebdcf5b64723cacddf80f4425326e3b411c3a84aa5b4b1ead19fd8e120feb8cfce3fafd10b59a21d9f5480e6b77575d47c9f1237fc459231b617241bace853a7dc13f93200df9cf6a733de5c8ba85f13501452a5c552c14017fa7f79d1fa88f48ffa505dca1e31e581af4b382237f61d16e"_hex;
        s = "9301ae4d76e84df108b70d94400c0b2dbf0b024fd5cdd5821c408ca2f52b7d4466a43abcbd8f40e9c07c4e4e56ad1ff471327e2e997d4e372d82c3e9f9db4d40d4d6308b4f7e5ac91c4ee2c194c038f8275dff82b9cce56ccbbd2ac3d12550f184b1cf938cefc85afc588c45c1ea055da0d4dadda266895cb4b84b846d8fac13"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "681201"_hex;
        m = "2ab6c6ad26e227177b6458a1caf18bc083c162a1f18b0fbc77b0baac19b7223e3df988c8b39dc9bcf4c7ca7ca70d18706a2bd057cef7bddaa397c16777f1763c596314c2e3b4961d774b1801c89f84c79cef6dc0d1333bc99e52891f1c95cb75055c3444bb10d7638c580cd7349015eca37701850127d1b0f04bda7d118c6a11"_hex;
        s = "8a270d2b49cd2897df192e12121ba6b92304e89a429753727e8cd7fd8395ee72788ecd58d91ab99b4385778fb8f9a5458a79790def0c05de8b5646c16f2f8f67652708573216f13335fbac257e4f6e46119fe5b50c309a7c01731c8f8fc240fc68f08f25879a32156dcded375c6ecaf0bf861066de3a034bbc00844dc74b8b6f"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        //[mod = 2048]
        n = "c47abacc2a84d56f3614d92fd62ed36ddde459664b9301dcd1d61781cfcc026bcb2399bee7e75681a80b7bf500e2d08ceae1c42ec0b707927f2b2fe92ae852087d25f1d260cc74905ee5f9b254ed05494a9fe06732c3680992dd6f0dc634568d11542a705f83ae96d2a49763d5fbb24398edf3702bc94bc168190166492b8671de874bb9cecb058c6c8344aa8c93754d6effcd44a41ed7de0a9dcd9144437f212b18881d042d331a4618a9e630ef9bb66305e4fdf8f0391b3b2313fe549f0189ff968b92f33c266a4bc2cffc897d1937eeb9e406f5d0eaa7a14782e76af3fce98f54ed237b4a04a4159a5f6250a296a902880204e61d891c4da29f2d65f34cbb"_hex;
        e = "49d2a1"_hex;
        m = "95123c8d1b236540b86976a11cea31f8bd4e6c54c235147d20ce722b03a6ad756fbd918c27df8ea9ce3104444c0bbe877305bc02e35535a02a58dcda306e632ad30b3dc3ce0ba97fdf46ec192965dd9cd7f4a71b02b8cba3d442646eeec4af590824ca98d74fbca934d0b6867aa1991f3040b707e806de6e66b5934f05509bea"_hex;
        s = "51265d96f11ab338762891cb29bf3f1d2b3305107063f5f3245af376dfcc7027d39365de70a31db05e9e10eb6148cb7f6425f0c93c4fb0e2291adbd22c77656afc196858a11e1c670d9eeb592613e69eb4f3aa501730743ac4464486c7ae68fd509e896f63884e9424f69c1c5397959f1e52a368667a598a1fc90125273d9341295d2f8e1cc4969bf228c860e07a3546be2eeda1cde48ee94d062801fe666e4a7ae8cb9cd79262c017b081af874ff00453ca43e34efdb43fffb0bb42a4e2d32a5e5cc9e8546a221fe930250e5f5333e0efe58ffebf19369a3b8ae5a67f6a048bc9ef915bda25160729b508667ada84a0c27e7e26cf2abca413e5e4693f4a9405"_hex;
        r = true; // Result = P
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA256 signature" );

        e = "49d2a1"_hex;
        m = "f89fd2f6c45a8b5066a651410b8e534bfec0d9a36f3e2b887457afd44dd651d1ec79274db5a455f182572fceea5e9e39c3c7c5d9e599e4fe31c37c34d253b419c3e8fb6b916aef6563f87d4c37224a456e5952698ba3d01b38945d998a795bd285d69478e3131f55117284e27b441f16095dca7ce9c5b68890b09a2bfbb010a5"_hex;
        s = "ba48538708512d45c0edcac57a9b4fb637e9721f72003c60f13f5c9a36c968cef9be8f54665418141c3d9ecc02a5bf952cfc055fb51e18705e9d8850f4e1f5a344af550de84ffd0805e27e557f6aa50d2645314c64c1c71aa6bb44faf8f29ca6578e2441d4510e36052f46551df341b2dcf43f761f08b946ca0b7081dadbb88e955e820fd7f657c4dd9f4554d167dd7c9a487ed41ced2b40068098deedc951060faf7e15b1f0f80ae67ff2ee28a238d80bf72dd71c8d95c79bc156114ece8ec837573a4b66898d45b45a5eacd0b0e41447d8fa08a367f437645e50c9920b88a16bc0880147acfb9a79de9e351b3fa00b3f4e9f182f45553dffca55e393c5eab6"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "49d2a1"_hex;
        m = "915c5e4c16acfa0f49de43d6491f0060a944034475ba518572c08366a8d36c7f1e6afc11e5e4649757bf7b9da10a61d57f1d626847871d8a2948e551b54167c79de88d3ebd40a3e35809b996a53348f98a9918c7a7ec606896ed30c271e00c51953dd97aa6a8fe1cd423c3695c83fcf45120ec0a9cd1644642182b60e599a246"_hex;
        s = "3d57ea5961db8fc144301ca4278f799911229d865ea3e992c7fbc4d03c6551729e26034e95dd71da312340e4051c9dd9b12f7700a821fe3b7c37785d5106350b667ac255a57c13da5842d90bcadea9e6b1f720c607d6893a2caa3c5f3c4074e914451a45380a767c291a67cac3f1cab1fbd05adc37036856a8404e7cea3654019466de449ad6e92b27254f3d25949b1b860065406455a13db7c5fe25d1af7a84cddf7792c64e16260c950d60bd86d005924148ad097c126b84947ab6e89d48f61e711d62522b6e48f16186d1339e6ab3f58c359eb24cb68043737591cd7d9390a468c0022b3b253be52f1a7fc408f84e9ffb4c34fa9e01605851d6583aa13032"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "07485b"_hex;
        m = "03d2f0693517cffb2b724c1f30502c5359c051c1bcd88dc1dd54b89e6981009d275a813b2bf016b74d0f6ed0d91e62d0884785c9afd8fd1fb7e99246cd4005cdda71a39cb649197a996d8ad2d23fdfb6bb015f24ec3d7f88af64fb83b4b525eb06607d133eec834cf7d6c9ab817b4c0dda370459d9cfba05ad0c1adc86a909fe"_hex;
        s = "511abd82218cab344979b2887b02600d2427f1eb12ac01d97684c2a443a9272834c3f79cded07a39dbee3770dde827a74dc994b17bfd8a26d07b239d26d58c42f79d560264c31b7e1c3dddef6d7556f228c394414f4cec561c3da2686a8eebec7702f32850809a93deeb84b2a02fcdba224d2fd9efb8e056e796f49b57d56e9f3e90d0b49b08bdee93a2e12e676fb4d4fa838c5bd88eda008f1b592a72465587be0ae17d9b156b904f44a7e04d3b58d24ad67b71b0f4c699fa51639546b62b9f83597ff03d465f1bb396ae15e92d0e92e85647d5df113e2c7518d0e3ad2e7aa7dac720c98347aa151e4f37fea081dbed350cc9c93f606b38f21a3e5de6d140d2"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "49d2a1"_hex;
        m = "dffe42bfda886e1a73fe8a8dfcf71c9fb44deb054588a9bb9199d554aecce08f2ff88f2aa6f8a0fb675fb03c8e685c27432ca7c33c189bfd849d34fa7b2979ac1f57eca389632426bae0b98398ad60a3342557e14e96041c1bf4d90b46cf7ad1348322d28caf43c4f7e86c0924ae703c109ec50a84ea2a43df078c3015a52b28"_hex;
        s = "8f4dd479239f2d08dc05d7d40539288b67c4d77210ecb16be76f0b1925e8b088570831e361a1ca57893135f8af64b8e2996b8d635899da4e04c68acb9b1b3813697d57da90c57f18509e0ab6705c704feb448cca5c07d258ecd884ab93f508cefdb25f2bc3061c4006099e2e33b27972c3edb0a0a33114d381c82ab506d041ff680af595ef3400a8bb6774030d2e38dd304272092bd32a553017f7bda4b998b27aa8aca12def327b1f11063a5342b0d55738183417d321c5682fc4ab64e79174216feebb989521e1e3d827647068003be34fe1d093964d28f4877c49b4065672448597a89b91919cfb55ca13836e7e6f3b3fd04f417cf1c16d9872538bf4e87a"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "49d2a1"_hex;
        m = "cfe99788f55ec6944942bd0a187d51b80fd8bd4051bd4f07c73e614eb75a8b9f997b176b2642b5f1b1877061ba9ce142c1d2a311583f072b7cbe08ed253681191c209d7b0d438fcdddc284d93d59d6dd80e48333a921dd31c9b6834f88768f8701e01102d3e8bdf074fbe0b8c93d9951f41545ef6eeb3be35530babc079f1fb3"_hex;
        s = "9fd6f6107e838107f906c26cb2910704599f175b6a84db485fbc30776eb7fd53bfe20c38c537b154a3e519b662bd9fdc8e3045e21f6e5ae97d0ff6a9d8632825544525d84f99f80e3ed4e69dc5e219d59ccfbb37c23c84fe3b3e6fb22f402f94e5225c6387fdf8bcdb3508f8832908fe05771521e92234348004e8fe19a8f24bebcab9f074327c88d066bc12081748d696be6135c6aea32220ea786ebd7800e6936365ff25831c28cb6c8a59237ff84f5cf89036cff188ee0f9a6195f2b1aca2e4442af8369f1b49322fa2f891b83a14a97b60c6aeafd6c2928047affda9c8d869ff5294bb5943ad14a6d64e784d126c469d51e292b9ce33e1d8371ba5f467b3"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        n = "a17a08272e656cf600f4650ef0952b15d568d9fb7f1b3f3559aa3792743f7d895e4e26dec2bf09996de8a99f7c434bc25b0c7d61e83fe5647c213b19902abfa053321a16048642cd3800de26172eb39ccab029130ceb82e5c25c676e89007cb00666a2d8f64e59fea64628cbec9c361abe25841551db01f58b80ab17f02a93cbaaffc2630ffb6f56f206b8a6f8e0f1e5790652e7c7227258dbcd5924e94876f983ed02e4e82272f5d44967bc501d1515d80dc25d5c838d0357d0d1704b0253d6e78802c02931000fea2e865c90b266c8a0b472e8eb17456777973342da6978cb45d2100cf91ca6f6d69ff30ee8f3164bfb180de0b355c067bd8f1a8544b9aac9"_hex;
        e = "66a13d"_hex;
        m = "41c00eae64f3e330222e114541eeb5eae1a705ca0c0687a68e7982fa07f1b3de3ee7402ab89df2dd8aa69ec06ba8e4460d611cb7aee88e8dea35e11fd3e4d77c4336379a71590ab0c3e909e0e3b6571915c86c3cc8a0517d6ac1130d816f72f6f8b7d946b6af936f76ff3beed2a0742ba0e4dba082b73a3eb924ff0c3a1bec12"_hex;
        s = "13165444a1f039da049b998e332cf7655149975713b5378ac5772f2e176ddbf338a25e297d873cca5f19eb4e4157c532d06249d1e99c2857f8d74bb74cc7593bc872daf5b45541a373aadc43a0711b3b2f27ccfed06d9578b2a3c7d10a12e398d0302f86e05f154e3cfd2a0e072aae157cae529bd5688fd0ccea22f58181d069eaa0957a5b0eaa2e3f5a4aeaf3d1512a43dd2f8434579eb57e23852d7323c5dd22359e9dfec59dd75ee3b8e234a41863fe0a68c46f777a9f48887a786cfaa40db1c7d9e04efb8a882d8169764b47a013b5d1d15f4cbf758adc83c53e9548e77de20f14b3b5f064465beaaa32ee41755aa48264a14df837ce5fb85a5ab91bf6eb"_hex;
        r = true; // Result = P
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA256 signature" );

        e = "391c9d"_hex;
        m = "671ada018b6132b381978036f19cb9fa9cf7d07334642cbf718c59896113fe2d00d70f1c087743830a13c927be53379398abc3769bddb54772bf1c2abd3ec017a9a35939c315fe940e5fe0eb52f438e1b8307e5e94e1dc348206e203b4d77b5a8a05201e63424b30b4042f4a5786a62a25106bf3c67989d0c8ea13daefe4163c"_hex;
        s = "2942af5fb4e5230990bd20c2095fa29e9aefe6e6489111971f0dd397e8d461ab3f59c0f29b86d11ff187984c54c51b0bea35f479a4b83c33dcc8f149f56eb9859a71e45f3a33b83d30eca87bf19803eb5888ead3151d9b673546e2c0dbdb523c34331cbd3a83baae6b55dc465de20d40c5bca9647d74b8399d6e40404828772690afb93b314a55efb5149603c8421fd85ba5b61828c6f679b53f929398d87affb8929e4684631aa2e86d492d3d7c9a90c58e465080442f69623e4eb2080f7af2ed0442c0bb3f0eccf45d4f075e4474a2c058665f25164c457fd19e5852061af9b232cfd2eae7b60001364c013a1155a9af18cbc134d1ee8d30c157cde3a9ffbc"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "66a13d"_hex;
        m = "be91864d3728f895c689f09b28484138e0afa29589bba7486a68f0bf4b2ea1e287cc11f46344c7ba9e27a2e049125798d97921847ba3b3d6a7f672b6f875e1e43b875c9ec6fa0ac40b470d3a6c18fb8e510792da78a9a7ec8dcb60a5fbfba39f014bce120851a9f9347299703961166170e25e5f2ad46bd2446e2355fbc9d05c"_hex;
        s = "631529e0b149ee1528d514861cac711eab8c01c1c22c7ff6ccbc08783a1ccb2748c22e57a1deefa867dcb1ae74c40b1969db2cee64c0706af8daf4c9e91c12672d8f0849af4bd0c4c5f8e439a3ba7e3ddf38a9b38db545410dec0aa40522d6a3cbc2ab53a838298f0b93ae7d362158f04858fc33ec03fa6d3b7ff0f27d74cc4abcedd25642f4d259d41511456004c24385ec32553ae5d5728a8f68707ddd6bfa51c2f4574e1c96ef4db0715675fa4fbc57b9091759eda387e16057e9d89797f61df9196044b98667866e12c5132928eb735fa2d02c0ee7e08ed68d80fe1f76bd85756a3967c6d3e1378a754fecee72362928cb622731bb01231758ebcb805f5e"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "66a13d"_hex;
        m = "4c2d1103c36e96d179291397b1238177d4af3b6fb9dc622d23ed80258b096be020346d970d7ea100fa7aa068d5f25d02d2d94e7fb081cdde3f0fbd861f2b7092cafcc86cd4539d9d72265fe33a41fd84293805e3eaa00c51557e502537009c0f516b6ca9a355524fea149831677627a6e2b3a7c4ef9fe82d7024812b5bf0b700"_hex;
        s = "4d8b5ba1f5409f476221b3527be6389c1ca3eb50cd62113ad2f712cb2142ceff3178948670c9cb7dccd44896ddec9c0eba228370cb23919610774e9d70d6eade95865042edca6e90cdc007234400591e1cce71bfbf5a546548d483e68905113693a3d1719ce376e72b180b7f3c7ecd13469b8edd7ef95d9e330d78cb36e37b50e87d161b1abdec433421a3a65b49b39cacde0678de41df894d6a2b0f171cf91052bf0f0bb7cc89889bed7699e33540b4ec8f93ca2c690783dc5d80fa5b815aab0feb3ef4f10c0cb46496aaf6dfd2e5b3a7dd64386ab9a4da0319bd927facaea80ba5f4b1d71e16fcc7550fd8211756c35935507a32f204858e2b475d28eb56c8"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "66a13d"_hex;
        m = "e896edb0455f372c01d222d40af9298bc17fdbf450b4d0923dd7e12d4095987752cde6ef079614061d83fc805526791e81d21c7adfa52132a5c6a148ddec09c97320caad8dc352ff1ad23c3eae69c3028d867de20610469602187959dc5e6791731701b27eedd860204848d4bdccef800b2364f66cfc26067b53d326e4f39b18"_hex;
        s = "6e21208ce42d4ec6512c300f6f9c0d43163eef7e05365448380ce3fec34913a701a5e30455556335101af1ba40ea69fc17b30c4192730336e8af2094d36873cc83617a3feebd2b09dccac1b31b9352c1db3c3dbb7ea1e774578e44c92ea925dafd9de71c46d3f25eb015199150e6e8c26ee612edc3fe2f0ca6acdca9274fcaa87d97e104112b1f85d1c3f3e92f0be7932613afe5a683c0e52f9234fd9ef979844e277e31d3c2b725bbebe97a9a8e619f8308c01a9b3ee48e5dfcca5b153e4890effb297ee0fecd30fd71b6dea0694530fbad6c65abc4621f23263ceaf2cfa21fcd19cb180812667e8b1ae108323ec289826412f124547ddd92024c0ea9784654"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "66a13d"_hex;
        m = "3f49b00ac1f9255907cc03f9b45dc787c250d9d6833fb389e2f746e1ede599d390cbb45ea3b7bc1b28365f16cdc573dcb988d9d5843fa8d4877587ed57fa5b878c9423b1c7f21fbaf3e138fbcac39cf89b3ca9a84b2e0c109be82a17a89abf95b80cc4ad3390975df0365653b23e8b02f3d30ff6e0f62864a4b8f506e9ac0c25"_hex;
        s = "90ac97a93a9f6c5c6e268e3464b6d547dc29bff8797d9f776e2f56fe1c30fefbb679ca9fafba40f400f08a5163d757e638aee083084581b760ab30071e075f90183db328e1ab519fedca1ed92a1e4e473b538e2470606b5379abd2e4b73f4c132e30c115bc34c73019880571c30fa6c6c1e320c13022317cd3acea8c520f87cf054e84be89a952202fc3f8d0d707cd8806b8b22bf2c0d7bf884688607a05b635210b9a7e2e1d2a28e324c1573d363d5a76ea0aaac70480671caa4969e5177448e62e76270197697fcaab720d811588c8ab540f053c8b23b7cefad205fd4c444bd5e73d80c62451158331face2b6f7ddb034dd5e61bec444f68d0c7e39d2df940"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        n = "c9548608087bed6be0a4623b9d849aa0b4b4b6114ad0a7d82578076ceefe26ce48d1448e16d69963510e1e5fc658f3cf8f32a489b62d93fec1cdea6e1dde3feba04bb6a034518d83fd6138ea999982ab95d6a03517688ab6f8411c4a96b3e79d4141b8f68338a9baa99f4e2c7845b573981061c5fd29d5fc21833ff1b030b2deb651e51a291168e2b45ab4202dcd97b891925c75338e0e648d9d9ad325c10884e1fcdccc1c547b4a9c36aef939e8802b62405d6e3d358ffa88f206b976b87f8b12b827b0ee7823f9d1955f47f8678f7843b4cd03777e46717060e82bf149b36d4cf3d0bc7e4d0effde51a72f4ced8e8e5b11bdb135825ff08873e2f776929abb"_hex;
        e = "3c7bf9"_hex;
        m = "fc8e19e3b26bbf7c8c33a452b7ee02cbcf56fa94a58b7cee3e0866481fd6f013c7ff47d27e4678704d1590d74eb701be26c748c2cfe9cdb99bb80b4375fff0a16a2b87cb6900d4bc478c00110659b6d257e7cc905d5926b0b46fd706b2b48aa6edf921f6fd019b08837e3b276a3ce6b06c9dce24d8454d7a931613ba5d5f84c7"_hex;
        s = "058bcfa4b10ac6a73918a07b9f0a8db1ebab9a0ee5c7f0a2261b98efb3592eeb6bf45fceae24ff20c2683e1b33291f49a7f86d7fe239c58a45910a14748e10c25a4dfa693e5a77138de2fe5f61de0a09078cd0d3c61b1e740bca7a3d4048d4fa12fe69412438efa18216819be40733500acd8087f429da734fce6a97fcdc9c32991dc847e4d653260890304f378a10b7754cb4ac5efd7a3db23bd44b6542b81ae9fc33edca6eb1570b1a39a0b8976626c3892afc42e6fbfa8bfbc191c3d026a6248e7ee391f977ea5f0442306ce87702ced7b3f00bf0a6040604d0a663859737ec6c04dc84763d1cb63c4da8381a08cc52b370ba09515b93d9a6d3e47c5929aa"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "3c7bf9"_hex;
        m = "4c587ab2ddd6b13bf7a916b5d571d7613f24258201b1421b9de4dcfb3d8a99f7ebd5f37704024634ea38273ffab4f846be23b913634f21556dfeeea3a91779be63078d16da637990f1cf6487271ee111c9bbc483674733378483008c9171362f1db6f199464373d97334759445f8bb4acab3ebdaf4e09f494a3bb9bfdedef7d2"_hex;
        s = "052bc5efecb052b92821c405e6f22cf374dd1ce4bf691eb8abcc1cd01254a6e51fe9237cfb9cadfe32a8780135949399b048d26f5de49bb9d008d39b749527eadd13066baff87765eb255021517a2ea69e45bd35db1fba9219c94f944b2c9a33a37779505c8eae52d6061988d152f9f51f0002e545973402294dda7f7c7cc3135c37ced8cf723d4011d1ac16bc1d0bd670eb7f63f079f30dad8cf55c326a33bc1684ff17a91509f4ead4f93c3c0eb6679eab612e05fc71b936c99ca8579cdeb9f26200a4bce89e330fd5d84b1ec98cc1d758243001fb18bc325b630a58154c2d38a5a8ac2ae6cfa54a20f7580a745c206990c142e8a580eb36266a3a9602a8bf"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "b53999"_hex;
        m = "425994d102a63f542766b12d5207ace27de9207630c2fdeaf741450413f1654f7061c563d7829e6665500cd33cb4647a78a9c7c9659ff749ef1c6a6b59a99d8532ecab1885121e54517005de386947d07b923602261467888852c27be6ccd5fd71436d77741f6825d20dc5d5b0ecfdeb6fea96a9ddeaf5adac2a74bb2322b4bd"_hex;
        s = "c1f91aa430083ad84ca80ffae2d1ac2bee9b22bd0947175ffd03bd294f6a3cbb5ac63afdacf02f7a6a274fbc33f8aa25cb08174c9c4aad0cb9cbaf02e6f72a8deb6ac52ba88da773b4fd07b33144b9a28a23a1db150cb095cf03b208e80dda3263806b6b0e8eeeedd624d4eb8028e6b98ef2a3e55f38f1b0041425cf7557c41d35d4b0383448c800076eea2c22ca2f333496bdf53564f39d76822f55cb767cc1c2d516a22b4c6fc1525608ba61eb42c04c788c7050a48b7f3a431b2553dbb52cc065a9869c49cc021d7e448dc7012842d3351f98820bccd4fb7640b85fb431fbccbfd4e2544b6f3c7c270326c8cbbd216333ac82260c5edb47a301acd05c7c7f"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "3c7bf9"_hex;
        m = "bf082fa4b79f32849e8fae692696fc978ccb648c6e278d9bde4338d7b4632e3228b477e6a0d2cd14c68d51abdeed7c8c577457ec9fa2eff93cbf03c019d4014e1dfb311502d82f9265689e2d19f91b61c17a701c9ef50a69a55aae4cd57e67edc763c3f987ba3e46a2a6ffb680c3c25df46716e61228c832419e9f43916a4959"_hex;
        s = "621120a71ff2a182dd2997beb2480f54be516b79a4c202d1d6f59270f8e4d4dbd625ac52fe0e49c5fd69dc0d15fb19ec58c9312a8161a61cb878abcb11399937f28ff0803877c239ce0b7c4cbc1e23eca22746b071b2716475424c12944660b929b6240aebe847fcb94f63d212f3aa538515dc061e9810fdb0adeb374d0f69d24fd52c94e42668a48fc0a57819952a40efb732cfa08b3d2b371780aea97be34efb5239994d7ee7c6ab9134b76711e76813ad5f5c3a5c95399e907650534dbfafec900c21be1308ddff6eda525f35e4fb3d275de46250ea1e4b96b60bd125b85f6c52b5419a725cd69b10cefd0901abe7f9e15940594cf811e34c60f38768244c"_hex;
        r = true; // Result = P
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA256 signature" );

        e = "3c7bf9"_hex;
        m = "bb40a410b0183b32df12f739506643bdd2fa7e6aed83974918ecda402cfb09dd1932af4fd7f3b1b5a0e8269c5da268c25e806b204dd34e28653f304cdf6545bfadbe297f6bca7493936b8e91f08bc56455059c4c8ec36626972414ee0ca04c82e1aebba953e5ab531e62d823f16b7f2a1f51b9f6979b07cb16602e309bf545ad"_hex;
        s = "3f6909f674d4c9c2c26b66d8ee3d7702c560b193a8fbfd0ddb3a9dc909a6eb7aa74d446b7993cdd5b7e272d826281e4cfa08000d2291c2ebe3ee6a77a4e03a79248385359d0885c61c8ade8cf4de7c8e51e879cc1e6089a91a56dc58d2b239e185e9afebf733e2f0fd061270eee0670122c44fd17af6860b6f59690a1b2a91e16522e6a75903bf4e6c97237825f0b01e4c236052b173a8d91f910b0c903590e16d7104609ff9c0194ffe0c09dac1969ea08b01497c8169c7357e8b1f1040604dc0f8b967bfd075284736aa22b0822d3cd13c48a8169413e0b6b26af56c577c829b38e3fb5c4ff78949634d14ff3a40d0d43584d832d6b51d4065e0900ef197a5"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "3c7bf9"_hex;
        m = "56db10c78e9fab7c1c356bf8b38e4adcc464ebd1a3cedabfe812144016baca547aea625656f0bf2e3f1dc2c9c4d310c650e01672520a4bf79aebb5d00600af805ffce9847e62b086b35270d367a3770fff33fb28047b5f888167b28fad647940cabaae3a4d1c08ea3f7d7d00e326061f9906a2d902499dda652c1263520faffb"_hex;
        s = "8432cca3357f5ee765bd37dbe2b2d107dfd840f8f720cf4a80144740f96e47529c553fd503a25bfac61ad76a24386af72d81522e6f05b66299f6aea3b98b23838e7dde04db8f8b0f32ae393f6bc0bd7070e566ba1fea53ca871d680f70cc9585aeece672d7c64c228c49bf1ce877dae73f9d8756433f5edc4331415d51957d23e490d4f25317d09a3ad06ec9229dd706cf593915cb156d7f7a32d68e52ca27aea7087d4fd1e194b6029246694742dc70c5136a26cf41b3abf9cf9cb65cd2e37ade6b9fe5ef6160279871230f35758f02c3b37789c1d74df0dc0f97f28bd789755982dd249c0960e64739b3c74b9c55ab810650529e7243bdafda7edef76fc748"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        //[mod = 3072]
        n = "9bbb099e1ec285594e73f9d11cbe81e7f1fa06fd34f3ec0b799394aed30fc2ed9de7b2a6866fde69846fb55a6ab98e552f9d20f05aa0d55c967817e4e04bdf9bf52fabcfcfa41265a7561b033ca3d56fb8e8a2e4de63e960cfb5a689129b188e5641f20dbf8908dab8e30e82f1d0e288e23869c7cac2b0318602610a776a19c1f93968c652b64f51406e7a4b2508d25b632606834a9638074e2633eb323324b8b30fdbd8e8fdad8602b11f25f3906439055afe947f9b9bcffb45dad88a1df5304c879bb4a6eddb4d3d1846bf907d2ca269845c790b2f0af8154aad9c4acb75e18a5d0e4f9f88137032b9964fe171dfa0d0f286090790f52157179a6734b5f9a64e3d2ed529722c3d3836d4501496f927a0f8e389ca35332b836d99e995f4a3e86f581bf9abdc7a10e06a6b31296ae3b43e6ddc9a0d9a7d0d9c4053af0875e851192d1de7b08d1beb7b857e227f8803a5620726a31920bcab922d3370a78033b315024a0fc1f6c276be565e58de77f294c8089ff4c43fb334d26006ab5757c65b"_hex;
        e = "ac6db1"_hex;
        m = "921961e184a5d9657697e3e65ceb1ed10204ec56e739df0e4f906ee194c9ed27bd9fbc0d514abe3a6e480cb3155debfcc8d9fc815719b334f7500a769488773b68e31b69cd273c824f79f58306692c0c232fc5c0c83415ef1dd59a73a063e9d7bc6ee7bf9e433c8344b3051ed616c9473a90afdde393ee88e9a5849e5f642b43"_hex;
        s = "55362a6854a7846c4d105dc8a358fd4c02931f117631968457f422939d266682fd705e2091bfd5d1bfb52b4bfad684914489ecdad9038b75c65916a9e967630b16c76656b58404ec11ac46d8684b3e72d4392fb6e7e6c929e43ad4fb6ce6198f241b39e8bcbbc058792dde31b195b91bb14236dcb82c28a5c24d633dd847d1548dd403b3a70149371f46432db1767a00c462758c2298fe9f1f04c2ff4b96858d084ffe5a624cb85c1f9be2a60fed40133b7c571c6c467f46a0f1e48ee6e2e6d65424bf8196b0d927e0fd4141264aa5df4129d52d2fb57b8dac9386a84ecd34ecb1feac3a2b99d055eda977ddf8027f1178348a30e4cb4ecef2291d7f520794018b39f5251fd46d97282ac21f6bce6539d19aa1c21c3c220a2ddb6feed262eceebd753eaf5e0eb98cb3eb7d324a3dac0a415a18b7f36170676e8b9d3e421a6f77046bee6d9591c93f7ef0242f464f15b63132a0aee80949709429b1e76d40d60f79b2a6ab362f12e2cdd0bc66868c80278043e179a36f2815e7916378b0fbdb8e"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "1ed02d"_hex;
        m = "8568ff68d40c9f240b5ff56d8919704a4819fb48b2f0741db6a3608a1aaddd861344d79813dd7f85e2f2f92bf00355adeadbc1d08b14fda5b5dd0f69c0fb37a9120e25a9ef166a0793352d9c7eb71fa3104fb11d55a38474220b205e6196ea04a94f506412be47f347b1f787dc3cb475e2fe31f6b9a6f0d026b6fd32a587dcdf"_hex;
        s = "191cae43b354617b1ebedb701c124e76339935835a3633b4f806fb835d0dc4b7e4abf00f8c575fad8467ca35bc0d37b58a90db835f4ecb9f1dbfdfaffffb6ef1e0b894dd65fbf8e36478adb673b116188d864f185be5fcfc17bf1e6cfccd499d632b3cb1722c75776cd4d8ec68d2512c1ca598b970f03f6fff5facb107c0e74d6aefffaac20f8e3aa6e825a1de1690a84c8ad1e766642f2a89d3032b58b8e6ec50ef6a8e69b6afd30a2755d42b55f9e21f69c8d9d993549d198ec6c17d12f09ab4be0209030dcb274afefa77fe461e6469ad51f56dc58ad2f06b620af36ba712fa798d9812d2b6ce8ff4554b58bd2a6a8abdd8d00920bc3ad3b61586e544eb073419a85bbc1dfaf775068dc004a7f0ae789d5023d013f3e6096ead893158ac4ba050b87f8186705179f531be573d9557744a70ee42a4b3eb89c824eb8ae1172212c177557267ef04157f9fcf003c2d1f6039671d3af71339c30fbf772f14b3d59e81739ef82d61ab61475e1b4c835fa50350da15610f45531ae85fae5ff9a31a"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "ac6db1"_hex;
        m = "88902b37b0db4246c41b50f180eb1350b1b6dac0477a3dd1accb0c5f541a85fe9637ca9cba15926153ce1edacfe66f574cd4b691adbe0c90ed8563ccb401bc93288e9baa06c7b837f191f8de0a5c9b2bc0a5b730eabfe56f13d43afa142779d8e99b86abbd791e90476ec64759d30194b631c6e425053134c3c0792f9d122296"_hex;
        s = "9d64c3b9a4ba78889747aef7c8565eb075e5bd92a55f9d34d3df6a2d740cd863ff98a04be4866e9f906cc6d99270d208a3dc2e53201cac9f4f758eecbe8a44db0243a3e40400cac37856079f2fe02d54d9748754331d9935595c35b22cc6c45686ea964642ec4ca7e0a88e4a4c0a6166733e361c46a592469cad7009ca3170cf3fbe485b1c8726e23a6e35f9691d9bf4029d82756c64a4d31ad0b8ef57a0ba2d55419d7cfabbab1a23c8baa4bf043a444b127920250551467d7d528425dc7c903c2c824e6b9b65f543ad9d7055300f19500356100411271e15b939d496b4bd4cc3ba4b6aa2ce65f4825275404cb19512ae27cc986b0af6fddff35980c2cc0e96829ecbd9ee19944838e4c83b1eadb6f78669890f556781c4e97d8ede9664080e47b3adaf2f5e04bd42d46012aeace3078f9068d870fee02b088f9674fdc0ca0064e9f0f63205836d7a8771264c553c945eb7c87df2a13d8efd3cdc8409843e7a246089970abd43526f3cc9cf993d419a6beaaaf6830208686a1fde4733f078ac"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "ac6db1"_hex;
        m = "973606b2c7e5658a9d8f264b8f5a266d0992cfbd6e9d3ff95c31a69a32c4f0f1cf44a5759d090d5ccf089768e6497b047a9b9f8f3786b8f82681b18b2d65500ada2217005cb06852d249ed17c9d637a9ffa7a5fc6d66882f854e8461b9983ac63c3623fa0cc4bf9530bcf0ff3ee9a086211eaaad1927f8c70300e9c5db45f54d"_hex;
        s = "355644f5a26a4ffc638c44ab4d0b7359f37845235bfb994d28e63b114c0e0f97d2e29f448da8b12eb804792ccc686dd807f44211d6af410bdca1196df84016b3cdae180bbb59133aeac5928560ad2cf6be61392dc9e28d7ada11658cf4a873bd2626ca839e697c79a5c4bb3ed4c9b8f48f83f2800e1907376f2e8874c23f1dff8bbf3b3f98bed7895d486079a92557a553a71e18cfafdc155775f39a77455b432b0c2c4f09990d130060143e7310b9d9e1ae6f2b1b83b90b36c6581473f60c3c61a10e286557f84e5d04cc36e12cbce835234d2d773221313ad7287c9957d94a1cda8c1fccd3eec45dd84a5d075d6bf823123fcdc7d549286142ab514db6d998e377429494f07041387de3ab31b02ac1606e590572bd9003e5a62b90b95b00c0eca73c744ccf4eae44374e26ba6033dd2baede95e19cecc840a045bf995a3250ce7b08e0c3267de822616f93a4dd9e629eb38b479bd31071b48976cf73ce52c3734abd93249300dd5c40635842dd2a290276190737a123008a4f0be557ca6628"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "ac6db1"_hex;
        m = "170dcd5458adfbdccc757e0b5abc19278112f24b418b995d395b46410da3624c0a8b49fc0d914fe6a02101ef6765adbfbb5e24739434be92acca9f43e19639bddbb012fef028c7c0449d52a9350b88c2f6e5e52a79648c0c931e8ace5bda5b8bd3a3afc4ca1b6e520012f99f8c57b3167bcec0d8bac30cb1367e8f4a4118d0a0"_hex;
        s = "6a4db2e6c13ee8ec6174bf57ae5bb7555e66dc2e3b618f259d913b5b8b6c16b9760290c9c576b563316f510ad2461cd5086b6d9670551ec74b8a9d15ebd43ccdfdcd74cad660a3fe3f36992c86559cd8e9e4d3568924b1f7e55bc5d8df4cf53f240fb3b945a08d24f205d5a7081410ea3e8136ca282fc99e6be0b1fa2faa742c9d682d08a77b791bb0421241e6a82f84605dda359e4f8475cef346c9f6a54a085492fc4bbb30b1047c66f5fc529ecb6aa9ece561e5a3a62f9a19eca2badbfa32a2aa205713b16081519c2cde2f8e8261726fad49145dce0d9e24f6e085e44bd86f670a114ba98d54389f0ed683d062735cd495e6a8a6eef9fd70355b92b4cf6cf0c24e898b6d3f7fe51dcd1548a1adc67ba585e2d18809ea658d6ec4bb5e33e8501d11a266f5e0928ecb58547e72c27db8b07aae31eefef865bcf6a08485675d3037f432c157e5ee428d292bfc24c654d8fca7a60107dc18461251906521e1e9965fc80c7b5f582ac3dc3798a0a2937e76d7e7fd7122d3fd9083feeb9a44ad7c"_hex;
        r = true; // Result = P
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA256 signature" );

        e = "ac6db1"_hex;
        m = "b2f72cef31be4b7439191d9b342065e62513792826f950481486dd4289429b6e0ae86a05820c99e1ef0144845cfae05c0f6f144603c3ca50992387c38ab1f76120e2cdeba624cae61dc51a9f3010e76d6ab92936a77bbb34c8ffb4f9ab00f4b15badfda8834e050c292b49f398a9a39f9eb75f01f8684b7d0be10dedd576b9e8"_hex;
        s = "8ca52a9040ac49ec2415054ee86379f297832a2a33892c9dec09de778982fb1bbff68b3787ef43ad15f9aa0c518847ba1b3075613bf187a6fc8a7fd7f0b43a6a24086c1d6c5fcb1db18c93bc508e609396ba019fa43dd19f95194c47003d6092303be35477a3137aa2adaa51b22618db29fce98b5bf791ac70be7e238c558f0fb42a40bcfe0e9c07e178afe7a2db74fcb03693ed46719d54d69d5de43ad6a93b0a5b7da6e05ebf7c4b02da42c7ac1f8997da7c4de00c7747361bbef534461bebc23477e93a48558b3ade7d09dce6fa6a378e68e7204ab35283c58148df0cf9444e5f91ad31cd0474815895555cfd7f9cef9164b91db4f98816d194f85bad581f410a655273e5d14491793141f9d928cb30a322c513935dfd830dfc75030b8b2ba1f46b763ec303bef32b4dbeb01781bc1f2bf2ceba27750082661558cf3d42f03d50409b7db521299009753c25926e3e6502bb1763ab68dd5c19dc0265b16a2d438c3ed23b74e60ecff88708e5601a478986dd1b607a2db0fe049664d136517f"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        n = "8aa12846ecb9d8b954d2ca0fd3f60826c76d2a98ae615f38f5a662cb6158f17f29050dc6a1bc2f60f3a9db2da6c9b27b8cabe25cfc25d005ad60ce298f6da3415ee0a0a00cd2fbaf1eb67d4fffbe03b2570ab56c10dfee9f4da86c05920993c92c4ac33a246f5102113a258e17736897f981b8b29ae695802fa1bcf9b41a5f1053bd77400a153d1d6efdf4e4c14703a34380da2921deac003b4a7246568527d9e37d0da956766f155d3b9a38ddb747f2706a72268542f594c90e0d2f0ef755f4aa67aa6a25004548c73861c0333597337a944c42f762ca2b54821425477e4e0e2a9b1842ed3f16d68ed31318dc396071b90e1e514cff975d198a581723cc98cb784d18cf197a14dd7b9d5036bd7724b9301f514236bf7c8b290dc5bd93ebb6bb2d18d3fc4f4d480b8d1b62ffa3de1224607976a27d40f912e50b46b915f19556781b2ac88e16c14982a0718bdb4cec77127165bd7151f0181cf56efa1ea345fee075a7b36a02e74a6f3eb035b608cdd2ceda4d738876fbd7ffb009019581685f"_hex;
        e = "74ef0b"_hex;
        m = "1d15d87fe7045f2a6650659acf23faeedc28b1bbd64a54f8f3bed617e3438975a6a891f4a08f99e6ef72c52efce3e7a15018f5b3aaa6bb4f4e8dcd069f75c06cf03799bf989f86ca4471cc0992a9010edb077b234fcb083148bedfe1d871d700a4c9d728f6bb8e9d0d556475b8feb0fc23fe2b56f041a5668957f6efb5c038f9"_hex;
        s = "1f1563cbb8650b8a7ff7f71aba6c06ea20643e4620f29e8d1aeb4a1be6f665ff9779ca9303437aad3264aeb0f2b250af32054585edeb44b0a913175e6006d31b43eeb9c97bbd679e5434e8f645b6e096320a5906a64264abdb9cdeefabd5ff61ee3f851484ec6bb0c7957d6db38942be1b3412aeaa7b0700028fac765cc4f03bd7157122420f1acd4828ea01cd32e0cacc55f43fd9bf58ac71961031f72024832191598ae69dc96b458a237cae0e3a81784a98a1b012530936529efe73d073eaf974f8e1680706581e0accb3a189d80dc71b051474e50cd9d8eaaf9e7be4108be1e7d8e6a89709c50c2d85034f0e158b208a205fc4b30922d0e19ca58e15e46384ec15650ff56b6eaef908b44c4f9d71250fd050ce96acc204d68c09493596ab2bf3052792226d60b684e516e92fa0b1585dffbc309fac46457c07a901e901dd659e4fbe4ec0b327f88b8b8bc689c3f678aac3519ec1f7392936a726b7fe4be534b27bac5a35a55e18fdeb08857850940476c14fa12102014872b81bc5dcf292"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "74ef0b"_hex;
        m = "50930141564ac38dfef23056b5cfd10efcf3bb8823fa6f5254f8ff45d4b0725a86076ac0b1b8042b0248006ed53d224cb08bd78b104f1c4b69bf9c96686118387b7c0cd193cd9028297a7cc27f4ccfb4281852b5ca7e787723d689384a68ff9437db319d86f12e2d7871ec7b3b64a2ed6b83722dd8f14b7f8a260e52022bef14"_hex;
        s = "65862ec1d10c408e4278ee1421e773f49ad426e368a48136d6f77d5a6de96ef4643ef3b8f7b451f9ef9ab4d8590752dd7adf1d78ce23411f3586564b67172ef718e8824d357b37f105dd0e38c0578df14220dbd83588c56c4cc658b5d4b07337ba3e40b40aa6d877aeb3cb95256d25e55b702bdb23026bcf05387d58ce020d359348536f9f108d111bf69c3823aca8655bd73a64789d258bc90b5006ad01c0640118e17aacedbc0545c543df8e05f254fb7d8846703723fadbd4179d4a1a5a7c371e980309d33b2d79061f741aae529d4e84c686a4077d3ffc66a8b18fab2f72ed06a3372efee4507425610d317c74d5566f4829b079012e2e066bacde53e43dd702fae3861eaf2721e3fc5818de552b5a9d084b5f03a451527fce2d3a608028163befb91ccecdcaaaf5cc357bfb698f0860350136b71b4b087b50e2d97a9a6765a6077f1b26e168b5d60b7a91330c3e1769adc479ffd866351eea4cae92609c0431511b91b6683d0d8d4d2a72be8622c7dd969d5977127ca5a6c3d0ef7ff77a"_hex;
        r = true; // Result = P
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA256 signature" );

        e = "f1d0f1"_hex;
        m = "b1fe0c7145b1e35a8062ed24ab82e862a0d695a53a1cc7430af1b9574bf2a40918229110dd8c6c750c295b9911034e79879bd631ac883abf1262c80a98de6923993a78ca63dcd434eb36340bbfecbbb73b39cddc008f2023a27d163ea1d64a269b1068a7bfea431f855121839c8559a2247821ae1e77a1f8210b4cfb4e226f9c"_hex;
        s = "43333cc1b7da9710ad7f58a595078672be48dbedafab37dda0e1328e2f2b8b91dc88d2c33e0d8e06fdfa3dbc43e24d827f3ed31a994bf662225e1f0827a205cd638c16f38d664752d73db2c84f26d12a955e237f7a4d171a14d720b43dda3fa728d69ee0ed95869fc231d8f6fffe93b1acb81692ab9ff0f926073280a3bdd4472cba3b84541f1f9cd4508bf780e96c80b4a705c9893639f127969343a1ff9aab2b98d154c7f929fc55a5fe9485d1d9ca411131e5c0ff3fbaef353d49a9f13583cf1ebeea6209c123df32abcb311edc94c04e5eb3e1389e5011499e7d0d5bf66bb69ba7a06586d414b1d7cedd0106259406235fee1cf0b2bb2ce679f247741baecccff27c6e2a3a514d7aaebed281cb6381e7fa8d8a092ef1051b5418fd9886747c9194feab56eb975fe193076b474c2056d20a818a5b4ea56648ab5e7d4ddfdca1238d95da14dbb51e0a72b6df8d4e4d708a18e1828619c999525772400a9ca91c20229b1a979d30fa7bf7e33129abcc8d91f61ff0b8f2042345c27a928b7865"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "74ef0b"_hex;
        m = "89574c2f705f32cafde26824389468218712eae98268588f02d683f17ad494df8b53457fd24651ef0561282d3e20e834960c8968f63a57342a14a6f2375bc10bef6d235fc2c4eae7d7c088985ca6bc8b1ae8c15c4ca7c5d0b1769cbae061b61fdc2e4e98e8e2e5f89c87ef2f392dcc6e3a2ff98c2bb788a9be84cd111ceb5b62"_hex;
        s = "45c1da7fa6d790ac28f54716f23b2d594a637c5f6785e37fec8350e5d5334edceb66c263197702e5e5d543a2a9a6893cec3608512503ca26831d8847c2563c326bbdf3aa5edf7a583d8252e2cf35bb16cf30a0736ccdddd41af4b54729c843b9c675ab33d3ba1e1f7f63d2aa2ec94da2a9fe4eab9036b0561d5ddeb6d3dfecd1e243381de0eed5d41b8fd6023826d3bf4ffece8570e800c1689a57c2987a0f5629dac772c5f40b475ac61524c0308dd7de872d2f2d68c6017992ee060c607826db6f263f3276f330b7d267defe6eb91f9e9ca63e552531869f0b36784813991da6aa930736858146a42eac2b17c3ed2fac55ae3e0c6370b5302e693f84615e4174576150c6454a5c5f7a4f72d03630e899363db71eeb8e4e919ab6d15e87306c626dbcc18bfe62bfb1878a5105cef0f5b4f06cc4b6d7fc12f29e687ea9d0e16b7ca009356a2cda1f7b48b22e43883582cc770803f6c75892174168ac6954c76a475f0bdda4dce703e5d7737f7019a43ac72447b524a6132dde51f925fcbb9485"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "74ef0b"_hex;
        m = "a8d283d3e616fcdabe06076c3368e022884108cf569bf363db860010955dafab0f4a0f54fc0c755982f87358d83e08a4136e15ea3d3b1015a87efc6e817e9908a86ed85bbf37912f827878bc56cb4e0f244b54af67530581848804e95b1954321b45c7305a1eb923658dfddfd497182a62dead66fc6b397018aa01c748b648f1"_hex;
        s = "5961403c27cac4677ccde42cb807477e004b7cc795f8e14049e78326769803f852175ad36d6cc08232c168a34e33eeadb7aaee642b6a75928ad303fb4140eebbfc2fdff5a990f8bea12311529cc4575594a56f6d362a6cf8623cf6580eae79525e502c7be1ae71699e2b7916cde5ab5149840ce8db96e839d0d507bcc3d6184ec68a99c30a1b562959d7873027aa491a9dee9094249e7e3e1913f263e05b6d892a8787686baa7ecb9a88e3bdb52a7e45fdf49bb73588173c722c5503bb5864917410da43ff55e85e4df1af4bdd3b913ee5ef8b9f0293ef36641a775dd4f70df95f157569899df3b7f2cf54a5e34575ff9f6ef5b93d00699586a247c2b42ddccffa5c88294b7bfb686970e0fb9a1e7a823a8b16ffa9b5e45726dd3bb015c88307062aab622fcdac7ed30b7c773793d3f7ce326d30535f4bc289918aace1feaa02c620be6cdcde24d694e7936c58c83f9e4bc3dcafbc542afa4daa7be014099173708452817dc1493d3306053e97fd1c258b062a982a5333925472eb004d82d8e4"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "74ef0b"_hex;
        m = "b2a9f33308f84f8718e860ee4e439ba1541a985f355c5dabc3a8df343660c69515ff713e5aac3ab2d10ffbf4c163d13bcecc1fed1eebd6cbbbb0f46938704be2983884c96b6063633a634d1325ee0715cb36c06f6a8f5225473bc5ad517f14a201fc34bd843d53001c8d5e34c40bc596130082ce626f582031ee58e6c7b5aa3e"_hex;
        s = "6f443dabd187abfeb167c7a76954251cb017b40dcd3c0de81909993fbdd6c99f64613e73aecc29eeb29fc9aab9ec54b55bc3539e0d34095248b5536b35f1a079a4f09ca2e83f51b07ef005a7e0a915be137e1d94ff2b26eda29a337b5b8d8652cb9f98703648a4b0d8c759ba48c1c37b2b76c3bbe116574c1f6265cc19703ce489186e3951e97e0d26230a82cd0b2a24def62b8af8e4962cf4e1a693d0d0bebd6fe45966b3a4e890e0a6f535919661beb109eb6d11e73ee2b97a3dd20074711bd4b817f442866d11c3fbf62255e05e466b36b8ffd57c6abe5592d72061d96435dedc32a822aa342b159ab21a993703b5ee7bd6d55508800b67667188810e062be554244db902947bd2ebc7f9e6c899f6ca1d3ba3a5c2edca8bafca8a5b54426b04a5a16a3c752d18647b578904f60a5dac531c95b0bfc37b7aeddd3c3564d0581f1088e85ed85ca366ef94eeb8f8d06b060f73f20778ae83bb884527fe9bc1a04d6dca59fefdfb9e14d68f97d9fb5fb1045c9a229d3015a4867efe88791554f8"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        n = "8c4b17ab9a0da366f67416075ce284ff69a2c1112a8b7d821f66e8bc5386cd1abfe499fb9a09523f1095729f61433cc17fed78789cde81145ba02d22ddb560332ec795ea6a764b9fb380f44ac63d64225772aa4503df2fdd20e7c1d17115d3c56176f49432b2930d417b84f997ed4e50cd557e2786e0275be8025f6f039a7a3b8ed421b4c224527c01c1a1bef6becda193eac7f484ab0a24da31d4bc8bb6f2d4a5f3817a246bd5a9c81dfbf55e8c5b18a8a63bebdcd245726ba5b6ed4f8981ab83933c00714064985d69a17ed017e3cfd7fd5d2c6e932a2e021d226013126e6272231ce8bf626121710cd19d0ff21227e4c4255be507809aeb0aa548f42749bae8e1a3e3b312d08f0226c5245c45b5d96eb8eaecd1b8a1dd3f9f908191325a02cb4ca57b25155447584749e2db23360233d9068195daebb7ca943311b58dedc6c809a5981ff1b66a803a4135fbddf1f4f2478559f9d2ba17d2da77b0f0b6b08662eb50495a16c301759cbf7281f4fa985800c14386e0db6df0422bbda9a26441"_hex;
        e = "e5a4b3"_hex;
        m = "897bd083c89256d56a247c12e265f3390962eace1cef2f7504e197bfdb7ea144ab3256f2798473a48247caf6c415e658c0f9ee627f6ccb68d3838d4ddf660b9cd904cad40f05210428009a98adef9a73c8e0453e4bed9cfff36de8edef6c5c839c59f6d393ffa61de5b7b2a0a5db59b0a77db7098859e863ee0970461178da20"_hex;
        s = "7a172ef111b0f2f9ec43bad8f6e8fa11e19222ed9575571716e55fe46b43aacee433447632849e0f486744054e70bdd98863f5f015b94ddd1571e64f6b9a26302e151d4865423791d596063bfad7e3b5c5494f4a3c5ed994c53b6d915824a1f1e8e3639f8873f9095a7842d88817a93bc2651e6ba94acce93830735654fcb5a4a01cccc090ede15ff5ed745a92d92d8186a746a693a94db4fae34db26c6ad0b4904c63001600947ee994e24da490a3de240e500b31b8be8b1b415599aa684c77116f12e3cb218cf388424e3276b1a3622f1c4115125f5af47d581b78b609a067ef5f33549fadbdadd098dd2c337897f113c8eca9a20f3da69aee2fe4a89bd3ff73eb4e8da271065a9013935731addb3480f52d07fb3a91261d8a030ee2cd9e0ab342b3bd62db62e359475ee9a36971ba37f5c3ae1f1939c276980140961e9542be9e0a4739fce668549fb606ae18774bbe62b20148dee0379f0f38fe982b25bae164785d3410c337b2f11ea74558d79991760847109dc0c77272a55afb0d3f58"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "e5a4b3"_hex;
        m = "77ba90225f3ba1722312f52b1a07c3f659aee2a085e939c3e5ae77a3bb0a0456d56637285f0ac93dfbdf89781479529c6e543ab1025e0daa0ab6fa4458b48b31eb29db76c4e80312f685d5e0fd5ccdbe50d544ef3ae7e7bee5db6864b853732ce28ae4d537dd37383c8b3f2b7db91ba427b96722d28baf489fa429cb83efa38f"_hex;
        s = "1f442887263f403f6ff9b20fd2780937596e99e3c9e640def7de2006f14026de1e140e0cd5d45d7fcb1f42a9127a661c87cbaa4f9b600d8ad7fde5beed5c125294ad7b211d550bc35429c71f84a837eca906a580aaf3e301b46deb59ebfa4b66323f6e136d178f7ecd8440d891eeed5c91ed785ffefcc725f2792868e296a8eb03c5683ce791b554636a787d579e3db81177b45aee1ac6bbd90d84144a706196d557b48d7fa8b551c3bf638ce93a6425eac03232256f4cca758ab2c427d996702b522eca24b0781f33aa2b61e1256fdb94b166f98cacea3d5da205f818d19b432d50309d8265eef151b0f40fceba927fd6b5ec9d1c2ba54eb9af22aa354299ffad07da5071a1fb4314c69399a5aa16c3b4ff3b61937debf6e55b5f44e91855ff0a64ab59f549c3b4dcbad5c4306b08be4b1be99d000ea52665e9bd1983fbfaecb15ba18adb3e88bb9429d6d1aa85f7f6304c253692ea0ae579123703f9d89f69669fdd4c12607d8c1b7a28f814e75a45122956c21cae47bba9e4ec1afb707e5f"_hex;
        r = true; // Result = P
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA256 signature" );

        e = "c15efd"_hex;
        m = "34a83157520e0413bc2ec4b48034fe5cc3fd2f69fb7992f95e5437ad99d555aec606e1ee98155fb1d9faf94b175ace2b9aab8c18999a41bbada96e5e851d5ef3dc17b558a8014cd9942b3cf7b1b6396768b2225eb483d50c8e894866a800d6295d24d61ce8997295d50bb73eb612e819175818c2b4fdf7f5e93aed4f69456559"_hex;
        s = "7a1699fcecfd4d337bcc6f4904d2356fff44aa24fd4a0324945d4a4dd9a9a552c59239dc9268783067477dade944adf592495a3b1e5a6eea7f58762ec4d5b0f3515f3b1eaab1273476cb0cc3080fa8c7d2f2695f4417a6dc538b8b2c58bfb248b7c41485aeb668a0a39ffa324f25074c75c0ae1c70496a4a37c9332fd73ced1d2fe561ae120c6c19d1e526c211ce8869ce236d06a9dab8f9ef453f8854cb4451033960a62fe279830667845edd5883734e730e50e7bae3bbcc619e5c4211ebf741ad2526bf0226440b7d076faa02a30f2c79132443de9fe9e6bfc12c65d1ee703ea274c06ffd5cf945413cfe13d1ec63d48ea477ba8c60a7aacc078b988cdb58691911975f26e1b33c2c0ff3e5026d9b1d7a6293eb330ad5513efd19937193b796c40114dd1ff32a2875963020f26177ca1b6a7d0c6a40a6c0be44b03555c0f4598f91600a336c73099fab278271c46d96f16d6882c00d5b3ba59f2a0bcb98f39b152c55eaee62a4eba026234f15963d7e7395de927e94893a8a175c65f0dd43"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "e5a4b3"_hex;
        m = "72e970c5fbeccfb254bb1313e33470e3074dd8d3fc60093fffc7c960b2a970c3c113a8fac64b71916a616844cd06486e29a1b1c5b2a02845c00c606a2f61b7a2069c040258959038688f62c1100ec05c64e9f2be929f49870dee6075eaa2a2d78aac0c457973348f966f8bf374f3df93014a2426650673ed2d9553e8a915384b"_hex;
        s = "6ce37157a92a7eda47c16b5b2d961c564ef7df9d5886043c07abbd1e74ec7f549c78b07e2140207e6b93e89ae69a74a5a76184e00ec03f1dd36c0699535e0bedb4f28634b194fcebe13d2c4955e01e4ef459244a7497fd647d5e6dd5f7ec156929d0e2f1e146d3397d3636726bbea13b38d7d38d4a5e4ebe68df7ff86c62c3802e18250a2cab3d200363c577895a33dc69c18d15309e7117ebf47b3b98c893785c99dd0077982ee084b4ac08913de46415e5abdbd223aca6ac5574ff4a61f5fd7631b776113f12044e5e53960a5af3867c8366e3367a20de73e6c4e0f7b9075a1a79374aee0232d06280c53bc6a148026e1686059d652d96c99ac41f909e278b3c408568adfe35cc55800caa58d03ce9f1cf533018ec4fcb5d66a50758229716c2abebe4b3e3c6ac778fc008db8985e5032d7825fa333fa4d7468504cd0785000f92833d5cdd61880bf40f803ac298343d75e18c003a8471e06449406bf1bafd988e162b0b8c62eee5795d957f1fe5d7abc6e7c8b3b43759f212d01def9151dc"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "e5a4b3"_hex;
        m = "6147121ced1b5f1d73306e4a22c31669b76c20764fa4b4467d86126a9ad283565c378ec3aad26e51aff2c4712e1e8a821559483a54a48a48efc5913752474996e6c27b56e15c44736290c6d7bd2e1d7b13a394cf277b195c6c24efa763f5a359236e419e39c2c7cbb392da4378fcb89bdbd46efc6f314bc91c2c948272e479e9"_hex;
        s = "8b5320215e2133754a182f38444a68fe9f3cfdbb7ea9d8e55d006789fb1d75c0fbe5e94201b15c97613a35c3ab54d61dcc62b978a8fab0ae3183fb7463814ec498eb0f4b0f5403044f33368afcf692b1b3ee3ef0ec1492c5c2ec370d75163b777705a0675252908bff8010e819bbde67b86b33a35e1fc43cb8da167691b6d69ecc19ae094a5461cadb0e977ea6b7ef6f3f639e4571a073d6033cf464e5eb17323447ac079e4e69caa7966d3083ecf616394fa25d2e30ef4e5b7e558c8c46802c2e35db02b7884b53b89f041037bf10ff30f291003323112dcc6b8eeebde3bf97e373305eab433061e3a634df865642743908ef822df62cedde8f4af403e7a924e22e667734e91a29d4b6c8f1c12da7023a1b22e6a3dd33e878efbab31220f4f2c923c88f1bb0d7b7497a9c687fbf59f9eb4625e6f92d7285bca5db93ae63213e3fe1333801fc3eca1d3a1ffa75319752a5aaac461d7a799659ad31569230266c1a62e787c25fa635b0d3aa248d047d9cee43fb12342a4c066dc971b893a7dbcf"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })

        e = "e5a4b3"_hex;
        m = "e9ba77e32581fb11b3d44a885ce8184207a00b5835016418cfe6e25921f4e30b26d1cd120691ac55dd711d11bec86a74f83af667972fdcab2e83d327d48055806d0900eb2b173c3f546a1e4f45788c76b7aaa27341c755771eb0567d314f39da46cad7159bfcf1f89f2516e7f9e0c671cc56d72539b218a726d535033e4ada40"_hex;
        s = "17c273523709d84746ae546c8f58086a5ab385aade0707b5b39adbeb507670453a56bd356a9b549fb0112eb3be73466294c0180a9061b04128a001f62025867277e28508fd1c94109061184f6acac575737ec4f93c58ee452089e6714c4dd9f23833278dc66332a914ac8e1b0ec33472061bab9c29cd8d7a0c1778c71fb973c851b6c9bbb7b7dfd24a16f146eef248d1aa81e4f62cafce2ea146314b2a8d5711de6625011ee7ffe7ac49b03a5b7e2d842e9b35969a934c75d16b6cb890f8d4ebeb6f74a08059e70e90ee39816cab34c4702ccd4e14718a8ab5c981f9c8f7cb3e91bf066ba387824c1b27e33b27a06d9eb3ff3fcace0b285f51cf83b117005bcc12da946b5a36e9308ac98e9103becc8ec5dbb048df722e5c8e6cbeaad8f2e27af33648c9ce5d7940013146f5d3cb8c30849ea75b209c36b745dc3179617933e22dc25af5169f784d6128af2c8694b5caf19fbc0585ca1780181150e8f8bbd8d12ea8b0d41f86b1b3b27771b3f36d3cf5ac6a2702b8711d52edc1cc96ce071eab"_hex;
        r = false; // Result = F
        d = eosio::sha256( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha256( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA256 signature verification failed", [&]() {
            assert_rsa_sha256_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA256 signature verification failed"
            );
        })
    EOSIO_TEST_END

    EOSIO_TEST_BEGIN(rsa_pkcs_1_5_sha512_test)
        // NIST FIPS 186-4 test vectors
        // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
        // CAVS 11.0
        // "SigVer PKCS#1 Ver 1.5" information
        // Combinations selected: Mod Size 1024 with SHA-512; Mod Size 2048 with SHA-512 ; Mod Size 3072 with SHA-512

        //[mod = 1024]
        auto n = "a9f1795fc64a9fac0edd4553ea5b722b34b5266bef29594fa80dc8c64d33c3459edbfd36fd7b85203dbe4ca17cdf7ae53e5fafdeed8e8a688264858db18124438a3bf3110a721d94276cd47d7e5c2e1547dd5cb80212d594571432506987dbb4a250de62eebdc19a79f876228b2c4d04a1b5910395a8714520e78b997b3b6389"_hex;
        auto e = "d43d27"_hex;
        auto m = "b2abe66d1e6dcd75149d42445705b71b7509d393ee38b7d69821850e4268231e98193c91473b88cf61a94e97021d27a9348e04c310bc72cf26091d5b1f8a9349a15e4bc8733ee683e256b41863537acb79be737cd98894d6cde614cad65f2c3b95221cfbeb9e6ef7604d7eaec1d03ae80d4127a493c5a55254607342ae0e755d"_hex;
        auto s = "3f8ee147643e685b325c13557f44945c99efeb0aeabe719ac1da3f6923d02ee74b0767558225548f276d4bab34e8f09c4909a251cdfd7be3cb7f57f4d8f4bcd01dff0fa532ac3116770f0527b56c4415df19fba04858e70703f06b6f02cdd6420d255a21953ae328aa17eb9e151ea1fc0916fe3f3506d8f14ef8e8e09f6e2e26"_hex;
        auto r = true; // Result = P
        auto d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA512 signature" );

        e = "83a029"_hex;
        m = "c4d94f011bee04446ce78f805d6950a9de2c6e59f7afbe1fc42ae619bec5c2c53b070614399125c0570c72e0246085ba9c26e1d8f061d45e86689e9a4127d5dd028707896f2ba26cf35d114c054828c3ae67c24e453da8a07e47b53ca32f384220429a89452441ef48c2b3ed8989ff6f1ad659e27fad048eb2ad75266b43b59d"_hex;
        s = "4052cd1149655d56d50c46d65c8213a81bc71140558a0d6c0445a180b64ffe3a91a0f3e6c3e9312966927d68fa2b1cdbb342af9fe729c1710076008c123db4901ed4e4a68f4a6c17b8938f2c99a6ae81c821ef65cf7d18a1271291d669d1072581c34a1a4badf4be10b00d2a31e0d611769cfb8576a17760656a6f64dd6817ea"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "d43d27"_hex;
        m = "abdffe0b951a91c54c7f00e1ff8e98060b413f131d9cb5589a861a053ed7b1e203b2e3414415873222ae60f527f1e7b529674b737149b7401d4dd3afc3c08d8a57d519c44f3d36af04f7b46f5c6a33afa6b12d92c53637ec918283b37a53aab06fefa87afeb928a5bc020337e721035b4ac6ec5a618bbdc6becc33f9abb98fbe"_hex;
        s = "5bdf363c7381eb660c572eaecc4325d0e977244f0bc229abffdcfe6a5e69b29b905b7cc83aa19ca3fa5c50917575c51fc6c299fcfce3d368326bccbc40b2437525fb39c103f32fc9e1aa653e2938afe0921c39a94110443551872b17728f8719d6ab98cd188d4182b62f6063720bb0550bd4f468668f4f4fad1ee3e5c7327fbf"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "d43d27"_hex;
        m = "b375b0e73c3a7d7013a9972c01b240228821261ed4c3eff6efca15113472f42a06e52152c25cfe34f1888b9dc3307f3cb91b98a6a1302f9cc7dc0f916ab487676d5cbe7a4fa747df5dfff5ee2608f1fd3080096fe96a4beee06bd3f43574e1904fa12f67cc6181f9bed87d251481bdef5618238296b76c71a33f08427ff9292d"_hex;
        s = "5b5341b5bdcb35e167f488f1510513fce5a01a813ee593c97264b2867fbb0846d46166d0eb2e07b0d3804bc0d3e75349a6687c798d82c54333ad5cbdb4d13c452bb479e08a7fcc2f7aecda3dd3946f68c6f02f47b69869246f2c5edd608ac18aabefff4891dc3eafc561a8b4d745c46052fd352ee63e427f21973836587ac4be"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "d43d27"_hex;
        m = "2cb9740e0c1b8867866aa81c64122295854ed681e8eceabf0651bf7a65bc23996acfc8566f4bf42c151b7bf7db94eb57f0fb065546477549e829bafb8d4a67086dd48d87533378edf41d992e7fcfc425759a9c36bb9f4b32eed7767af6566f68ded0adeae25c7a70ca78ec09774d16c8bc357f6d6f7bd441bf62d942c768a580"_hex;
        s = "1aece09a2f10ad4a72dcb389e771ceeaafe0d2b3ed89423da09784089f210e375124e65c040f67c44d2ba2f65ca7852d33e508831ec58e592bb4c9c440959337048072fa09d38b515e64940e35bc2a84764c4864970cd6b7dc6c63d284e6022ed1661149a4bf0c14c83b6f6f5d9fd7e22baf43e9b569ec26d8c42c4a597f026d"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "d43d27"_hex;
        m = "0da95fc957f922a88554a6a14b2be6d22599e1519c99f808c57797c30a8417872c0ee326898fda109b25f56cc2422a6743a590cc9089c3d6ca1c8a428432b7a7ca3b4f0a6172ebad51585e29a16198bc62edcbe4ef79cc2d7217bb47aa1be65bec18eb9f680b1d29aed5290171effa798a59d9c13fd3d9b6c65072fb05a86c4b"_hex;
        s = "96c37595427da33321b72448c89addd4ce9e63ae6e32a089bb780d57682099d35c92bacb405aa0979fb70725dbd06af1a9f6e9ad91457e50deeb5b91138db45a6b1e082fe3d9778355cabb6e7f4934f7d0d7a1ce0b8face619a9ce78cc024cdab6ac02f3cb6f8b6adfd1e0b245b227f66441b3863e8ee04cd83ec08b456b0f24"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        n = "c946321761fc295e104cac20c4003e8f6b29ba1bfe247458fd006e27da27dcac8438d1f1b97dd6189f5d98aef968c1ffe5e0976d8a6cb93e9e703519bace48c0cdebe292174745e9fe24bd1283f004a022d2fc3b03db09a0c38a095d064f9dc14abb0490241125af6744535e83d11b252306af61b7d231e843463f79ced2f60f"_hex;
        e = "a97a77"_hex;
        m = "046a758cd3cb2c2030aaec074068234bf5026c6de0940205461c7ba87581b30e58d406744ad5c24028b9dbe4aa2ae104f39030db668f67dbbcd01b935305ccd6c927171aca022e1e26f486d027f2cf6d21cb29ea4ab19593ccf5a9f2191289f27fed1244fc5b580253e453925fc7d5cea83dbf6134027574a0128f8b6fb0d2a9"_hex;
        s = "3c2a05b92025d230664c230d8546de1d970458cdc68ee8100ee53d5f3ea57593bfa3547a8b91ac6cccfbfe61013c5b313303016d552af8d6c2ef239b30da5c5560539db4cf242edd91517724afd9882f0377536e095f64d7d61bd3b3efe27433717c2d76802f13d676d5f14b561e3e12077c774840dc93d49e9e27a1547d13f7"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "a97a77"_hex;
        m = "eeb93216aa9f6030b5baa3eb3a4bc92d941a0aa2d5bb3a16a2104423450fd30dfdc552ea989b170644d9db85a3686e4a1ddca8187ab2a3f7b0d527daf967667e29bfea953faecb243a07252a2e5ec982960f330aec83bd0577ae12be65dce46f19aee260c65fe4533d4c692003b4449da7bc92c052b6ef08a0a2ea18aef5b6a6"_hex;
        s = "41a8bf967f62204cf9a0e94d9e989907e4d07ce93741be7de06d5c527185c80d60cfb90557dceff13190729582c3fa8af4c28b2a6a43af6e5a13808824541241297af16a138dd281f72a170a00f7d8ef41310ec904477bdab2c32f4e18b1bfd6e3d6d7fdab5d2a23e2450e0e2bae225cfa633d7949cf9d4210e7913d49e5d5bf"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "030339"_hex;
        m = "f9ea187db1584bae05ec20b78eab1c5f0537e2075799ef8efc3d8773853eef3975e5dd10526c2db1fc07d58a3d251b1ba0f206a0872112f078ea27a5b84ecc7d1ba299001a4bea6326c7dbad3ced7018ba7513ba71ba4464fbbf8ccb4e70b2e5922b3296307feb8c2c341868b48b811ef9c6f39e3debedb42dc69c2c722d093b"_hex;
        s = "44b4e5e060265ab860dea7823d1a7d53a1f79fdff6ef2cd4e93ea86e59741817cfcdb88a5517a21b69bd9d73e2426c9429041c40a32845dd098a66cba52d147c32cbc5164144dab8d8642dcbe3dbdadc1cc7589de3a35383165eed8fda2602a54d8a02a9a0a992c95732933efa30c0cd3f4d95519e8d661247ecf9bc5464e543"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "a97a77"_hex;
        m = "e4ae864a45eddc459a59946c7bfd18cfc119394fdf2520bb7612873923d329e89c1c76c3fb6a8cc95943635b9fbf47e599478cc04c9d7d578a1c9589c342f24f1e6b069fc8df90908c0fcabea51ce4f0d099b2f8a592a2db26cdf032994f1dd093229da55656d0e25c46335e341dd8398d9813bf910d778f74ac00fc4c0592b3"_hex;
        s = "8b7a625dbea9214f23cfcffa0554f3a4d64393f80daf01d01422857dcb74772f48b1215750319376cbbdbccfbf241d4cee1f190df04e5bd03e0e4e24e1cff426174a3ad1695ba0401c01fa6711f99fcc91a6852b6c77b2284ae5454d5819278682e6667bde72a69f1c111d1aee504c5a80dcdc6747d19bb287e85cc785714eba"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "a97a77"_hex;
        m = "bb825caec83ec0fbb33fb18c1afed63805b394a219bedfbe0f4650906420783751f2752bfd98c2c3f2c654facdefe2723a6684b920c47fcc19895fd9250647499f7a86fe707b6ad982975980783c1d5e9cd580eb1836192d6a3a657f12aa1a918d61b7b087ae60474dfae9a681ab31031148b1be69dd54eae8a1890891d69715"_hex;
        s = "064210dffdb7ea65e1de82f40e0bc3d450590dac4a8ad44427c2d6f13376fa9ae291990023fb678dfbe04a994cb84ac4698d71a613010d886d0aa6015aa092d52bbf857900934f8616444f69b137b651b61105bc64618b1fc69f589cf257d74c0a199c6a2bed8f26e58a0ba72778ab10f4419ddf5b9f3c5ec1c4390c8611713d"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "a97a77"_hex;
        m = "6d47a76b64deb512410e0e8b8b53104e27125fff792a2aa0cccdb006f48e038931ba0c0057ecd0ed2cdcf1f412787892e636d10b27a817a45b519313aeb77f34ddb90ffd5223b2b49180955fd22f687defb966f381628f4946fe3816c706c6b937ebb74a9daae2d136a1ffb514a169770c44239fcf8119f7577da9f885a46282"_hex;
        s = "311263208e8021d33f3125bfcd72677f28e6a807b359ea71bc87b466396e98c6bc5e361b26c4c858ddd129a8dc9cc4dba02b1f39b87a51d184c6a6a1652ae35759477f7939b275e71d09ed52e4fc07900c3ec90785c6b2d6edfe59059a8181aa07a00a56c3bd5dfee7618ac17e0f1ec4e8d252a2c61aaee69abf62212c98f44b"_hex;
        r = true; // Result = P
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA512 signature" );

        n = "ed88e482e9d7d30dfb6ff2e20bd93b5cf028fd5e49f9415b72f77602e688e9ce0d153c5131cf1223ee78e322f207edc1eab0832efeed4146e3af7715a301fe847605e009d18c05db26b3034ad84ecbf2728a6d384694625528e1002a83f47166e46dac3d0d7d146fc06419a2d2a64a9482267bbf30d666e694e5b2180c3e8f09"_hex;
        e = "22478b"_hex;
        m = "079d6e31776603dd6cd9f0856940e75fdf130e4846beb3ab6ba33ca30c635c64a2598dd77e68ba8417f73bb5a33907d8e4b2252645f7648225b54ca473f454767b9d56beff3a3ffe8afe0b980105f1367bdcda69524418917b3355fc121cc9523970b1302365fc136cf64778ac2b0b414b9a155b972e379e13273ef4126223be"_hex;
        s = "9563554bdd55d7eba323e370a74810726a6357780b763aa86d8c1e0394893db72bf85cceb76ed11e801483717d746169cdaf652c9cc11e0fa006166e05e54d1c2dbea9f8a01402f929d8d8e8eb0f1f028b98a779d9c44642df01ccc649cac24a4cc760cf52bd7eb4bc0f1809be7cdded3e0965f3462841ae6d0a1626e061bc4d"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "22478b"_hex;
        m = "6284989fb234eeb086e39dadb61cd985c75ff1e00fb88c561a9632de4ddb0f89c930f470939b9feaf1533c0317d32c2a022d042aa5a1d95c436ebb1a1ce87f764bcbc22cefcf2ad6897cef5fa5409ababdbf0dd45a6ac4c77c535a503c3f4f83b0fd08bd0ff717db1507bda9a98cad9dbebc13c6773cd5ff8eee1968f60a0717"_hex;
        s = "0db9d569fd848047e693ef1826fc1b7aaf1fe449882843455dab2829d418fde0b90b6c2a0ab2bf1122ded1708c9442b05a6a44d42bf5313ea793ca1482825e8327247d3f35a7fc43457a3f55c60e3f506d9df6b7037ab5db46b440edf014b4def3936a3ff7c1feb4e4ff366731ef519e4408863ae2e8048bbfbdc9101857e893"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "22478b"_hex;
        m = "310c04b35510e779f1b1e7177d18d32eeaffd15b2b210054f4ee5b33c284e1111bdbf3d7173ffd511f045884f5756f42f40d21fb9aea67d6437e37003788a844e74256dd74dc0888712a90ddea9af3dea568cad1a715e84bfa153d8eaec8fa141eabf66c75d05145708b57c9656fa72c847894845d8acbdba21a36822e2b21a9"_hex;
        s = "9029571a3b5a0c4c5cd165661cec2868c896240281172a4089d5bff1214d7721a692383bc733d131ff7b5b41f1c8a15428b4d80bb3b225bd381edc5df7ab230e499116e4b336d1b0731e55782b088eacb9c7cc4e31a629d29dd81a31d87f0d169b975f7214e356d28366002ae65dcfe857cb1be25083e8d5c24303a52b73fdce"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "22478b"_hex;
        m = "a86c47e276bd53067d97392bbdffc290d338f3b38fd8d409e22176f1fd8d33ebb7ab38052f2a4197b333a430e1fd91d00c9b9858e2186b3e4bc5e68594d24cedcc1cd4676e4664cb410b9ccd7dd2162e2f83ec2fde9a7b4b6f7a67254603e0c0ae6623ee7b38430beec629ead8a9d910029af820cd878b9716e602b95c4975cc"_hex;
        s = "85b7f16f782fb9ce2bc1b00114aec5fedf2e279ba0bdc4ae6a0e38e41bab63353ced11ccf3e55c8fd5dc99736f97ff891d13ed59c1f123ba4ce3daffbe08aedbbb7a0a90ac042fdc3f54253eb61b29b64f194610d42087189763baa351e0fa61b50a5c9875c0ca8538bf2187ef37d0cb1e6b5352bd017064955f2a0740db628f"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "22478b"_hex;
        m = "155958a8c08e561a69d5f41efe76304ffb0ffc658a2c8765ee17bd1521f211b3bc027ae6184ebbf5b369e837d58c26cb73e7b28853392537719ff600a2a9402377b3c5e9647334d921cea72e51f07089629b15e4b4bf99c7fd4cfdbeec44070a0c144297ec24462e7dad39ecbbcb96f38fd32d5ff4e66c7c5ac6dc3647e9eed0"_hex;
        s = "5535cc093d3e54097bace607a8f75ec913c4d0219663ce6a3b493480d14bac47e85d23c1b7562f91df292725965c31450558f46904b8e50b42bf2e0b6308056aa83691ca2349e39d167baf17d069d11db8390dcfe04b5550137dca253ed5c614cf9e50eae496bddb27c70ff6615a5c5b8a340fa314dd672dcb5d214728d51002"_hex;
        r = true; // Result = P
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA512 signature" );

        e = "903695"_hex;
        m = "0a87d48ac27cdc05dfbd93afab38c18a339beb5055180e5a196694c0450880c22bd1ec67c6a8b5630589753e67ccb1b3c8aa54577bfd5c7b9847d45297f602571ee6e1e91828d23807028e659b365fe583879027837a2176c75ac020777ef5d88bcf9d59e184994c8c30c76c70ff31e80c3c85089617c6144da640720b29c10e"_hex;
        s = "d808e2fc131998e6ac727bf628dee867b9849f47bb92ab663192e83659e5091511db6bd36bd2e5281fee2157549212982748584abaad8b188e389776896f5b60b82441b6fd83b6494ede3f6bb74a795a10c344b557b92b13d8b7f172721720664a5e3031d218ff2dde8aeecd21d6c96ecac396ef78001fec388ea8ac9bb17e9a"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        //[mod = 2048]
        n = "b6515048e1f7a3506d6bf028ea0516592078a2ebd6db04af6040bb5dde8888787e1fd973b1d160da25ba9095450d866625aeb7cf684b522af4edbc20adfad09e9c4c42919b7691e1404afe8815f229001bf7f8e2b1c511d56207972e3efa588f04f7bea82b64c45bc28bbc5e3ca3b1be8652c54a3393e95a58c78c34c7c7ceeca983e91920467d184ecd5aad0114f83d0517e6ee82944cf134e9efdb68f14322517acc10285c892c94e6892c9659fb85af6d11322df94edeb77a379e97c7608e5d23c89b56a722b54d91f0811855c21e0c41ed362ae144e2f46eebb97a9057c673ddccc0f2ce178c3af086d1f93a092a2ae58bb0703ca66318913e69e36fd997"_hex;
        e = "662f3b"_hex;
        m = "e5b327e067ed7a242749d21d78e0b1d68d288595dec82a55cdaab1768a5260b4346ff95641b040a71fd9b7aa1b16ac0a838f7550073cfb5865fb750646e0763562cc2af0eb41dce52974bc1662a4e0d2fcab88e4e5d3a60a33ea9ea908994abeb9f141182f4759c58d426aca1232551742a345b9403335527fa0b3c69925e338"_hex;
        s = "488df2a0a8775e6e65c6f457cb9e29dcc8ab6c37a12cf820308732052bfe068e3c6f3c4e73c17615aa6319b76d62df6cf48378b834dc412b9e5875f7fe16bb2670c4ee51cdc259df813d5faa541472581103421a9718e79b8c671b1c7b50f6d4315b96423ba6aca9d060a32372c4c237f02eef44f54f872bf91b5a390adf9c5a7a884416add7d15afd8fb8073243dd587ac8011a88d5566cac84d5dc4ca3f2d6938e0d03a9e8d016b4aea22183425c2bd4696d85501e264bba7dd980c3ac45d77a363955565f4675c5246802abc015236d69005d164c0f18a666d43442902be38fcc381ffb6b5a046af05686b0ad32b25c1e2d82707797016ee63fc9a952d2d5"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "a3e187"_hex;
        m = "6b7450077038ca8478e7a380292151ad413c1949d78076efe497beb4013f036f7242375864a894d5732b3b906feb1ccd606315fbc79c5e8827a024fac432743cabbc5b35f2894c9f4134c1179261257034aaf24d16dd17ef42649c4ba80488601dcb03c7a343b88cebec7d3c18e9363fc6faf6684baa68cb3cca6ecf341d0784"_hex;
        s = "1933ff9ae5c520efeb711fd17a571a209c2ba9e0469e39a5341a70ca46c6deb2359005fb21c9e914e8a5037345906204261476427ddbdf29212d84c6e4e1dbda61aeb21ceddad1c3789d99ea28ebf72c4fef790f838191b30587e00fa841d63bfebd00bf468b462ae935eaaef2f83ad596b29a0d538ad99b44d615217f0643f0d9bd755fa281e35bedca37b238a89b78f9d911a24c40ab3cf69dade4ce4a30bd3104f890a6cf410a1e76e625e28495f6f9b385d698e6f8a6eadf0df3af03b3e078f4b0c984bddf525f220635cb2993b72ccae40ad3378cdf775431c2ceaa1aaa57f355eefffc0f34b5d70d1a41aac9b052594f0132308b0e329e34c0d2fdc519"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "a3e187"_hex;
        m = "8b618f6669b9f0450a57cdc57f5dd0bfcc0b4812e1e2c2eacc09d9422cef4fa7e9325c3f22c0450b673c316929a339dd6e2fbe10c97bff198ae9eafc324133702a9aa4e6b47eb4c621495afc45d223b3284d8360fe70680359d515aa9ea02e36b5610f61053c6200a047f186ba33b8ca602f3f0a6709272fa296025258556880"_hex;
        s = "ac87aad4ce85038b8552c4a6e93ed94368bb3376ce17ba1d08812e004b43a952e27fc50daee8929094e747dfbe02584a7654d950d21700605e699561c03e64d2016404da7b9c0b0011ff64f206225db1c8b5f974bbeca720a7c2ec73e6fbf58adcc6f5cc24df6d09ade74416f30df70c4449820f24378b90c176f65651ab1c1fc82d3fe834e7b66d0daea47b8d1931a81d1fedd4e6996c56edbe496fa237fbd41876a460780100e4e6f0864b6f9282abae4ecd98630548b5cb42e66cf9eb890e0651f159f356283af40c02913d2f3bbf6d8ebaf6b7d88e6699f482d7825428ccb7ef8129dbc665bd4df8e9a07c339a1134e907e439d0846480ae6c888c1e9be2"_hex;
        r = true; // Result = P
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA512 signature" );

        e = "a3e187"_hex;
        m = "e2a14fdf10cbe13b0afa4294d073af00b19f02c2786987c9e3e80c79573e37aed1c01dfe20570f3f5225b7496c6c65fd5eaca387350c0fdf93fb6a965c17eccfb34eda8c25435b2b23f38830b698c2446ece487e9cf408e2c0d5b62745871cbe6c94b10f87586c0667aadace17bf6fdccb4a1a3013e81bd754bc19b579566f81"_hex;
        s = "0e340359f9f1fc5e974d8ad8c189efdb2849ec93994b152e497e15289015d915014c73503bc69b83803dfa9d8216181fcdc64782c27fe9d464ce12359aa60b44618119df19a8f5defcaa171c44c0c0ebe1991131132aab4b19c02438b0fead22bb34e51bbd565665583bb6eba36e82068e2e3040a177dab3c1d3a6f81d0a3901a934c10e2abd73e8b9ef7a1be29a7fe18b304ce57d073f85b1b6873ab6b8ed94d5a0a0f3e5fc9b4857aed36de4ca72deac235861297fdc51fd9553eed189335935f23b4058f293c8cce8bd9bfc8fbb374ecf4eaa0f2a1f06ccea4ff3071beff69d70efbe07513ef0bfa02dc2c6b19b5ced674a16b6672b6e04a32ae14157fe10"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "a3e187"_hex;
        m = "fb200350b60d1e9b4a3b1b4d7341c55c635bfa791569a438de3bec72450baae8144b1f28afa2e6b5a5312862851a10fff3437e37fa5700b9a40efe96c8af34ea24d365bfab6b4e2e2004dac7e44a94340dcb6118b7fe6f3d9f8469efeeadeda3523e3fdd53723f50e53e984639d93b42d97c0ce4f467da0ef62495455c0fbb5a"_hex;
        s = "624183bf2abdb79689a45158a4876a352b19077de88aad06fadf3abcf4d2683b126fbf84c01ef614448c63e8a78d1e8749fd89a9b2550078c18989fea591c2a7c47e6a0bb4491dcb1868a43e75351ae2a7afe27782195f453bbf10643e6c3a23c01f2e713b6ded81e1db7ca4ecb3554fa9ae8005b80316cacdb4530a66dc2a073ec494bc3419df2f275db5a33871d0a8d9cd0d8bcf90aa24f096a79a4c8f5c0dfd8b1887535e59079c974f87d26bfeda7022399685748414df842ce04783b6f57bd2a2dbbe2e225f89c764b9775d7721157498446ce3d613332ea2cc589f7043afe3cae32b779ea8f1ab22fef99f67a0720306dcdf2d2cf7b35b0bf3630e03bb"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "a3e187"_hex;
        m = "64ac0940e3926d11b78494ee758ee6e7f9f034ddb622a99f4a15fe5355bcee188ccbeae909bf0dc4e51e520c0900052d41ce777e934af66bcecffcd365daa7af7eca69f547e401bc899aaaa07f0d9268e8d08de65bef0b1fdb3048acab98c2606331f02b440b313ec98103707ebd75e1157fdfddb719d00398bf48a6cefd2773"_hex;
        s = "3853af577c8f5f96cdb01de108ef8737886118ded95a315a5f2c34ae22f8fed6aad5cc1debcffa3576cc0a5050f572cfd171413275254455f19312054f06e9bc50f9d2dcdd1fac7ff2fbf456c2c9a1217992acbce6f867b48291911de8dcbde4e0b85a92536157d939dab1a42fdeeac9b15e5ed3ca542d1cab43aae3723349e405f998705fd0edb19d9f4631e6c7cf7ad1962e99fbfe11629226a634eacc2ec2bf3ee2d87c2f6fe934a2293f5ff81b4dbeab62eb4d94bdb4ed481bcc4bf400c2050faade7375c811967596ab5415cc6f60fb6169faa95303ceed5ff261a93e0c2a2eb657501db9866fe858694f57ba25ec2f514d8f75980247597a006ab3df80"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        n = "f5596b5c452079319067a1bb3fd2f9c600abe8a8be658285a99b19dfee65f03c52d7e826943a934bb25e79542b7a9e179b6f95698bcc83e19cc6db49bdf718957206d83621ae4e384eccdf283b52fa3c4e7c0859859b574da49cecdb87249f20f16f0a9d63e6907256d5db57ed3cf12675b0ae63b458a1d4b64a2c508cd6f18a4ec57e5cdf2c62edebf1b739bd01d8a280d3bc88a8a81f9627e4aa83f0656b03ff04710ab4531f4f854a6a9fb326728b8752f61acdcc5e1d8f523e69b32b1aced6e9850a777048f294365ed98fb85fb4c0a0829279d0346c8efc1ec6afe7576116d15339cdcd1a8fbf4999264bfe22e9b6e5b6dace317c7689b866a72152829b"_hex;
        e = "534f11"_hex;
        m = "142565e97e8f5f95ec31fa8325beec222b3eedd82062bef364146ae2fe53cca53d3e51829e6e00faf189b7fbb814b757d089627553aa4447bc14517b4c176df6adc5327ed649edb62e7be950f4b1f17eded710a900c29b66f0c171a62875822cabe38e45ecc82fb3eb2c1aeaa13aa27f9e4f7eddf151cb3a484255c958151231"_hex;
        s = "ec232493d315f0c4ad232653ec9de464c33f956af3718c5b9f1266e7402c61c5ee9c177f14f8dcadd1d074e8f4087516b77b2477e4fdaaf48fd138e89903ff04e11cd0fb07d832ba545025b921496443b52978e215239474a031c44bf96ecb4aef393fbe0fb52e819cae819af3ab41c48b80afc60aaf41eefcf36cd00c2aea08dd09e5aee0056ed1b7f15ba237daae1cf4fd944dd09596e5dc0f029bf83b52017018c046e0cb58e3f24593117a624064d5c9afaf9df69bf92c816b72e625bfa5e9cd96e963c62b0cf82eecdc1852c1c02147030fe540dc270e454b4106f8116cbed3231630c7c1345be5f8847f8627fa082675c680a98ff109649fc4399d40aa"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "534f11"_hex;
        m = "53b72306191a180e86830fd37a1f13847739cf6ab30149ca6b8ccd0d791d261e29a315144982fb117f96d969e0757a07bdf5ef0dc0ef3cbb38425192b21a3cb9c9729c9f3fd759e24c6f9270353bd7ec21999953290ddedfae40392bef49fa99da2ca2f123a09a4a9416242ea4f691f94a2cb58213e398fd73906e205833c9"_hex;
        s = "6f17ef5b663a05ad79a4fd77515845d7dcf6fe5eb928f4e6567d7d615277ad7963595baf26971c1ee8db870c9e830d5be09732b8911476b09c1493aa1ce8faa2b527349ebfc882eb93acca56f5c0f5682c784c4094ef86aca1bf36acc97b7a9a96aa349c5f8d2034b92b8a8725be2091f7adaf8c3a1ff14a1e900a35bc6f2eee130595411a3c94aff5d7a0f9f9f5a8df9bbd5b28676ebc587c1f1e26000cc8b789e8c6974cbd49d58c139fa5847a924f14074d340b7bd4f325773f09d82a0da54da2d7df251951c5950762c9a3a0d2db10693f4aeeb97780367698aca99a42fa47b5f185e4c607cb0dda51aa2d93611e2f5bca343baef36dd6b0bac18cfa6b73"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "534f11"_hex;
        m = "b286242ed447af64ee029c7f33b5428d440503773f30748ff843be68868d45ea025387a58bc546668d31e9084377208d7bbdc76e9a630d2edf39d535ecf05cdc82cf1cc58ca7f16d5f097b0440b6c37c265721e0c26f5de7bd8d14c941c65d51ba62ad33ded6f8a1ebf319192f5c7481ce3dda75c03aade019a644c98df69070"_hex;
        s = "dfc19a45dd3b67cfa9a47615cb7f5365f28b85d5c11ca965846326849a2002e64b8f0e377be83641ca5e795f190aa609bc03f94bae4ea25e681959ac85e0ba28f6d298244c8c6f5c18edd868005c375221729dc434ebeb21e5063fcb281761d2b626276dd14b6e70ab53c3909e8df9f70f8a93a1485ab9794e7ce5c424a530329bde2834b8363e1f857dd9ff8908f4108c305ef2c303018392324fc600617d5ca4d041eea9a77f116ae29766ceb75a1c5f4931674044c5e48c7b214a2bb6f1da81ccd43ca056776da7b1c0702a9f39ba1cbd861251ea25620eee495e6a8cb00bb0a0963b609086ffe552bc8badaa9aa6a06a9710fd96f6047b8b1660a7680b34"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "534f11"_hex;
        m = "a5374f49877cfd0734fe20ebe12c360d950416748ae3788ad69cb7cc4ac8d6c69b5ec23fbf84d6b19aa4a4fcdac1f35a200c049660b21a798af938866a8b2de7cd11cea6e5048320eec005b712db65c88ab451dd074f93235060da1e2ca5bd9b8279fde6bfa70a3e787cc9865120953d1d2684b04661eb6e6ff924fd59bf8ecb"_hex;
        s = "2e985464b882f7c6672154a107154add844b4be163ceb8053be6b6fd632cfbc86d934e5aea7d11878b4df6e24fb0dce099c5b52bfec0897dc57fb03465adc2067a779d011e64ceadfb1e0a7051c5d248094ec8cc239d80c6e70591d617e54f503158f2b22b93eeebe017897fcc8f44703c815f07a476bda567dafe122bc07363818c83eddb6f777bb9e84f11549f3cbc283b78b3f2277c7a54072c13032a416c6470395472303c84adc17dc6128cd82c6ccd907ccb93adb0990289bc5b2eaf948c2f421ad0caf2655cd5839c86aa854370550ce033bc05b7638b8edf67bb5ea997bd904df293b89a0d16535134b66a6fd5551aec3dc09f29fdecbfc6f474de6b"_hex;
        r = true; // Result = P
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA512 signature" );

        e = "534f11"_hex;
        m = "dbed25e65429b89264ff6928e6ea9424b862a2df1daf870660fe8f4bbbb55b5a7604260f53bc4ee62a650fb3d18b91933e582522f068cbee8bd8f92cc2a097aa79234e052b05021c8a3d9dc4666b0fbed06b93e67f2a33ac73b88ec8d79fd92a2c742430a4abde1cccaf9cc56e33168db6c27292939ec62960c7d888c45a28c2"_hex;
        s = "d5c50cfbf215c17489ba4d29b5e2f84a4ea244ef0dcec72c3a077e12d74d586574aa9683cdd0546c3581a723ca048415c6252894e40d3bd803138f78c7c493fc679aa1104e2844bf51618c3571789175828cf7d59addabeb8fa2745d08a247d5937600f8bc0dfe2e1ea7abd257b3e1c207a3be3e2fef8344979c4e0dbbbbfcaa908e1c9c6da303e510f0bb455f4b91dc7fee576e358fd5b2aa8f1e6440bc229c004c31e6e61123aef01a0d382852689ac04424007f55b6fa6aa298b9a93b3eceb6e585f69a5714231e60e1db27b2cf94f7ca5f6fc4118c0604ee716f41736c7efa6c43a3af42b27b585cb9c6356be864e0514e2bae881f4ad5ddb9aad592d7ab"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "8f3795"_hex;
        m = "562eea18d9654547cb566556964ead28616c18e0920dd7f691883c8bcf1cd6f90826deafc597d13c24a65fa9dbc2840c7bcbf55af281bd7d543d28a6dbdfe0e52c0756f7db88635f321930b82e4e5349cbc73ada81a8cdc60f484f52772e853d4a391b98251e43d87c189f2a96da6106d9c9b10748684ffa4a137935adf10f2a"_hex;
        s = "4df68855dfccab1e7a94430bebb9c631770e7bd75538a9017e2df5b35117db59f8c9f620c1fe41bbc5bc65155355a83c1c1da767bf7e6c40ed61464a53009d7d8d1ee31e7e82c4b97c520d74a60e0de0597b977d07ee95fbbd4e5486d7ad61ebe302de0cd634be178a04c8b9498c89b7ee1c674a074e70ae0f93e7e5dda89c165808a8ab55337a048ddb7eff91a8b5309ed9941ecdf3ddc3b1e235f7cf139b681b97cfbc584d9c0359b26a8011dccd7d5ff0475d52959d35e30ad66735bfdd06e63749dd775e65d9407375ee9f5f9e73bf77b75fe0a5923fa7fcafac08e10f0563dfedc2aa2abfaff6f73ba293497eb0159cefd63c974553a24cf0602353fd4b"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        n = "981ff4f5e7569dde9ea2f3630f0463002799dd234a423f6e960c4b55a57ef478e9bd58b94fe4303c5cf3a97d076e3ff845fdef29be7e9ff293acb652e86a5a260882cb4e7724a44a08ebd11a168fc389588f0cde26847644febd1f7c6c031ca1eae47f9941a4dca32028f1408eb96db40a386bf922a8aed72fa27a937e181f8dcf35c946bd5405897a0f0fbe00f18b66de336abd51ee46b8ffe4cee6667f3de4dec041774fd79a08b0a2be1fa16806c6b58ed795ab9044b732f69a1cf88f61ba862f24462bdb036d5d5701ba205e37c737e8da703e9dff2208051e537939e1f2643efa2261f268ee31021379681cfad9a1c03d91a6f17a316cca2e810a0ffcc3"_hex;
        e = "08475b"_hex;
        m = "7120a0657a833d7f9723b647eb6867f5d9f6f1fb1a77e8eb0c9acc954d5b3b6f8986643b9076bfe3ac23fca8315c397b555077ab42534fc16adfe1a91bd90e125316e716d51e641e7c305a00d086a76bd7d9af852e280dd257b682585552310176da0f40710295f7b052b899ef6e1a8c069a82d1037d8ae67c2597eb244c0e05"_hex;
        s = "385f2fe2bb8e9483bbc05c316283ad01f8aea41bd83ad941fec99bad0f066fb1c7dc960d536d4ed5302958a0df7b943836878a1c906b3f3f778e7335407676c7766183ef61624c32da8e79640ad5390660a46610b2b172dfb7fdf48e556408e0da06ddeab4468a00abf93d6e3fd71c04478b49f394e849f1923d4a57b76f6407675fe647f7bcc59f7493128e62c0cbf999dd4b3c62cbba2accfbf77351abf76927b89cb6f57d900d631d2445231f75b7d2c3ef303a51b38f9e7f0d69a68ab397674628a825ae74605f32deab2a0ec2fde1fe820b48d824b68acef3f0bdbd7804eb15899029bc9d349951d732eceeb3c42ed02ab35d112841f8e411b28435ddbb"_hex;
        r = true; // Result = P
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA512 signature" );

        e = "fd8739"_hex;
        m = "77449a132998a90b149b91bd05fb1e53c85e28d7923e16a69cf7a122111edba82a156fc297dc2a9d222ababd8fbdb6efc6eedf7f3488a6ac6edaee59170b120505ae2afd9f968ad089ec8c04847e90078f5a4068529c1947bd84270bedcc0f534f38532e076ed28e93088efaabe8b2846ccbd4fbb6217761d31dd49f5908da78"_hex;
        s = "240add12876bc54e013030c890f3abf774a109f687effbbb6a03d0b828e8e1ada27e424db835c78dc0d6905b212fbfd55885417d571e7da1cb1566a1cb713cb04a334eaa68545cb17cfe55c037230a5a71e941fe51517530392ed35b844ab7e891e9230d67250c7fe73a9d969523815dcbdae4c01322648cb0c686aebba24c4e57cc4859fd0e38a23dd43f86373d7c3250bd03d8400887926df0f98169c132f819180b9fc482ec77304b8af96a5334401912e6d210361218267c21f2c65d3a83c376516b869466278841e267d73237789b33e5a7ac3f1feb2a1a3e9bae60523ed5f814124805f11c151357fbb8a717fb8c858c66e647ddcb59c20c2bb8e86abc"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "08475b"_hex;
        m = "f99ed2fc9e07ccafe0704660b1906e93542e3c7220d8551c81d8303f3f6477e90315b09b179b1ca06daedf9ce3476268c511f61d931aba6f05cfbe3d4d2768659c1e17dde7650700eb5875256f300376c97a5d00a3c81d06ffa6ec9b79cfea70cca151ea98cf557763564e23ddb218666851ba40d7484788764502824bc4c5af"_hex;
        s = "268ffe2eef8407c215d1e0d02d3b23d387900877d4b6ab515a9d35e30d6c64830e748ab782191f2f9a9c133765ec3863708dbdd36d5e4ce9dd262f040766829e365ccf8e19b146355770ec4dc3a059581efe466e59fdf1d6a7d0c6a24b052c54b5a0f02e73390cd70ac56c0a004a9e45ae81296b3f5f1677db8c0dbae012295eb884130530215c175239e7160182009b46607a71a6186c48a1b8cb45c1dce3fd2f31aba568065e8e490f021454a674b8dda3e436b375f0daa3294969492ed269e9156011b133de86ada6a84225b1c297b71b3462cd3ca037585bb805179d76864a9083f927e8e1360d9302a2be39166bd5411c997000d882b268623bdc5dc9d9"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "08475b"_hex;
        m = "019d049056b4bbaf6c585c6aa4b7670ea52fd6814e6dad83eed6d334b82520d67156b7d56cc49604b88e6b2a983ea9bd33addced8d213ae5b6b97a4d420be913f80bba6bcf2f9d1416d094ddf2d402690d8a052f8dd506c4438d8f5d25225c90ff82b45a653dfa66ece77f8c9abf9a999a8dfb4e34d13cabfd19b96d4bb3a2d5"_hex;
        s = "772e888d14c70c4e546fa77a85d1be25ef85bd24ea52db68c2c0d3889edf96a6d7d31696536a12fead53f44a055847be51567a6466730991383e5aee41da40c90d6c951e36c865fa4638490ab44a27cbaedaad7d415b80a51ab465c8a18df567356988020d7e6ec0404577ce8f02d581e48228bc342f6bfe2d2eb2dec17f66fae7debb40b839b1085c16caa417bf31a7bfa540405f76671c8d80dee48d8a1cd44b456ee61ba601938bb3626805c232ec3978936bd8dcea073ea483ba8cdc29841b442fd28b4b4b1a282298776d83b2174114766b2017e5ad547a1021fcc3b829ba30f0cbdcfbae09c5e0101f8ebf1fdbfa1e1d029bba61c1ca1920fb36ea6e2f"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "08475b"_hex;
        m = "1c0c43b58a3c85bc56763bb26f8060b645988d11d0651bc6d32e886b624a1b38a2d8cb5ed0b05e998499ce0937bcf03e03585792abb877bbdb6206a0b192a86c7be6cae1c35bcef089786986cfc94aa85b8ffdc2b8b60e3c7e07714fd39f211732a008e96b261fe6eb7dd6d03e91b61dd2a5454afe482a724285911fd15bd160"_hex;
        s = "5be423f5b70087c95d748e060004afca6b49fea89dfb37c2460578af2484c0b9ac384193dd47bd06736c071b557aad22684016e6d97e9597f49d11edd8bc7e6dc44ed1f94403d171b215b00c8f3a6721e1cd4d37cebf67b705dee052a2cc97415fa9fac97180fd60ae20667af437d3caf6b69ac87eb9afc3c951a49719f32a9e12062500b958a5b48136bb41e4d6434d5fb59814384e06a4e4d0a779f044e873d5ceea1249f9648153663234cfe9171f988e12926059c896793bb56630432c5d3305d70b436f041c3eb1b6377cf01b27f507a9a8389f57b2b17010b808123ef23201da72f39febf7ea3841cdbe376d3ac89471f2494e948702f618ce382fde3d"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "08475b"_hex;
        m = "21ea231df11ec8a62b2bb1fb3a19d608e3ed32a531cf62d4b26c6e43e39ae719e83a32ef8063231b39bdce35e02a99d43cac9699fc83106fed956410701312cc2c5a148600176fff3baf075710deb7d0449ea1d62a4ac33cd103ccc97c532df3521072ea5783d3d89bca0667b27b5885638afc64a46da3c4c77d4d74eea05e16"_hex;
        s = "20d90f8361337e7196010e8778794c721c881492e63ceac4a7bbf56daa41fbb9c1716be12b56b79fc826b090c3a2a73f85fe761c9249f0be8577ca78385d11ece10270c05d07590b8d3c889f4cf9cc0881c066957974804f4a74aa9eed9a7d26871885260b2d67c96b1cdac2a6ea61650d8324dfc37105b916ecc406d604f79bbd7c8a7754cf805cc9c74914dfa1bd2dd6ab62b0e228673ac84faeb9b38c94f3f1a1b74d83188837dc7cdf8521bb61c7378c3db6c2305bfa906ab1c6ba3c2fe557feaa5c97e28304a64f3b4153265cf51910a7636b3723cd56131ea16ab4ad865224088143d36f7fe25c9f18363953b33692c10fa3aed59eb70172d7f4708b"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        //[mod = 3072]
        n = "9689eb163a617c0abbf01ddc0e6d88c37f8a6b0baec0f6cab8f8a683f372a53d028253a6ba502da462adaf4fd87c8dc2b03b6c07c2b6aacab1d8c8bd043d89f4effe72ea2547c73c6366a2efab9c916945820fb880890bc085564e57ee76f7107a008f71e941e9fd631aec78f82e410ea9c893faa3d553cd1ca628af1087ca1b0c6aef3b66edcee14d1d7dc48293ddd7deed1ccbe487c957585abb9509151038d53f46b068e3e139c7689bf8e8d38669896b8d082e65e458e1f82b8e8ec926e7aa0f97d08526e9636f2c00af4c2bd3d8bffc4bb93cd47b09af18883e11b639d47938d036f7cfeb77db74a2c09a6dee9df98b18eff2fda7d3f4135083bb3b59e2172244ec37bdbdcfe6e199d36dc949cda1cca123fb2be07803d003d76af3d7164453df77d44c7f2599636ca44d0b7a46218326b0c814ed322b9c4279b060f1b9e14b70f55a3751c4343763cdbf9c14637d2210c59fbd037be17ea6706846fdc7b9ab90278c01c458e64442f9256f3ad1cbceb22959d495063aaca1a3959eae03"_hex;
        e = "4df3ed"_hex;
        m = "54a8d256702239dee2ebc1dc681938b467ce4740dc5fff1796b5b50fa3f31000085860cbb568319bb746216bb065eec9845fd3d95625159cb359d9720cf838de6a3c958a5dc12e8b35e6f2e5757693528588db3fa7a343182c26c2c5e8e7e375e31b1a9a51765834c593dd53a1954ed7d10f077bb921b2126be418101e08384b"_hex;
        s = "869091f55f7e61bd18d88b974ddb408df8a724ca72232b6326de301cfc985e8db211180ad2057a4f4f73c07e48973b00d2833655acf393b31d155c11e9ddc05dd5f4516ac50fbc674cd0c577c79b00e5567629cbcf880b729a7ae0ca9eb040fdcced198243d40f5e3b59f35f2992da079e9f174844f1b2d0f1307624f4d868f558dcd1c6064297a152c816db1ee5848f9e670d8d837911c85b221430b309dcfb4853c3dbf6a2d8c8a6cd3d697ec325da6d8740081bb86e98d092a8794009915f5f55ca9ec074cded2745c50f328af98f78edc94cb6b416cf543d59a4d493824462a21fa6e368943d9d541ac233a7d708fcc7248be670051abf60199c656b8595dfd29e19a207d5c2d33a97dd7b66737023e62bbf522077b8531ededd070a2b17f7d1f9dba47a89585eb72d21c3dc6fb321614604899553bc0834baf3b7647a4aafa046964a805f05477c9e1def5c40430e82d635e7f90713e822e355edd10f2a65c886c4d94bb306bac35dbf307400eb7d8caaa36e167760209c80362e8c763a"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "fa3751"_hex;
        m = "6459ea1d443df706907ffdd3ca2f193f93f5a349b50357d26748b767cde6ab5cbfe76b1acb2b9eb97da5c4d2ddc8d18e3a3b1a0326d475c1c2c49ca73c0fd3fc9540cbbba85ac52d6811fabd693a3b09a281d535715ab784df3ad7292606d15a70ccd1a7e2b1b48ad92a6a3f736f9fd5522d9a869c7b654446102e9493b3ed9f"_hex;
        s = "2b72942573b825cd1f0172119c23440a2b384b7f2a3c5582bb02f764e2b159ea9ad880ca61b3df7ca249134f4bec285083c7ebf984b192808e916af687ef6c6a9a6722a4fa9189fac1521d03853f3dd5a95ff4b9dbdbf3c7077f720650ead01945ab5bfee582ac1643526fbf68efe1bb3b6f7d2b4b01f2155aaea38a2c7ed29add23ee791a703d11e3b1b7c500d9a6b647c1337bf537c071e5bada6faa025bcaf5e5d1196998909c3d64758826939ae7fe1466dc6efc10a2b25e21186c2d135ceace33cdf490b13a0d10c2527e04200aa70bc1d4f3cfb04b5d2bc17aee881d3a788401f45443470bc639232088a9553c8d792aa5707654f075476a66b86368d5a92b4c84a3b4baba1b0b98bdebb85b48b82b8409f2e9c1aa500670329ff3b6e83e25c561110d47b2fe93ea2946a74f9730da9b7d126f8d7c3fa4a51fc30144a827831c186390998d552a1b677afe5afee46e9d4a5774a56355a4d1967677e75d176aef71c3fa061644d7a9582385877de67f87724b0a6e868f3a2eeafb68c53b"_hex;
        r = true; // Result = P
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA512 signature" );

        e = "fa3751"_hex;
        m = "e4dcdd4e122e9466560370fb59ee0c4c323fca47e57772a029ff1b216f194f411f166af725ca43d0ac3d0e4029a381359c8e36f21363511b6f0a620c6aea8d6fd915e80e2fbf24e543f5707c538c9a744857775f3b9d86d539c9d0c44364120799411e3a39f77fcda2945c58dd909f2ebe005535680c58f50fa32cee026e282f"_hex;
        s = "02ca1d1fe97e0c3724d649dbe493c4bf8825d72f0e1717a6a8767453a3ef20bbbbc62fdcef7b816af229dc1ee2464a19b63825f47dea9774745dfe4ffd36ea72eaed7137412bcf0d0d5a9ffb02ecf15309aa047fde0a32a16876bcc33363b7290b6ec9c019d82767d36dcecb841b6946dac889cf3e11e614c4dd07e594c50e1557665c6ef76ef2205d57a2c8e6d0950ad7e4e476ce2e095f7e376c21f96c38b53327c94a9c4547982ce396eb2070bb73df03a09efb3bc6fbe5c35dd89e3ce54ff093739c678aeced539f04aee3c4d391b1399cfef4e24529033098a29aad09e715daba9c4323837b48b5292bcbf32b39cf15c6430714a930bd840b8c15d7467e71e99ef6726e1ab3d05a0e96939082391956f7f0492676a05771f695d24d7c7c22c64d7ef99a295ce34cb882153162400a9d6bacb4e1002ee51317477fddd9923fa1af2ef60e40da01fa19a43e446144581b3eb8f4d44d16b31c0b155c7e95ec52da4676c6abc1075ad271e5b39a5b3ac7672f1c65a1f28d402c691e8024559a"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "fa3751"_hex;
        m = "eced7082ee6e916e753959e7dfbec00d9b424b64eb90eb2be7eb22e9c648674859bacc26d82edeeae158cc14beedcc19e713bb6dc71603e1c35cc22f799b29d34549221d0a5435852f14ac3ee77ef50eb69a495c31378b8b05dd73863a03eb9cb982b98f0c4a5fe766533f8ce3d7039410bf3c5aae5b49d0b3557b1692e8774b"_hex;
        s = "11aa09883b9f571237215bacf3ea7f100740a1bd72748804bca39e9ef8527692b5a8e1f94d255cab186edd16fbe76bb9d673ecef79f2614fc0bf4e2b3c28a93c39e6fb31de6c21dc93026f8ce717767d57bef1c91839568b9da11c1b48cd7e53e132ea7f9b12f80c3bc1a6b9ba1e7d234ffc4f251e6ada2588b21b457d9bedb51d14b1214144a81a3b987f00b20c6cbb314840363fb4a605495124abd45ac3d7e9d65e8b95dff0ba916d432749dfb24e5fadac418ff716097d86943a6bfa8dc5ff27dda853c63c1b2ce3383bd78197af3e30635d0ae65e203300ded374a790245cdf4d1640ba5d0da8d6ea35ba0263efde90c7b1a8ac1e3cd0f843e5fe57f681055de7ffea80e92af36bc183efaed08a5842f9bc8369626d60ab2c460de622b9b3c36e6e559787264abefaba843bf443cd9443eff990db82feece2cdb5e336f84f641176f82b41efa2377737089792b4a9596a32cad5450a5f6a93f947d249dd734be9b3cb6c825af53c27070eeb7c1713aa607fa89e44a542dac00b80bd246f"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "fa3751"_hex;
        m = "404f0ccd8f6ae6f81cd7a4efe9a1f630c56ac1987002698e0138507e85f09a89e976347a1a1214fc6addc20b36d217a9c52844d274e017b1109a7a1484ac3d1eb475153ba8efe459ed843a5638231cb44d9205941f062be239f103cd5c1b077a6af4b7f98229de786d7516b639ba8ebb23500bc7bb9c2d8842e5f48f57648205"_hex;
        s = "11368e0d1b3900af8ce2fa432a871bc448e0d49a71eee2b201b67b496ce00854138386c3cccd6e4210f84c2e1de653f70f16d0240666fed5b9fcfb247d8c77f0ae9826fc32d0ed6aff6e94eab735ffa2dd108b842e59e7d04e3eddcdcd087b30a3d65cd9f6566dad10bd2e9d7bd2b6c20167552e77270ca43a1ca5aee8c9e7bb5825970ab74ea79d3ae73b12d34274d58117b568aa724a6766ed40afe8d2649dffd5bb9c1c854a70a10ac5459fb9bfe4bcecbb04103ffba4d314c2c5aebd805acfdb113f5321ebfa19d0c809e8713e35bdaa8c7930c2f2ca5792206aaac8e44b4cdf1434f04acf6c1df428843b14e1c8401555742707bd5f9e4188f38206fe11c13f29947ecd97f5f576d4ebeffd1f29d38e43d76348bb43840d9044fb7785a0d7d04bb27206b2907759c29a70acd14dceb05d21e7c8bd907df3746b666a40e35245f7bcd723446b4e88ab0e2d8d5b3456041ba111a8276df1e4625e5863c5dd6b2c7ec1ac55aac7eb8373cea752a6396558fa7adea9d8c4fe0843241bd67f2a"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "fa3751"_hex;
        m = "abdffe0b951a91c54c7f00e1ff8e98060b413f131d9cb5589a861a053ed7b1e203b2e3414415873222ae60f527f1e7b529674b737149b7401d4dd3afc3c08d8a57d519c44f3d36af04f7b46f5c6a33afa6b12d92c53637ec918283b37a53aab06fefa87afeb928a5bc020337e721035b4ac6ec5a618bbdc6becc33f9abb98fbe"_hex;
        s = "183fcc6e78a7811df1b7442c3bf543e198ce6c691ea6b3aa1952bee39d3218a2b1cd55af26efe672b11c640af1de241fc1289cf10643992fbfe604e1e965d2eb9e19f3399d9fe174ec4129bffb0e041b15f8b7e7b25b535882cbd5d6983d8d84dbf91daf22078579670f70e1f46b723e5a0004f1870d88daa8d7d22df709226ee6d7b484ff47a44db43073f65bc6974493a807391861adf95535b560a47e0ae96af5239aaf1e524758ab6c7a2d3bdccc2f2cc173251954504b837e27f32e699e7604a11d8205893d8cbf9a5852af1f65f8e0b1e1851b4f7a80ff929d5f4f796aaeebddcbfc4c3835d6381b2341404b77d90c78be4d97747b2d6fa9b88610963795ee95f70bbc897b486cf4b313ade25d56ced2e8b6584b921567d32cd627e9497f39f743f020930cf5141668e127152fd92df34b44e3cd142c1668fd71f7f83246f2be3b2ff95bc1ed7e193d75adc5369fbea93314f03a305a825946846f59af8c108a14888e894872e4c0086599faef2f5a0edfb4e085c0402cc56e69930f59"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        n = "dc09c7fdce01962419294bb4e9c7896347d9bbfffab1d7f35b2e36671d7766a4a4a6b16e8bc12adba6503d4d967efe51e89be652d42b8e7b1b12c0ab34d00997b72a5ab3859bd7d414c72e2997521384fc0ce01f2488f443f1afeb043b14099b3b1efb0154020ff10c50eab077e534270cee6e95fd9352c2f70350c0103a252fd041f9583b67bd92d5d712c21d6036834392b72e622fc0f3d3e1d1c09d512fc6486e7f5465999dffa16e2c5e3fa25267d8f52dd639c84af6bbbb76afecba35b8775ff1cad59e8280d73cb3fbbdc084a60429f7dd9bbe9198d2c8351c27c4ab61ab68d54e9222ebd9177550439a5b5b9ae13c49467aefc41afe435f0dfdaef913238a1f6ecf4692167c19357a2625b06942a5c5856100a6c9d66fb4ee37173fca4ff9298d4d4ba558aac53a75f14be641b1701550fc2a1e2cb4b2c734d29b266cde310888397ac19667fc577422c90a897c3b2e65ed62cac471595b18bb124501a663b093d1161d697f9df6bdb151bc9608534a25f983b14117505040fb481d53"_hex;
        e = "5a75ff"_hex;
        m = "32e5485f4834ecff046b3f554de9f9d02aa8f95b2812d0d4fd1683c06a7a8d3d667324377873bddf6542d2590b50e3b58d4abb21b0ebf45d8515bd6f4920db978972ee85894ff6cae7f3158d7cde977f83702f11fdb583e45482eb803ec1764ae4092fb044729ea7d3a79157673c1c145542de91d6198650b086965d1205673c"_hex;
        s = "4f8d07925bc0ac7e423a824b1439cdcc486e9612f54c93f5d4fd34f64ad67369b172388e06da52ed100d278c77d6efecd3fdaf56d0a572dfdb978b9449d90951494809c2e88b4a25cf879967659db47dbd43656182958dfef8bc9c54c3a4d62fdb48066735ef5aa39cf89834e479a99e8d22700d288abadcbe28c6667e437515bb47c3d1662d9556ad98abc81bd1ce1b8990155c369ef3827e631164ce8d710c193246bd625692086d0e7f239ce3aa9d6b8d6a5728c64d24992465935aed196ab1715f88bc36118c52ba3cf48cff4e61fa0080282645cde0fbe9493150752093054f1f0889ef7a55c5814d6cf667913cfce4aff2941d1999dcaa5525bd497909839223759c62fdb1387dd4c84f72a32705ae7fa14512af2d7002b315c8c183f0bcaee254ad976270d035fb9d2f4cb22fa2e8a2535d9f345511b22391171aed821e754922b2f6c797debc339264fb28a9788a1d385f99a0333ef388113be22c7b93e18cc80b3a91d6dbe9dd46587544eef85335030a70ab73283e539498f2761e"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "a1befd"_hex;
        m = "6de2659492e82a0541143765c7cb73d457c9b695b608231137e3b81fe97b23820f5ad7b3d05660e230b8f3373f9e4a5d909eaf41edac5617493eef9ff6ae7ca619df60cf5a23b993e05cf0877c628fdd24a5522ea4148077903d7b617db596c570ba286f9717df22374856dde6dfe95dfa26c8e341064a37f32784ede4591be7"_hex;
        s = "1ae7122bd67306b4f3d0c3c25a6d3f3318b8ba13c64267f1c4264eeb974131d51566fbc71108873b4920bd48bccf493558b63ded97441cd674a3f020e1fe2fd09e093a18e654a4a379443394e540a53f5c24d67cce5f15be955c446ca872b2505a3b07be1fec5847261e76cf708dcbeef8db95a6fcc87bced3f7cdc1f524616fc0539df58075f818608fc38809ae8e489a35d186c8053f9cc26e869866b98347f888f701635df245248f29982efb7b05e80787cab12cdafe54d065b2ae3e0bb3a03ad0a727d77f6fc3cec60a32c5af590983d08b0d2d0a51dc50f3a6bb2f9786d6c77c37a32c917b91f5b29c65a6911a6638222256ef04b4bf76269f846db847b29d9edccae04effa28e357a76499389b831d5e8dc7c42036bc4277a71b4bab0edd152ccdbbddb8957a3bdbbaf1e4cbfb2b8af678ac7706d16ff6bc40c4e8fc4cbb30146f66b8e035363c935c5c72d78fafe2c8ddd4f0793b98a71a6b7ff6b6892c7ec193d1076fc243ac061801a72cdb78ba2f1c34881c6212af2a7689ecf51"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "a1befd"_hex;
        m = "d9fdd81eb8d725ec727cf671386e9c4d7968b23e4d37a39414cb6de55a8ea401fff5b92894547c7b07f6e0b1836dfe0b92275d8a8542715f15a161a34a400e489cc450505957823c46b242c8897b72d5c6d282a78927f250e44e126c59d50d0ff99525fcce87401877d9a41e1241ff935f92aafd218d2e50c8f908a94ef6a93e"_hex;
        s = "9658a72570e4ee228863702a79115dd33a0d562762306cc603ca2c480aec784df73a32c067400e5539c68e34fcbac59457b0d89e6eb6faeac716234cae40a5a40593be11cbc9100280663007ae815d4515210f2f6220a09582fff1c085ae1dbf7cfa9ecbd3113b0f1803c47c65893e8cae0802177aa0a056007bf2863298cf172425c61d4798cef950e632f1f6d7618521dbd7aafbec3cc3e41c3f4bc9e80e437e71b4d6f924b15509cb355fa2d9e91176b861b81e4eefee72e988e7ed8e4eb7b93c4ea35c28332aac9de918e49a7575473d9cca1f117aacd06618a1fc9e1c6c6f8a7b0d4cb5d04187bfe930e4fc5a080ada4888e6aa5dc3e984c7841a225c50fae637369150863294ce5c0398a0c7d045098c644256ddea27b63b921fd87f86ab719962b71b5d8582a91f762cdfe3b1b2c714dda16dd91155fc9b5be378bbf2635997ad8effddb3869bf0cddbc113cc97d67fd69ed4b7884246cd18f0ae3a63c2db35ab7cfa4b73777cd8e005d6e222215a4d8818bd6426c4adc9b1c69565a6"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "a1befd"_hex;
        m = "f5277358fc0e0ed9c50e381423ff803035d7107e961281ffd557f42625585ede55fa23cf02b6e7dd0b3ea0f24564f0fe7038b33c6a71d4b6a30f640bd13eed70e57c03f53dfe1d0a1b50a341563d48554fee9a6c2756d7992fcd03a5a0fa370f8df73c5115b05965dd8c6888be502f3eba40ee96358735af61d8f87bfb56e5c3"_hex;
        s = "d261372ba60cd5812e0230d6103e1f9a777b77f8bc9de3f27bcb3d32e23a60f56f4631350703e200ed9a97d3e2d397234576c5f5c1a347101f62142cca0a53ef9e2b22e724c9d02e5bf4fac684e2803e95640fad841aef7626bd6ef22e7a97ffff31237a70118504ee8bfa0f0e71fd80b195e8221a296d62fefe991e4be69785bad174ab44728605a3d1c41918d33a60fd5a002465ba7b02341c30e6b058b47cca3f5c8a289f5ea3401c2dad9b32ca2f3511538407fa5c03045528e977ce46c8dce655f445588d4a1cb8cb5d76e84776ae86344963b675a3428ca717e4f940ad29199cbf87d27334eab76b878bb015143bc2537fde09a8aaf2649ed29a5d09570959f011778677177e4624e0ac7d9146a2493d5d1299a408b1383ba61df26415d64bcf38e1441c4e0123dbc5ce22e7e077cf9eba5d632d308c23654f0453758a984700097044fe48c61f1873e5a3274c7d5cc7d68b392e26007a534cbec0167760adc5f8b5fea3e2e949e963fbff9ed89e844a3ff2e145d7b4b1193f724aa014"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "a1befd"_hex;
        m = "4ebfb0c3c540ba37f357cf30a2bc9155305d091f7db0a3d608477abc54a5d6889150f3157827055c77f678a00e487ce8797cc1b28f1b7fe6ea69ba09483ac4b331070343da41f4d14ae57064bb512f6543568a54b38e85bac0f00c5f60a17dbc770d67b3b337927eb44d3fe67180b0b5d713eb6db3b1bc3ad103f9266582098c"_hex;
        s = "6c640306e33515434ee5723d46bce72dcb4c5716311c9ad1d0182987a3090c1b4de97bf8c7323cef9f7d36fc0cc929b2bac1e7f6b1456409f51656b9ac3b9290fdf7910f28a2d0f72e56c94b1d1e5a76daa35e62c93e373b6c6b4435dc1394e131af3c0658e41dff438208bf6b159bc54f5dea67d04e0f794a251256f915e8f9770815c8d89ba123e0c057bf5286e95f017e65492904975b7d493286a634fbf3163a18adab3caaea230c2766deaf36243a37085377f3db5f091cfc707805cb8a9999a06eb3b931bbce312bb2ff53230fcb0c920a816164afbe947ef666617e39ac521db2156631b0f1ca24daee37a521e938be66d36a8819d2c648db87914cb7c7db43ce885d1db4b58b99b3c0a35af19c9cc4e0af21db9d133cf7a2699429fd06faeb3365e18cfe8d14295584167ce708a047b2eb3ab1c25bd1089c4fa5f9ace5ea02a8e7a5f170c398940270405eb6fd2382733247f4c3faca94b368d9e104668854bd3b3db5a5c8e9f63e5547da813ac8ae5b020013280287832703af91d6"_hex;
        r = true; // Result = P
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA512 signature" );

        e = "a1befd"_hex;
        m = "6739c2996ed518592cde7619a0a5f361c09c51c36a738c189d80af0ce964ebdd24ecea5f5f3561441814e59ab2b4ff952281828fea451c4d4b912c84b65fd39b85f54eb3e80d83e52232d9caf56d4d415a21c36c763499fcca6f82afaa289216f01e959cf1a4a5c4b002fcb2521806edd244ba63f6862bae82e25a95ab064fd6"_hex;
        s = "bd4e9adfdf12d10d9de2d3c1d5324cd2048a57e0cac12ec5cc054f2f4c974b5c5dc3e8aca34a2a7d2907d3b930faaeb194f84fb6a9e99a2a7762346545f70bc384181b0213767f2a7381565cf4a17f3fd52c0d107b12d964605b576f2779411c38129a99300c902c28336ca76920b6c8e52e1c366fe92afe8c7c0ad93f38c07a9fd83926c1e634e026dbe67ae1f3df76a9bf6c75ecf6ecd660e68b0bb571028504bf233443e238aa573727713d659bc1d15171baed4d962017ab5689ef894802a65b4d522bf3b377aa2d3a42b718c8c7f205cd4c9c4d12f4fb2657bab0460c22737a5ee6524e96430493610178f19eb3750cb56f27e6088d26424ae13e863f410c7505899705168015e14ee1c5a1d4112b097f1e0f9dae32f64b75e82558f8f41bae65ab7cbfc400cbc1fd45601b53d26abe2f53a6ac660a7e940584e7fa90a0b8c4d906c46c4bb3a6eeed2327ac4409fd28b77b24c98e5c5f14a8e3678f965c46b455b02d7d0d58f24daf5f7b03362554d6809da7a90a3da53d81148eacea68"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        n = "acc1658b0b236d34992af6dfcd916f29c532a00faba18ed2be4835b1dd03951a5e3a46f2da3bb27a955606bd81d2be2d797ae651af241be9e84a52242e137c0d2fc5be00d692d094fd1606138fc280c113aa7e8250a484aea7c7e6f83bdd76d4966a5d1cf1d3ad1deb899ed53b9a633ed6c4617e38ec226523f6480bae9397b34ca5adc6e0fe854ce2e161866bf2621afff61f32b7dd08ce3ac931346315cfc6b66ba37e292bf0b5d274cdf98f175d247222843ff90e63e3d85427134dcc00fb20e51d84ac1b1132393fdaf7596818b56a9b019d65cf4b4302e9e11057ff90508d0c0c2c7b5f9d57e180e71b2f103a60ef6edbe40b1da27d16018bf6d4a4fabc9c73d5827f0e52c4a16e11d4bbcbc6cea5ff5bb2284ecce4b6080064c2794fa1cf6789565e16842882a7d3caae5051a9a45327b74bf4cd5885736bf5bb9bb045082aed3454fd40fe3c83397bb56115035f358735c290b43d5cb1f67b8853651dbac0cb9a197b46abb1121736a17d917dc2892eb2c5b3c4881ab472db54a5c4ad"_hex;
        e = "c4d755"_hex;
        m = "76dbb0c0d2069fe7c8287301f57169ec11c79fdad4191c4913f111362d495e8da5a058e5104dca6a32123a1a64f46d35384a2dee60154967cc8fdedc1307d51f14ebad44dd277a9dccad2ee9f35518c8c1e8aa72df777fa959f29decfef6f7ee09e53646013cb868dd21d9d46c3c728df4c8a0cd1aeac7f70141d6cdb6becce3"_hex;
        s = "2e34f1e2f8064b52d770593345194f13460cdaf2bdc502e14e77ecffd093bb57fed459b1f1a26c15d58ef9ab1da879917cfcb2d5793b8c774bc94f0494c66010ace1159c8b546f616125bd79111d81614de5b0f6cc42d95c41bee3789e897adc94aaffbb3bd51e5f022d0385b7a1956cb013353c1167dada2a9c7d0052a0e0cda5eb0bd30f310099c1dfd36c809e0ed49d14ada4d39551a02d6d7e6db2a3a1ab499854c9445d2e9513529b181ebdaa6f97a3e84c246277f4e9ad6428a82c3745c050951ddb16a074f477cb10ee2765ec436c83df7342c6055a4c4206c88d826d04c7d342d5fc46a90c22a5b68ed57de78287a2047149290f16778ebbd253aacca35602f2b2f855a277ea263fc2ab286a42f5531248ae38adb65b8ce4b28185933d8a03f4787ec35a41d9965cf8a3a46bd970831842b94c99dcdc748ede26611f151fe33a64921e197ea329e26ff3cedddc830198a94c1917e8b6200f453c69e04cdaa9e872167aeab367ef9dfe7905581ab0796d611b15b97e4f6b351869ef3c"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "5b1365"_hex;
        m = "3c2cc086a13b1d1b232f0f131032f1ef2dfd616ba03641680dfd012a00c221c38b59f1cf30509c620080643f05e22f4bdea44341a97c4ea6263da90018a8dd43ef84678ca5f1b811e6f9805873682ca8c8ddadbefd227cc0eab9db778eb75db8b2d6a823c9c57a111bc2eac7226bf1f034d1284a63cfd39fa29a1ff72998a80c"_hex;
        s = "51fb0f16194df6288533f7b91df149c79e8d474b4d44a51f903902700fa561836c4c6a09c9c5211737217b2de1d6d73106f4709ebc219a4c71d02516a9e42dc4ef9e372db5c3d05e3ba2c3da25e5e8519cbdc3998c0ac5187df777acce31f039480e11d745c6c0b235075cf1805498ea1f15bc911f6d94b3d332084ffda0000ee0d72572a5a24f303857447081129392a1693552c5da4ef6791e2a0f6e68a889e98c1ca7d8dfadc7beb60e8ca4756cb8f56efc62d3accfa16462f597363441dd9ce27328ba9014ff366600ac42140e1b4a4b9a068bbf05fc37acd0eb7c9fc6803a4f87d706d72b570e0fd405f6fd5b7a3926f5e7206d23bf2dd39598de89fa1e66a2fc4533f516d15f0e44bccd0e8d405ee95f1586d17ee25feff7bacf0f3a008e9c0a15129ded95f5a50fa7cf129517604504ba89fed73cbd4e96da21e824b93df4cfd6776961d0d14e5c3a11cf29a836f5c87fcc60e9c837717a632d070737b470f9a374c916166b5df2afd7250cff6f03ddaacf68b067bdf0edd1ddb82d2d"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "c4d755"_hex;
        m = "9a3482f481638f436c51f7b74d3bd19a91e99b02473c7f028507d421071fe80b1ab6fd87b8e491a9f587e3499a4db2b40f0f48a07e61b7663567636b4ceac0df88aa5dab80f622a4fe7bd605a85ae31ce07d5e43e82a42124ad8fcd377422d36aebbab471fc1c99c51d4d8d3c189ed3cccdae5d2cec0a7708c04a941cf51b679"_hex;
        s = "0f5c8dfe8b67996bb62af65fad25c816979b33419babafcfb3d35c2887a0375ee7461487d4d65b1c03306919abad43793a93643b912cf906c4095356b64f8a3e01dddd2446ff3c07ec62bd6c1b39fca4efd95904ccd0cf87c1bc5f3659825b86daca6b46bfdba8790c4f958ac9647cb1991e2661a01925c79d1f9b23856e8035507b1cd66956a47e97e756443c6ebd46105f8788b0713f6d3f04c3f16849aae50dbe920a35d5e5c1345af610f38ee98c153b02dcc6a1175762af98587c203bb6bdc93300af93a64798d8f621a0805a3212ec9edc90ec4bfbb63d6121ce478a96fbf3e731285daa14a638d5bc9dfd2c365e9d1d70b80d3cc461bad93e7b2ee984228206b52c9bd1ca44561efc558a6133e93d82079b1d5bfc5006742848b95a7e50fc3b14f3590f76f1e86decfb7af82d49853b3b1a8b54d8bfc7bed9f50c78ad01a1b8c7a24ea959efc8c54e0a6cbde288d36673fefe3a3a308cbe895de7e1ce747073eeac6df67fd3e15b38de300d9555450948d2c72c592f1a3182be99d760"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "c4d755"_hex;
        m = "adf9b0a89d93e05bf18d5610d03d9e70474d4a169bbfe6abde2f2e4fc1587e3ba9da89a5053b4ee4de2b48d5af0ce57d78b13af00e66f571b53193daf058d33f98236ace2ce3f8f968333bd8197e82c82fc265591493b4673c62ad86feff72a4a25dbae9bb96c6e2b72e97dfb49c5e9995063418554d0bd49c49e41b905643b2"_hex;
        s = "3b62f0d4fb1b702eda45e08c47d87b2caba37728133b54bbc654f1e39d4290050392a412226429384178be20a2bb8a2d737f08bffd1396052e4c82d625e3ff46955852b4ac9393ff7e620c8fb7ab5a7173f3cf67978127df7dc4496953488365e500ff13a1ec170ab95d48ae4b7c0392c4822f531a7a534464c91401d40561384c0ef1caab31f449a926e2b39dfc1cf0a048d121080ec31776da00f2c392783f15dcccb369844d7cec262fb6cb755660b0a08f00720b059b0c272262f2a943b6253c353e6069ccbd3c70b0c3a1474cc1d6f878e7a8495b4aad1d963351f9d23b69af996928a86f113ad50b327c26ccd599425c67c4f7bf8e495f7945efd4b11b952c52266ea3ebb46e445d18c596b8d2d6a9e8c70f0e3ceec51784c7477b662b304a5530caf18c3c8a232fd11c63258002714c298c258d724d8e8d4f4117bd74d2d92dc66fc324a257ab2f907aae0c7a8ed9e1aef7e9d0657472349eeb3da29972b11a9005fd93dead2361df7273adc8b968e0d608d782878ed75fd7113b7d67"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "c4d755"_hex;
        m = "8b02e84531d5623e528e208c109a68ad04ffbb6ed29d075400b41e3b08a7673dab00d3d589b31344efa70934f0727c9cb7650fe31bc874487466dd81ad4db3a29bcf8b418dcc56d82534d76a66c75b6a0d1fa4d825f126add69076797eb2ff4b0377f7d167a791c09c3b74769a206ddfb037609517a0854bcd38d06ba060b1fe"_hex;
        s = "8a5503759f374b78b8bc654ffda8f1add7ea05e24218f9e9c140709a90c5bf8868f081bb2a01a43d724c99e47ebc2634859dd11653b1c5a4d65dd306719b7b4cf2b66f7ba3c93e8731a7adf715c5b0365e0f9453b14d08dcc88052c97d4fdf05f4c92dac2ade4708abe6fe752ed57a5f39281b0c5aa349e3c4ca056f66ccb6fa07154b12657ecd5a94db390e09320dbd2c452e84d389bf2fdf4686b21905497830aa57bc5ced3d23b519f6d6c300ca5d3903ad18ca426b13dfd5bf56e7b47300f88ae7fd0b085807951db84ca9074ec40d285334e85570f0df96afa9d85c55aff0bcc2ba28f2d5fa4860159575ee84194238424213b7673d0f50bf903351e274eac603f2e4218ea8c626fced0aa08097f6630d92139feeabb747ae20e2343c3d8c7647ec48ee2c0d00031b9c882f91efbc7e8487a0010ad3c51f160b902b59baca8f19e8fe90402e1e0131b37a936e101e15f8e4cfedc727cc160c6ae206f3c70ea09f08f00c9bd1837296785536d1bb9785014c59665cd2b930050161d946e6"_hex;
        r = false; // Result = F
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        REQUIRE_ASSERT( "RSA PKCS1.5 SHA512 signature verification failed", [&]() {
            assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s,
                "RSA PKCS1.5 SHA512 signature verification failed"
            );
        })

        e = "c4d755"_hex;
        m = "379b6b72a139346febdb0fdce95394c509a6c5f0876de862e47b922594c00549f76dbb298a5943f05fa44c5bca9a00c05eda934f17b71b98d9dea24d19397949da14d0d2dc7f841b10f3380d4e38a7474a853864c5ead47c00ebf4ed766efe5bcad7d1f5ff719efae710fb7cdef43265b8f1dfb7f7cdba1841eab18d12243a86"_hex;
        s = "88f3e8e1b41671191471092d34520f6a43742702a629f1cc9d2b806c9e6cc1f3ab47fe1b0281570a0825c0de59b24554d4b78b00de2b807a92c51dcf22def3385635b477b9129a34c8543d24173f13167ad7fd7bdc108dd5f8e3f364c3f53ecb26fcc59145ea6ac74aaaa7cf0f1aff4b1462256b87e8d5dc9cf74ad2419b965217cc9ec90337cc01c7d9928ecd310468ca69cce111a16ed5bf7a07d3fe4dbe0b34b59645527547ffb9264ae48eed86d05d1caa8f519d5391bd2ce830d8ad0bda965a735cd4c061797ae661d0bb0431a8189a35aa0b4d2a6a6877b703bea7f09422372913e4ac4e2981e3c917f7bef9f9a1727fab29af9320b9ed44d5229460b06055c2ae911f4eeaca72de9c3b6269ac23943b13376e5009ebf8d349d34a28a07ba2f85466c2d488b6593f7abdf0f221c7aa51e142ba9e6828d23283e39671a41531f01a04fcd3dc70172dcef185e26bcee509a143150ca7f4e2dfdefd2be9dfb98ed0c7b12de9dd8d5653b88758ee1889093dd529657042a86507426caa6488"_hex;
        r = true; // Result = P
        d = eosio::sha512( (const char*)m.data(), m.size() );
        REQUIRE_EQUAL( r, verify_rsa_sha512( rsa_public_key_view(n, e), d, s ));
        assert_rsa_sha512_signature( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 SHA512 signature" );
    EOSIO_TEST_END

    EOSIO_TEST_BEGIN( rsa_pkcs_1_5_test )
        EOSIO_TEST( rsa_pkcs_1_5_sha1_test )
        EOSIO_TEST( rsa_pkcs_1_5_sha256_test )
        EOSIO_TEST( rsa_pkcs_1_5_sha512_test )
    EOSIO_TEST_END
}