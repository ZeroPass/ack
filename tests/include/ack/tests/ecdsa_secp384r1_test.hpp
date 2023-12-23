// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/ec.hpp>
#include <ack/ec_curve.hpp>
#include <ack/ecdsa.hpp>
#include <ack/keccak.hpp>
#include <ack/sha.hpp>
#include <ack/utils.hpp>
#include <ack/tests/ecdsa_test_utils.hpp>
#include <ack/tests/utils.hpp>

#include <eosio/crypto.hpp>
#include <eosio/tester.hpp>

namespace ack::tests {
    EOSIO_TEST_BEGIN(ecdsa_secp384r1_test)
    {
        using namespace ec_curve;
        using bn_t = ec_fixed_bigint<384>;
        constexpr auto& curve = secp384r1;

        // Verify that the curve parameters are correct
        REQUIRE_EQUAL( secp384r1.p  , "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff" )
        REQUIRE_EQUAL( secp384r1.a  , "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc" )
        REQUIRE_EQUAL( secp384r1.b  , "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef" )
        REQUIRE_EQUAL( secp384r1.g.x, "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7" )
        REQUIRE_EQUAL( secp384r1.g.y, "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f" )
        REQUIRE_EQUAL( secp384r1.n  , "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973" )
        REQUIRE_EQUAL( secp384r1.h  , 1 )
        REQUIRE_EQUAL( secp384r1.verify(), true )

        // NIST FIPS 186-4 test vectors
        // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
        // CAVS 11.0
        // "SigVer" information
        // Curves/SHAs selected: P-384,SHA-1 P-384,SHA-256 P-384,SHA-512
        // Generated on Wed Mar 16 16:16:55 2011
        {
            // [P-384,SHA-1]
            {
                auto pubkey = curve.make_point( "6881154cfe3f09affbee04cd387b27b7854326faf8906c4b9c9e6ac2c632e0d59717b3f33f6d747d7b7cbb4e4dc01fb8", "ba295ae0966f06ad9d84b3bb4da7f99b56044c99f88d71082cfea6964ea3c63bb79806a6a41fcc314b55b3f64f82b68a" );
                auto m      = "222638def3abc9e846fa506fa6e05ca6bf35a13947147fbfaa20bd0c3c7fa836bac8a0c257573d32f05b6387eb3913af4d14d421f8b3ab6eb182542a48be0fef76466c7fe4acf7de2af7ccb82caa1a37f8be08db46f455f9b3ed7d006b0cda1f0a99e9a09e4caa00d11b143fd645cdcd402af41536eb89c9a77b0ff47d46baab"_hex;
                bn_t sig_r  = "2112385a75d4edda89ae2bc3c74524dc792544a3a52fdb588da3f0feaee6a11623db275e2ab8abdd998cc42a29c60856";
                bn_t sig_s  = "8d308a3987b81c595f8cec19898b1a42da8eda97496af280033b0f915283f171fed7e2a221fa9c78927962189333f437";
                auto r = false; // Result = F (4 - Q changed)
                auto d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "2f2f43f244ae027c3d2ec5c900393f80a8ad0e9b9a12a047195d29a39f2b7026b071688dd9a6764379d02a5ed8035ec1", "e43d45851bc76c37d34dbed996a65ffcfbbaf0e2cbfbc9f62d2116bdf3b330bbef5acdbcd0aa6d949f771daa17cda1e3" );
                m      = "7fda17a3d3bdaa614f5a180211867fc08cf4a6de1fa407498b990e6730589e6eee8bcce705b15a67be22df10d58e62199e6480efca7878516a92020b0544bd04bdfa05f74ec61c43ba392f933a9dca5490927532b775d300ae4171ca9a842f15973ba98a4edd2211340d6c9409649329599f38123c02441340959fc1b5d73173"_hex;
                sig_r  = "c011c52e9cb02048957a233704ff9a2c1d4c56e08ebb083aa8ba351f041a23a7d0da19088ac6c60ea2ca117531c7cf35";
                sig_s  = "a66ca9bf06c35d129a8253a0f793acf681e482d9994868b275a230b215286e03a66a0de77c7a53174375137fd4688556";
                r = false; // Result = F (4 - Q changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "9a5e1932d318bfa7986f0dac4489c6f55775427bb60fb24bac7646b9994bbc3a9b5cd15e818cc4e832afc1c3fca9abae", "64c89e7c3399c136b2718ab675944207157f0bf23d9e2a807ae7ac3bef81da7ec3c56c2d2c08afc53301af2a3cc71861" );
                m      = "053329a0b61466a6198e05d23c287a9f8b4cef88bcb5916da9a50b89b67a659430f46183d28463d397b1f10056a911debf00acc99df49451e146458332517ed7b862fe41f008dd381d7ee2c8e78942c56a147dacccb966ab803725e6d423505e027786baa13fc0c7cd5efb268e3dd8b0464629eebf88e487b8901d22c0b28863"_hex;
                sig_r  = "4cf6c63fea6c80efc105cd99afe2b53da05ae16566ddb20b9d40a076575ffac419b6807fa336fc6e7c7416c59775ef09";
                sig_s  = "aec2d96054b4b23c49faaf9903ccf63bc96281fb7c1b9d14daa54bba51bb2b2f4d3a901f3b0b9cb2b62976459219350c";
                r = false; // Result = F (4 - Q changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "b3aeff27b65540c6da10a88008404b1d49239c87fbf47932518fb87a9bb132403d1f310f531d086340bb4a68c3e64b9b", "567e75f442fcd81017b8adc4cce634f5ffa3cd497d38221d34dc1f43aef99133131ff1b197f7b9f37beecae5c438849a" );
                m      = "33602a6ec9d3807a3bc3bac1a4429865d64d1c1d3715d62cb5f22cdc46770dc991b70075691fe4243cb6a8633b517635b08ec442b1c6ecac08efbe54e7c1e7911852a5189833b0bc7be99c2ea94337f86cc295f2c9c83d0b50e494908e6e4519052f7aa1d905a1867a1b6dffa62760b6bbe26e3cb88878b50a17ed5fa8e1ad1e"_hex;
                sig_r  = "3b94a2514eb915b71e18c867ad7f508a35375c5bcd4b797b86054798569870b2477e2ac14406628017d829400efc63b2";
                sig_s  = "179a10441a0beea3b375248e697e0d19e24bb68184c373fe4302839b97dd7353a5a25929c2733796b0c0d8211bd67c51";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0874a2e0b8ff448f0e54321e27f4f1e64d064cdeb7d26f458c32e930120f4e57dc85c2693f977eed4a8ecc8db981b4d9", "1f69446df4f4c6f5de19003f45f891d0ebcd2fffdb5c81c040e8d6994c43c7feedb98a4a31edfb35e89a30013c3b9267" );
                m      = "3f0783a58e66f3d2c0ccfb5fac3f09db6f8609d0592bc77fdffed9cf0e137d26a867057665f3ad81beebbbdb723d5a47c580828f10f7347ab8a9c24d195f736dfae6eae37d88fe3b4735e7c669a80ac1913e5c24c8c1d5cdb15f994f3ec2f1c774752e14f596b38c2fbf037616d608244d3da7d4badf351330f947e04cc350e7"_hex;
                sig_r  = "8d9d3e3d0b2b2871ea2f03f27ba8699f214be8d875c0d770b0fff1c4ce341f0c834ac11f9ec12bfdb8320b1724c8c220";
                sig_s  = "62150dfba8e65c0c7be7ef81c87241d2c37a83c27eb31ccc2b3c3957670a744c81be6d741340b5189cc0c547df81b0d2";
                r = true; // Result = P (0 )
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "b4b92211edbd41c5468d2ba70810bc37b5e7c954c7bd0db80c4fa89ccba10bf07cdab953828a068bc0104d28e4040c14", "93ed318efce3dff98fc782b788d78658ea5ecde4f716e2d5d0ec2d87a2e761daa1f1658cfb857762caa567baaccf9924" );
                m      = "66ae60b818e65b19c0efab7223a38dd7b8ed1888494bb01dee42d0f0c913ff9f2e16e146a5533956e28af9e8c46faaa0041cc74469e639257b971ddfb17100ab78363439ff2b3883bd17d54adb48a58b75202b4cd5aa82493417bf230436b65cfc3ac64a8e1e874b7b64ca68bcac1cf30e6f363fb2f736502d3e41940ae248af"_hex;
                sig_r  = "aa3978eabd196ddf9cab2815cc9cbab0b61cd639deaf70e093a10a58ddf9f410ee1ab965ff8fbb98efbe812421a613d3";
                sig_s  = "02761a2947e1855806b8a25b9ebb0762be9f5517461a371e5783f34b184f32c4ea684b362119b1a2d8a3ff439f10291f";
                r = true; // Result = P (0 )
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "63b4cc14f9efd3b8f29e65806591d1e9c54f34a3f5231339bcdbfa4109c42d946a59cdd7bbd2591fd1b2383a0819772f", "55ab3d208109da6ef039c23cddd52a5af619266d8fe066dcabb1af885ad5501401a78c44ed3b5fff2892fdcb2a3ac8b2" );
                m      = "11bfe43227da93f9ef79a85c243da7e5893a720724f12f9a64da942ae1ad232e158847c6817983e70325dc4ad7a9ec5e3780d4f376a7cec331f33a8b4171e1ee4b613f8de1608cf9b72fd5621ca36fb7aecb27bb432d21845d8b05e3a4099ad2e458409e8de176d5187af0d06f9f2fe2b9ac9d609ba1206f49a88b2d11e3adee"_hex;
                sig_r  = "a3f9b840fd7201356f35b5dde39027410aad26ac61919c14fe7b0535bb74e7218cb3312bfa60aac63f14166f32ceff26";
                sig_s  = "1b1bcbcb0237fad4e406c8d4e3e39b55642d8535afa9ccbc9c601cb4e01891df79f1bc792687cb3a5ee7703565c4a13b";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "f82f82f8f7454ce7a94a040ec0bbb52d49e3b9f8ddd095704973c760ee6067a5c28369656f22d70d8bb1cd70ef9bfea0", "0e36e256d02870ee5646a17aac4b280c9d1d2e1d4803eb3cb32e7f754cc889522120efd7c4d8a82e509a4d8f266d3ce4" );
                m      = "766c86593bd80ece725a75108a2fa8bb9ee5d13d4d89d0e95ca3105816280d2a82c4f8bc6d2977a34699b37bd7ec4fd5237ddd09ee894ef5311128487ec1cd8387ac24dffd62515bd1fe46087c6f0fc1c37f84aa822fcff167af5c93a2c6e2811c9375a940735d639f856061fdbd28bc400302112b9ce7ed45f2045d9a03ff9e"_hex;
                sig_r  = "27a2332f3c59464f5dfe7bb1201a3936248d375bde603724c048eb8f7c0c2be3ed4b56c14b51d7d68bd2554526b36d9e";
                sig_s  = "e1f90367b0cc530c545f95163d9ffb1208c943685d5ae221052b83ee40953397be581e5979c9855b20246e9d26d57acc";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "7d40b51127cb1642dd8538d4124138a2f49c41b4d12f702c1b0cec8deba50c3712e01c2e1e693e00438af0e86025da33", "e734b5939b673c45dd32baf20d234f01b7124b391d14beea231e9c604e813fc83b3a77b0cb1f2ce4873a69b0165e369d" );
                m      = "1eae9b93f81846153ba466ce52b83c1ee8f2589f88c50b01552cacf14a6bf825b081a3f558005c35f65171b730f33efd38d33dbd898dab5315e9c8005e8d8ad6c026b37b480d04245b3030fbe3fd44141f8a015d45e9772b327cf9f3f3836a9bdede73a1ba0f8236dc17727bc7f26c32d6328531df081fceeea80aa573524f35"_hex;
                sig_r  = "abf16821b6657e0005071f78c679cbbb130bee6e7ca63526eef0f747fb721feefe6258dae1aa02064a700e963bd9dedf";
                sig_s  = "3f7e61c34a30cc5ff7a8be375fcc9c38a76dbc0c30a4356843421ca37a7bcf24edcd41d8235903bb522fb6e5a8033885";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "a5b59d59599c105e39f61354da99c7c9135c749cf996cc2252eb83b008299cdafbcb44227d2d2c4a5ffa44823922893b", "0399fb0edcbfd0b76b524f22b7b87ddbb4fa02f510661615312a4492eb3f2001e0fc0e479f77c33a88f9a7e20757373c" );
                m      = "8e25d2238f24f2b9c3600eb6ac8de5f8c42accbd27939c0039430a2b656d5af7d287f83f139b367cc0d1fff2269ab3912199a70a6af4236e0079d2f22c3a22594a030b40445663c787a5ad0e2107b8280538e02267ea4e36d1f3a93df06302572b93eb0d5928d842cb2cc30a4f5bb319ba274d3abe905a0596a655d76e839feb"_hex;
                sig_r  = "a4c9cac2409a9bfea1ebe28fec4e19545f08cd18fdd31048f52a3f2d32b2ed859dcae4dc12fb2fecabe542c4f03191ba";
                sig_s  = "b4d83f927ad1980d96cbb0ccc36aa640f786293b8b19e4dd97a797d192b420f630a5e42ac42d8736e7d42008f445dbc1";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "29178ce9127e1048ea70c7d435439e9ff9915387e51b7e5ca10bfdafe53565978eb3784d9a4226f443d4834f4d451685", "5cc2970589a453488649711bdf3cdac9a200519aae65b1c6bd54fed0d965755b36b74d978d674275bd71a03e8f054b0e" );
                m      = "9b128ae06a780515c734a7f98e4c17adac89bdcd60fcb0a1d079d856c69440d6cad4952d73f0b3fc399638af1e9eb3944fce8dea9d3de7f91730e11b0662287616dec1137c191a06e628dbec01a99eacc494db055edc54ebff99f7161d8d04aa5afa9244a1adbc87d8d7de67681310a42c9c232aa51632562b0bcd52b6dcd0e1"_hex;
                sig_r  = "5d6f5e9a94d9c92a0890c558bc0408b3405cd04e33f663df16701e80520e4394f1c54d3c8225d36f4753a799aaf6ff90";
                sig_s  = "d895b1cc522ceec6a7867867b8f603245c6e4d48945dfc43af721ebae4683d40a3c21b905ca3bd4b974d36806825b2cd";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "9f03569f8c6ca2c16d707f0ca36a8a8cf214a9d5c14034829d709e283cd675eb4e3090c6b973429efdf476c0782e0a7c", "e1b842536731e91596782787d57af17db85dc92fd2fb95ac65339174aee66775ce0a4721d1faeb29da968ea5eb705e59" );
                m      = "8d94d7b6b6e16b863be09b9217ae9488d8cf1f76aa344dfe12cd32a702c2ee7f2f5802f97c041aa377a365193aacf05c8aecb505414fae1c88a2954545134d78a7fdec43893ec98ba7584a018815c869c22219a816c4dd70a48e24e78d08a3681fe63548810b5f0c31415f6d2b16a141de875c262b81ba95872dde37bb21c75b"_hex;
                sig_r  = "31ccbe22a360b1786dac89394c6ef4ed6604943e50837395f96052821f6182914840096e90f2ad650917bd91d7bd4cfd";
                sig_s  = "d97199a6b952dcaefb1defe23def92bf2ee236ad18046a2ccf8924d42ee10a62e70ffe7f3c909b11112278f160d98b7a";
                r = true; // Result = P (0 )
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "b85e78a935d169dd5ba8f558f964b21c07804464816f9231233184675f557463a8b00470ac0ca8278cd008f4642e7962", "8edf7be8584c5f207939d479e65173e2e69673090a8538fa93efb4432127895d92b4e4cf13b7632a830e9a33b37f75e1" );
                m      = "c3221ec7fa1ad3f33665614e9e2512b853c7b9f515ffa78a2405f1b29f91e87acc2a69564d25977411dd3441120c6c14fa5d479b1526de21667c696e692112563d9a8ab7146dcfb042a33bd5184deb581ed80ad22e059b7b5ed8c5fb51789b82b2e87915b947b8ed452c2d8b0c62f80e15791a7f7cc3d7f47d2437412a6d4c1e"_hex;
                sig_r  = "fd2876b250a94ced71734aa7a0d32423b2c6f039c926c557e748f38e23bbdb46e17d1204832c6f76c3ea854e1da23979";
                sig_s  = "76409e381799502c81194ba87540aec0b89fc4680dd683780d49f82a46a7191b40f5f06ccb02e45e704c31fcd59382b9";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0c74aaa0527524cb6171ab741896b405a6ac4615e474cdc09c9457b18bed33c6383e1b92f2fa1306e8e5dcd1667e45fe", "7b00d934dfd876f6e07dc0582b20ed650be104fa603a5a1255c62b6059d2685aa9773f1ba31254d213c815d0efc8ed93" );
                m      = "6485b69626904d88f55350dfcc3dbb46bf71e1c59a40be5b8c9e52c491097839d5849dba67920d866d8494231d67b36b0cec035ced20a47e679ffdad4918e566bfbae52ff34f2c74a0c79aa82a62e0bbee8c8a10fcaf915d864c8febb905ea2e0bd1e671e0d365667143f8a564828b975f3d797c65f1811a487833006876701c"_hex;
                sig_r  = "832c62b0f34986eda9d1ace5068a0c5318051b0d0166d3dacf137ac072cc359f109ad6e17059e700bb1958bcf4101246";
                sig_s  = "6bb56f4eb550688ea66e5dd09aebe7e0b39e2716b4697ebb68f113e080f0ff26fd0fc947a34f3c5a8a2f10e07dc1405e";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "4104de08b4108ee26ee239e0a5d340c1b1aa48b1b3b40717debd6ed3ff0d777923c106f857a3830ce7f3d08d0d6d7908", "00498c38393e6393edcf254804558f86e461df1f5a6557bc5144f8d2f3806413d372b6ce417d531c08a52d1e38e8b949" );
                m      = "83170d2ea8cab8ca6da17af60d596c59af3dd9d8ed319930c0c328fad7a7a12a8127fcbd6a19f64e5bb2e26f1ce3ca1848df3a5b20d220b21410c010dff89f271b816942bc7fcd63c3de218775c46b9090a67fd4c64e2e8447aa755e68db28084f99a1393092ade8f72ed00e61c28e9a262093fce6f75b8e28341687b1aa4162"_hex;
                sig_r  = "9924a3273248db20db007309560a0e616572ac799d773529a5215786cf4a6e03cc73bea81d4810c1eee4b5e975652eee";
                sig_s  = "6cc8ea4c4c56da87c25946a198e86917227bcb90da7be1dcde7b6547bc45a98e8175dd54af15bb6ef955b4cb48b7bb0a";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );


            }

            // [P-384,SHA-256]
            {
                auto pubkey = curve.make_point( "97c3f446803a61a7014f61cb7f8b3f36486c7ea96d90ee1767f5c7e1d896dd5114255abb36c74be218c1f0a4e7ebba3d", "553ed1fed72c62851e042f0171454f120029adba4ee26855ab881d9470355f1947aa1d2e806a7ff2583660fedbd037a0" );
                auto m      = "a444216c9072caf87fa57c1f04aff9cb83dc2ede9968bda41c9d918825e526c2397cb7d771a7e120582424bbea8ecd56a69bb468cd61437f5a65f04953f9d4018c599afd9edbd4d26e861f86829b9496f829f2b601df73e931fff96559e091417c0d8b8c8129443f7efb985d286c7167b66d2b4d5903583a928db3ed6a883117"_hex;
                bn_t sig_r  = "7b06d6c2b63f1cc3bfdaa897d07dc15a83bdf35d979f70c34578332b3f4920422bb24867c51bde10831324df424e04ec";
                bn_t sig_s  = "4bef715161f400dc98d4b63bd13ff4ad4a6c981ead44bfc662fe9bca4b56cd790698e4deddf9a4bd69327f26bfe801e6";
                auto r = false; // Result = F (4 - Q changed)
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "08bd5c6cdc1f8c611df96485090e20e9188df6abb766bff3c1ba341ed209ad5dfd78b628ec60998ddfdd0dd029352fbd", "d9831d75dec760e9f405d1aa5e23aac506dc019fb64d44bd57f6c570d017e6609f8fdbb2dc7b28ca9e00e37cd32a3b73" );
                m      = "43c5ffcdf6f9e21aba1b065596745e8738f7b39e1db486a6ae52218d66ce8125fdb155ee281e01b27fa20d0e37d6468a2daedc5fd30573e44b256c5af13df27dea56fd81aef689aad7c022cea77ac3c40a1d64b8c0cf7fb5a128d6a1799da7b8d95308613ceb2260e10b37530edd42925fa5abcdad5d0646ba5bc78c330346eb"_hex;
                sig_r  = "8b372c86ed1eec2163d6f7152e53696b4a10958948d863eb622873b471702ac5b2e75ff852149a499e61510905f98e4c";
                sig_s  = "b2ed728e8b30787a28f2a6d3740872e47348686c7cb426411379411310241d25f08a026b853789b1157f1fc1a7f6ff49";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "10a784abb3c549444a62c28df1c926b8aabb20c8d9aa4b1f7ca830258857cbe9718dbc9845fa9cbb78587a373baee80d", "a1ad0c10b5ab6780cad49c8cd3eebd27de8f1b382ddd7a604458cef8e76ca632a7e44e1c63141a742426cec598029e2e" );
                m      = "5edd325885296a829b50b16b17e3c4fc3491f1d53384103f1c09a21a169329e07b3758d55c52e9d578fb9e35e8754bfab9fa5e319d0c7fdb45444eda6a2a0a9aaeaa9b7702cce742047146228f9f687e7684d9b4aaa3be03813c004f0418c1a2fe3aa8ddb3658137d7e954e3683a08e0eaad26c0cc3ae0031b191909a3ebade5"_hex;
                sig_r  = "d9e52be2a3f7f566899cf6daaa38116d092473066f3a1bf91f3df44d81bca1deb438d9d25ce1632599c1d3576a30f128";
                sig_s  = "0cad30bce4b3d7f40b3eef762a21bb1a3bad77439838b13024b7b2c70316875a99e80723a74a9e7a404715ca06a5d673";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "8760182393132d69011edfa127e36f92eeac8272641c27f52f3337ef8af7451e6d14f4e4590c7eb9fafb76e8c92865cf", "ebc2b123ed871ca570ead40ae8f6f32335393c569b21b38f626d09c064a3c8668e9fb10a4667e0f0c68bf25ca98fd6dc" );
                m      = "4fb73e9e8cbc3e829f99472671ee8719f796dbed096b3cbdf1080ad7f5c410a4541e3526de816fe35ab9e664bb1c1d1e9add2522b9a91eb461b45ae4426e1dfbab7dad03a1392706b9314c03104ea7b40f3632577b0b7c991d2b92460638707572b3387add6ab0f05f6f553fa1fcc50fefe74783cd8b781a35de5ae0e7fc5a58"_hex;
                sig_r  = "1db957e5c2d294035d7f476a0cbc28a4aac2614d8212de5017076cd836bf04ffe237dce8fec91f2fb5ef82449ff1c65d";
                sig_s  = "3e3b9058d0a9c5b417f9c6f86557b9d50e7a902694a7012a1be6bb70708497e4d39fc1f6d6bc60dfa52d23cab173385f";
                r = false; // Result = F (4 - Q changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "2b1f98d2acdda8347b9a68c75174408eae7de3d6b9c08c26e73ce9ed2ac147b8d90cd82e30ab43909d63f6b457de2071", "33f5e6f5f5793201991e014cce0045d04adc352298e32f45f4e374450111c8456b5c2efaec43d157949b5c191b2bc934" );
                m      = "b66ca1d77adf6b2b20c6ef68e50d353a9f5cd0be422f5f6fff8f74506280a55d7923cf047dfdb9147b916f6df6cad8c52257360f746b77edb9949ed4ae9a63d08a7da07c4cf32836574a34f316292b8cc5a6b057129a6baa1182be8a5be1c43739e7d9b0abe07801c2d4343a235037b9aaff14694c051fde4b545931ff9e9a3b"_hex;
                sig_r  = "23d046402cbce807d232bcf0dc96d53c72992e0ba1ffce0d79050c0f4c5ad9bfbbdc1c96c730d67ff3aa3edaa3845da9";
                sig_s  = "2cd46a4fe5d120b3af3a6d9ea63cc78f4079e8b5520a8fa96828334a4f182ff4d5e3d79470019e4eb8afc4f598b6becb";
                r = false; // Result = F (4 - Q changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "86ac12dd0a7fe5b81fdae86b12435d316ef9392a3f50b307ab65d9c6079dd0d2d819dc09e22861459c2ed99fbab66fae", "ac8444077aaed6d6ccacbe67a4caacee0b5a094a3575ca12ea4b4774c030fe1c870c9249023f5dc4d9ad6e333668cc38" );
                m      = "862cf14c65ff85f4fdd8a39302056355c89c6ea1789c056262b077dab33abbfda0070fce188c6330de84dfc512744e9fa0f7b03ce0c14858db1952750d7bbe6bd9c8726c0eae61e6cf2877c655b1f0e0ce825430a9796e7420e5c174eab7a50459e291510bc515141738900d390217c5a522e4bde547e57287d8139dc916504e"_hex;
                sig_r  = "798065f1d1cbd3a1897794f4a025ed47565df773843f4fa74c85fe4d30e3a394783ec5723b530fc5f57906f946ce15e8";
                sig_s  = "b57166044c57c7d9582066805b5885abc06e0bfc02433850c2b74973205ca357a2da94a65172086f5a1580baa697400b";
                r = true; // Result = P (0 )
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "9e7553eab8cc7e2e7396128f42ab260c6dbb5457cbff2070ea7c0db21def1537939e3f02699e5dd460eca3798d08bd6d", "892c0c8e47dddf858e89099a8fc1026e8b8333532b22f561f7647f63f9c79dbf5e8dd18fbfe6ff34902233119c5d5aa3" );
                m      = "cc0aac1010fad8555f81423ac25203720853dbe6a465c244388df90839113d59ea3d3521a8a9cbef649f8abe8d6ff8b0cf17ffc199dddb2997511c4b50e944d41cbcdf5d2102dc98d6f9355b211f130d4e89983f63e5dfe6e1b4ffb3caabd1ad96563fb5c0e5905dcb738a59ec2e5d47684707191ff32746a0cbc65b02be7841"_hex;
                sig_r  = "2452da6a48c3749b66e576e0f1f768d51728be17aea149164c4e1654c5ce27f625a4610c4a2eeddb3a0626d3abc6c37c";
                sig_s  = "499504fb58c9db24a7ff5f7921e1312f8aa583c08a308e080f5ef1acf5cdae7927c4101573db069ab0b6de7f4f1cab38";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0cf4dc51e71185a29c0c6fa3c075d9da5bd7ede085053344dce5dbbe8329e8ac9045f7246c9d0efed393b8e113c71429", "fdb7917b73974b355cf9f3bef6a0a460c2d39fdf1fe32a7744be0a54ddd1cfa8d03914cff4b5ca536b40707ff2629aa4" );
                m      = "b9d8d5d47edaa2dca7d7d687f98264b6e21a8e1eeb20083efedb71c116d13150d95f62a369a79f0f45233d2751a4b36432c7c12e19c8bef37568fa1a347929398b7ee69046e11911e3db472c3bccbd68653d99e461b4e5cfa617f94d59798f333ccf13abf426ca8be0f6587a453632a50c159d96695ad03dbaac716e811a3586"_hex;
                sig_r  = "3812c2dc2881d7ef7f621993b161672329b261ff100bbd19fb5826c9face09aec2017b6843d69336b813b673c5402527";
                sig_s  = "5dc102fab9d6325131c556ec00309c2959d1031a63fbc1e2d5d04996d3234ed33875c0ab98e5878e9bc72742519ed398";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "6c590434988155236b43147389c6dbfdd27dcd3387e9b4c2587ece670753a542a13a736579887791cf53d31e5ce99994", "35a20194ff3f1b55f7ffb2758ddd4b98dd0d9e0cc213e10ed25e8e0430fe861066c1d4423c67f0c93f7ebd87fd3c561e" );
                m      = "6d9cf30d59cc9d6e560e9c52f8be325d19eb3cea592e43bd9584411d76064729c03ad54feb4dce435fb662ff069ca3e19bd16c312567f05018feb8f913caf7553ac728ac787ea3ca073a328633441d7c5cc4d30ec194f248c0701119f7dd80c99e44f469f37cc6726601c97e7d94dc8e549261b46d219a7ea36bee650ccd15cf"_hex;
                sig_r  = "89ff866889245e797926509e563b1746920b78c9370a6cdae52663730d131e558e327d1f5fef8faf9e6c802fa29504ed";
                sig_s  = "8dd68e2de2f788e598b3e5a60c18d81849a0cc14b3b0e3c931910639f3125e5d6045f00330b1fa989252a80f95419b04";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "499cbdf18ec4e69b88051543c7da80845fa2de8be2b9d9045fee7f104a8b5b7d04e69142de9955c5ab18c5a34ebff075", "a29cb8d28836b201a389922b6f8f93870f09c80a00242d00d32656a43ac1440fc55bcb123551a73290f603c3469be9ed" );
                m      = "2de0c0671213bd4326ffa5a1070ca605733961b11e9f939f805d2d6974d5286e1b1c00adac360f32bd58432629f8c932e241ffaae742c9336f4c95782d4b73255cac0644c8c2d7099c2ba1fd0cf4243344dd8dc0f77004730f5078479955c385959e06303ef2fda8df81e7237251e3e84a03515505e448aa1330a9a1cd4822a5"_hex;
                sig_r  = "25d4d243da6fd9b439a9242c3656fade7acb7a306e8cf23ea89e3ff4f9330be19c61aaa42d7b426d12c8e0f96b80dae5";
                sig_s  = "e7a99cf4b269bb4a6210d185e9654602523b5cfa1cddc94b1db92018aa557ecb6adda44c816975f5ec1756b6df3c44fd";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "9a74ea00203c571bd91ae873ce0ed517f8f0a929c1854d68abd3b83a5051c0b686bb37d12958a54940cfa2de23902da7", "6f20ccf8fa360a9ec03d7bb79ff17ad885f714757ef62995f824908561dc0c3dffc49d873627936a2fff018b82879ced" );
                m      = "69de70edec5001b0f69ee0b0f1dab6fb22a930dee9a12373fe671f9a5c6804ee1cd027872867c9a4e0bdfed523eb14600cfed64fca415188d56eb651d31731cd3e0efec7251c7defde922cf435ba41454a58d2abf5f29ce5b418a836cab1671d8cdc60aa239a17a42072137cfdc0628715c06b19a2ea2e55005701c220c0924f"_hex;
                sig_r  = "acc1fcac98c593fb0a0765fce35a601c2e9570d63ea1e612fff8bc99ac2d4d877750bb44cfb1014e52e00b9235e350af";
                sig_s  = "7f53de3afa4146b1447e829ebac8f5645e948cc99e871c07280cc631613cfdaf52ccaeccbe93588a3fd12170a7ec79fa";
                r = true; // Result = P (0 )
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "e22f221809fb7a054ac799a70b3d24744eb7c5096c8671770399527c88ccf9ddaea0257a0ae9430d927ff5d9f109c533", "af4101d60df9b306ae92da7592f4faf3df422a3e33f1c2ed2973b2b900eefc346b4cf024de650abf537cecd12ac77618" );
                m      = "383ab0251157e645e678100ad3431b9ad96c6279e237ada71d85db0ce3a96fcd4805b2e7676e9a395f1d2f14f24535b77160b22d3d1c7d2e02ec4bbd82058f397db468f4d9ff0ab8306f9becd234f7a7b9c5a4ed44b7474913fe984b5b9e995fae9a951e6e8f2975df67a0180cea81fd4c97eea60a25c15e2ba21092ab0eebd5"_hex;
                sig_r  = "c39a8e79f0560b9f26504469a470c7b2230c0d25de07c206e87dfbde9aff0a5d85322f56dfb50d4c1fc67c67d615dad7";
                sig_s  = "2ad94dd13a39cf4f4cb24c2c81d4c1181652363addd856dc9ba7455458e40ed047cd113129bc87f43949d5a98a0d5205";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "fa8ebc3682d90ac7356f0b75b9e3376e76518676e0bedd176cfa7fa57fea4b3a399dbb2bf735ec90b9c1705cf9fa6f57", "18c3fbca0150ec10696b3851f31fb3ba62c0b6be509d249e0d4b374c7a08e49338e0922e2a8a9319999e6569ab8d292e" );
                m      = "b23e83d372422cad7bf633ff84468b5ca0f1902eea801bb2e6e89b45d2f75ef9e08c47e010decdd2cfbd9280b01511164e00bd8323fd06a019e83d3dd23c8aa0313ad5196925b5b7d5c25ff8fd198ac2a234dbe0a13fbd04c4002ea89856e91e789e07e25d56690e0481cdb776a3035a64f4bd571097ef07bd49994f95d8323f"_hex;
                sig_r  = "fb58ab09b8a7ef7a6ec05b854eae11af9b713f7c7540e25115f609846e636ad4f88dcf4dd61e311273df23ccda474f03";
                sig_s  = "485be4c21b7c3a9c6b39ffc9f0c39f4050f76d2a6b3fae203d016318c541c1b4ad6cfc0d0950636ff6883895dd49e4e9";
                r = true; // Result = P (0 )
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "e5f331536a2940cd67234bedf813c12e15aefa9a1a68429f8754bf2769a47c9c2efb5c42135e7b01a110d7302e097eac", "63b2398612c863febd482184e834d3acb51408c49aacbbd35d8719746f37cb13e013c9505ce034cd815aacd10d2f7a0d" );
                m      = "eeef70ae23d95330a71bdde1feb196d599481e057bdbd5ef519ce445a9b5acb46ede325a9caad720e4fc49c198ff5f0910c56a06d0cf76f450da1ad35fecccdb4442f64daa6149ee6b67ab1307ffb5c4b6ca3e72a644d36d9e71c4dd3283d12041e73e6d20ec19b3b20654593a4cca4b2fd9aa12f17d5b00b7ed43df74548010"_hex;
                sig_r  = "96c35f22d036785a392dc6abf9b3cfb0ad37b5c59caefcc0b5212e94e86739a2674020ff79258094d90d7d59f09d47a1";
                sig_s  = "373cbc865384734c56952f7a35a1fdecd88e8b343ee3aa073d30f5f25b73506f1e5f5857f668b0080dec6edeb5e1be96";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "c53ad865beb1e2b92764065f1a6bb465ee94aacabe43426a93c277d02e00fe36be1c859ba08a031fc518a0d007668979", "6728d42bae9bc097151748ffa0982964bdd16076fa0e7cc15837c1f773b08d02c3dbc57339091ccc34105b84781150b4" );
                m      = "7875194a0c3261cf414652cd9970219e3bf8185ad978affebd92ffd40c209a0d17dda0d5b79fefaeba3400088720598cc757aea1fb31ce976fb936726fd4b48d396a35cf4b78d16ddda56067ddc64728dc80b874c5286128b7b5da88808c7df5c3323791720e7ead8b50144dedc15590530b89cd022fd7291c97a4b9889d0568"_hex;
                sig_r  = "d4f0dd94fc3b657dbd234767949207624082ff946de9ce0aeb0d9993b8c7d7935760e1bf9d8b233bc7d6cd34928f5218";
                sig_s  = "0941df05062aa8849610f4b37d184db77ed1bc19ad2bb42f9a12c123017592bf4086bf424b3caad9a404b260a0f69efb";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );


            }

            // [P-384,SHA-384]
            {
                auto pubkey = curve.make_point( "1f94eb6f439a3806f8054dd79124847d138d14d4f52bac93b042f2ee3cdb7dc9e09925c2a5fee70d4ce08c61e3b19160", "1c4fd111f6e33303069421deb31e873126be35eeb436fe2034856a3ed1e897f26c846ee3233cd16240989a7990c19d8c" );
                auto m      = "4132833a525aecc8a1a6dea9f4075f44feefce810c4668423b38580417f7bdca5b21061a45eaa3cbe2a7035ed189523af8002d65c2899e65735e4d93a16503c145059f365c32b3acc6270e29a09131299181c98b3c76769a18faf21f6b4a8f271e6bf908e238afe8002e27c63417bda758f846e1e3b8e62d7f05ebd98f1f9154"_hex;
                bn_t sig_r  = "3c15c3cedf2a6fbff2f906e661f5932f2542f0ce68e2a8182e5ed3858f33bd3c5666f17ac39e52cb004b80a0d4ba73cd";
                bn_t sig_s  = "9de879083cbb0a97973c94f1963d84f581e4c6541b7d000f9850deb25154b23a37dd72267bdd72665cc7027f88164fab";
                auto r = false; // Result = F (2 - R changed)
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "cb908b1fd516a57b8ee1e14383579b33cb154fece20c5035e2b3765195d1951d75bd78fb23e00fef37d7d064fd9af144", "cd99c46b5857401ddcff2cf7cf822121faf1cbad9a011bed8c551f6f59b2c360f79bfbe32adbcaa09583bdfdf7c374bb" );
                m      = "9dd789ea25c04745d57a381f22de01fb0abd3c72dbdefd44e43213c189583eef85ba662044da3de2dd8670e6325154480155bbeebb702c75781ac32e13941860cb576fe37a05b757da5b5b418f6dd7c30b042e40f4395a342ae4dce05634c33625e2bc524345481f7e253d9551266823771b251705b4a85166022a37ac28f1bd"_hex;
                sig_r  = "33f64fb65cd6a8918523f23aea0bbcf56bba1daca7aff817c8791dc92428d605ac629de2e847d43cee55ba9e4a0e83ba";
                sig_s  = "4428bb478a43ac73ecd6de51ddf7c28ff3c2441625a081714337dd44fea8011bae71959a10947b6ea33f77e128d3c6ae";
                r = true; // Result = P (0 )
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "9b3c48d924194146eca4172b6d7d618423682686f43e1dbc54ed909053d075ca53b68ae12f0f16a1633d5d9cb17011ec", "695039f837b68e59330ee95d11d5315a8fb5602a7b60c15142dbba6e93b5e4aba8ae4469eac39fa6436323eccc60dcb6" );
                m      = "9c4479977ed377e75f5cc047edfa689ef232799513a2e70280e9b124b6c8d166e107f5494b406853aec4cff0f2ca00c6f89f0f4a2d4ab0267f44512dfff110d1b1b2e5e78832022c14ac06a493ab789e696f7f0f060877029c27157ce40f81258729caa4d9778bae489d3ab0259f673308ae1ec1b1948ad2845f863b36aedffb"_hex;
                sig_r  = "202da4e4e9632bcb6bf0f6dafb7e348528d0b469d77e46b9f939e2fa946a608dd1f166bcbcde96cfad551701da69f6c2";
                sig_s  = "db595b49983882c48df8a396884cd98893a469c4d590e56c6a59b6150d9a0acdf142cf92151052644702ed857a5b7981";
                r = false; // Result = F (3 - S changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "5140108b93b52d9ad572d6129ed6564766f8df3755e49fa53eba41a5a0d6c1d24a483c90070583a66e3cfa52b6fb1f31", "ff52498446a40c61e60c97554256472625633eda0c1a8b4061481fecfbe9c4503e99dfc69e86c9e85c8cc53dca6b8dc4" );
                m      = "21eb31f2b34e4dde8d6c701e976d3fbbf4de6a3384329118d4ddb49adb2bb44465598abf6df25858b450c7767e282ccaca494088274e37353674eef58f583937d3d184ef727317d3672397a74c8fe327919a3df8fd65af0bc8cebbc40095adf89f1bf2c5e6dc6ba44633fd8433b25f065f5e3eb4840af23cc534415406745a31"_hex;
                sig_r  = "b2726b2ba9da02de35e9953fc283d1e78700860d4c33dce8db04dd41499d904866c1b8debb377f6c0dfcb0704252174f";
                sig_s  = "0775b027068d7ad55121a278a819f52099ace750d5e996eaec9dee7be72758736cf769650148fbd5c411beb9b88f979e";
                r = false; // Result = F (4 - Q changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "31f4fc2fac3a163a5796f5e414af6f8107ab5e4a98c755d81efa9d5a83c10128c16c863190112fc29d3d5f3057a2edf1", "fe208743f3e96c3a34b5fff78c9716c074a1ce3dc01c3f0e471ddfae91cd88e7dda38dd0e5e1f91b00b8539da3cc10bc" );
                m      = "58ea3b1e82f97708053d0b41441d0aa9619050e86ac6c4f7781164e5da3019c47a839366509fa95812e4f64afdc62b627c7a98f633dd05db45c1d8954fc83bdb5042679378bb7e4c7863aacf2026360ca58314983e6c726cf02bb347706b844ddc66aee4177c309cb700769553480cdd6b1cd77341c9a81c05fbb80819bc623f"_hex;
                sig_r  = "706911812ec9e7370234efd57b2855975eab81e9c2fe783aa8e442dc6e7d681dab2dc0dfc6765f87ab67001108e3facf";
                sig_s  = "42c89efa22d853d32f619c9fe13e9852889ac98a9fed5d4fa47fed238e1cbe70d7970af9f7bdf84e51176af4885f2490";
                r = false; // Result = F (4 - Q changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "1f7911dcfe63a6f270cf75b8584d9b1b4a00afc1fa43543c945945b8a821ebeb37fbc705a000f9cc7c35f7d27027b7bb", "f11835ec80c4ac06d99247e73bf72522109ac255e6109262de4dfbf9619244f74fb6c9ee57694537d7e79c248db34dc4" );
                m      = "188cd53097ef3e64b78b9260bf461708c836f25f2bcc98b534af98b96ee4b324e2203a7e62dbc396966f56419fb5135cb124369aaa025f396eac72f05ab45950d9e02cd5a2357eafab9f816117b7f1de192468895327802ec79f5d6b5a3d44d7afbed7b4a308e365655b8db2bde75e143062ee48b7c51688ac5db0bc7c83ec9c"_hex;
                sig_r  = "3587c9c6885adf3be1086825f9a41ccd2edfa0bd95e7fc4dba5a9710f41d539132de7772f14c18e318f8992b66d2a86c";
                sig_s  = "73a844d729599d4e3e3c1b63e9c4bf5a73d1f69e0160857fe63a56c381c051f5c37ea6b4cc4caacb6ff26ef9699efe30";
                r = false; // Result = F (4 - Q changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "2039661db813d494a9ecb2c4e0cdd7b54068aae8a5d0597009f67f4f36f32c8ee939abe03716e94970bba69f595fead6", "e2d5236e7e357744514e66a3fb111073336de929598eb79fb4368c5bf80814e7584a3b94118faac9321df37452a846fc" );
                m      = "6462bc8c0181db7d596a35aa25d5d323dd3b2798054c2af6c22e841b1ccf3dc3ee514f86d4a0cef7a6f7f566ae448b24dcc8d11eb7a585d44923ea1a06c774a2b3eb7409ab17a0065d5834ab00309ad44312a7317259219543e80ddb0cc2a4381bf6e53cd1bb357eba82e11c59f82e446c4b79314119182c0de96a1b5bae0b08"_hex;
                sig_r  = "164b8ac2b34c4c499b9d6727e130b5ef37c296bd22c306d1396c6aa54ca661f729aa6353b55d7cf1793b80b5a485115f";
                sig_s  = "4e7187f8f735b7272f2c0985315b5602bb9b1a09f32233aa10570c82d1ccedef6e725800336511e47f88ddbbbdc08f54";
                r = false; // Result = F (1 - Message changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "46dcf8ee848c6459fa66d1cae91ccd471401a5782cb2d3b9b9264189f0e9ddf7197b05c694931bde3306240cf9d24b7e", "79d9508f82c5ead05c3f9392f3b1458f6d6c02f44420b9021d656e59402e2645bf3ba1a6b244ddb12edbb69516d5873b" );
                m      = "13c63a3cb61f15c659720658a77869145ae8a176c6d93d3a8aa9946236d9fb0463db9e48c667cba731afaa814ba0d58357524f8de28d4c4bbe2691dac9b32632a7dd0f99fd4cb240290878305011f7d3e37ecc410cc1fed601e7901e8be6414ea44317584843a2d2ca2e15103e1ea49365bc384355b3c6fa6ccdd452543e9769"_hex;
                sig_r  = "5ffba3b5bd7c3a89ec40b47884b0b3464e8abb78608c6d61e1e62c2ca98d44fcdf61825d69dffee8408d0849d0623bac";
                sig_s  = "0d2597b5fc3842ffce1957172253a8c9c0e4dbe770ce54f70f139e0545dc34ec639d609e14175bdb2b812ccfda00c9d4";
                r = false; // Result = F (1 - Message changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "097cea75f685cf4d54324ad2124ce3f77b1e490bbaa1ffacde40dd988f7591e1c5d158e6f232500d958762831914af7f", "716d8bc056daf69ca2edd21b89a6ae9923cfcae87bfda5f9a6e514dd4b9d28d164fcc613ca2afb9660adfece59f09b66" );
                m      = "6939a9118adc307107aa6b0057c280d10fa44a64700c7bd23e1f33a478ad2cfe596c05f72b540cbdb696aac6ab98d9ca8c62f33e182657130b8317a76275a5996333a5d3547e2293b401d0adf60f91e91d2137e34f3336e017c3c6dba6bf5b13dd0de288f9b20a896a92c48e984fbc09f920fab82f3f915d6524b0c11236aca4"_hex;
                sig_r  = "1c5d4561d2a3af8835839b543098c101c715c545eb7d00300c5cb05bb08dac29e732ffdc31c50915e691999ad505104c";
                sig_s  = "c3442f2fb1498fd47c2f959edff37a19783e3ccee80dc6955ca64db087fd188e67358e7b9223535bbb858d21ba6a978c";
                r = false; // Result = F (2 - R changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "d2e2b3d262bb1105d914c32c007ea23d15a98197f0ed90b46a17f3d403e406a76c8f752be1a8cd01a94fd45157f6511a", "e585fba180017b9983b4c853ad3a5dd52e079c5f0ef792d1a0213b6085e390b073de1a4b01749ceab27806e5604980fe" );
                m      = "c82071e42c45ac3597f255ba27766afe366e31a553a4d2191360b88a2a349ee077291454bf7b323cb3c9d7fec5533e4e4bf4fb5bc2eb16c6319e9378a3d8a444b2d758123438dbb457b26b14b654b3c88d66838adfa673067c0552d1b8a3ade3a9cb777986c00f65cace53f852c1121acf19516a7cf0ba3820b5f51f31c539a2"_hex;
                sig_r  = "49c001c47bbcee10c81c0cdfdb84c86e5b388510801e9c9dc7f81bf667e43f74b6a6769c4ac0a38863dc4f21c558f286";
                sig_s  = "1fb4ff67340cc44f212404ba60f39a2cb8dcd3f354c81b7219289d32e849d4915e9d2f91969ba71e3dd4414f1e8f18f7";
                r = false; // Result = F (3 - S changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "cd887c65c01a1f0880bf58611bf360a8435573bc6704bfb249f1192793f6d3283637cd50f3911e5134b0d6130a1db60e", "f2b3cbf4fe475fd15a7897561e5c898f10caa6d9d73fef10d4345917b527ce30caeaef138e21ac6d0a49ef2fef14bee6" );
                m      = "137b215c0150ee95e8494b79173d7ae3c3e71efcc7c75ad92f75659ce1b2d7eb555aad8026277ae3709f46e896963964486946b9fe269df444a6ea289ec2285e7946db57ff18f722a583194a9644e863ae452d1457dc5db72ee20c486475f358dc575c621b5ab865c662e483258c7191b4cc218e1f9afeeb3e1cb978ce9657dc"_hex;
                sig_r  = "addfa475b998f391144156c418561d323bdfd0c4f416a2f71a946712c349bb79ba1334c3de5b86c2567b8657fe4ca1f1";
                sig_s  = "1c314b1339f73545ff457323470695e0474c4b6860b35d703784fbf66e9c665de6ca3acb60283df61413e0740906f19e";
                r = false; // Result = F (2 - R changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "a370cdbef95d1df5bf68ec487122514a107db87df3f8852068fd4694abcadb9b14302c72491a76a64442fc07bd99f02c", "d397c25dc1a5781573d039f2520cf329bf65120fdbe964b6b80101160e533d5570e62125b9f3276c49244b8d0f3e44ec" );
                m      = "93e7e75cfaf3fa4e71df80f7f8c0ef6672a630d2dbeba1d61349acbaaa476f5f0e34dccbd85b9a815d908203313a22fe3e919504cb222d623ad95662ea4a90099742c048341fe3a7a51110d30ad3a48a777c6347ea8b71749316e0dd1902facb304a76324b71f3882e6e70319e13fc2bb9f3f5dbb9bd2cc7265f52dfc0a3bb91"_hex;
                sig_r  = "c6c7bb516cc3f37a304328d136b2f44bb89d3dac78f1f5bcd36b412a8b4d879f6cdb75175292c696b58bfa9c91fe6391";
                sig_s  = "6b711425e1b14f7224cd4b96717a84d65a60ec9951a30152ea1dd3b6ea66a0088d1fd3e9a1ef069804b7d969148c37a0";
                r = true; // Result = P (0 )
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "d1cf635ca04f09b58879d29012f2025479a002bda590020e6a238bccc764478131cac7e6980c67027d92ece947fea5a6", "21f7675c2be60c0a5b7d6df2bcc89b56212a2849ec0210c59316200c59864fd86b9a19e1641d206fd8b29af7768b61d3" );
                m      = "15493aa10cfb804b3d80703ca02af7e2cfdc671447d9a171b418ecf6ca48b450414a28e7a058a78ab0946186ad2fe297e1b7e20e40547c74f94887a00f27dde7f78a3c15eb1115d704972b35a27caf8f7cdcce02b96f8a72d77f36a20d3f829e915cd3bb81f9c2997787a73616ed5cb0e864231959e0b623f12a18f779599d65"_hex;
                sig_r  = "6101d26e76690634b7294b6b162dcc1a5e6233813ba09edf8567fb57a8f707e024abe0eb3ce948675cd518bb3bfd4383";
                sig_s  = "4e2a30f71c8f18b74184837f981a90485cd5943c7a184aba9ac787d179f170114a96ddbb8720860a213cc289ae340f1f";
                r = false; // Result = F (1 - Message changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "d15ca4b2d944d5539658a19be8ef85874f0c363b870f1cd1f2dc9cb68b2a43a10d37064697c84543e60982ab62bb32c8", "062fb7dfc379fc6465302ac5d8d11d3b957b594c9ef445cfe856765dd59e6f10f11809e115ac64969baa23543f2e5661" );
                m      = "bc5582967888a425fb757bd4965900f01e6695d1547ed967c1d4f67b1b1de365d203f407698761699fec5f5a614c21e36a9f57a8aaf852e95538f5615785534568811a9a9ccc349843f6c16dc90a4ac96a8f72c33d9589a860f4981d7b4ee7173d1db5d49c4361368504c9a6cbbaedc2c9bff2b12884379ba90433698ceb881d"_hex;
                sig_r  = "e2cf123ce15ca4edad5f087778d483d9536e4a37d2d55599541c06f878e60354aa31df250b2fc4ed252b80219552c958";
                sig_s  = "696707a7e3f9a4b918e7c994e7332103d8e816bbe6d0d1cf72877318e087ed0e230b0d1269902f369acb432b9e97a389";
                r = true; // Result = P (0 )
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "c83d30de9c4e18167cb41c990781b34b9fceb52793b4627e696796c5803515dbc4d142977d914bc04c153261cc5b537f", "42318e5c15d65c3f545189781619267d899250d80acc611fe7ed0943a0f5bfc9d4328ff7ccf675ae0aac069ccb4b4d6e" );
                m      = "4f31331e20a3273da8fce6b03f2a86712ed5df41120a81e994d2b2f370e98ef35b847f3047d3cf57e88350e27b9ac3f02073ac1838db25b5ad477aee68930882304fc052f273821056df7500dc9eab037ed3ac3c75396e313bf0f4b89b26675af55f3378cf099d9d9a25a4887c1cfd2448f5b2188c41d6fa26045c5e974bf3e4"_hex;
                sig_r  = "b567c37f7c84107ef72639e52065486c2e5bf4125b861d37ea3b44fc0b75bcd96dcea3e4dbb9e8f4f45923240b2b9e44";
                sig_s  = "d06266e0f27cfe4be1c6210734a8fa689a6cd1d63240cb19127961365e35890a5f1b464dcb4305f3e8295c6f842ef344";
                r = false; // Result = F (3 - S changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );


            }

            // [P-384,SHA-512]
            {
                auto pubkey = curve.make_point( "d4e93c4bafb54c06814011309e9f3d8e68b76a5452e364ef05ccc3b44b271e576c9028106b1584f09271c886d467f41d", "db730ccfdeb6644362f4fb510d5254bfe6f23e891e936132f90f1913e93baa8b1f8c0613a0f0c61a760ce659f22babc6" );
                auto m      = "a594969c379cb9e26a7f8db462d2382699b2a6212bc7aab15e768093b2c3158ad5c725c3680ae1f8099e3045a77e744a5a3fc9c15f118ec5a04e186b4b6ca46027737305fcef397257c46cf219d7a1612a93bca36b1e97148caffe0b21fd5d69e572f823f995c0fb8784c8920b6d0353eefb31abbe578f5b5c0b503dde205049"_hex;
                bn_t sig_r  = "8d0fd14a59c24b0c2a34b438e162f1f536fe09a698cacfe0760d026d1593265d02f2668d2a5e49ac0b21e93807aa9c18";
                bn_t sig_s  = "3162ffd2adc9dd5ec1bb1d97d2b0c27b8ae234235ffb374878d0b76382002ea505e885c178d56a2d7809bd1d83117ef1";
                auto r = false; // Result = F (4 - Q changed)
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "c665feccf51e6bca31593087df60f65b9fe14a12022814615deb892eedb99d86069a82aa91319310b66588185282dad6", "1e6e25bb8ae7714415b94f89def0f75dcb81d4af6b78d61f277b74b990c11aff51bd12fc88d691c99f2afde7fbd13e51" );
                m      = "d497dfe02aa5e4fa13178dc1ebda8807f9ef1656c1abc448619f2e22a809d05551526a0e9706febd9e0f7ec9b791bdabc5989cb1957377110cc53006bece1a025c5bc7e9e64eb1517a6fbfff058e0ae85d67adee20fe536caaaa9928bf7afc52fe8cc662037dcafcdae4e57630b0c15aa1552372b5bf22f500cacfdaf52e7b89"_hex;
                sig_r  = "0e18c4063137468fe864fdc405ad4e120176eb91b4538b28ce43a22ae1a310cc22a2f7a2b3a0f3d15e0f82038b4a4301";
                sig_s  = "5a1620e42041ce4357daf824befbb2ed65596bcd8214e88726149b26b1f416b9472a8877413f1c3705fc2edf4731943b";
                r = true; // Result = P (0 )
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "a6bbf85e8068151482ce855ccf0ed22988fcf4b162c4b811cb7243b849299e3390a083147fbd68683203ba33588b13ae", "5c837ec9f2eda225c83ab2d5f10b1aa5bfb56387deebf27ecda779f6254a17968260247c75dd813ea0e1926887d46f86" );
                m      = "047bb55e59e957f9a8d038a8160fc9e078d73d1cbea39297b8028245b23734b05a6a5f231b729f3697fa3e4d19f6d1c5274ab56c4319dbd4bce742b65d31dbe25425c1c382f48681a243b85a725ec5d9fb1f6cb3d74284de0e8fecd7fe3abbaf2e1cdbefe07893f54e7685eceef8f827ab705ce47d728befbbda5809008adfb9"_hex;
                sig_r  = "9c11879e59659848274fc1ef5a6a181af813d23708b09a24dc06c089b93b918828dd938a75a34d5a681b0af362dc19a0";
                sig_s  = "9c362231962ba7579c4a874e87bdc60dc15cb2e0677149c8ea31162963e05a6614616f67a5269616071cf095be7ff44b";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "9c1eb5cdb1a873e4c275b7ded8712b9058ee0d9ded06c96a2a8d7c652b82e894e2f918dd8e18138e5c34821744b97952", "dd474c93619f02b5d4fe30ea7805c1a13fb80008a81bb5f3eeb95cd11f38841b8e34d64f2c6cc2d6cc2587365eed6b6e" );
                m      = "67caf5a42a7150b0e4905067aaf2828ded4aa245f195dd793984b9feb76c9e2fcffc2326b0af42450b9e0ea13481aa4dc979bed8633dccbf40e1a3b821a674408dd80d14d8aa411080619b7536c72a4685fb93273428aafe490915f0734387c2a956d7d20a1d93c28c64fe3913cf367705366bca6693d2d22f6c6fbaeba86be3"_hex;
                sig_r  = "f17b2f2fa3b5c8e9c62a633e5d417139ddf3dafba75b464fa156c99b3948a0aca532c7fd3e14a266eb17e7fa80881da2";
                sig_s  = "01c246866983fa74d6dff38b1ea091f8afd218b5a42467761b147c19a3bb20cd24be8ed1f95f1e61863a709d2d0148e2";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "20622a293edc96d83fee77cf1ee8077c61d6f8ed0073d53cfb5ee9c68e764c553fa4fc35fe42dade3a7307179d6fc9c2", "710fa24383f78cc4568fe0f4ecbbe6b11f0dce5434f4483712a6d2befae975a2efb554907aa46356f29bf7c6c2707c65" );
                m      = "ef353a0ff016e6618ee11a09203ef5a8c1eb6089478ba3042c5002acae01a2f4d99abe37b10f35c1bb03de8b8a6a443cb0d8140f86e64a905f72ad7371f6c3e20a4962531b8dea2a34764909e743885659a9998aaa0db5830913d22697a54c5313af9115c3a66bebe2909b110fdae6fcd4181b6b414e53816504c35d99a367ea"_hex;
                sig_r  = "45a6cf5cef06256139caa709292d1e0f963d176add188572e9c7be29af21a95853a98e23aef0a0850e58d44d60b6d780";
                sig_s  = "df8d71cd5ab22fc718070078103483e5258734872ab935435f21ea199018e49a69c064a63801beb0759fde6e2c4a85b8";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "83a4fecc0bf0a353b0acf6f54094b822f2b12564e172b296f3461cafa7315d7d31d0089b1b4c18ad3c86bd18f539774a", "e4fd57c5b2937e6fba1e7d72fc3f02352bd79c13611931935f4dfd073b9379f862f2277585137e996e212b5b6533dcba" );
                m      = "2fc5392afee78db70368ab391d7d765ea656f13b1f71e5f7550d77443d1091b0df7efc9f4e4fd568827040e3fa7a4b07b6f8eaacaa640711c7d65b04122f7dfc4deba77736382e47a36dda3f379cdde3773a2c7f101825988f13a6b6b64259615c5b6897ba2866d0a0924b4626a0e8db1a97696dd506273a2fb0914283b3d8af"_hex;
                sig_r  = "fb02804010a570d702ebfbcf3d6cc9d55ddac2bd4b4de56d325e9790571b1737f91d3fa1d4caeec6eea806195aed3187";
                sig_s  = "1fd20fe383e907e77639c05594642798619b2742090919bedeefb672c5700881baf0df19b9529d64bc7bb02683226103";
                r = true; // Result = P (0 )
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "208a8c5a6b59458160c5b680116c8b23799c54a7ee8954a4869425a717739facfe4fe24540505cdc133fde8c74bfca78", "22aa7aba797bde1e8389c3c3f8d8d9aa2a914f4d2d7aaf7187ebed9b2761975718ef97660ba0b8a71dee17f2b982e2cf" );
                m      = "9a6e7e81429fcdf0cff8343d31f4db2a3d9c44457e6935d30e72d7f5d4d9d1bb6a68311db4fe3eeace1274fea67d81e066f6a4e7bd78699d25c7a89d7ad65b02fb994b265c8f52a182c1df8fdc2822fbd265b362df886d72bec90b78bfd8f73fa74dc615e6e026b9fee64672af86aa3df458159b6d6bbfd6c74dd2849104a24b"_hex;
                sig_r  = "0b4e835ed83151d2bde96e201c54544ba5f301aca853957d3c538c9858fcce796b60fc50f5600a48dcdf13e5bc029827";
                sig_s  = "0270adf02d31d5428d523e13d7d315c1929a1d89bbd0f61eec0b1186abe1c307cbba6b1067a68bc3947e6196d49719a0";
                r = false; // Result = F (4 - Q changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "80ae47e99107d6148b1088c6694df5c1273ff336b66e45b68a7c65fed735129dadcaf2b900e9f8ec50eff70a5ba89ea3", "47450efb5669bfacd7cbff1f801aafa0812ff88a6ae7b5a1f85e88e19129ed995f509fbf8dec15ce42bbbbd33814c09e" );
                m      = "0b1c2410d8b0cb48defe7f363d163c6de740dd81c9995ce689b22c4276aa2de84d17ed5604b41aca0a9b65a1c00ca2db5cbd49898dde92a52bd8c370c9fce268aca4a1d0ec130cbd7d20f9d2aff8e9e9f24c4a7c48211609427a5177e001e75fab90de23ede74f974dbdef1b04233b9eb0a71baaab7c864a6b46db00eae4cecb"_hex;
                sig_r  = "bae6fba7b1485ecdca48219ead3c39295fa9c196b1f0941445b1ac768e33962f68d37f1f1749eaad7200064aa202fb41";
                sig_s  = "b411a38d02deb42d1015a7837b033c89d2f37d92c70fa8bb1f592223f7750520b950f30277abfb4155a3ab194b3beca0";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "45cb6dcca8d2e80ac04536a22f9d68ea2313245550108ddcd32799d154c0a55492e49463e826275bd9bf0d5e380205c1", "6fd124f5a6c745751ccfb3ba4dd9144ea8fd41a4d9a4b34820434da66aa7385e73ffe71e6c11ed1beb6c7af22ce00edf" );
                m      = "869ca9414de82de07f22f7844d8677f62a92a5bd236173ddc3b2b91f927de15cc64f87694c02b0e212267d70cc65c21d02ebd202366d7e88b292785f0ab49436df50f8d631fa0f0969009ab28c98af2a6d4ce79b7ad42228958d772ae693a4304704b695e82c7b905fd97a484a18a2e32f61e961508389936d7b984e2d6b2e54"_hex;
                sig_r  = "2c782c4263eeee63657fbf20fa287a1a81fcd14b1d3bae333928ba4fc31abb20edebc130714380608e38ea74309eca9d";
                sig_s  = "716113d95bc9dba532bfb470112b0d43d9cd6560ad15e0de2e514994801ff339bcf19ad4ee2b8af573f57c038fbd70f0";
                r = true; // Result = P (0 )
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "36c1459d9e9f7b6c1598778c784cbf94661a2b11370c02ee092f6ea0ca20acf81f1ed5048a28a1466a91689df26bc291", "d1367418c7b216bd32c6dafc8b2be99d02cab68df990758b2ddd543b7eb6ff6e285b649ffe588b1811b549cfb5f0289b" );
                m      = "6c702f33dc562b5771abe12fd776e766f2328402538b99ee2059fc0c561622c5b9171b753e5dec6a6b5de0f2b8e8edc573293ef21344fb03acedb7047737e2b2284738bba243aafae8af1c8b6827fce77013b80c71990fcd517f0c19c65e7a501d4495e1bdd2c7fbbcd38aabe8a2db205b6fcf70331930551bd925e7e00c26a8"_hex;
                sig_r  = "40c338adeb504193444bdb95336177362031aaadc5b7e151e42030df9dd8687f3cb8fe2292fd4f9206989c089d966dae";
                sig_s  = "be4b2ba251094c24de006c89af2b5c77e6937f36d7bb703b4f8edcfe65d45f4b2fd2486222163ae0ed9e215c0a96f488";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "b5eb6670bb0b0d3aef10e533d3660756b7372a2a081d9d920130034f48202cd43b9e2d1e5893d0cfb322db65ab839716", "e28444770396041b489b302786a57fca9a98f19685cb4b455d219151e64645ad30dd3149ec96f3bc90879834b65e58aa" );
                m      = "75fc1d1be05faddbb5bbdd05bb5efa45fc8967b62af04f77bae1e737f0ea5fd84407b299a774cdd38f3697be8d9fc241ff4878856765dda9891a47cebeaf5eff6df79ca9e61c5624775dbbd7643fca27c1ec9cd537063f2b778d1302c4428898e06dd647acaf6d091394db9c629847850ce2bada79eb741c89dc1e38c7829d9c"_hex;
                sig_r  = "0887a13df940907864b425ec0d8f91ac719abcc62b276fa08c5122b38831c8930abd3c8454e98182bb588fc72843717a";
                sig_s  = "a380284eacaa36a34e35f04fbf6e28ffb59176f41ea52d9c9bc1362eccd8e0d699c2e08111d93e9dc2785637b1f4f09e";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "700e8f65e052e918a63a96fa57f4eda849f9f9faca3302d6ead66ebf85838f8145a6d6718a681b7bef73170d7254958f", "9e9e10357658913007803859165926cd1e5e92c3a644d834098cb1cbfab466349bf4238a5154cf50ed77c77a78263e81" );
                m      = "141723104f09367f4b02c187ce292861d445d462d3adc5eb67649633d3c24f132149d12db67e498b98da8d7d7b0cbed2f67459bf40ccd6f629d98d30bd7b414d3b8502b08237f867e013d7369fc9b7f505f67e6a14f1e57ee0170391007c30e4892acb0e8d1490f0e6c20b4721000f08060fb86580a339691e45d140e2d704c5"_hex;
                sig_r  = "59be870e0fd684b000cce95c616d9f34674354e9d20db15d204b8a6285ff55258e4eeb49da1573ef1030cd6b2626dcfb";
                sig_s  = "c0bbbf71d87479d82575458be9f4d686921db7ea458d620271f51ec3f4d1afe3bf25ef9c0c400eb7b92cd7058fb17346";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "a9de6f029445fffcf16349b44095cc83b11e3d0d9f08654b158014803b1cc31b8dfe00b1a8167c6f704d69cdd62c6512", "27336a503a669ba1d1f3619f51dc8aa2a44b2075c682a36f071be486e7dafba9adfac2ce74be0442b7251e99304ffc05" );
                m      = "e4622318a8a04eea5288cd81100e60b224f16a2f4344f77bfdb40a1c4c263d1b73da80c1fbf30d13aa0c05be31267c77c802162a7be7488b5d9fcafde3cfe073fdd5c7a05208e10cf9ede811effb8bb72cffb0c59335ebce348b805a7ddb431911d6991a5a914172d6b8088e8dfec2cee36a52b7e12a63c6732abb476b5a2bda"_hex;
                sig_r  = "f93a4d2eb94d087f28572847e0099ae2ee944efacdad392ec268c9c1e632e6ccd670c36584e58aba52a4c2b07127d55a";
                sig_s  = "941ee89cea6e7ed20213a95482fae134707ddf4d292ab1952ed5464f1f1138669dedbfc9998b696eaf469be5fb240c80";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "e63500d6d13069c01fafc4518f1d429661c5bb6ad1ff0383037ca6a469a5c20c453dce03bf6e4164f7e26f849016b3d0", "83b7b731c2531c3ac61b194cf3db6dc02ccdfa16d9eb49f97bc4ec3fe6c8bd865ea27f1538531ad07dc44fc5107af8e6" );
                m      = "c2c34889861d29db3742763a00e42bfbf4e160537ccafe3d2f1d64557835d35c155c19fa2924f735dcf848cf35eb2880dafc2e8b6980717112f11533bd072ec1e4665aa934b56012eb6cde0f6af3d6d012c4ddb10344f2e08254835fae6ea8555f6c9ab7c451b93d816255dc2911d0275719b4187a1e9cecd435ce85b5165d91"_hex;
                sig_r  = "eb78733e73fd64a6a1f23eba5311af23d26816fb8847671e01fdbd8dc7d5fce1a0823b080ee99e8d75edb3f100e16077";
                sig_s  = "bcaedfe599f98b51542c0f94ae1010611c6767ac3abb2bd887399d62fd0f1b3a0e97deb24c95a76de44521bf24c8645e";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "3ebd869be687f82d844416e6816d698d82e1e22a1f451d50b6c146134deb07f05204c0b04e7dc07ebdcfd916531dc7c3", "6e4d7bde063edb7254a82b9d9249d2a2b9ad8988c37a84ac9f7c09daed42b1fd28f7cca1ea8b4f91a66e878224800bdc" );
                m      = "17aa6d371c82c58cd209a96d374733e53d41eecba295f4d5e9c4ec0ea0d7a6d268947999ec64b39957153cea7549595e177ce530d60e7613075a378b2012a16485e7ce7fd0f8e9560ad3490c6be17c13edeb60f3f7391a54353f7ddd615e4db831763d645101a60d2bf208982c4af2d082a95e42a2ebe436c0ec5b9de80a61a5"_hex;
                sig_r  = "575f87a8a7980555a198cfdec279cbb2f89551b5271d242397c29f6bc4bf413dc30312a7e626ef7fc77a9124a79bf9be";
                sig_s  = "f0b7d759246ad36ba8240c537b1eeb5d148c38d324f48028c598eaef6e49d79ff3f6cfe3a32fbbf6f3ed3aaaec31d572";
                r = false; // Result = F (4 - Q changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }
        }

        // Test vectors from Google's Wycheproof RSA signature verification tests.
        // Generated from: 'ecdsa_secp384r1_sha256_test.json'
        // URL: 'https://raw.githubusercontent.com/google/wycheproof/d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d/testvectors_v1/ecdsa_secp384r1_sha256_test.json'
        // Note:
        //     Test vectors with flag(s) 'BER', 'BerEncodedSignature', 'SignatureSize', 'MissingZero', 'InvalidEncoding' were not included.
        //     All test(s) with BER/DER decoding related errors were not included because they're not part of this test scope.
        //
        // Algorithm: ECDSA
        // GeneratorVersion: 0.9rc5
        // Header: Test vectors of type EcdsaVerify are meant for the verification of ASN encoded ECDSA signatures.
        // Notes:   ArithmeticError - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA have arithmetic errors that occur when intermediate results have extreme values. This test vector has been constructed to test such occurences.', 'cves': ['CVE-2017-18146']}
        //   BerEncodedSignature - {'bugType': 'BER_ENCODING', 'description': 'ECDSA signatures are usually DER encoded. This signature contains valid values for r and s, but it uses alternative BER encoding.', 'effect': 'Accepting alternative BER encodings may be benign in some cases, or be an issue if protocol requires signature malleability.', 'cves': ['CVE-2020-14966', 'CVE-2020-13822', 'CVE-2019-14859', 'CVE-2016-1000342']}
        //   EdgeCasePublicKey - {'bugType': 'EDGE_CASE', 'description': 'The test vector uses a special case public key. '}
        //   EdgeCaseShamirMultiplication - {'bugType': 'EDGE_CASE', 'description': "Shamir proposed a fast method for computing the sum of two scalar multiplications efficiently. This test vector has been constructed so that an intermediate result is the point at infinity if Shamir's method is used."}
        //   IntegerOverflow - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified, so that the original value is restored if the implementation ignores the most significant bits.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   InvalidEncoding - {'bugType': 'CAN_OF_WORMS', 'description': 'ECDSA signatures are encoded using ASN.1. This test vector contains an incorrectly encoded signature. The test vector itself was generated from a valid signature by modifying its encoding.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   InvalidSignature - {'bugType': 'AUTH_BYPASS', 'description': 'The signature contains special case values such as r=0 and s=0. Buggy implementations may accept such values, if the implementation does not check boundaries and computes s^(-1) == 0.', 'effect': 'Accepting such signatures can have the effect that an adversary can forge signatures without even knowning the message to sign.', 'cves': ['CVE-2022-21449', 'CVE-2021-43572', 'CVE-2022-24884']}
        //   InvalidTypesInSignature - {'bugType': 'AUTH_BYPASS', 'description': 'The signature contains invalid types. Dynamic typed languages sometime coerce such values of different types into integers. If an implementation is careless and has additional bugs, such as not checking integer boundaries then it may be possible that such signatures are accepted.', 'effect': 'Accepting such signatures can have the effect that an adversary can forge signatures without even knowning the message to sign.', 'cves': ['CVE-2022-21449']}
        //   MissingZero - {'bugType': 'LEGACY', 'description': 'Some implementations of ECDSA and DSA incorrectly encode r and s by not including leading zeros in the ASN encoding of integers when necessary. Hence, some implementations (e.g. jdk) allow signatures with incorrect ASN encodings assuming that the signature is otherwise valid.', 'effect': 'While signatures are more malleable if such signatures are accepted, this typically leads to no vulnerability, since a badly encoded signature can be reencoded correctly.'}
        //   ModifiedInteger - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. The goal is to check for arithmetic errors.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   ModifiedSignature - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an invalid signature that was generated from a valid signature by modifying it.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   ModularInverse - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where computing the modular inverse of s hits an edge case.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['CVE-2019-0865']}
        //   PointDuplication - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA do not handle duplication and points at infinity correctly. This is a test vector that has been specially crafted to check for such an omission.', 'cves': ['2020-12607', 'CVE-2015-2730']}
        //   RangeCheck - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. By adding or subtracting the order of the group (or other values) the test vector checks whether signature verification verifies the range of r and s.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   SmallRandS - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where both r and s are small integers. Some libraries cannot verify such signatures.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['2020-13895']}
        //   SpecialCaseHash - {'bugType': 'EDGE_CASE', 'description': 'The test vector contains a signature where the hash of the message is a special case, e.g., contains a long run of 0 or 1 bits.'}
        //   ValidSignature - {'bugType': 'BASIC', 'description': 'The test vector contains a valid signature that was generated pseudorandomly. Such signatures should not fail to verify unless some of the parameters (e.g. curve or hash function) are not supported.'}
        {
            auto pubkey = curve.make_point( "29bdb76d5fa741bfd70233cb3a66cc7d44beb3b0663d92a8136650478bcefb61ef182e155a54345a5e8e5e88f064e5bc", "009a525ab7f764dad3dae1468c2b419f3b62b9ba917d5e8c4fb1ec47404a3fc76474b2713081be9db4c00e043ada9fc4a3" );
            {
                // pseudorandom signature
                auto m = ""_hex;
                bn_t sig_r = "d670d637fcb2da85a22f74ac92939ee2ee5e7d1bb8d6d0afd6f1ef0f883a43872ba285430d4df43f93784e1cd6e6f637";
                bn_t sig_s = "3774da5d699f6bd62b329376e3b6d3612abc67cb945a109d506d3fde45f4c33893c4428250ef6ccfd6e417400344eabb";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "4d7367"_hex;
                sig_r = "857f3cd339be8d0a67a5e6cacd5fd267e666b610b660fcd6ac053f04d8e4606777b825327a00796de9d7d77ed846f0b5";
                sig_s = "6fa2b6853764d17480de64c271f2f8b2d22da6289cfda991f12fbea2b177903cdb3e9bdec99cbfce079f6b3a381595e5";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "313233343030"_hex;
                sig_r = "a95f66dadda96af63a18d8cd32cb6c1178a4a50e64dcd1ef29e6e10d4fc6f58923b66f9d93f424bfc5d0da8ac546b07e";
                sig_s = "c8fcd88a1d86ee74774031bc938d8607a9993e9c4c3c2d77066a1a929857a8a71b711a98942bbda1e17e93ce2f10cdcf";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "0000000000000000000000000000000000000000"_hex;
                sig_r = "d51fc2851f3f304d75fbfcbf153a8203f48751403abb50d0f5d55e0a6eed96adbf14a68dce9e38d45a163e24a7c7249e";
                sig_s = "960d4e0f9e19e5a069e359622bb01a9ea2d5eaed385b2d1db114a0c3b3372d3083abd2a648e9cf65a209c26b22cfb329";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2da57dda1089276a543f9ffdac0bff0d976cad71eb7280e7d9bfd9fee4bdb2f20f47ff888274389772d98cc5752138aa", "4b6d054d69dcf3e25ec49df870715e34883b1836197d76f8ad962e78f6571bbc7407b0d6091f9e4d88f014274406174f" );
            {
                // signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb199";
                bn_t sig_s = "c1f76a498ed0346f9408ed7c781c375dcad7dd1a1e31ed9db8cf6e9ef629f3245cab89992728e8a222cdeaf035059adf";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // valid
                m = "313233343030"_hex;
                sig_r = "a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb199";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending 0's to r
                m = "313233343030"_hex;
                sig_r = "a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb1990000";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending null value to r
                m = "313233343030"_hex;
                sig_r = "a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb1990500";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying first byte of r
                m = "313233343030"_hex;
                sig_r = "02a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb199";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying last byte of r
                m = "313233343030"_hex;
                sig_r = "a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb119";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated r
                m = "313233343030"_hex;
                sig_r = "a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb1";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // leading ff in r
                m = "313233343030"_hex;
                sig_r = "ff00a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb199";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replacing r with zero
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending 0's to s
                m = "313233343030"_hex;
                sig_r = "a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb199";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e940000";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending null value to s
                m = "313233343030"_hex;
                sig_r = "a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb199";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e940500";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying first byte of s
                m = "313233343030"_hex;
                sig_r = "a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb199";
                sig_s = "3c0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying last byte of s
                m = "313233343030"_hex;
                sig_r = "a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb199";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e14";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated s
                m = "313233343030"_hex;
                sig_r = "a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb199";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated s
                m = "313233343030"_hex;
                sig_r = "a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb199";
                sig_s = "0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // leading ff in s
                m = "313233343030"_hex;
                sig_r = "a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb199";
                sig_s = "ff3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replacing s with zero
                m = "313233343030"_hex;
                sig_r = "a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb199";
                sig_s = "00";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + n
                m = "313233343030"_hex;
                sig_r = "01a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad42b7370a52226a14223d0c093c1ed1cc62325717fb333db0c";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r - n
                m = "313233343030"_hex;
                sig_r = "a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad49cacd5a139b84583739ca52f308bcdd0494d3eaa19a98826";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 256 * n
                m = "313233343030"_hex;
                sig_r = "0100a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599a9bc75da517651d52bae5c4652a29e3f0382252c2e1ab982499";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by -r
                m = "313233343030"_hex;
                sig_r = "ff5647cf40422f70d0e02a4bc4ba3c4daf42e3afaa67a6652b9befdcdcd2108c9d34494d1e86c38ab4c9c6a7eb19914e67";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by n - r
                m = "313233343030"_hex;
                sig_r = "5647cf40422f70d0e02a4bc4ba3c4daf42e3afaa67a6652b63532a5ec647ba7c8c635ad0cf74322fb6b2c155e65677da";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by -n - r
                m = "313233343030"_hex;
                sig_r = "fe5647cf40422f70d0e02a4bc4ba3c4daf42e3afaa67a6652bd48c8f5addd95ebddc2f3f6c3e12e339dcda8e804ccc24f4";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**384
                m = "313233343030"_hex;
                sig_r = "01a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb199";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**448
                m = "313233343030"_hex;
                sig_r = "010000000000000000a9b830bfbdd08f2f1fd5b43b45c3b250bd1c505598599ad4641023232def7362cbb6b2e1793c754b36395814e66eb199";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + n
                m = "313233343030"_hex;
                sig_r = "013e0895b6712fcb906bf7128387e3c8a2352822e5e1ce1261d5f72c64f244689a538891cb6a386653b70a47e56484b807";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s - n
                m = "313233343030"_hex;
                sig_r = "ff3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12624730916109d60cdba3547666d8d7175ddd32150fcafa6521";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 256 * n
                m = "313233343030"_hex;
                sig_r = "01003e0895b6712fcb906bf7128387e3c8a2352822e5e1ce122971e160d7353b1a13157c3661d22f39c5b63799475ce90194";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by -s
                m = "313233343030"_hex;
                sig_r = "c1f76a498ed0346f9408ed7c781c375dcad7dd1a1e31ed9df16c211d01f2c54504917be6de78412735e1d1856840716c";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by -n - s
                m = "313233343030"_hex;
                sig_r = "fec1f76a498ed0346f9408ed7c781c375dcad7dd1a1e31ed9e2a08d39b0dbb9765ac776e3495c799ac48f5b81a9b7b47f9";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**384
                m = "313233343030"_hex;
                sig_r = "013e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s - 2**384
                m = "313233343030"_hex;
                sig_r = "ff3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**448
                m = "313233343030"_hex;
                sig_r = "0100000000000000003e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                sig_s = "3e0895b6712fcb906bf7128387e3c8a2352822e5e1ce12620e93dee2fe0d3abafb6e84192187bed8ca1e2e7a97bf8e94";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=0
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=-1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=0
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=-1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=0
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=-1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=p
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=0
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=-1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=0
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=0
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=-1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n - 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Edge case for Shamir multiplication
                m = "3130343938"_hex;
                sig_r = "ac042e13ab83394692019170707bc21dd3d7b8d233d11b651757085bdd5767eabbb85322984f14437335de0cdf565684";
                sig_s = "eb4fdca338493686d519df6a7457abb18f48d0249cb9b7d539049b8c021e6cc1ce45c4594f18c210ceb030025f6cdbf4";
                r = true; // result = valid - flags: ['EdgeCaseShamirMultiplication']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343236343739373234"_hex;
                sig_r = "975929c1c18f6535b6b21e355b7280775e46be07126af04de8e39086840fd66fa3e0628df5e86636cf24ff88156a8aaa";
                sig_s = "5169223a02ab84d89f29687397069f93a69595085c2ad8928695bbf409fc0fac803eb563c3b5afd16350928296b6e2a1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37313338363834383931"_hex;
                sig_r = "ec749d0d9f1c4397caee8bdf13fe15609c01e3bf7013c0fec61de8b8105a91b50fa5517dc85579cf814530a8d0075353";
                sig_s = "95d0ab006017d3aff436f45f6334ce812a8706f0d15073afda9cb3ac0a617dbed1e67e8f8a1942ccbb1335f2a73fb8da";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130333539333331363638"_hex;
                sig_r = "7b55d88ee033ad9f5ed40eb04c2be01ec132b2f0142f458b000266d0933cfe89b02230b23bac8cbbda51e131811261f7";
                sig_s = "6aff261cf15f0d16bc45b7a9c45c6c64bcc81439476f83a884cbdd03144cd1664b9c2f0864dda4d743b5b0e2040b6401";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33393439343031323135"_hex;
                sig_r = "735143f5c366cfcab3538d90bfdcb030867fd14da07fa769b19bb83d21cabb1d3b57effc608f0e829b56f962cd8d3a8a";
                sig_s = "71da9bf0ab8032f3364a35c4c76497ac152eb2088f31e330d124f39195e99dc52b9173ab0167ea7ec50196e968898d5f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333434323933303739"_hex;
                sig_r = "57c8e3316af46afbcd92e9328edf23aac8a39eee1f389e8092b7c0a44af82c98b3f82dd7196d0b6a5f0e8cf825d77b9a";
                sig_s = "295e9b5ed2d0772be013206b642595cc6c54742121477327244c342f794aaa6f5c49eaa2647820ff0177ab06c933fc15";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33373036323131373132"_hex;
                sig_r = "0986511c8d8fb8eabf38ee9db774f25a4ec6855f90db689127bbd300adbb5fccea23776b1c9d16f5a001338841344ce7";
                sig_s = "3c2462e7e78b087d57be5b1d350142b57199b10f2162201bfbc7b2c87444eb7fdb6bec97c2a81eaea9b4bdefb095a60b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333433363838373132"_hex;
                sig_r = "e6cc1eba338d1129ef0323e275ec178c64add92bb1a6eb4b1a6772dd4d21f9c392f78ccc870b5404f9c7c37e54ef0a1b";
                sig_s = "c2c310e2233c06e0661e08f02abad4c08de5ad44934ae2c82aafbd2e4ebe76bc73be3757e9006fd21d31f991341e1b44";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333531353330333730"_hex;
                sig_r = "97f981449d986522566b9ca9d9eed191b0826090227801ff2551d86dd70ea5d43fb7d69fb3dd5e619221fd48f9fe790d";
                sig_s = "14fc61201682a3c7fd9f1e0567e32aa5a81bd5b06424bdcaaabc554b45e9ad6e96b566477994f5bb1a4d6f2cc7eedad4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36353533323033313236"_hex;
                sig_r = "7381be0f0ebdc1e7103e928468501aec1a2781497471d4a01451a4374ec754d888d03c21e4724e62e218b8662e645441";
                sig_s = "43bc6698e0853b0c3af0c4d3247e2668bd14b5d1efc0af47783a6347a07336c8c9e7ddaef59371c45949ad923a77c127";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353634333436363033"_hex;
                sig_r = "b0c84f4153134f38d5223ff689adafa8be0187b6f996b3a7e73bfba2cdf0c20a174bb8b53f636006de4530dbe6c955fa";
                sig_s = "64e07297c907d9e1d2af55460e791fc088ba9130be9547021087daafde1bf743472c3e1698510fdb921980c244d27722";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34343239353339313137"_hex;
                sig_r = "f555cfa9c4af250e0d9738418588d0eb3419facb96040e8bb9270b2ee85affd50b5e9cc24dfa97699dd0c9ed54fa6f67";
                sig_s = "f4221d01cb61e15476a0706c7d7e6a8ed6dd42d09979a728dd8c74cb56d8019dd9991ce4d9ac2c5d4c39947b7ed24941";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130393533323631333531"_hex;
                sig_r = "5ac7fef863284650e2e2364b3f3084d5dd6660142719eacf512b2b0691597ffa55efd9b10ca9ce16503a381de08018c1";
                sig_s = "d1e95c9b3391c0c6c65f290ee4bd536b7f76c1d38a10bf79f37bbcc313a0fda2ce6e21195572cff19c72fe014cd27d29";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35393837333530303431"_hex;
                sig_r = "23af8731c5917a151967941f4789e824aa29f134a1d489ccdb42d56adbd2cd6ea40063fa8c3130d02434afedd4563da4";
                sig_s = "11984e2cd8e02e3a91e04776dad088bbec2e5a42236a1eff29482932e3f79f1d6ba1ad28eba984c340d961f33a5d94b2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33343633303036383738"_hex;
                sig_r = "828c2d20976e45f148c7db7d1d60f7f37e077a4032fa8a616ba507d4affc02f9eea6833d0dd68fc99644d68478967871";
                sig_s = "30fdebcf6efbc0f2844e59344a42e3397c006cd384781c2a63f8e878227cf276bb088376370119bafe2d8918cd2af5f9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39383137333230323837"_hex;
                sig_r = "bae5e2b56187ddcc6040a9ac133181c93a0bde87cd2fe55c83898cc600ed0d28a2ebfe0d6cd6f56396ad7b105cb03b29";
                sig_s = "6dcb1b4604a334a60c7b31e4156ce8f0a5ff64b75c6d247bceb4c2dc303d6d1b26f38bd54b5e5ec92ba98909f4b1afdb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323232303431303436"_hex;
                sig_r = "df27ad7f85d6d4844462d9888ea3944375d3e22cf25e38de58c8f20324c104ddf006fff2c9276f09efae862cf3591cc9";
                sig_s = "cd87ee40f38b4defabf1a214e4dbeb009d2eab199d44aca7893cfa810d816484c1be562fcfb1993fd5cda00a119f5bb1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363636333037313034"_hex;
                sig_r = "8559ddc69f03c1d163fbba98e10a51f169c988a0aebeeca86694c396a478d98c3f2618aa06993aeb9dc646df8136ff52";
                sig_s = "baa7939ec4bd412d3958e50ed2d201678d34b2a368f58cd84882647f881ffb907cbac5ef868da1b5dae5e54bee33d2bd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303335393531383938"_hex;
                sig_r = "4536c3f6281e6286170084587d1d70654792c3a48aaa5138882634248cd2221939f8ee7fff0da299cbb329ed26de3b2b";
                sig_s = "33874deb77fa1c35ee217024130c853c71468fa44a0558b07d2c03cf3047280cca7752e80f44287144c1fcb7222c1659";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31383436353937313935"_hex;
                sig_r = "81e29b73bccb4c0af067ba7093970300a1db40a822ab830f47898ae2506707aa3523cb73eb753d3ed64e33164819c4d9";
                sig_s = "8f09293b9099bb08ccf46710ff00269a1285e87c12c3bbc3b94c3256d5dab415c5e53a1f6c96d85779fe7306605635ee";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33313336303436313839"_hex;
                sig_r = "86c6bc10ebbc30f550d70b4a5a728b07c4aff11a2210e03fb9149663065561fbdc7b343faf8333331762e6f91c8d61d8";
                sig_s = "95626bd31fffacc404ce0d25af14047fe13dfdfdd7b6cdaf3a7ad3f1bea88db11faa8022e6f645f8bf26b66ff5fb6067";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32363633373834323534"_hex;
                sig_r = "8ed8c97cfd78079f422711225c866943d10dd72c62fe3fb89000bc3f3f16ccda78943d27b5f2dfffde6b04880329c1e8";
                sig_s = "cb62a92979aba5af7fc47d076f3c7913f579e84a419074bebbaf9b4f92aa0e7f24d6e7fae53f38a7bf06f3e3e1e4d533";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363532313030353234"_hex;
                sig_r = "e0c042b064728daadc7c51b703876f368543dc2bdc31473c3e76a84518954e01f34b3035ffaa73f30ba5008e5656d4b2";
                sig_s = "ce862b3a290614d70a84f77e6f62ae583fc8de5739677072455e29216b8f4324a754617678ad84dd58c7cefc2048527f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35373438303831363936"_hex;
                sig_r = "48a511fdf410b2cf3f1f8bf86d8a91a30771887fe72aa44eb726436f0c8e7dc27b66f5cac3f7b51ecff7c54f9d6f9c6a";
                sig_s = "c2cf9a4af2f989c533e222b3b67c96a39aaeffb7d86cf0ea71e837b517eee76fca502d7feade878a49732aee75b71580";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36333433393133343638"_hex;
                sig_r = "0dac46dae950896cc689b348c031ad9d776a4b9022d44b2225f02124c8ce2558dbae399c8d5e5d3a09eb3ea0c4f24ce1";
                sig_s = "d057338639b25aa835a9889febe4e795967a22f9f6841ea973b892725778c443446e398441d2319210be996c1c5aa7e0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353431313033353938"_hex;
                sig_r = "8eab1877a7fefc207bd036be18306d6f05c55c3e164e0f5eec869304e72707e35a2fc1ab4cb9c85bbb34197c19beb31d";
                sig_s = "8af62763f64f46abce9124ad211b13f8104e0034d205db50c1491c99eb478fefe4c3b590f2bb63173441548210a6cadb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130343738353830313238"_hex;
                sig_r = "e3f7ff3ce02eb4e0f05b64dbd206c73c016a675d83ca0fb4db2e5036015f9082a2c798d64d2a58ad831cf892b880ae95";
                sig_s = "5a8252381bbedb9f30c50560579c21e388bc02960ba5a891f9e28886c4f14d5fbe6549018793da91581d808a26e0faa1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130353336323835353638"_hex;
                sig_r = "206aecd410ac6934780bcc8741ad0bc9970f0edf0485012c115c04e8a6eb9cb949106df4086d08e06d91de4110d3c106";
                sig_s = "26c1e68862189ce6bd1a065359efd2fd7381a81f113bdcfee743ff8eb9b4e9f19292be250b7971b8a8fe5d2bc512e51e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393533393034313035"_hex;
                sig_r = "30b3c484de8b08ba08923045777f4c7b980bafacba605e97dcf140ed1bc71601f4124d9c145d173d719ca73505bebd6e";
                sig_s = "afe66045b7f7ce02b86603420ffcc168812d10f7531b300f6de6de3ac43543fe0df748441a62e6ec947f2efd2deac35f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393738383438303339"_hex;
                sig_r = "530461b01e1f9098f2a85624193b50b41c14df312f6747580cb6ef9475799898a105b7c8e582d2de562b501977fc5c88";
                sig_s = "875a323c291eb8a8a7197772a90dd6a9668e8392e507399968ae25a026ad0085277602b65deff5a386cd615641a89604";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33363130363732343432"_hex;
                sig_r = "e0e498bcaea54c4fcd021e03e73fa11dde5065a7f6fb0c6a1218a8ddd79228de06d0c261be7dca047a30a092d03d10e3";
                sig_s = "4e2dd4d03653313b3ba7fd140a09f7e3c59e2042b0d902700e63ca53c73d11a103d9efc987ef87d75586bc7e1a035136";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303534323430373035"_hex;
                sig_r = "3409654af038b6d1a9c09fceda39a3155fbf28a57e1df4c9e35064876455c2534af075b0e4d7960cacd23a0df9f42e27";
                sig_s = "5b8a3ccd8d4f97135ecf8b5d09423c6b72bc045dcb31d1640e50001464208ce23daee21049dfd1f9b3ced26172f6ee7b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35313734343438313937"_hex;
                sig_r = "031a7190173c2b5af9bbe16b91d5d12640a7fbfbad118237049f7b7b975ed918c91fe78e22cc0bcf58528e3bd87bbb38";
                sig_s = "6357706f71db16d524e1efe7bb2b43277f59e77cdce8fc71a631a84913e333ac1bab3a16f8655a4223a8681e2f3436a9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393637353631323531"_hex;
                sig_r = "346cc96a4f931181737c18932f73a364eda5c3cb7972b5e0446e83cbae8a25e0e7948652b2c9dd3de2f5eaa6ea00c830";
                sig_s = "2ec44b5a7ac35229af089437205b987cbf2beb1cc7b757eb47c8383ebd6d1ea7db169515437ada08f2f68a51d5d1230f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33343437323533333433"_hex;
                sig_r = "6973eef723464352e96f58a5eb3b176ea350b4cc51734fcd2fb50d24a2e24447eec760d410ed93cddf1a50524fafbb97";
                sig_s = "d74f45b20b662986e555d396421ef8258001e538929feea9fa5a9e44e3e647031516b8db95f33fc3c63106e3aa8bc6b0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333638323634333138"_hex;
                sig_r = "69839151e3b3fd33caa7a00cb8d18a1b4427d1c83712a50daf4ba25b9465d5c301fc37cc046815ee5ad89d3788f6ed81";
                sig_s = "9059a83d790ffd68e262eae802cc0723a0a2903d19e45516c34a9fa922eca27a3528fb4f8161d2f65c36dd90014e0a0e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323631313938363038"_hex;
                sig_r = "8d415cada3039cf8ceaec19b75bd97bdfad4336e4affb856fda544e46e0447b6a737eb780c7ab2997c3ad35207758b8b";
                sig_s = "2263661e4ec79487f279c9eccd507319c185c3cca77b2dabe900237b424df2db82bb275ead03a0c7e1452f4b235ed635";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39363738373831303934"_hex;
                sig_r = "c4d368ea98589f828edba7362e083d052e286e683db1af2a8b14529c59214aeb55b8080abf6ef025c59ed2c11d8142d0";
                sig_s = "46557571e457adba970327dcc5fede7604b5f7a4c5bedcada8f745e8ebc44b5b074c9905134cdd644164eb85bcdc30eb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34393538383233383233"_hex;
                sig_r = "fdc4a9e63ee8a2437d0446ecbebe6d9567aa07768dff1f86a629180525b13c0116777e0aa0d82b8711cbb4cdde1f3d58";
                sig_s = "55db077a644062bfad52aa5344945977ae8ce1ec5e69c39a6a883129dd49b622dc63ad168a11f985992ddc9274971ec2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383234363337383337"_hex;
                sig_r = "0eb8aa22ec8b935c8bb3fc4f15d0d476dbbff689fae373b71ef8b1677692115bcd2ca0f3d9884f47ee4e8b9b61ffb0cd";
                sig_s = "fce80bb7ecdb612b92f9a4b75453aacb7a6b66db3663ce983eb9d42d08deb083a169996f635691fda31170cc40451078";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131303230383333373736"_hex;
                sig_r = "54d90579d215219f5a129c24be7b8be7415040d952af17848cf720421f5112e0ecda24b9f9f8657a8eccbcd47404348b";
                sig_s = "88cb28669566a92d70f9249171453391224eb3a6cde2c8d1092f1dfa099556d775e925bdca1de18fbb6281ae9e8f8139";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313333383731363438"_hex;
                sig_r = "524d01afc5c2017bf6903e4ed032999202976c4217f77b4c106904d774bf724edcd648de9729f97101b03c5589b804c0";
                sig_s = "c22be2008aa068663862ded1619c52f7c1c1b9da105295bfb23c79478adc79d133ac1ee3ddfb41f125dc890153b53b90";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333232313434313632"_hex;
                sig_r = "d7d854c08b768c994f435d155ea9969823b364e326ddfc98d769df83b4d2ed2154f09c3e8007a9be6d000f1cfae7ed17";
                sig_s = "15bf0f7d89206d5e90398f62e63917de6b6fda4df13566852b62f61ae3181e20fc2fd297001e90a40ff8042e4a2c4889";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130363836363535353436"_hex;
                sig_r = "abf3a5f3c46686df96a328bfcffce36911e79ade8e36eda9925a641d55330d1b4cd8adc5f7b4b05679b047ee70876900";
                sig_s = "0f97f0063c6997d601ad2f2827b1c9324d79a2d7695b372be8fd55b583f2e0b0159c83ce3b2cfb5b5211993bb861af9d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3632313535323436"_hex;
                sig_r = "554ed95d83fce6e0e49b4b68236aa6c9755a9242b6143d414c13bcd8a765cc156982bd7693bdd24cf2154fabe74ef345";
                sig_s = "e4e29bbb96ae1ea94f826a735d2599271903cc295182fdb1f0052810c01c8385d01ad9ffa443d2dad13c1c6e948d7b4a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37303330383138373734"_hex;
                sig_r = "a31b42c8760587f68042048b9b2ac99ea55d5d2898dd2c565971bc5f038da313ad098e14fc996b2bb7e3b1f5485c6783";
                sig_s = "ccfc345706e0eec6c02f9eebc0cac90cc5807a6505dfe4cbeee837f4b6763afdf067cb1f97a5fe686c3b955b83d81f45";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35393234353233373434"_hex;
                sig_r = "318c147e4dac1e9513f0b9dea9f33e2e08d222d613ef08210d62f4427599a94c16468610ea16738974e3f69361dd35a6";
                sig_s = "f26e2bd9da86f570f865bac5f3ed10dba45e83c2854b6361251b0ea4d504303868aad33fa68780241f9e42a1bc4c8875";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343935353836363231"_hex;
                sig_r = "3522d0d163a4ddf96ab3de77c3bce47437ab27d11f0cf744578e53e5043b42d1b606c80ac47655d94d5750928b8a7734";
                sig_s = "5a49186d3b7c44aeceb66f1346dd5efb7d7f6869a48d93e4a0a1b495d2c42ecaf37e50e443d6999ea0b06d417958bc12";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34303035333134343036"_hex;
                sig_r = "33232fc4a1252216f81fa75ba0582f8bbd3677e31ec41386e5c1d335d078a5e35ae3795e4f6e116825b6d704b9133e65";
                sig_s = "cb4104bab332b7fca97c832c9169295987fd4dfc5f4b3390e78a68955e7a05881edb653da4729ce8afe8dc9c93a12bd6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303936343537353132"_hex;
                sig_r = "1db7492dfe34dc9072b3a8e5b46c60f4b6c349948f17e804181069e3614fd76f99f992a27f4ac4c4a4bba9b4255f73ff";
                sig_s = "8b9849be56d77b1d9762ac74e367497e0655f2170a36671fb989f00a778adb854aedf6c02bfa1a87d57df76a1b63545d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373834303235363230"_hex;
                sig_r = "2a10831254b51ee0fef4da0a76c9d069c495865fff2293314f8a82e27c674db73c5c64ec9451447df990a3e165fcb599";
                sig_s = "e043fbffe24e82cd416e06bf18dc1009c24551772f4f718fbc35e2ecefe91656e4f338364b67d0592deaba7032dd59e6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32363138373837343138"_hex;
                sig_r = "58d0938b3330d1a3c33968803f0132b03a7706f5b6ec15044e266a863bc388d0b64d55d6fa5e136f5576bae0131c1d23";
                sig_s = "3a148453c83bdd1b1ce1b194bc2a2c3e6f969372e2d4363d360b095c9afe03b11244d67942ba30d90d796a0c8992d5a6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363432363235323632"_hex;
                sig_r = "6b0ed94b24a40760f803d0728c9f88fc4ced9ae66c81ae96c47c23299fee5f180b168041f129e267ec2a20c9304755d3";
                sig_s = "be555ce7cbed2b4aa19dfea7c38b782994cc6945fd1bf27b96045e4dda5b2d90209ace7fb3dcd12fad93e2b406a68397";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36383234313839343336"_hex;
                sig_r = "b6f56623da31ae12bbfa074491e10c30b3352f7fd70ede8270971cbe760bb7b83583d0268f4918fb491fbaf49f75604d";
                sig_s = "93326ad817f2c0c24bd24c55f96a0f9fe2d714aebe5cfeef5c612cb27780c27d5325b2974bce3bab12f200c92c084632";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343834323435343235"_hex;
                sig_r = "b17e28636fbf91410820a4f0f699639f66fa91cbaaec6e5ced4b99671c7319f3eda33f9a870636ddc08d881e7425ff39";
                sig_s = "4fb90b8736458b693b5bf9319a3a06bf78e296e700e7c76b4bc25686763d79b54d4ac5b0535668f18ef36046dbaf83f1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00dfa721784921f3697f45769245087c8997e82ca4f5692605cc7dff7235091bd53ba451e2252572818056fbd14228aa27", "7ac54ad5c36344bc092a370f7e149f55d19e4fd9df5022d89d761960911efcbbf6e3b8f3e29114a3ba0729d27e226faf" );
            {
                // k*G has a large x-coordinate
                auto m = "313233343030"_hex;
                bn_t sig_r = "389cb27e0bc8d21fa7e5f24cb74f58851313e696333ad68b";
                bn_t sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52970";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r too large
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffe";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52970";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00de9829daa1eca6573644b003ef87d6a390be7ad5b69f97f6e74337faa19958642936e272f4048976578573d0238e5627", "29989c988f81b05bf4918dfd9b2c2b444f305e4a851e26baad31d2091f9e917a7081f479632c5cb16407c9e2033834bb" );
            {
                // r,s are large
                auto m = "313233343030"_hex;
                bn_t sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                bn_t sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52971";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b6d8c17908d4a6fedb44f1d0fd6a552763069be2c997660447ce4cb2b2cd47657d9337267cecc42d89842d05b8313625", "00a6be94cceb6a9ad74fd2841cfc46fc12188289d724d41b24b07520441cb6c002957b5d2e9ff7fb12fbf8a245d68ed1b7" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "d1aee55fdc2a716ba2fabcb57020b72e539bf05c7902f98e105bf83d4cc10c2a159a3cf7e01d749d2205f4da6bd8fcf1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c1fb7338c0b11b7d0522f7b34b8ee2f1ddf8319c6cde532a138077062bd8c299f287aee32d8c7b5596837ed0c174690f", "00c48dc9933947e4288799ff45344ae0c2dda6bf22d5e0bd167daaa13949ddcf7762f47858bf5c418b2d7a1ca12e7e2406" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "b6b681dc484f4f020fd3f7e626d88edc6ded1b382ef3e143d60887b51394260832d4d8f2ef70458f9fa90e38c2e19e4f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009fdd44cd61f939e15533c7ea1dc439f35ab5920c9b51a0110c494af15ef08efd01c75e70c6ba4ea514bdcf3f146bf7ef", "008b4d04f4c3848d5f5aa32d94278993bb72cf66fea4de1a873b3ae175b45cd7ce98775d2523920f7f33398c89529ff9ce" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00dbe8c22e6c4bb95778b4fc8974fef8a7a2ba0e56951d25fb18a8855e26bc6a3afa8af2c7d1e504a2859be29e20201527", "00b2fe83a33bc386658e144caa05e36c07ac0bfd2bf73aaca2107c79c5548334fdc6372e24cee0460b11eea6737b2ba0ce" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "02";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "529865605596bdfa993e838049cfea67915da278dffdaa258266b32718df0b5d9e8c9d1035a3ac08980849bf7d934ca5", "1214b858d31f75b6f73d8a0b546f84eb328b1eded40a0b33e4fa97b06ea4b7cde46d152ced80b6423558dcec7b2116c9" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "03";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c09d55452bb9376b730f5dd7a187fff0145cf7d26bf4872df7c1d7cfcfa5af8a1ecb6c9fa3bac3361f0c503db6f0b834", "00c7993183f29419412f5b9fc0639c7ca691fee2a8b6d340ae520e4595dc4685a730cba58b840639cab6bbaf31a4fa64e5" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "03";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "20f3d7826045052262df3330fbfdb96a98ed587298ba67774f484ef036d371be7e0fa974a1e3c5a0d72dcaeb8375395f", "0094608a72e9ba34ff09d478fc6cf8833077d00696ffc008b4756f628c4e3e4733546fe04a785ae46eee810c1db0ea2c5c" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "03";
                bn_t sig_s = "03";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "325338f677836e8c523b0c014fa7e0d68ffaed360c35eda0d87304ef5ed9bf7eb81564b2c381ef76dfa823220001e672", "00ae72772695f6bc153613fefd9c5ea340cc623012a26508c7b55a6829ed99beaa8ce97b18865db43a1fa071bdcb812723" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "03";
                bn_t sig_s = "04";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r is larger than n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52976";
                sig_s = "04";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008d65f327bf1f60df97f174122343c41dfc4d4ea02b4759cfed7a5e8c4c387e08a1d5dfb94e3da6c540213ca8f2f627df", "00ed9d52419e1ad73ad3c528a54627278ee921d2fd61d94928e61feb8b3a36b29c4df354f86ecbaa5b5216e4bc42362b98" );
            {
                // s is larger than n
                auto m = "313233343030"_hex;
                bn_t sig_r = "03";
                bn_t sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accd7fffa";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "568eaf1f63c840c7b45ddbdf6079c7830e4dd12c9a9489522a0afcdaa4ba5cadf3627978fca641f7b526c0a9a770b086", "00c41c73d93c35413978a7544d58c010a0b00e1eb0de2c7b58b30b6cc31853f73c030c2c4b0276b2c4e749907beb600dc8" );
            {
                // small r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0100";
                bn_t sig_s = "489122448912244891224489122448912244891224489122347ce79bc437f4d071aaa92c7d6c882ae8734dc18cb0d553";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00f0a5c7f9a60eaa827127a060a8464d1e86aa2af9e8e7b5a1d391b4e5e99664cf7e54953fcc87820f94b14af58b1ce172", "560e0a01d632e5529af97362fb884f6aa28c3077030adda9d62bfcca112c469cbca1bc89e1c3037f7bda5a7824b66d00" );
            {
                // smallish r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2d9b4d347952cd";
                bn_t sig_s = "ce751512561b6f57c75342848a3ff98ccf9c3f0219b6b68d00449e6c971a85d2e2ce73554b59219d54d2083b46327351";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009517e58ea80dd51f878ef6ca5d5129c292ac5ee9f0742f2d01bcc7e57d8277e13dfb86e5737a883647175e2f9034d6a4", "00c04490cf98f55501023eb511bfd9172ce6e2d3bf2fb50332a153f5b18306258581d3008efa149a509afe2334f417fcea" );
            {
                // 100-bit r and small s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "1033e67e37b32b445580bf4efb";
                bn_t sig_s = "2ad52ad52ad52ad52ad52ad52ad52ad52ad52ad52ad52ad5215c51b320e460542f9cc38968ccdf4263684004eb79a452";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0092763643d11b8dd390fb00e7067660966d141920264f26d36ae3ddc5965d5b0b7ab9047f3a7b6df2dc50fb34b45f83f9", "00e530a3b00f81d4e7db16323b42a1e37a20b4e61a4084884266c2a2c9a13fac5b1b45c435b9954dd471bc29b4faf35dbf" );
            {
                // small r and 100 bit s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0100";
                bn_t sig_s = "77a172dfe37a2c53f0b92ab60f0a8f085f49dbfd930719d6f9e587ea68ae57cb49cd35a88cf8c6acec02f057a3807a5b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6e29be8bf01240c48654bd9cb9e6e4b721c8c5026645bd8c87c660efaaabd10b4b62151b8a3bd1b51eaf1593ca466af1", "1f711cee8397ff42b2824363bc96b03af8d700b507d33193c3690b53c85a4428d4f05d9a714a59068d741601eb2a7183" );
            {
                // 100-bit r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "062522bbd3ecbe7c39e93e7c24";
                bn_t sig_s = "77a172dfe37a2c53f0b92ab60f0a8f085f49dbfd930719d6f9e587ea68ae57cb49cd35a88cf8c6acec02f057a3807a5b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "207308e6f1fd1bf539d8c506863b002683e03d8b16c5942472a1a260d88905e15b28ea254147d8574ba8be5f2c9cfd09", "02f3dfd62e0a357709e086ff0fcfd87d1cc2b7232356735a98ba099f2aaf78f264ab4598e162dec425619a6e906daa88" );
            {
                // r and s^-1 are close to n
                auto m = "313233343030"_hex;
                bn_t sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc528f3";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "61e88253d94efe976c07076ebbd97a4a823442d823bf8461d00cfb44a3133b4e174e3a0fac8893387498432934c0cb7c", "00ecd3b9bcf204fd736ee21d4accdcbc4b692312e1769225632fcd7bec206e74259cc40a3c2609e8d2cbdfcd8f4f26be04" );
            {
                // r and s are 64-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "9c44febf31c3594d";
                bn_t sig_s = "839ed28247c2b06b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ba8bd967967e3083343efaee44b67b6f257faef887fb3c2988b1b09721af48c242ad1abe168a123c30c4b7ba544dde15", "2578d88b9b1727e422ea165862288260a9928213afc72afbcdfe0e6350cbac77f12b1f1e3b8848052506c558abfc3762" );
            {
                // r and s are 100-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "09df8b682430beef6f5fd7c7d0";
                bn_t sig_s = "0fd0a62e13778f4222a0d61c8a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "18fa3b1ac43ce85701eb590e100f7b7a901d2dbcee747c5a756c8107e09d919c8c8e34e6c64381c3c146d3c0ff67325a", "008a318fad68c9bbbee72e14560891a38009f58954da86a903e48478d66762fcc7ee320087cdb54ede30fdb2a3e928db4b" );
            {
                // r and s are 128-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "8a598e563a89f526c32ebec8de26367a";
                bn_t sig_s = "84f633e2042630e99dd0f1e16f7a04bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "56f40bdf5d5c725986cad1c52b407f2977e2495f600c9d4ef335efc82843fe63093541d1acf3147bbb689c0ab728d695", "00870fb2b7fd5a61263bc953a94ec8a9a4152d386970acdc0e4f943e5eb42c18ef4840bf6017a38afa67f8d988a7bc8b60" );
            {
                // r and s are 160-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa6eeb5823f7fa31b466bb473797f0d0314c0be0";
                bn_t sig_s = "e2977c479e6d25703cebbc6bd561938cc9d1bfb9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00dc24f59eba985876596d7e48ed8207bd0c4f4212f7efbe57feee0617c7060d736f211ae1698070ac0b74304aac5e1aa5", "00a6612e2df4d99aa40a7e1918d43716a22513edcb9670d86fc2a2ede769ee56bfb283de1544a95eeef1fc02df07072b3c" );
            {
                // s == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // s == 0
                m = "313233343030"_hex;
                sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                sig_s = "00";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4e97e504c56febe883186525474379d14680f26a62f421952aae89c4721d00ae537ea63f816d1caeb3c811da90118f17", "00a284c40e24fe0ea83c2bccb2be5aa6a5941d176acbe3a2b32699c176c2db1db710bcc662e3a9d6c06dff6f2b2420dde3" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "427f8227a67d9422557647d27945a90ae1d2ec2931f90113cd5b407099e3d8f5a889d62069e64c0e1c4efe29690b0992";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "128ac2ef6db923f724cf47f7d68aa74d2ce31a810a5486adde77ff230feec3036e5a4424f82cb52b02acfdcdd0de6f76", "35fc030ef2afef3ff465d9c53771737d105cec6a49edffa018a3cccd31d6b9ef92c09364f4002fedbfd5a31056ab24f0" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "369cf68bb2919c11d0f82315e1ee68a7ee8c17858bd334bf84536b2b74756a77e4eee10ecc5a6416a8263b5429afcba4";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d8d2aeac3f162e1619b3b6512707ef9af5b8235c53e3e11c0b75fb2703f007b2c7e0fde988a766eae82f2b5226604fc8", "008e84a47531577ab03589d64bf9f9f05bf5b8b95d24884e0534fe992000b35950bb7db043afe3be07b312f0fe452d9a2a" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "2111832a45fc5967f7bf78ccdfe98d4e707484aad43f67cf5ac8aa2afbde0d1d8b7fe5cfc5012feb033dffdec623dfbf";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1cb88451fa09e467dfedf7c37d8485c01351dedd65ee6206e4e8c64bec8d54934a5be20f6f95db5904617cc88ac6f80e", "00d801e633cd3a5ba198fdceea5542242e6c7f1711d31f4884c31a483bcd0b1df862f56085a3856607246b510baa91b254" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "20cd002ab7dca06b798fecef3f06a222c2d2a65e9ec92f74659a8d82fe7d75e9af739f0b532e17d6c5f622c4b591442b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00cec5c5216b1ebb2fb3cfc5b78be8e04048ce5c9d727f93c1c92f761217f3bc0fbda7a2dac5b175a92ed0f04dd9904867", "292b4fda8028a749ce72d7d62f0315da96e3b4295014a4a94b414e40491f58c333b881666d444f487a2cba015d91cc4b" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "3276fe55314e426a8ed83c4c38dc27c8fe8cbba0b39bad7cfc35e963adf10ab37251ea6829b8d255a77dd0b655cf9ff8";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "55f0df11cc1fa0c15643f118765246eabf5a492e83cbce0072ca36e810e043995a680fb3b17125901c365658e1b05672", "6b5f85375b44979c2088453d21d74317022c8ecd3b957c74d2479c99141969f46b34d3e87cf33b0762517182f591b26a" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "1a80b4a3d6c88775821e26784463080eb7de510762ab0d98223e532364c7089b07af73746ae4cf076c5277dcc80cf8c2";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00fa081fa00728982fa13e216a50b52dc2eaf84f458ad52c81d5f607a1fdc2562b97617fe07e6c3d6dea6cac20b78d8cc7", "00ffdbd588c54fa20f6f7d9a6c8d7601382dfc39ee83d25f96cb842d4fd8f940e02d369edb37df28b54bc59752a95062eb" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "74e780e38b3a7cd6cfe17d5c9ac615895bd97dd4076b5f8218ae758b83d195fba64eb9aead39a790ca0f8b8387376265";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009dff849ecc2c3af8433c6a9493663ea4a930d98734b99bfc9eed5cea462735eb1a03d3e23711735d64565cf20324ea4a", "0092cc11ecf2b41aae833f96d3f0679a4baa2017d156115658cfbf5f13b6a9a89fd6c3e96af2a59670300de8d4d1fb6112" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "6ee5f8daae12c862e1f7f8b59294ac90448c4461e29b36ed623a719dd69bb17b3a4b7c29b9eb5c39ca6168bf6b597c6a";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b107a43b4ac4ffb8f7b55f06679e2204d377ad2ee635e7a0b48ff46911a733b2b3084ce6042bf7ce279686f0703c7eaa", "069b7bf6419d9cb63c479da1c098e477ae88e3c167616721c108a5a813ec6f03157837311646b0733b350e224bb76b7a" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "5426ca20a25b0cfb1ef230c62f91e98005f346e229233f1803e8944bf421fef150a4a109e48cefaa4ea23eea627fca41";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00dd63d35451728237f16085f3feed8d5a1923cb67597f72a66413456260ab9619dcc33f959627a7e503e9f358b8eff3ae", "00b6354b52b1081e4b172eb847e03a9a940bb840603bd305e826b48cb7895934e3f77577403ec8488636d7a8ffc069bf17" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "39fd1a0ae3964735554c61daf085c66bcc2e9e5350131086023aa99549fc5f9057c848e75a1b8e58069fe0b9b23fa3c9";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "61980b43979e2a4b03e904b046f8797446b51836baaa64bff51fbf24bd0b31f3a0a022c14da8e94c3e7a23979f731aa8", "00a1e5f7efe41546846af368fd63391638d632cd99541ef83f3150b3c1d56e553e8afb44d72c98dc0016f66a7b5fba5204" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "707a37cfb7367c2e551ea1f0caeac6c0fdd2b562e1bd8f1c7c51a5dd78f21da8cb179bd832cac3d3aee21fda54729e66";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008c03a059fb8643d5fb8574bd166f7360f8243fa0e40a7e17fbb35b680111ef2a7f9b23cdc42f7a66f10a16dd2c40432b", "00a6dca1075c8396b7ae772732851ec2b53b3599aca001850665a6bc1db8bb24966af7dba572ad3ec9dba65ba9418b78a7" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "15c99e2ae11f429e74fe2e758bc53ffea26eb6368dd60d10daf860f9c79fa8cc6cb98fee9b87dd38353e970539a50a9e";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00cc17b0a942599b5e4f24b674f4b31bdebb9568365052a5666f71268234ae517ca804fb257e0317c641ef090d06e08e18", "03643985acd19af4a665976436cb1305af99691cc9d162060800beec9b8fc9f986844ef85311a21b35da41076e3da8e1" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "148c732596feaabb01be1be3a220740e84bbfabe6d82ad0db1c396fa047603beeb95a1cd37fc708a9451d3cc29a45b32";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b8033e58411dc0a379ebae87a1e8c2339e4a4d1903ee96c64a6895178a09e6b8058cb9218832d8656c594b2c74b77415", "0d0b55352982f22998363646ef74dda98d869a3e3a330e8e6b80f35fa78344b6ed681c5d9819e6a1f226861595de1993" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "6b3cc62a449ae5ef68bec8672f186d5418cc18d039af91b45f8a8fae4210ef06d3f0d226f89945b314d9df72e01a02bb";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "46dedd90f787db11f13b1a0441b819b23a4613d3083b50dd1833f604c1cc3946bd7b6390827e34c4c5e4ed169cc2087f", "0353a343489639d9f6fb8a483cde06e97ae1df63428aa0736e150ddf3036dd1175de86edb104418b486982e05eb721a0" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "7db7901f053b9cefacfda88dd7791c01fd569ed9a5243385eccae12ba992af55832a2e5dc8065e018399a70730035bd8";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ee131cfe177bde1f414ae7b1b0767afbb1fdbaf3a21525e2544cdc153ae1cc60048520de09288328081545686dc63a30", "4077fa824ef65642af4bc0f2e80faecc1e4df0a771a69db47d8228fd7bd8248c0b30838f92e22dff34f2bac0ea561e63" );
            {
                // point at infinity during verify
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = false; // result = invalid - flags: ['PointDuplication', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b7ee6be7e79ba7a1e3c866b45b5a24bf6d07239718c7ed2fb79af878fc6c3cfd8194de0a31055991699fd6c2ef82bc8c", "00f848e8773f53a727c9f17690aacf42e27ab0a5bc3b3521571174d8b3e73dbfe4479cf644a69fc337751b93de5e8f5eb1" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e15615779199fd5ba364d8faf22884737e9d4606710c73a274c0b3d2a9a5f9599578482d8eb0103403b4114b21593476", "544ff1972b88e63e31f38822c25965b06700a45b37001faf828f30ec8417b1c8dfb064392432efc5e2f924bb5e791dde" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294ba";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008d5a8b35e8b996f816bf2d1f3730ca44445b32eb063cb329de526a7b160d947febb1e9f3985e4404a6b1c5aeee2b32c0", "00a05b85287fbb013a771a4269d1d63088800a5eaa8e12de51de1996b88a0531c743b2c36d1ad1c5455e8ec0d4ca7105ad" );
            {
                // u1 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "29fef69d4aab0125e270cffa43b94c5466b7d4ca1efdc852c1f456d03de085408baa191f65a6c05483dcbee4d840467a", "2441185832a99f5145ed73ea54774e814dbe15018e705f8aad95eea9e22160e94541e8df64c1baccd3df749e6b7af611" );
            {
                // u1 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "ffffffffffffffffffffffffffffffff44a5ad0bd0636d9dda1feb8c60148bfc57e325ef1d899af2e547ff6c0264d950";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009b3d7bb633c34a4318062fc0e1a63bca8346efbfe6bd4ff33d9190385a5c5c77503603aa41b1f5d65cbcde08fc91bc43", "00933964a01e00a0937785ea34c60bb41a310c94e03a2ad2eb44d4b4ca1d651d264f4b0a62ac529bccad8de076e3f8b92a" );
            {
                // u2 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1cee4d3d2cdb64d4c9d0279aec92ca9471391b79cdde4686226386a1e3f89b42650846a0b1609d584be5932b4a608725", "595252558241530a6aaacc3dc3ac83e1a4c82fa3402269b3497c771ba00d9bf402a3183fb8b8f7644408b9eb0ceea504" );
            {
                // u2 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa84ecde56a2cf73ea3abc092185cb1a51f34810f1ddd8c64d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ae0577be20fb0dcd34c5a7b61d3cbc5188b714c12c7ab06df756f7d3b4f776314718b07988b1d3d9452a36f126b6e5df", "00c966159f0f5681c81b3403dd0c1218dabf642fd52d74cbb04c5f044800cbd1967d39504f4207c99c072eef41ea3ea471" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae91e1ba6ba8986207eadfefdd430548b3ace5662942d73d4a07ec446cbf8e103";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6aae5918f9923bd4164a49488fc522bab02a6e6ae51f85ff757ed18c90570287aa1c22fe073d827d3c07ef6ab915539a", "00fde40d804a046c26ec949b25f4376158b5187add82c2eb612600d0490294a08c218827a779b046b00f3bec158f30f89a" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "bfe534e980897d2679cd9a3780bd3dfaf493984eb534f6570fd459354c0da4dafdf7d438eb989f74910d762c1a607fcd";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1f37c46517738db2f6954ed3920e220e89e30b0ec2b6657342fc84cb797208c97d0ae5f2cb64d9d54a401db0f1f8fec8", "00c9aa908ef1d282749a4ac27a9a8889479c7a7a8f778e85d682f4189eafa00bda4a16a162348cd33184e8776ee31a43cf" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "e11190e4512e6cd9a3fca9a9cd73aa99a855f7a7102eae214b8ce295399c2d2c07dda100541da32154c7a72f65961f31";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3f73521f225c5a2a1fc554ee9ddfd4e14e71958f20d0519eaabd567086f6764cf39beb89d733c247ab356025702d5e97", "78db565bd8801439a596783b4ee0a48e9386716cf1110dfcbdc3e27797da11e0e30084d125ae9a3f4f1db90e526feb88" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "ab1fb141339f5290ffffffffffffffffffffffffffffffff1ecdffa53ea3f0a5becbf535894f588941ef362ce95529f2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4b18cab482e99d1cd059794ba0bb516779ad6a432282b7d115e9aab13bb077cb8057b41eadffc8467b3eddb1dd9ce21b", "18cb56fe71341001076b84096b9ef35a1765c7cab761186a768a73a4eefdae10b27d9dd8561000d99ce4802f7be5c366" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "fb141339f5290ffffffffffffffffffffffffffffffff44a234aa9863d18eb0fd0c6e979ccd9fadfeb270fbe0aaef97d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008f49c7984fd20e1264e04afa91d536daffb8cbdd9c3f2deaf56fd9137d16830d01fe29d03d6a63f096061cbeabad7d0e", "4304531294ff633b09f51be4b26df3284bdfb76671a0945935dbe4a282ef830416c4deed3cf6f6204a7402de803de17e" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "f6282673ea521fffffffffffffffffffffffffffffffe8947f32058a85faa8404973c54151034e44e96206114898c987";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "53854575481f84e621f46c8190b9a351c592b62c5758dd3b54c5bc6392397acfb59217470b496c9d08ae7f0bbb61308a", "6b62b7e71148440f36117fd8d6770d9d54357cbe52b8a92ad006b706da71b67b197b9d338c77575b4d6994a863601a0b" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "339f5290ffffffffffffffffffffffffffffffff44a5ad0bc4f8fa79d82cd1486814ccbf45244c9619195fafda5af6cd";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0099777fe147e7d56eefe190d6663a834fb241234355cf25acd61d3313f8aaf86c2751f5a83d5c2d60fcf57b85842e48e2", "00847b062abf370e5065896a76d8046c48606fb9b21222837a7c4b120ba778832ebb517bee2f63830e447dde58dc780254" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a76276276276276276276276276276275b4172f69bb50e0fc803429a4b367061ead3d8a82405b1f286ecad2856b84940";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c7bfef909a8abaaf6f684807dabeb66119415ecd8b330c6cd1abc7a817f581bf045b23487e0b2a8fc5b42f70ed3777a2", "28c16340b107bf486049da3308dd443eb44080423134bf37187386a205dfcbc5e39ad5b3e423d847617fb0410d80fd27" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "1999999999999999999999999999999986dd5e1ac809f15c95cffdf470020dffa26383cb1c8dc2b1e3ba665799d6e288";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d293cca4e69ef23fee051fadd8d752bdb0640e1c0ad69a9efba80f7156d7c7b4d1b34d5372b55f3b8b7bd6a9abfa61c8", "2b7aabb1cf818485ff1853e10d1a095fa86af694a97cfc92d0eb14a249b73536ef1f371c3cf83758af0f7a677e7320c7" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "5555555555555555555555555555555516e1e459457679df48b54e842006d9541d4bb74fb48333a64c6d552400cc4870";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "69e6a54921a0f3d9f0c28b72fd37803ed0b25189417b52a7ec9e70bc17d128edfa5328d1f39cce22fcaf75a51037656a", "028b82fe82d9a5c5f1a529cdcb7dc6f8b25924993ecccccfaecb63f9aa0918c18575d4f51512e04bb3f10a65811fc7b6" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffa252d685e831b6ceed0ff5c6300a45fe2bf192f78ec4cd7972a3ffb601326ca8";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a76bcfdec3e35782bb6748d1e5618a57dd3d077f00f8d9bdd3fa2b5d13f8281d46debcda0704da00d7ad1fbaa758d72f", "0096f210ae33e995fccb11772c256b15cbf1ddb0744e6640acd9a7ea0c628e93ade4fedc368184ca9fa06c11bcc50c5fdd" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "f088c8722897366cd1fe54d4e6b9d54cd42afbd3881757108978180b96e9ad85affbd7594e67254e20d9e04d192da452";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6608ea63d56c6bb7f5fc56688a2fb5ce3f06ef67c1f3c357f30bcdbe32bc5fad3e58edb340ab5417bab5b331a8c4f7f4", "00a83f1cf80687d5cee7729c02a7b62aacc14e829d29b46f9ff08626d3e3014e98a1f3a5dd88d92b005f3b6f8b4775fcdb" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffed2119d5fc12649fc808af3b6d9037d3a44eb32399970dd0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b2f4923dcf54ddf300d90f82b646c82b9395b2255048b9327a73e598cb2a0ac71807270ece0ce3a9172ff63ab2a4b579", "2db76185037c879f4188a794892a07739ed15a6eaaaa94ec37aa82cb092e39934ad68cc4b390efc979c55cd9e69d88d4" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "79b95c013b0472de04d8faeec3b779c39fe729ea84fb554cd091c7178c2f054eabbc62c3e1cfbac2c2e69d7aa45d9072";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00cb814875d6d40960dea00196d1a9156db9ad46d636a798e80ecdb27ff070e41f286a7c0acc35de6272980928ecbf39a9", "00c1d2e9fae5462024d7671459d20b8711a5d3bada784eb95c44179bb036f60cd1940561ea4dc14c3161ad3c26925feb19" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "bfd40d0caa4d9d42381f3d72a25683f52b03a1ed96fb72d03f08dcb9a8bc8f23c1a459deab03bcd39396c0d1e9053c81";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0dbd9ccca18e9edbb0d2ca8c7b33de0ce5e2ce4b641af2a4e8e4e105705ad2c04043e22f7bc9f32474a9ce05a2772f38", "00ffb8419e769afd848df80677f632cc6c292cf73f74505a043bdc224553dff4f6d1d4d2a94f6d74a7893bd37dd199463f" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "4c7d219db9af94ce7fffffffffffffffffffffffffffffffef15cf1058c8d8ba1e634c4122db95ec1facd4bb13ebf09a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00dd259071ca02a423555760f7712c51eb25c6ebe52408cd91c7463283d45a6318cbffbcc37389cdf1926233bc60b79ae3", "25c0e41d49d876b7bcd08da82ac29674b346d09185f1ee9552b03eee982f493ce0b03169fc421c42325e2160fdaf651f" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "d219db9af94ce7ffffffffffffffffffffffffffffffffffd189bdb6d9ef7be8504ca374756ea5b8f15e44067d209b9b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "576571c8489bc8f1f17c3a5e692ffa15e87501fce3544f6ec51a4fd5c9c84f33e95dd47645c61e70a53840243ba55f60", "00e4b2f7d1815179c60c1d9ad6fd4dddf856569bd33986d3412b1030f8dedc48a2309bce01e324483f95257069a48773cd" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a433b735f299cfffffffffffffffffffffffffffffffffffdbb02debbfa7c9f1487f3936a22ca3f6f5d06ea22d7c0dc3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "536c24359a4d7a6c9d1366a8a9ac4702332af87117db4d8ad3e941932d938dc17f1869f95621f22ce9f66a86100cc57b", "00dfe809d5c1875807f42510af20e0d6ddc169422090192df9741a0d9b6de9ce608ad9ad72adbf7a17269f5dceec7b6f17" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "b9af94ce7fffffffffffffffffffffffffffffffffffffffd6efeefc876c9f23217b443c80637ef939e911219f96c179";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00f7ad2994d5e2d45e8013495b67ead9033eb89d0a7bf795f443cca19e4bc4b62fb141505e0b45f4c353f139d7693848aa", "2998c1024fd34cfa167ec75ecedf967497a9a3b1d3f7a30915a9b8ada601aa1706d7c4c99f52628519775e4243d84b3c" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a276276276276276276276276276276276276276276276273d7228d4f84b769be0fd57b97e4c1ebcae9a5f635e80e9df";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3a591e4e71d27b46678a3459361afa394f991ea553b8c06e337960dc424762c5cf2489864d323aa2ab53933fdc93f71d", "00d21330465eaa43aa2e6572fe087fd192e39bc53f8356dc7c5bbcaa693ee5a2e56b952079a0a49ecad45903c937e2b94b" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "73333333333333333333333333333333333333333333333316e4d9f42d4eca22df403a0c578b86f0a9a93fe89995c7ed";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3379e51b7535d0abf2bdb1d96fd98105193f9fd248439233fa003133083b424d6a9da59ed9b1f13f2e73b427c7c45ae1", "297dc5a37442429e16879236c3fa309aed2cdb1ed288f7f39d6284aa09da0b961c9f4d242f89c8741af1faab3c90c4" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffda4233abf824c93f90115e76db206fa7489d6647332e1ba3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5d47c565466e38dbcb22e83198f8499bae2c3de0696330b3bf64a59b9cbf614e727892b2cbc6114b48009d4172489a49", "00d535292a338ee880368cb829a49170ceb86767dc07df68dc2da8eac3b4ddbea6366447d05423b0097a9c86a04b88995b" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "3fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294bb";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c05afbde4722ac351cbc7fbed85be84cccf9748a89bd834a05946cca51b5845a4e1d27b3affd57f80a34bc0e84720a35", "00ecc37a2f4b1a01cbbe918cc9df54b87bd52255868d0f918e0c5f5332d18532caf4e30458ab69a303022fdcc43931d6ed" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "dfea06865526cea11c0f9eb9512b41fa9581d0f6cb7db9680336151dce79de818cdf33c879da322740416d1e5ae532fa";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3c246b196629148260d8453f2f54006b32d098bb7dbeb2efe9216a745decc80434bf28e4cc4167ca461ad2434c244abb", "00ae83351bb64b8681dfcafb3d52495f947039a0923903856407b005a5bfdcb6e952fc867433c6947864453a7db0db9db2" );
            {
                // point duplication during verification
                auto m = "313233343030"_hex;
                bn_t sig_r = "b37699e0d518a4d370dbdaaaea3788850fa03f8186d1f78fdfbae6540aa670b31c8ada0fff3e737bd69520560fe0ce60";
                bn_t sig_s = "08f8607b46952a98fbb62768cda34643a5ba7ba37e3b0e6470e660502dce358a819d965dd882555b8d139835c06d4a7f";
                auto r = true; // result = valid - flags: ['PointDuplication']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3c246b196629148260d8453f2f54006b32d098bb7dbeb2efe9216a745decc80434bf28e4cc4167ca461ad2434c244abb", "517ccae449b4797e203504c2adb6a06b8fc65f6dc6fc7a9bf84ffa5a40234915ad03798acc396b879bbac5834f24624d" );
            {
                // duplication bug
                auto m = "313233343030"_hex;
                bn_t sig_r = "b37699e0d518a4d370dbdaaaea3788850fa03f8186d1f78fdfbae6540aa670b31c8ada0fff3e737bd69520560fe0ce60";
                bn_t sig_s = "08f8607b46952a98fbb62768cda34643a5ba7ba37e3b0e6470e660502dce358a819d965dd882555b8d139835c06d4a7f";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "665aea8c7150c125dfc978cf39d93372b822b9bd503f43f659981c9af6813b13479d895ffee6ce7e5b424e5b8a4567aa", "00bb36fabb598230f5deabfda1b8bb364b4e29a7ed04d1ec45bdc602098c9a1330755e7c4c7739c4dcb898476783242c9f" );
            {
                // point with x-coordinate 0
                auto m = "313233343030"_hex;
                bn_t sig_r = "01";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a295709e20608372fa22e764be8eb29302f5a89af22e947ca3fcbdf7c4992a5675a9c5a60d65e3b8acf8e291c67d5b17", "10cb799efdfddeaa04e2426f2c6a08f2df7e4160f8618925355947c159aaf406ef90056414093c42a213b7cc9d006a09" );
            {
                // point with x-coordinate 0
                auto m = "313233343030"_hex;
                bn_t sig_r = "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                bn_t sig_s = "33333333333333333333333333333333333333333333333327e0a919fda4a2c644d202bd41bcee4bc8fc05155c276eb0";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00accca75348f7e5ac63f8dbd2c8f05be5f3c245cae8f0b029fb1ce6362f3c5c14181bea69cfab5da4dc0a8a53396760b5", "4d0a19e7be066654d27ca925a92f67a75fedabd414db72e6177d142267c365b42a3b304dc7aefb90276801018bcd661b" );
            {
                // comparison with point at infinity
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "33333333333333333333333333333333333333333333333327e0a919fda4a2c644d202bd41bcee4bc8fc05155c276eb0";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7875a539f14452b88b6d7bd04fc9f20840cb58881a5337fbdd673579f6e18a08e23e4099c7e2a29418fadcb33e248392", "00c2d17f5866099e6c1e9a244dac48994201dbb6cb7bc0940572d1f05c8d8865d215f58bbdff43591872834d0d473b95f6" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "52828bf33158db6b6df5afd25d567b8318176ea946410396d123e1c05114ed1bcebe0eb86c6e5a2161e67be8e73606d1", "7571de1a0d4af076ff0b659648c4421fe9209943c26c59f37d51c5c08ab7af62b0db021d41891b4775cf6d590788c1e4" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00acc56e53377950c865db422481b8d6a23b85797a6196cbcb85ca49ad2f0d2a7846d78d178b816951c8d63c20cc1a09de", "4bb0eb484864b8bce2eef0133efc8ccb2ed6e81b00461971528e8ae463318de16c668cc4e5c536f173f21acb84f01e89" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "6666666666666666666666666666666666666666666666664fc15233fb49458c89a4057a8379dc9791f80a2ab84edd61";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b75eeccd7fb25e5f541c103a9f4f5949a75106ba37a37777ec91101fd8941c0ebe33bbdb9c456a5fadd046b8ebea32b1", "70e5ac6fc398b0719633cd9bdcdb4603f56f896f8c673d52dcf80cc59db81e1c4603dd5bda1179dccc0c466863cf7188" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "99999999999999999999999999999999999999999999999977a1fb4df8ede852ce760837c536cae35af40f4014764c12";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "537dfac2315c48a04624cfd8a8b168879f6888f96c67803f8ae7a31082a0185b8925a74a99bebe543d113d6e46fe189c", "009b449167c921fa8d02f373f5ce9baee5e70f556608af997e59dac9e23f589be5972aef1313bbc7f4c40e718d49c0cba8" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6aae76701acc1950894a89e068772d8b281eef136f8a8fef5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6640e0650d9025b936f2785e41516dd451092e2251eabfe9b32fae26702b7b89e8b3fd726d182b107b95dd3952a3776a", "19e24468c2d120789dccb27aad379e205d54f9dfd3a7229b9f82c9398130e8fc210ae424f939d7e079afd7198388e75d" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "0eb10e5ab95f2f26a40700b1300fb8c3e754d5c453d9384ecce1daa38135a48a0a96c24efc2a76d00bde1d7aeedf7f6a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "145e3f8e547067310c512997302aaa4eab971a72288a9b6e4ba846e39a619d0e1ae4f136015ac975fc5283b8e61cef40", "0099c2ad9913e61dcce2fd3cece6e989755e5aa6bba0ecb070b5d176f47222eb9ee655b8843e413cce14ac219ed79a5c70" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00decf587c31d7df83446f2da47c5158ad7794af76fcc726c201b150ccbc8e41bb218ccb9ab0a9fda741c8173f98e3f4b2", "3b9fd5db1b326b12820dab5a8da938af2a23cd82467b69af7e8ab8bcfd79d12ab0acfc443b709af02fa160245c5ad50a" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2b020240aeafc23c2d50341e46c35c569e3edb36bc6c54014c8d57a29eddda6e9b866490f2ed2aa1e24292b7fb5b45b5", "00cc98cd746ffb5f67575d07c81434c0cbca096ccdb49aa7aeeb56f00919d6cd365aa29a01bd85d834d450bae4aa7afd1e" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "6666666666666666666666666666666666666666666666664fc15233fb49458c89a4057a8379dc9791f80a2ab84edd61";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "240130e45f786d74cdd9b5575ca87a036079ef81ecff8acdebc283d0d0d846ede13bf64c4dee83eb154370d32bc9d6bd", "564a1039c819a9c4eefd97a0906cbc29f986ac4fb48bab4a44f426fd187f71694407391c8c953487436e6d1296601ea8" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "99999999999999999999999999999999999999999999999977a1fb4df8ede852ce760837c536cae35af40f4014764c12";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a964e60fc4a8f1e305f5c31486fd216f59cbf69181492782022b2ad3583e6c073b039d92f53546f6aef6caac99e43c17", "00acc34410e90c177e1935a521285b402d69b08abe49ba09292b57dc04d04a7155891862f932652f3478c7a0ba28a51328" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6aae76701acc1950894a89e068772d8b281eef136f8a8fef5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00dcfc5eb16c7a60e4b1ad10a23b76279e59c5e81420801fc836e83d108ace75d866583650789152ee2b711b343da6bf13", "009275225f1477b593a4814d27056a40f629523051c6b339042ac609b5c8a1fdeebc63ee48b45f18bffff503cdacf72bc2" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "0eb10e5ab95f2f26a40700b1300fb8c3e754d5c453d9384ecce1daa38135a48a0a96c24efc2a76d00bde1d7aeedf7f6a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffff44a5ad0bd0636d9dda1feb8c60148bfc57e325ef1d899af2e547ff6c0264d950";
                sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", "00c9e821b569d9d390a26167406d6d23d6070be242d765eb831625ceec4a0f473ef59f4e30e2817e6285bce2846f15f1a0" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffff44a5ad0bd0636d9dda1feb8c60148bfc57e325ef1d899af2e547ff6c0264d950";
                sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ffffffffaa63f1a239ac70197c6ebfcea5756dc012123f82c51fa874d66028be00e976a1080606737cc75c40bdfe4aac", "00acbd85389088a62a6398384c22b52d492f23f46e4a27a4724ad55551da5c483438095a247cb0c3378f1f52c3425ff9f1" );
            {
                // x-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "281dbd30737a13d6cb67de51c49a60017e86cbb1e5044862adbf83f80974b0fc08f48dea2b3a253b0043e332efcb996b";
                bn_t sig_s = "bf107be3f19987ec921be2e00212c269f3c49ae86b513e3fb986f7fb1f581d9f993b08ba6f5db3657ea9fa60bfb8c6cf";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "44b25dd15efd870cbad4b9e4fafa83fccd033d95528304e94a53f56bbcbc8a11d1da2c2c570bc8306476acf08184874c";
                sig_s = "72a5d7405a2b03e18c809f8371f1097cdce03bc08317325d50bed7cad26a36700738fc1e044f5209eb01f93407ca01c9";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "93af9f6fba6d774d5c930b3644f811fb46a9e54954da0f3db670292b9fcc0e8145ab032e602c995f9389c841254e9868";
                sig_s = "d2ffd5ca020101935216dabbed1fdff3a4dcc7db5906bd87319cb8d8cd31a346dff4fbc7b9ac864beccd2e89e8b58c06";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d1827fc6f6f12f21992c5a409a0653b121d2ef02b2b0ab01a9161ce956280740b1e356b255701b0a6ddc9ec2ca8a9422", "00c6ed5d2ced8d8ab7560fa5bb88c738e74541883d8a2b1c0e2ba7e36d030fc4d9bfb8b22f24db897ebac49dd400000000" );
            {
                // y-coordinate of the public key has many trailing 0's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "83c340568db683c26521a072c2ec0d3c6301e6141917b3d31051190768164966a4375d6a596daddce23fa35a0663bfbe";
                bn_t sig_s = "26f3e0761e561df924a6b12a74ddcccd4380de02cec1f30739b780b4f0216be00fc4f913ecd12491e56c82c39b181f62";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "f8dec11959a61ef14714eb32ad8ac666618c5a0fe1cb6caa75ca4df0c965b72fbe8a1011b5ae826f25d306cd48343d33";
                sig_s = "b56f1efa8d1b32932ddf6cb6ea5b20c13c9602a3be4e0b40a4d24caa0a52b1cbe9b9326fa4d8eb1739380fd2e5d1751a";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "1d53c575c4874db600e7e58488a35017fbe0dc78575b9fd336983cf49805cd1dcfd9156c7e92503681b1d0fbce96957e";
                sig_s = "3bd64bb7d409e1d9f3cf71918d3eb0fbb399cb9a9c3226c0d6a4e5e0a54bc17b01f65de803850581981d0d5bafc2fdd6";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1099bb45100f55f5a85cca3de2b3bd5e250f4f6fad6631a3156c2e52a33d7d615dd279f79f8b4baff7c713ac00000000", "00e6c9b736a8929f2ed7be0c753a54cbb48b8469e0411eaf93a4a82459ba0b681bba8f5fb383b4906d4901a3303e2f1557" );
            {
                // x-coordinate of the public key has many trailing 0's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "d3616ab68474a641fe2abb8d02fd606e3b8e5567a8fa30a8ea037bac09f2e1d747fe7383adbd4f5449c50c401461b05a";
                bn_t sig_s = "2ea50df8beeb2cece8b6d7cc7da29737b46bb10f2c3c18aef346c3f4ab7d7230f56533f2097f7fd65460c8a26fd4253a";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "4a6b5fd43110bddd1295e311b0f8d12df3d0f9b37fb39108abf7bc1b867debdd3e1aea523058ebf6edfa447f47b7656a";
                sig_s = "e519e0c2c5f5fde47678a89a3f7145626b0a5edf5aed705c1a56674fb85266d881b56ddd135486909737a73edd5cd673";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "209e7963d1bcf312ff25967584af604229aa5cadebb1af44d413baeec779a23c3d4ecc1407fb6aa010e1856208ea798b";
                sig_s = "a7c1a17207547ab389001f4e7a3e9c93ed25dc94305d5ae9f8064af323b57a1112c93cf21c1d13c2e6ab44803b341974";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2b089edd754169010145f263f334fc167cc19dae8225970ae19cc8cb7ec73593d6a465c370f5478b0e539d69", "00d1951d597b56a67345acb25809581f07cd0eb78d9538a3f8a65f300e68a1eb78507df76de650e8f8ee63a5f0c5687c98" );
            {
                // x-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "08076af74d9aca7e8736110c77dc8e500c211d574cac8c2ec914d5e30ee663b5bcebab44b7116124a289a32e1c3c6c3c";
                bn_t sig_s = "8f2e722c43674685641c57c8c1ed8dcea74aed0eb50c394ffa44b033ab5a5a58af422612cb1f8e08f5a7b4fb8d027553";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "934b89b2647372376d08a70d0d9d5126e4bf627942294862ccb3c64a539305c645ad7a7e17068e7196b4fd99df126a0d";
                sig_s = "832a0278c244b9b18768ed498e2c7869e2c0b5fc2c4c5071f45d8b173779dab008839ab10c10df1e1e47e9a41248973e";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "ea9bf433ebdeb5515c1e56607803098c2db8af5cbb54bb256ada709a00d5a626de8eb6eb0af53ad0beac869c6bafd86f";
                sig_s = "9eae95d2c41b670f2ed70fa0f01370141749bb4447ca063677308c17485cac90afd7df1da16c542f204526fa342dd44c";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00fb01baad5f0b8f79b9cd104d12aab9310146add7d6b4c022d87ae6711178b94d618ca7b3af13854b1c588879e877b336", "208b3f5ad3b3937acc9d606cc5ececab4a701f75ed42957ea4d7858d33f5c26c6ae20a9cccda56996700d6b4" );
            {
                // y-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "750bfb52b08003d4cc11bbc677005ff76facd7922450bd0b9d8fb0db01b6162ad106925096a3f311405aee322ba8fa4e";
                bn_t sig_s = "aad1626127816f28526f9244bdb5ceb9484c7e45cf6fcda0f921e2621514ccdcf28f06d41466fb52e619356cc3d4ffbf";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "3ec493f00b1ea554b8725b7e39d50dea0017cf1558d70a0fe11c72d6ba4a5df084bb4cd3faeb8f7057612f1318f3c165";
                sig_s = "e6297e29986b6a01490aa6d0ca7ddbfe8f173340688010d9dd278a0a93be09606a8da9b3159e3f4e55a4010a6590dec2";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "ce1d27dba63bbd9332e27f471e22ee105768f95ea1d031d4617b9e88033c9596d3e67abebb6d2e8b7e52c5bb3368aa5b";
                sig_s = "cc85133e6553ff21812987e58d9abe00a8acb7cc1354247bcfdacc8a914189c159034b92d59932301f17e2447863da4b";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00fb01baad5f0b8f79b9cd104d12aab9310146add7d6b4c022d87ae6711178b94d618ca7b3af13854b1c588879e877b336", "00ffffffffdf74c0a52c4c6c8533629f933a131354b58fe08a12bd6a815b287a71cc0a3d92951df5633325a96798ff294b" );
            {
                // y-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "7054a5bd3eec9debc0113eafecf27d11b5186ce67aa430b57c6eb3c98e239c16370bb8aa6d0cc8cb2c554186b7dd82b6";
                bn_t sig_s = "e820c50fb0ef6208407dd37d34796ea21771a988d5eafbd9b12caceec15e1519861407dfced9f20d7898ee0fa0afb61c";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "80f3ca043a055dd0784aa37d8c3afabbfc8160606afc1d54463b3af1e56b8269e5fa850808def439f83cfd4d3a375661";
                sig_s = "fe0030173c18cfd88b3ab317430e55722ec9ae8a3d8fda64243c325262da11a2f7183d2d2a462b42ec2f6a6c8f9bf12b";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "b57d6915f6ef8bc76246fe073372ac289fbd9c1b9451e261aeccb927dfbc39419fe51aa936afc3e5ae6d18b99fa7a863";
                sig_s = "dacf1c1c7a6ec67e4a6a4b2d7c0fdad0a9e8e92f65a2bdd3b42548aae9853128fd36291d492ca1b51990b3b62fae3860";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }
        } // End of Google's Wycheproof tests ecdsa_secp384r1_sha256_test

        // Test vectors from Google's Wycheproof RSA signature verification tests.
        // Generated from: 'ecdsa_secp384r1_sha384_p1363_test.json'
        // URL: 'https://raw.githubusercontent.com/google/wycheproof/d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d/testvectors_v1/ecdsa_secp384r1_sha384_p1363_test.json'
        // Note:
        //     Test vectors with flag(s) 'BER', 'SignatureSize' were not included.
        //     All test(s) with BER/DER decoding related errors were not included because they're not part of this test scope.
        //
        // Algorithm: ECDSA
        // GeneratorVersion: 0.9rc5
        // Header: Test vectors of type EcdsaVerify are meant for the verification of IEEE P1363 encoded ECDSA signatures.
        // Notes:   ArithmeticError - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA have arithmetic errors that occur when intermediate results have extreme values. This test vector has been constructed to test such occurences.', 'cves': ['CVE-2017-18146']}
        //   EdgeCasePublicKey - {'bugType': 'EDGE_CASE', 'description': 'The test vector uses a special case public key. '}
        //   EdgeCaseShamirMultiplication - {'bugType': 'EDGE_CASE', 'description': "Shamir proposed a fast method for computing the sum of two scalar multiplications efficiently. This test vector has been constructed so that an intermediate result is the point at infinity if Shamir's method is used."}
        //   IntegerOverflow - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified, so that the original value is restored if the implementation ignores the most significant bits.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   InvalidSignature - {'bugType': 'AUTH_BYPASS', 'description': 'The signature contains special case values such as r=0 and s=0. Buggy implementations may accept such values, if the implementation does not check boundaries and computes s^(-1) == 0.', 'effect': 'Accepting such signatures can have the effect that an adversary can forge signatures without even knowning the message to sign.', 'cves': ['CVE-2022-21449', 'CVE-2021-43572', 'CVE-2022-24884']}
        //   ModifiedInteger - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. The goal is to check for arithmetic errors.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   ModularInverse - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where computing the modular inverse of s hits an edge case.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['CVE-2019-0865']}
        //   PointDuplication - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA do not handle duplication and points at infinity correctly. This is a test vector that has been specially crafted to check for such an omission.', 'cves': ['2020-12607', 'CVE-2015-2730']}
        //   RangeCheck - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. By adding or subtracting the order of the group (or other values) the test vector checks whether signature verification verifies the range of r and s.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   SignatureSize - {'bugType': 'LEGACY', 'description': 'This test vector contains valid values for r and s. But the values are encoded using a smaller number of bytes. The size of an IEEE P1363 encoded signature should always be twice the number of bytes of the size of the order. Some libraries accept signatures with less bytes. To our knowledge no standard (i.e., IEEE P1363 or RFC 7515) requires any explicit checks of the signature size during signature verification.'}
        //   SmallRandS - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where both r and s are small integers. Some libraries cannot verify such signatures.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['2020-13895']}
        //   SpecialCaseHash - {'bugType': 'EDGE_CASE', 'description': 'The test vector contains a signature where the hash of the message is a special case, e.g., contains a long run of 0 or 1 bits.'}
        //   ValidSignature - {'bugType': 'BASIC', 'description': 'The test vector contains a valid signature that was generated pseudorandomly. Such signatures should not fail to verify unless some of the parameters (e.g. curve or hash function) are not supported.'}
        {
            auto pubkey = curve.make_point( "2da57dda1089276a543f9ffdac0bff0d976cad71eb7280e7d9bfd9fee4bdb2f20f47ff888274389772d98cc5752138aa", "4b6d054d69dcf3e25ec49df870715e34883b1836197d76f8ad962e78f6571bbc7407b0d6091f9e4d88f014274406174f" );
            {
                // signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "12b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28e3113083ba8e4ae4cc45a0320abd3394f1c548d7";
                bn_t sig_s = "1840da9fc1d2f8f8900cf485d5413b8c2574ee3a8d4ca03995ca30240e09513805bf6209b58ac7aa9cff54eecd82b9f1";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + n
                m = "313233343030"_hex;
                sig_r = "0112b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19a25617aad7485e6312a8589714f647acf7a94cffbe8a724a";
                sig_s = "00e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 256 * n
                m = "313233343030"_hex;
                sig_r = "010012b30abef6b5476fe6b612ae557c0425661e26b44b1bfde13e404c1d1a3f0fdbd49bfd2d7ced1b1ef6d69e61b6eebbd7";
                sig_s = "0000e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by n - r
                m = "313233343030"_hex;
                sig_r = "ed4cf541094ab8901949ed51aa83fbda99e1d94bb4e401e5ec7083591125fd5b9d8bc2cd7c6b0748e22ee5d5daffe09c";
                sig_s = "e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**384
                m = "313233343030"_hex;
                sig_r = "0112b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28e3113083ba8e4ae4cc45a0320abd3394f1c548d7";
                sig_s = "00e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**448
                m = "313233343030"_hex;
                sig_r = "01000000000000000012b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28e3113083ba8e4ae4cc45a0320abd3394f1c548d7";
                sig_s = "000000000000000000e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + n
                m = "313233343030"_hex;
                sig_r = "01e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc5f8fc6adfda650a86aa74b95adbd6874b3cd8dde6cc0798f5";
                sig_s = "00e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 256 * n
                m = "313233343030"_hex;
                sig_r = "0100e7bf25603e2d07076ff30b7a2abec473da8b11c572b35f8d94e69f521d5bbbff6c685df143cd5abd3c062f48c46be282";
                sig_s = "0000e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**384
                m = "313233343030"_hex;
                sig_r = "01e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82";
                sig_s = "00e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**448
                m = "313233343030"_hex;
                sig_r = "010000000000000000e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82";
                sig_s = "000000000000000000e7bf25603e2d07076ff30b7a2abec473da8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=0
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=0
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=0
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=0
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=0
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n - 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Edge case for Shamir multiplication
                m = "3133323237"_hex;
                sig_r = "ac042e13ab83394692019170707bc21dd3d7b8d233d11b651757085bdd5767eabbb85322984f14437335de0cdf565684";
                sig_s = "bd770d3ee4beadbabe7ca46e8c4702783435228d46e2dd360e322fe61c86926fa49c8116ec940f72ac8c30d9beb3e12f";
                r = true; // result = valid - flags: ['EdgeCaseShamirMultiplication']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373530353531383135"_hex;
                sig_r = "d3298a0193c4316b34e3833ff764a82cff4ef57b5dd79ed6237b51ff76ceab13bf92131f41030515b7e012d2ba857830";
                sig_s = "bfc7518d2ad20ed5f58f3be79720f1866f7a23b3bd1bf913d3916819d008497a071046311d3c2fd05fc284c964a39617";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130333633303731"_hex;
                sig_r = "e14f41a5fc83aa4725a9ea60ab5b0b9de27f519af4b557a601f1fee0243f8eee5180f8c531414f3473f4457430cb7a26";
                sig_s = "1047ed2bf1f98e3ce93e8fdbdc63cc79f238998fee74e1bb6cd708694950bbffe3945066064da043f04d7083d0a596ec";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333632343231333231"_hex;
                sig_r = "b7c8b5cf631a96ad908d6a8c8d0e0a35fcc22a5a36050230b665932764ae45bd84cb87ebba8e444abd89e4483fc9c4a8";
                sig_s = "a11636c095aa9bc69cf24b50a0a9e5377d0ffbba4fab5433159f006ab4563d55e918493020a19691574e4d1e66e3975e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34353838303134363536"_hex;
                sig_r = "4a7df2df6a32d59b6bfed54f032c3d6f3acd3ac4063704099cd162ab3908e8eeba4e973ee75b5e285dd572062338fe58";
                sig_s = "35365be327e2463dc759951c5c0be5e3d094cb706912fdf7d26b15d4a5c42ffebeca5ae73a1823f5e65d571b4ccf1a82";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313436363035363432"_hex;
                sig_r = "9ad363a1bbc67c57c82a378e988cc083cc91f8b32739ec647c0cb348fb5c86472015131a7d9083bf4740af3351755195";
                sig_s = "d310dc1509f8c00281efe571768d488027ea760fe32971f6cb7b57cdf90621b7d0086e26443d3761df7aa3a4eccc6c58";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333335333030383230"_hex;
                sig_r = "95078af5c2ac230239557f5fcee2e712a7034e95437a9b34c1692a81270edcf8ddd5aba1138a42012663e5f81c9beae2";
                sig_s = "40ee510a0cceb8518ad4f618599164da0f3ba75eceeac216216ec62bcceae8dc98b5e35b2e7ed47c4b8ebacfe84a74e6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36333936363033363331"_hex;
                sig_r = "a538076362043de54864464c14a6c1c3a478443726c1309a36b9e9ea1592b40c3f3f90d195bd298004a71e8f285e093a";
                sig_s = "d74f97ef38468515a8c927a450275c14dc16ddbdd92b3a5cae804be20d29c682129247d2e01d37dabe38ffb74808a8b7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333931363630373935"_hex;
                sig_r = "bbe835113f8ea4dc469f0283af6603f3d7a3a222b3ab5a93db56007ef2dc07c97988fc7b8b833057fa3fbf97413b6c15";
                sig_s = "737c316320b61002c2acb184d82e60e46bd2129a9bbf563c80da423121c161decd363518b260aaacf3734c1ef9faa925";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343436393735393634"_hex;
                sig_r = "679c3640ad8ffe9577d9b59b18ff5598dbfe61122bbab8238d268907c989cd94dc7f601d17486af93f6d18624aa524a3";
                sig_s = "e84dd195502bdcdd77b7f51d8c1ea789006905844a0e185474af1a583bab564ee23be0bc49500390dceb3d3948f06730";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35313539343738363431"_hex;
                sig_r = "f6f1afe6febce799cc9b754279f2499f3825c3e789accef46d3f068e2b6781fd50669e80c3c7293a5c0c0af48e068e35";
                sig_s = "f59cc8c2222ed63b4553f8149ebecc43b866719b294ef0832a12b3e3dbc825eeab68b5779625b10ae5541412ec295354";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35323431373932333331"_hex;
                sig_r = "f46496f6d473f3c091a68aaa3749220c840061cd4f888613ccfeac0aa0411b451edbd4facbe38d2dd9d6d0d0d255ed34";
                sig_s = "00c3a74fa6666f58c4798f30c3779813e5c6d08ac31a792c2d0f9cb708733f26ad6bf3b1e46815ae536aa151680bdee2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31313437323930323034"_hex;
                sig_r = "df8b8e4cb1bc4ec69cb1472fa5a81c36642ed47fc6ce560033c4f7cb0bc8459b5788e34caa7d96e6071188e449f0207a";
                sig_s = "8b8ee0177962a489938f3feffae55729d9d446fe438c7cb91ea5f632c80aa72a43b9b04e6de7ff34f76f4425107fd697";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130383738373235363435"_hex;
                sig_r = "8bb6a8ecdc8b483ad7b9c94bb39f63b5fc1378efe8c0204a74631dded7159643821419af33863b0414bd87ecf73ba3fb";
                sig_s = "8928449f2d6db2b2c65d44d98beb77eeadcbda83ff33e57eb183e1fc29ad86f0ba29ee66e750e8170ccc434cf70ae199";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37333433333036353633"_hex;
                sig_r = "e3832877c80c4ed439d8eadcf615c0286ff54943e3ae2f66a3b9f886245fea470e6d5812cef80c23e4f568d0215a3bfc";
                sig_s = "3177a7dbf0ab8f8f5fc1d01b19d6a5e89642899f369dfe213b7cc55d8eaf21dd2885efce52b5959c1f06b7cac5773e5b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393734343630393738"_hex;
                sig_r = "6275738f0880023286a9b6f28ea0a9779e8d644c3dec48293c64f1566b34e15c7119bd9d02fa2357774cabc9e53ef7e6";
                sig_s = "d2f0a52b1016082bd5517609ee81c0764dc38a8f32d9a5074e717ee1d832f9ea0e4c6b100b1fd5e7f4bc7468c79d3933";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323237303836383339"_hex;
                sig_r = "d316fe5168cf13753c8c3bbef83869a6703dc0d5afa82af49c88ff3555660f57919a6f36e84451c3e8e5783e3b83fe3b";
                sig_s = "995f08c8fec7cd82ce27e7509393f5a3803a48fe255fcb160321c6e1890eb36e37bcda158f0fa6899e7d107e52de8c3c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323332393736343130"_hex;
                sig_r = "0b13b8fd10fa7b42169137588ad3f557539a4e9206f3a1f1fe9202b0690defded2be18147f5b2da9285c0e7349735ea3";
                sig_s = "0478ad317b22a247bf9334719b4c8ee84acf134515db77e6141c75d08961e1e51eaca29836744103de0f6a4c798d3eeb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3934303437333831"_hex;
                sig_r = "15804429bcb5277d4f0af73bd54c8a177499a7b64f18afc566c3ce7096bdc6c275e38548edcfa0b78dd7f57b6f393e49";
                sig_s = "d5951f243e65b82ba5c0c7552d33b11f1e90fde0c3fd014aac1bb27db2aaf09b667c8b247c4cdd5b0723fba83b4f999e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323230353639313233"_hex;
                sig_r = "359247c95776bb17492b7bf827f5f330fa9f9de7cc10441a1479c81776ce36cdc6a13c5f5149c4e39147a196bb02ed34";
                sig_s = "f6ed9252a73de48516f4eabab6368fbff6875128af4e1226d54db558bd76eec369cc9b285bc196d512e531f84864d33f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343134303533393934"_hex;
                sig_r = "a557d1f63a2094f683429ecb35a6533bac897682775c0051e111eed6e076c48867cae005c5e0803800b050311e381cd6";
                sig_s = "2a2f871efcf03cf1c8f509e076aaa2a76f1ea78d1c64804ea5b063b0324b8e98eb5825d04370106020ee15805dbedf81";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393531353638363439"_hex;
                sig_r = "f22bf91169b4aec84ca84041cb826f7dfc6f33d973f3c72433b8a0ca203aac93f7eed62be9bea01706402d5b5d3b0e65";
                sig_s = "7841d3bc34aa47e813a55c25203c5ec2342d838d5b4638c2705dcf4bac9c24f765b5d4c28fa3c7fda7a38ed5048c7de3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35393539303731363335"_hex;
                sig_r = "9c196e39a2d61a3c2565f5932f357e242892737e9adfc86c6609f291e5e6fdbb23029ff915a032b0c5390ba9d15f203e";
                sig_s = "d721e28e5269d7813e8a9aed53a37e652fec1560ca61f28f55ab4c262cc6214eee8d3c4c2ba9d1ba0ba19e5e3c7484a7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323135333436393533"_hex;
                sig_r = "8ba1e9dec14d300b0e250ea0bcd4419c3d9559622cc7b8375bd73f7d70133242e3d5bf70bc782808734654bacd12daea";
                sig_s = "d893d3970f72ccab35555ae91ebcfed3c5bfc5d39181071bc06ba382587a695e02ed482f1a74fe309a399eaee5f5bc52";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34383037313039383330"_hex;
                sig_r = "2f521d9d83e1bff8d25255a9bdca90e15d78a8c9ea7885b884024a40de9a315bed7f746b5da4ce96b070208e9ae0cfa5";
                sig_s = "4185c6f4225b8c255a4d31abb5c9b6c686a6ee50a8eb7103aaef90245a4722fc8996f266f262109c3b5957ba73289a20";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343932393339363930"_hex;
                sig_r = "d4900f54c1bc841d38eb2f13e0bafbb12b5667393b07102db90639744f54d78960b344c8fbfbf3540b38d00278e177aa";
                sig_s = "3a16eff0399700009b6949f3f506c543495bf8e0f3a34feb8edd63648747b531adc4e75398e4da8083b88b34c2fb97a8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313132333535393630"_hex;
                sig_r = "c0169e2b8b97eeb0650e27653f2e473b97a06e1e888b07c1018c730cabfdeeec4a626c3edee0767d44e8ed07080c2ac4";
                sig_s = "13f46475f955f9701928067e3982d4ba5a58a379a66f91b74fad9ac8aee30086be6f41c9c2d8fb80e0924dedbe67e968";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31323339323735373034"_hex;
                sig_r = "2e868871ea8b27a8a746882152051f2b146af4ac9d8473b4b6852f80a1d0c7cab57489aa43f89024388aec0605b02637";
                sig_s = "6d8c89eed8a5a6252c5cead1c55391c6743d881609e3db24d70ead80a663570020798fbf41d4c624fcb1ce36c536fe38";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303831313838373638"_hex;
                sig_r = "abe6a51179ee87c957805ecad5ccebca30c6e3a3e6dbe4eb4d130b71df2bf590b9d67c8f49e81bf90ce0909d3c2dab4c";
                sig_s = "7110582fab495b21bd9dda064fbd7acc09d0544dcf7699be35ad16207ffa10e8904f9241a709487ba2ba7e34430b81c3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343534363038393633"_hex;
                sig_r = "50252c19e60e4120b7c28b2c2e0a588e5d107518cd61e5c7999c6d465ea134f752322d8b83f5988fcdc62bd9adb36ccd";
                sig_s = "193899352491dabfe4fc942e14ddacb200673729d61602cc0baf5732d262f36e5279865a810ce2f977f57686a0d0137a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333837363837313131"_hex;
                sig_r = "eb725fdd539d7de8ea02fac8db6ec464f40c272a63e6b2718c4e0266bf1235dae330f747a6052f4319ecbe7bdade9bd0";
                sig_s = "ae84507648ba2d1944bb67722ccd2cb94b92b59e89a1ae698c668bb57f481c42b216c23da4b1d8c0e502ef97fda05ad0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303331333831383735"_hex;
                sig_r = "25aa56fcbd92f2cf53bddbaa0db537de5843290731c1dd78036fcbded4a8f7187ddfed9f5ca9d98ea7b12d24b8d29d57";
                sig_s = "028f68372d66164810bf79c30a191116d496fe32314605dc1668289425fb3a15d7532dde1052a49a35866c147abde1d9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323535333538333333"_hex;
                sig_r = "54bf7adc8548e7cae270e7b097f16b5e315158d21b0e652ce1cfe4b33126ba4a65bf227b4cddcaf22d33d82478937b20";
                sig_s = "bfc1b8f1d02846a42f31e1bd10ba334065459f712a3bbc76005d6c6488889f88c0983f4834d0bf2249dbf0a6db760701";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34363138383431343732"_hex;
                sig_r = "d3bb29ac0bd1f6058a5197f766d6ea3216c572ded62af46318c8c7f9547bb246553654279d69989d9af5ef4ccacf64da";
                sig_s = "e10281122c2112a2a5a9d87ac58f64fb07c996a2d09292119e8f24d5499b2e8524ebd0570097f6cc7f9c26094a35c857";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303039323435383534"_hex;
                sig_r = "bc32e85e3112472408f9324586e525325128a38313c34b79700cb0a3f7262a90a1fcc40eef1f1a3884032a7a21810e0a";
                sig_s = "c02f52541360358107a13dbea31f83d80397710901734b7adb78b1fc904454a28a378514ccef80ecc70c1d8e55f11311";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373536343636353238"_hex;
                sig_r = "f04b9e17c71d2d2133ea380d71b6b82c8a8e3332703e9d535b2c2bca9b0ad586d176a6049afa35edd9722edb5c33daa3";
                sig_s = "bd44d4a6263380ca6f22e76c26d5f70f41f4d7cae7d4b9c1b8dc2ba5298d9d12408b04614e2f3796cc19c950c8c88a10";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313139363937313032"_hex;
                sig_r = "c8807351d8e261338e750cb9a52f4be4470b63f6f181cbe0e81d43b60824ba4be1bba42b1783897a0d72b0614018b02f";
                sig_s = "52e3a598c8be982127e961eed2b04f21c86df4ebcab0d955a7c66ec7f818898798ee75367a85022276b912c0a072bff7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323333313432313732"_hex;
                sig_r = "6152841b6fb460546eeb4158a3e5ffa54f51aa6a208987be899b706055cd59d8ec7c01f4634254fe050e1d4ec525a173";
                sig_s = "73f0c5f13640d892c28f701428e8fbfb736b6478bbd972c8c684977556ed599a70d313e06b126080e13068d56e1c10be";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363733343831383938"_hex;
                sig_r = "842f8d2814f5b7163f4b21bd9727246e078ad1e7435dfe1bc5f9e0e7374232e686b9b98b73deab9e43b3b7f25416c2be";
                sig_s = "852c106c412300bac3ba265990b428a26076ab3f00fd7657bbd9315fa1cd2a1230a9a60d06b7af87aa0a6cf3f48b344c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343630313539383237"_hex;
                sig_r = "e13f6d638b9d4fba54aa436a945cfea66dec058fab6f026293265884457b5a86e8e927d699bc64431b71e3d41df20044";
                sig_s = "9832cd1b4177118ed247b4f31277da15f420179f45c71a237d77f599a45df68247bac3dcef0868ecd1665005c25b7c6c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38393930383539393239"_hex;
                sig_r = "09fff1c2e4ff8643cbfad588620c2bf7aaca5cf4242969142c7145b927bd82ed14f3ae8c6e2ce2da63b990b9f1be6d64";
                sig_s = "780c816f6c86343b008235ee986abf2136123ed247e4751e4d5467334f08e5e2ca1161254f68c3e6678e2d0b87d1cc7c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333236343430393831"_hex;
                sig_r = "ffae6e7d2cea71b5a9c73cbc1285a8d252949772afe1aa27fb137740fc429c2a8c8648c9a5ba678a32f7ae7689b395ca";
                sig_s = "89d54cd13a162c34189ff524813690e79768af8ebe794cc941dfe7fdf2cb8dd0b42519f034ea4d4f1c870046d13210e1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333736343337353537"_hex;
                sig_r = "efa3c5fc3c8be1007475a2dbd46e3578bb30579445909c2445f850fb8aa60aa5b1749cc3400d8ffd81cb8832b50d27b4";
                sig_s = "b36a08db3845b3d2ebd2c335480f12fb83f2a7351841ea3842ec62ad904b098efbf9faa7828b9c185746d9c8bd047d76";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383630333937373230"_hex;
                sig_r = "f577095f7c74594aa1c69aca9bb26e0c7475ae5163058ecc074b03af89e56b12b6a72450589dacf0d7e6b172d0017a0e";
                sig_s = "bee756a0b5d0a677bf95f98da512854f3ecb712f94570e1ad230eab17c527b6a8bcc9ae202b657a3611ecffa94ba0d54";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35383037373733393837"_hex;
                sig_r = "0ae7688c7de5882eb9c3172f5500015552f998fb53702c6cd4b03404d5a0510a8073db95db544808dbd76659fd20cf12";
                sig_s = "bc610fe5f04d8909cc439615fb7e302d3d82992817647c50c1f467090a52b328cbbc0262f18ffb6fd9f3bd60013cea08";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353731383636383537"_hex;
                sig_r = "5dc8a6d84afaaf900d78c6a91dc5e12e7d17891a52c1468253061d704b8940bef85b9fe807a0e02b56e8dd37c22fbb82";
                sig_s = "914258de52932c4604dceb5ce7cc0a92e021edca9b819b84a9f25652f9af13f956a1139ee95c7aa7a079e3ad8317fbdb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38363737333039333632"_hex;
                sig_r = "da55a6dbb845205c87c995b0bbc8444ffcba6eb1f4eb9d30f721d2dacc198fb1a8296075e68eb3d25ef596a952b8ea19";
                sig_s = "829f671dccad6d7b0b8c4b39ff3f42597965d55c645fb880a66fe198d9344c9311f1598930392470379fa5ff43c75d04";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343735353135303630"_hex;
                sig_r = "3730dfd0985de77decdd358a544b47f418d3fab42481530d5d514859894c6f23b729af72b44686058de29687b34b3b0c";
                sig_s = "65bdfaf0ac217a80b82eb09c9f59c5c8cfbf50a6eb979a8f5f63eab9bd38ee0938e4b23102112033b230a14ad2790e3f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393733313736383734"_hex;
                sig_r = "55210df2124c170e259af1dafa73e66613aa18ced8eb40a7f66155d50d5f3124edfa55276de4797013177291e8afeff6";
                sig_s = "c314d3a310a60647dad3318ed7f0405a64c3f94b5ac98e6be12208c8ad9835fa6b81a0ea59f476608634657b66e00ffd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33363938303935313438"_hex;
                sig_r = "f6c9897144b5d84964515eb0c8c3d0d9c6687c957887e93c29b2a21804b40307fb88bfd5cca11c95885d28867cb33a74";
                sig_s = "656bafca242290f7d7e9801b6cfd4bd1b07e8d7c6c1c59fd3d8e82e9846a1b2855c85420e4ee6ec2d97fec2161eeb243";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130373530323638353736"_hex;
                sig_r = "bfbcc5f343e2ab392ce6c1c02d91c00650c47136836a5d0622d476ac2b3274395721b1ab21882ed5cabed093b43b133f";
                sig_s = "043e9fc64c6108df73f9eced90f91185f83d89662f5a9d810c1824fbfd97b842f784305fd6b9c28c80d32d52b1538d12";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383639313439353538"_hex;
                sig_r = "b8f793ddd47e657a9081cbed1600fb22b38ad6a155f9c006ba98de1f383b4c0918ceea72253e0f869524b2369cd9bd8c";
                sig_s = "96c452ff58f42e0853040a6d5c7e750b57dd4af06e2df8194e8d524e81ac000ee3315bbeabbf6a21f61b8904c55378d9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313734363535343335"_hex;
                sig_r = "263ab1c93567e93b5ec4e380b0d3bb5ea1ce693c14a47afccc539aaf197f099d331ea9e26f1a0057148d46727acb6188";
                sig_s = "621db07ce94110e2be74fa953a00a8a554225b3f2c0f6c56b4ebd4db2f57ca2565ed3323fd708bb56ac6e28bfb40f2e7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363434353530373932"_hex;
                sig_r = "96f4a2b3529c65e45a0b4c19c582dc8db635d4e74f0b81309696b23be920ba8ec553d4b370df4c59d74dd654bac6df58";
                sig_s = "1573ba1b280c735a3401d957ecd3b8908e4e0b7d80239ce042594d182faf2ddf811c9056aac4c87f4f85043766a26614";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353332383138333338"_hex;
                sig_r = "96a691b19a6294b311a438f8da345e480b1deaa1e940cfbf02177d5f08479976ea58aee31011d50b5542be188c9d63df";
                sig_s = "8f67dc9e1588aeb8be180013d41a036f9badfad9fe9340910cbf87243776f54bef7da2ebf3a7643866eb9a3b23fe59b9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31313932303736333832"_hex;
                sig_r = "cff27948c6d902c73d103d0802eb144dd89c1b0e3b9f9a5e498b0361dc122a0d555160d8c64d61539c1dbbd4bc18971f";
                sig_s = "b60827488c9f16ba28378fd59b1a29c65073335a7f236131134674c62c8396f193c76f2395ddaaa4f24b69161eb69b4d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353332383432323230"_hex;
                sig_r = "e90e22d9e535dfdfd86e098d5d6a0ae08f69d4a3ffaa39f6930bcf5f5ad02ee0d0472ae984edd9f0bbe5e7d63fd4f6ac";
                sig_s = "e3f57b0a4629ecaa21f2d34a7a0834d57ba20f99c6e31b43c37811cc23b9957c8f3356f4462214d3c8e58745e50f23f6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313536373137373339"_hex;
                sig_r = "18b70e272a98cc48e1e0af73146f0f972bbfbeb6b985feb2c4acd695a7a41b99c415be9c46aedaf3ddff67a65a89e387";
                sig_s = "47d6bcea088f622ad35d88bcf46d71827bcba2f57c36d6fb8a4bf2befdc0d4e3ef366d5966c4d076d3cfa43d6626717b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333033303931313230"_hex;
                sig_r = "acfd981c55fd5286cfce173726d51c3d25f65b11b7673729a62167256774f7c894b74662a212c706e00cef096074162f";
                sig_s = "f4d471c97797c24d96aec1de85a249ef468d6036cd712563aeb65cea4995f3ee85e769b874f09a08637a44a96084be7a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37373335393135353831"_hex;
                sig_r = "f15fcbeea8b64dad5e8566a2c37913c82d6be9d9668df469bd0b591c3923a6e12644eaf697d466fa7cd513983d946a40";
                sig_s = "70063966801079351526999e5c5c2c5f627e4c8bc96784bcbe715fe7c7afcf69785d1c8c7ccd3725e364101638396597";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323433393636373430"_hex;
                sig_r = "d995147939ae6d8f62bb57372227395839e25a0d4308b899d5f506cf9e0a01e8115b7e4b822f037ec95752bd9e892f5e";
                sig_s = "9bb4d07333e468f8482a790a2a2e650e2c42da8240ec5e402506b368122f046680cd71e0117897cce3df4a1555fc8876";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333237363032383233"_hex;
                sig_r = "43c6ce5184476f3f496afeae3cb96a3f9f038957686c93437b8266a233022371d266e904aa096c3566cb33824b88075e";
                sig_s = "680c13245a8bc560b638d26f0c5f261964130256939552d3fffb07b658355611612c268a89541055d3c2bf9e82cf4da3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32393332303032353932"_hex;
                sig_r = "447539941dc350767fc841083d25d9247a0807e1e22e0bb9d94f504f721981b413d521efbd75e4fe831ee26338cf3de3";
                sig_s = "00395ab27ea782cee4be53e06c7616bbd41d6926b18d219d75d5979f13cba2f52101019b0ec0a41ffdbf29ef73ddba70";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36343039383737323834"_hex;
                sig_r = "a0ba8e8b979c20345e34fca98531900164a859923bd6986a9c39236a2f5de053a252997f35e5b84b0d48ba0f8d09aedd";
                sig_s = "facd6df04358fcd95fa9018a6fc0828dfe319812ff65929c060b18ad4b9f06e7fc0addd1b695315d71c15e51dc51d719";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36303735363930343132"_hex;
                sig_r = "b8378390f71f0bb6663f1846daf6908f8c84f770ae740cc8054122494cf0ffa9437ab26040ca22808fb29a810b70126e";
                sig_s = "427636b929a500abc34d9f22977b81e734919afaf3ed2c91eeada7074e0c16bdc52f960eaec9db5a879c1e6414035101";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333231363233313335"_hex;
                sig_r = "f36a9048fd94803d3d6d1b11430b90b94ef8d5d2ad89018c69473ce9cfe0d6105b3c2fb2e7555ccd25f65af8c872bdc6";
                sig_s = "81254841e7ecbfd0d810afaaf5afd6d6c5d0542bb00cc183b1db01767120afbcc0006ddcba8db7baf65f302723dabc4d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36343130313532313731"_hex;
                sig_r = "d8a4d96409c191baa9540bf35f1d5192f9352d7f0e14f92c0e8e1f19f559b42ed3c6b7bdb6becc56584fb5c09421e2e4";
                sig_s = "d966ba13d4245e248eafb46f2a3df92c2037d5969c7db6dbcb0ff4b21850e16a18a29785267239886365cf721a212536";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383337323835373438"_hex;
                sig_r = "1d5d86fd48e65b0cf0b0b46062241f89cf65785dd818f93f1162771a38a15f20febc261812ecaaf6f4f2b86b3362d7eb";
                sig_s = "0c76e363de1432513cb9dad6493931381ecd25f142e61968b6f20d7b1270cb9e38a7ae54e4778aff4025eb00c6a67aef";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333234373034353235"_hex;
                sig_r = "0508eed148f061114be18e8a86188feabf76b873b36eadcca9c2c60e24a2002fe456231decf7a8f6f032c08dbe0ab5a9";
                sig_s = "694c0ad781b2341e30e1d0739ac99672064f48821a69852c7940cf1d621738199c980d56d2a0b71b3fc6011c6b2444ba";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343033393636383732"_hex;
                sig_r = "726ef88bb7947a043116c111cb519ddeda3e6ffbf724884a1b22c24409cdf2779d93ce610c8c07411c2b001399103d6d";
                sig_s = "95dc1d65046caf0e8dad07b224798d6f7807278e737883e7c7bf0b446791d4ee144c26f710134861af4e6771d4082896";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31323237363035313238"_hex;
                sig_r = "eb0e8e3c639f5eba8eccd9020d0ec62d8ac73f3fddbdfa08fdb2155deb0a536923ebd55e20020cab9f8e39a43a88be11";
                sig_s = "c796df399fc35883dd5dae6817d02d3d67a8eec6601585e5e36fd2c134eddb1447ec12b144dddc9aae28a84f22602641";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34393531343838333632"_hex;
                sig_r = "e8f8c69d0396ea900f9757736d2b19dbc2d2a8c01dccf490c8b9455bd63b34c095867e7cf3b84dc7c3c3d6b51bebf405";
                sig_s = "58152a7564eeb22a3e26597026d0cd7835725bd512245448cb5016eb48ea759809fd6949d0ee5d579643f72f908c16bb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343532313237303139"_hex;
                sig_r = "380b4e48b3ff012af7c08bf871d9f4da0c708b5494a986d3d80b1979e579d0dbee61db9bc3c04c396176410788e15a0f";
                sig_s = "e6971c013c965a7e4df10f95620a5092fab096bd5b50828f4bc91c5e479bccf6e0daf287e7ef580fa9ea153fa1a507a2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373331353530373036"_hex;
                sig_r = "8061de12029e2b000d157a455ecf2301222f092df95b9551b78cf0ef3a64f12212b57ec7b16d2c0f258946f51cb1633a";
                sig_s = "0ac2ca6ad99b29ca29a0dc38b34443ee41020f81ed9087cef7681a00c4fe60653a572944ba37f1fe51d112bfffbdd701";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363637303639383738"_hex;
                sig_r = "e74f2a791eeb7341cff6cc1c24f459e6c0109924f7984639ae387e3ceb58758a1bc3839dea1fc3a3799562225e70a733";
                sig_s = "d90e4d0f47343268e56bbcb011bd4734390abc9aa1304b6253e78f5a78b6905aa6bf6a3892a4ae1a875c823ae5a83e87";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343431353437363137"_hex;
                sig_r = "6a1cd0ff7906be207b56862edcbc0d0bbfb26d43255c99f6ab77639f5e6103a07aa322b22ed43870d1ce6df68aa0a8c1";
                sig_s = "655558b129aa23184500bd4aab4f0355d3192e9b8860f60b05a1c29261f4486a6ae235a526339b86c05f5fac477b6723";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343233393434393938"_hex;
                sig_r = "81111fdc5f0de65583c7a5668d26c04ee52e08dac227753132cff1741cb721e112aa793c0d5fa047faf14cb45dd13e1f";
                sig_s = "9a25cf1e6c152bc3e216e021561d194979f1c11fe17019ed7bac2c13c4010f209665e3b6f33b86641704d922b407818f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34383037363230373132"_hex;
                sig_r = "9b66d122a315095b2b66ccb97272c476a2d760e827fdea05732d634df3d066569c984dd941aad5f5dec4c2e1b7b94a00";
                sig_s = "96c32403c85bc3d0ee87f96a600182796dce53d54d7467ae660a42b87bb70792f14650ac28a5fa47ce9ca4d3b2c25878";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313634363636323839"_hex;
                sig_r = "2bb062a002088d62a0b7338d0484fedfe2af7e20cebf6a4788264eb27cb4ebc3cc81c816e6a35722cf9b464783094cb8";
                sig_s = "46cc21b70f2133f85ab0443bebe9c6fc62c6e2ec1fd9c4ddf4a6d5f3f48eb7abf1ee7bdf6725879fd1b7daafb44f6e04";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393432383533383635"_hex;
                sig_r = "33e87061ee9a82eb74d8bb4ae91606563c2e4db8b09183cc00d1119ab4f5033d287a1fc90a2348163fdf68d35006fd7f";
                sig_s = "96db97c947ee2e96e6139d3bcbf5a43606bae1ad3ca28290fbad43b281ef115ec1b98bc581ef48094f8c1aa8e36c282a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323139333833353231"_hex;
                sig_r = "70f80b438424ba228a7d80f26e22ff6a896243c9d49c75573489ee0de58ec60efd103838143465bd8fe34672ba949617";
                sig_s = "115492bd9365b96f38747536318bffb819e7c146df3a5a7a46d6288c7fdf31cff570b22176aa398daba9073ab1e7b9bf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393236393333343139"_hex;
                sig_r = "ff16ca0389ea6948f4305b434fe0aa589f880f5aa937767c31170ee8da6c1ad620c993d40ddf141b7fda37424d51b5cd";
                sig_s = "ba0f86985dffc61d6e35a37de06918b11e431b72403161acfb8f05c469f1fcfa6e215c6f7eb5a0a5e0cc9e7be79ce18b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373639333836333634"_hex;
                sig_r = "d60c24bee05f5198cd155ad095ffb956bbcfb66b82fc0d3755119915a62f2f923557b85ddc1d12e6a757f23042cb601b";
                sig_s = "2c4d968b5eac930b51d283b418fcff6df3a9d6d66e3812cd1bf5fde797fd203a7c439b1b381e4fe8b44e6f108764a7dd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373335393330353733"_hex;
                sig_r = "bdf634d915a4fae7a155532ca2847c33a6babe7ef8db0af50f485db3dd2c8bffe722394583932f6eb5cd97f6db7561d9";
                sig_s = "bb425cae2e5483174b5ed873af4329da4618c14458141850bee3c7bf1ffb3f2030159043277dacc708e9d32f63400083";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333030353634303635"_hex;
                sig_r = "061320a3bcebac33cf399d45d1e1e1b34f37288fe4753f4fddfd496eff427e1d26b1b91d749cc34c12f4ecef837c0e8f";
                sig_s = "fd5cf468cda319fe06e773a190c38de6e150a321ac1c416ad875432cdb7a07134c446f13068e71a1a96e35da923974ad";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333037363535373338"_hex;
                sig_r = "d620f063d33efa859b623f6c9a92340e4cdd854ffbe3e5e01379177aee31715ce587b00bd0aea98fddf236d2fc8a7a74";
                sig_s = "671f4b7c187297dc236c61888b6d9397e97783077cc4101807d79ee62e4a53a78c4b6a3a31b03178668af894a3d8902e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39363537303138313735"_hex;
                sig_r = "91c556c5bddd529fe903b86afc0eb8fa1f49425b779a39114ae563bebc947e633ba4ee98948faa8940dfe2562c63e1c5";
                sig_s = "198b00079d8db072d25b0a49bc8bc36457926f3c101527528df6679f92c76f1b487e6695d4b92fe33b4ee7046a6a5df9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4bf4e52f958427ebb5915fb8c9595551b4d3a3fdab67badd9d6c3093f425ba43630df71f42f0eb7ceaa94d9f6448a85d", "00d30331588249fd2fdc0b309ec7ed8481bc16f27800c13d7db700fc82e1b1c8545aa0c0d3b56e3bfe789fc18a916887c2" );
            {
                // k*G has a large x-coordinate
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000389cb27e0bc8d21fa7e5f24cb74f58851313e696333ad68b";
                bn_t sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52970";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r too large
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffe";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52970";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3623bb296b88f626d0f92656bf016f115b721277ccb4930739bfbd81f9c1e734630e0685d32e154e0b4a5c62e43851f6", "768356b4a5764c128c7b1105e3d778a89d1e01da297ede1bc4312c2583e0bbddd21613583dd09ab895c63be479f94576" );
            {
                // r,s are large
                auto m = "313233343030"_hex;
                bn_t sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                bn_t sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52971";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d516cb8ac8e4457b693d5192beeb6ce7d9a46bef48eecf3ea823286f101f98d130f5a26dc6fec23662eff07f14486fd5", "008456932e74894b7f0e3bb0dfd362502b3765dd80a3177209fb221dc9b51aaf4470b245391405bef514176b13a267a720" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "d1aee55fdc2a716ba2fabcb57020b72e539bf05c7902f98e105bf83d4cc10c2a159a3cf7e01d749d2205f4da6bd8fcf1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a8380cd35026e13bf87be693cdb6e75a82d765b4019b529e8d277c4af6c9db27ebb5d3f86e88add9d5b61186f04c83a9", "0092a187507c737325d2cc624acef3cd036bfa99e0c1518be65c88bb51f900f94123acabad81d15130d3ade7ff7e4364e1" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "b6b681dc484f4f020fd3f7e626d88edc6ded1b382ef3e143d60887b51394260832d4d8f2ef70458f9fa90e38c2e19e4f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "554f2fd0b700a9f4568752b673d9c0d29dc96c10fe67e38c6d6d339bfafe05f970da8c3d2164e82031307a44bd322511", "71312b61b59113ff0bd3b8a9a4934df262aa8096f840e9d8bffa5d7491ded87b38c496f9b9e4f0ba1089f8d3ffc88a9f" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "44ee3335fa77d2fb02e4bd7074f45e598a879c0fa822ec718c21dc13b83440edc4e3c10a1858423e03044c9eff22591c", "00d027c49933e5510557d6b4b2c6f66fe5dcb9302a3b13fdc68048c3fcac88ba152b6a9833c87fdc6280afc5d11ab7c107" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e2f87f72e3c66c73037fe77607d42ad2d9c4cc159893b4b9b8b0365d3a7766dbe8678b02e2b68f58e5a4f7681061a390", "00e38f2142818542bef6b2bc3a2c4f43c95e5259d6bd5401531378c7ca125a1f6cc609d4fadfc5c9a99358ee77ff780c8d" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "60e89510c308089a747f06374c5388416535753b33514480bf8251ff4014754ebaf48aa655dc41ca89f373257a7e50b1", "4dc4c2bed99597c146d577f4333843855da27e395fc81aa90205795bd555b3451dc4b9536e234799185123c4792cfb1d" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0a82d7df701a1f0c02a8265fc471d4851a3f08b5c82897766c18400a270c11d4fedd7b5b085e532674b395b3653f6385", "00ae089577be259cdbe030a661868d7b3b5413218a48439a6753f92316dccf692f2520058048958a6ed4085583ce78f45f" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1301dee63fca91b6de8835480c3d86297b1e6a0a7339fc5011a50c33f350e9938743df496aeaa1e3170ba1e2f0c44918", "7b6812948761816232e414e23b0f9904d171da5cc0492a341e2b4f9477da0a311cdac7c7d01037ed7dddb3376892fd44" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r is larger than n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52976";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00cce27e78386d68492fc58dd5f191a690c2ebc0a452442fe0dd331f458f18c8fcd922e148f8f251bf1b85e149ccb3f192", "0095395c884ff97f670631e84b7e0b0dab503ba9c7080eda0e1c66b04e160728067cfe88fbcbbb0f52cfb733cd951fcf26" );
            {
                // s is larger than n
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                bn_t sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accd7fffa";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0bb03fce3c01ebcf0873abd134a8682f5fb8dbffa22da674047e5c3e71e43de582ed6abb908c2e4faa5d96186278b6c1", "00ba3b22123e68ccc56f17dd79ff15565706f71a0b6123c77af3cd88f0af024cc5259781516edcaf5fe990646e7b66999d" );
            {
                // small r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100";
                bn_t sig_s = "489122448912244891224489122448912244891224489122347ce79bc437f4d071aaa92c7d6c882ae8734dc18cb0d553";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "58f246090d5e49863bc0bf2d501ff72f551c5f1c5e679eb49064fd02e221a2707326ec2d140bcc817afaad5065761566", "497c823fd736882cbf78fb92b1a5589b67e8067497c710a4cbb39dee2c5431bc45cfb96c9f8454385c9f2b3ef2d3d31a" );
            {
                // smallish r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000002d9b4d347952cd";
                bn_t sig_s = "ce751512561b6f57c75342848a3ff98ccf9c3f0219b6b68d00449e6c971a85d2e2ce73554b59219d54d2083b46327351";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00fc6984dd6830d1485fb2581a45a791d8dca2c727c73d3d44c89f0082c1868af5ca74b4ca4ae22802640a9ebfe8c7ae12", "00998d63a5b5ad1b72b899f0b132e4952aaa19d41fdeea48b1ed6b8358dd1db207fd66e01453ad40f67b836adc802d5fe8" );
            {
                // 100-bit r and small s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000001033e67e37b32b445580bf4efb";
                bn_t sig_s = "2ad52ad52ad52ad52ad52ad52ad52ad52ad52ad52ad52ad5215c51b320e460542f9cc38968ccdf4263684004eb79a452";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1b8def5922303d647e8eb07e3bad92f924b79b769eef168e7541de1f4e0d28ae9733eb98cf8a1fb6dd52ca02c8c75b51", "00c7aa4bf679d49d8114122074da8f6044a427371796a5654a6106162d5f686abb73ebd896ab08c7062687f12171fbe4a3" );
            {
                // small r and 100 bit s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100";
                bn_t sig_s = "77a172dfe37a2c53f0b92ab60f0a8f085f49dbfd930719d6f9e587ea68ae57cb49cd35a88cf8c6acec02f057a3807a5b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1734a039a88a16c2ff4aa97d2399121f56f52ef01ed5e50887f736f65b6e51d6e8786abb4e063da5d1ba812dff998403", "00ccd698e6c296d5cd69178f8a82481a865da331627f1c4b324fbc02b36e8b5ed58a31f728e904d203a388755302195765" );
            {
                // 100-bit r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000000000000062522bbd3ecbe7c39e93e7c24";
                bn_t sig_s = "77a172dfe37a2c53f0b92ab60f0a8f085f49dbfd930719d6f9e587ea68ae57cb49cd35a88cf8c6acec02f057a3807a5b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "52ca47dda99172cb8321495acf988548295988ec973c1b4ea9462c53e5768a704a936410ee847b5dbf1e9d0c131da6c7", "0087a47027e6655792eb002d4228ee72f7c814c9a0cecbff267948f81c9903ac10eb35f6cb86369224ed609811cdf390f4" );
            {
                // r and s^-1 are close to n
                auto m = "313233343030"_hex;
                bn_t sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc528f3";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0091aa326dabe04a6ad266de30873518f978f634c740705152539787b5b42dd9683c4185ace936684683b4c136b5f2ff20", "00cacda42b735cbee78e7b6a43f50b851b85e998c365909f763d3e64210eded159ebf21818dec0e207b877b99ff595beaf" );
            {
                // r and s are 64-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000009c44febf31c3594d";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000839ed28247c2b06b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b1f52ae15400a0e0a4b39aae9a11e675cfc918d0c672189a86f68c0f306b115b6b470b931d19b2bbfcddada74f30a72c", "43cdc9522c0f73082251b4293982bc3e90960384f957f594d0ebe6eefe72af1ce7387f46ca5824ba0515559c05444f59" );
            {
                // r and s are 100-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000009df8b682430beef6f5fd7c7d0";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000fd0a62e13778f4222a0d61c8a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4314072bfccfe420f64cf79393bf38c773c4390f7df826c6a59043b3e0d55e8e69d37678c72a5e68a114e04ae5a2de76", "5a4b87638874c3b3ff687ba7fcd08238d46385e2aa6d65e2e53a6d5e205fcfd9b744f4087c6292b665dcb691ca5e86d4" );
            {
                // r and s are 128-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000008a598e563a89f526c32ebec8de26367a";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000084f633e2042630e99dd0f1e16f7a04bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00eb99d6bf52d08c1118ce27b0e4c09ce0d6893d5a9da2757b7f03057fcc17bd8afb4c48a60e757ff61d5e54e31d6536a9", "059ec79354b3949d53461e6adf7671ddf20402e1c9337464775ee56d507832728124c514e1dca506fe5fa72f7e1778ff" );
            {
                // r and s are 160-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000aa6eeb5823f7fa31b466bb473797f0d0314c0be0";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000e2977c479e6d25703cebbc6bd561938cc9d1bfb9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00bd3d91f003e18adbea73079d4eba23b91fc17fcec14c9eb15a193fbc9ca39c8c747cd7a2c9623e05dd587ccbb8ab4c44", "3adb0a0706aa5ea7a68042082fccefc979612a7a1a3d694b00793b03f89bff866a8b97c8e77990c29360ce795036c764" );
            {
                // s == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // s == 0
                m = "313233343030"_hex;
                sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5abbf618a084f67138c418a896d61af3af1826040835b73e7619846b495eba6f7eeaa2e9cc61c85f6100fedc25c16743", "00b065a427bc503139529e4faa63dda553aed2696fd02c2b6ceb2d941d2c4363cf9ac7a6759d50e8b9d07fe286f17cef5c" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "427f8227a67d9422557647d27945a90ae1d2ec2931f90113cd5b407099e3d8f5a889d62069e64c0e1c4efe29690b0992";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3942027bc7f33c10b159293f2abd0af935642a546ea20de9d85c36a0f4ed40cfada782a297bb2046d633fa53e26adc52", "30656a4f1804feca511d41372483af36387f658c44fdc5e7f02487ab70e1bf9d185918d7820fee0ea57a4fe006abbe70" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "369cf68bb2919c11d0f82315e1ee68a7ee8c17858bd334bf84536b2b74756a77e4eee10ecc5a6416a8263b5429afcba4";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d5db4d230cadf5bc6350f74d0bc5015b14d377934c879f74caf483dac49ef9fcf7a6676aaac5b405896d5be6ae0653e5", "00e3509606e26f71415a7f8ce37698e1c82286cdcdf3a7def73c347e32b45b32b6deeb34c4038373a30a7f8275f6daf541" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "2111832a45fc5967f7bf78ccdfe98d4e707484aad43f67cf5ac8aa2afbde0d1d8b7fe5cfc5012feb033dffdec623dfbf";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "629e253d5ef8c23319bbe9a56af387d92f867ef9f81c6d9f0ee7f5ac28412b0227eac75d982814e8e24d82b8308cc9c1", "4ef3b9286c9882d7e853f7032f01dbe88206a7f92ec7c776cdfd2117ccb2ad2165fb8650de299107037edb69109001db" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "20cd002ab7dca06b798fecef3f06a222c2d2a65e9ec92f74659a8d82fe7d75e9af739f0b532e17d6c5f622c4b591442b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3eb89e36a222831fba4be0b7ca40b7df6e4d795f921089b48989af0add1fa6c6e846946c25e4d195f9ac5dbb34147e41", "2b3081be4324036a3bc79e9b6cd78d0d48500f0fce1e5a0fa31d833f86d1afe2f7adfeb5cb9662c74763c85f0f9d339a" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "3276fe55314e426a8ed83c4c38dc27c8fe8cbba0b39bad7cfc35e963adf10ab37251ea6829b8d255a77dd0b655cf9ff8";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "66d0d1cec3fe7f8a46e766d1f7f44b2436f48164e12139313887c5992cfe5944059ba97eb10df411182f4242cb0d0bd4", "00a3e39ee77a4c472aeb3f110b088b5eb92b7d2885bce326eb8f002e2ce3c858910717841499eeb7f739441ba0ffb3c02f" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "1a80b4a3d6c88775821e26784463080eb7de510762ab0d98223e532364c7089b07af73746ae4cf076c5277dcc80cf8c2";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5ea90d3b95fe4c25b3623cba85867df605039be9c78b0489dcafb2c613ce6887c53fccc95fd342156466d0f8c05ba628", "00c81f3c6e5b5a400feffb76814c47f2ae486ac575359ee6dbea6e3a0fbad3747558934a5a1079883d02aa06bb071001b9" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "74e780e38b3a7cd6cfe17d5c9ac615895bd97dd4076b5f8218ae758b83d195fba64eb9aead39a790ca0f8b8387376265";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c8793c0b7d239c26195cbea62a97b350d74e64609e3946eca0061b19fe480332be3ba3e4b62de5c5032d7437015adf15", "00af8878a280a6469441d0ab04d0d331ffbc1389b9bf81991660b7b8c2ee20b2a0ed31b94742b5a7413fbb758be5927f7e" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "6ee5f8daae12c862e1f7f8b59294ac90448c4461e29b36ed623a719dd69bb17b3a4b7c29b9eb5c39ca6168bf6b597c6a";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "57d1385205e0cb872d619c2aec0b3442cf449959d33c1c4e76b55f9378e914fb07c4f26929832c3862de9be4b3d5fe18", "00f10779e7e09e2f0ea1ca2df8f801167bf384f061a2c272720e0a6f4b313341f29da004e91b83a738b14e7c3b3235a549" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "5426ca20a25b0cfb1ef230c62f91e98005f346e229233f1803e8944bf421fef150a4a109e48cefaa4ea23eea627fca41";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a982d9378c598e40330f1f1254494315e65a50754c701c46fbd2253b50673c6a794b72743e412aa92201df95e81af63c", "00d05e4c775885dfa050743dbf3b5d020be409bababce230b80d7aea32f38973a0b659aba3808fe7f9d2ae67ef9639d971" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "39fd1a0ae3964735554c61daf085c66bcc2e9e5350131086023aa99549fc5f9057c848e75a1b8e58069fe0b9b23fa3c9";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00daf193bd2f16d613aff2254bdc2dcd1eeb036d6506a50e07a26f83d3830629fad4433d3232628f5f24ede60bb6eb3e1e", "00e299714cc03e73b5e1a7fa0e1adfb2709a55883d9e97036007b31b7661f6fef6a1dbe418b633a5f3639f7d529da97285" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "707a37cfb7367c2e551ea1f0caeac6c0fdd2b562e1bd8f1c7c51a5dd78f21da8cb179bd832cac3d3aee21fda54729e66";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "09d4064490c7736106946b7fc6d88957c69d6f2f62e4388262603a43c129ceabe8d601ab2a700394b3b950840364bb6c", "7907bc45387fa1200b7cfae3171488d104738c60d22cacb71ed34a72bf1d315f7370aa181b265810c083996fe3a6b0fc" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "15c99e2ae11f429e74fe2e758bc53ffea26eb6368dd60d10daf860f9c79fa8cc6cb98fee9b87dd38353e970539a50a9e";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "650323415ec7cb87c02b670ba5dff00e6741d50c78f044ba179891e1e1e00cecc56803566872a288dcecfea93ae74955", "084ff6f9ad4f7ae7ec9c808259a5b640984000f7d86b412b4d04506fdce4d06cfd9b176d07cd869be6741de771438020" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "148c732596feaabb01be1be3a220740e84bbfabe6d82ad0db1c396fa047603beeb95a1cd37fc708a9451d3cc29a45b32";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00dcbe590865766687b59e391cd0e7774c8c71b48a150fd71aa85f12ae56a574a7d6c815eba1c1ac2ba98c0246e7a77ffc", "008adc0f6009441969497b33ec3ba5ca9056265ca6af4a732540ea71f4a0cb64c4a8296585be4cffa7f70bb779997300ff" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "6b3cc62a449ae5ef68bec8672f186d5418cc18d039af91b45f8a8fae4210ef06d3f0d226f89945b314d9df72e01a02bb";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "334ab85078a211761e6fe39b56b715047f6aa5f187f2eef32c66b10dc7aae5af2d43e3feb356332354f6e3231e723dce", "00f5dd6d0a40fe6c13e5008e310c848139ad58eaa1e9ba242ab383d433111ff11a494a57ab9f0924a257e751418aaaa66f" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "7db7901f053b9cefacfda88dd7791c01fd569ed9a5243385eccae12ba992af55832a2e5dc8065e018399a70730035bd8";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00f896353cc3a8afdd543ec3aef062ca97bc32ed1724ea38b940b8c0ea0e23b34187afbe70daf8dbaa5b511557e5d2bdda", "00c4bd265da67ceeafca636f6f4c0472f22a9d02e2289184f73bbb700ae8fc921eff4920f290bfcb49fbb232cc13a21028" );
            {
                // point at infinity during verify
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = false; // result = invalid - flags: ['PointDuplication', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "370d9e2e31c712c8028092f802319d7fdf5b3319a8518d08bed3891508c7060cfe2236e18fa14fe077093ceae633e543", "0fd79aacf9d16ecc19b12d60fba4998dfc682702ec7c8bdd4a590035773b8c9c570ac7dcd414e03252f7a0e6f53b5863" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00941e6cfa356e572dcccaeb594b06955d99dc4bf07958fc98ffa17de11c7521bf2c7aa8ff260952fcb7aac078ede67b47", "0090a78a0296b041a10f003df1998da4cc4a1614ebcbf5d239431f33d90d3023edc1802e8db6dabcbae67cc314da2aabab" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294ba";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3ecfd58a3ce583866e0471d16eb3c10a411ec3b8671f3a04769b1ed8464a71cf1c76d8d9b7e3670bbe712d6f554a9383", "00d980d8bedf57470d6b45cc1ad0c6426dc70a0e4be901106a36663bfcab04fcb86008777b92445120d5e3641d97396362" );
            {
                // u1 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "f9b127f0d81ebcd17b7ba0ea131c660d340b05ce557c82160e0f793de07d38179023942871acb7002dfafdfffc8deace";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4150ccd0fa45aa2ef6b5042ddbb1b87c5ffd1115a8fe5995641948acda82a7b190762d84352cd74d1ca01e79f68f9cb4", "00eb11be9d494c181c156e23e77e532bdf0a20c3cc74ba8c29b1f3eb2bd99129ee0d70ff0d593f0d7a6d6887e7c55930d2" );
            {
                // u1 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "064ed80f27e1432e84845f15ece399f2cbf4fa31aa837de9b953d44413b9f5c7c7f67989d703f07abef11b6ad0373ea5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e78fe2c11beac7090ee0af7fed469a8ccebd3cccc4ee9fccc8ef3fc0455b69aaa082dc13e1d84f34026cb6f0af9e992f", "00f34ebba71bf3a4050bf28e4084b5c5f5d4098ec46f10a31b02fb4bf20cc9362f6f02a66e802f817507535fac3ec0b099" );
            {
                // u2 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ee24ab8a34d05af684939357f32759cc5a14f3c717529a20aea8e0c5965d8a41e68925f688471994b72021ba51b28c09", "0a55693c92ad0cbae9edcf515e2b4c060b888d82c81e4a3b6a173b62ed04a46fa95db1a2f3949980fba2e371263c4fa9" );
            {
                // u2 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa84ecde56a2cf73ea3abc092185cb1a51f34810f1ddd8c64d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3d2e916055c92e1b36133f5937b37c1b0102834eb77008a3ba9c3da446e9065971d68ba913091851e10cff5b4cd875c1", "39aa7aadfc2caf7107b17ae1aea8b299d61bf15aca0cb3fd6f1ffde8192bfe58f0822bbbc1f55bddf6b4fe9c8f2b0eac" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "533b0d50480a3ef07e7e8af8b1097759bc03ac9a1c7ed6075a052869f57f12b285613162d08ee7aab9fe54aaa984a39a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ae596697427aa250156c05ac4338e48980a7f093ea1f1fe67098b43f6539c1b20ae74338f9bf270d33663c50abe8fd00", "1ca6a52732db74ab15d2f249a3d839080f898367dfd64992cdce2708deaad523a2a236b43400424241c91a35b530fa50" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "d49a253986bbaa8ce9c3d3808313d39c3b950a478372edc009bc0566b73be7b05dad0737e16960257cc16db6ec6c620f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0088738f9981dd4d1fabb60ad83c2dd6dfc9da302209ae3e53498a883b6e39a38bead9b02709f352d3e6b6578154eab252", "009388a05c6b9f3a4028abb9950a51f5264ecd7580a423fdec9472faeeb57f92e31c46bef2a781fe5edad026009f198262" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "285090b0d6a6820bbba394efbee5c24a2281e825d2f6c55fb7a85b8251db00f75ab07cc993ceaf664f3c116baf34b021";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00f421541311c94fdd79fc298f8ab1a3adfd08029fdad439a94d4cea11f7e799bc439609f2fb7be3f349d55e484d0a0d36", "00b35330bbdbec1e75f2984483d96bf210d722c1830292ffc35a2f6a21a4b50519f565f024bbccc97228a2f8ad8fadc0d5" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "b39af4a81ee4ae79064ed80f27e1432e84845f15ece399f2a43d2505a0a8c72c5731f4fd967420b1000e3f75502ed7b7";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "399be4cfc439f94f2421cbd34c2cd90bae53eb60ddfafca52f7275d165d14fa659b636713b5d4b39e62fd48bae141d0e", "1b23e3b4f0c202ed7b59db78a35c12ac698c603eab144fd09ac2ed8f4495f607e4d2c87a23ce2ec33e410ca47ecc2555" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "af4a81ee4ae79064ed80f27e1432e84845f15ece399f2cbf28df829ccd30f5ef62ec23957b837d73fe4e156edccd4465";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1578bbff72137c4bca33d7385a892be94cb059f9091ddfe890345f712a9fba5fc77084cec11084ed048491604a07f66c", "76bbaa872f0710d82a08d9dddd833c7be7c7e8e265f49145157eb4e8e8280076a37ee5873271db510034da19da24415b" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "5e9503dc95cf20c9db01e4fc2865d0908be2bd9c733e597e8a5bb7b7a62abdff6dbe3978ae56536d0fb01172ecd55f57";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "33ba451c85e729058f83041077a4695eb47df93e718b09a4618c753ac803cd75c1a91290c2ff5a635389d07149571dab", "1fc7d8a71776851ff244ff632fe6f92e1652e5284893c4244fe775d8efc589d823dd03f3919027f004537bd8ee09f3a3" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "1ee4ae79064ed80f27e1432e84845f15ece399f2cbf4fa31a3ae8edab84dc3330a39f70938e3912bd59753de5aed3088";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "040771e3390216fed2c6208bdf5bfea83ab1915b166e626569f12efd410a39b7e7c76f70f0012843a26debf4ccc33dda", "00e5bc5f7e62d054eac31cd022afdb71b7c638f24c30cbad0ef35ed2fc9917f356e9c3f04391b21d1035274b81537fcbf3" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "bb51cd3ba8eb201f53ddb4e34e08c0ff7dff9378106784d798d5a3440bd6dc34be3a0eaef8776619a0c97fefb15720b3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0098d3f16e1c510a933e648e78d01588319f002e9475df8942a2a89db0666bb7c88b32bb248140e44ac4ab28111b2b7923", "0099a926f4a66fbe28ff65c09f8306893aec094b89d0fe529e3577c5ecf30a7944caaf530f4575eb113fcf4c200d2dd4bd" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "e707e267ea635384a6da09823149f5cb7acbb29e910d2630c5fb5afbc42aa8436349b214a3b8fb9481ec999e005091f8";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d1fd602feef80be9e55a19d1a9799c72a899110c6ac21fb3c21357069809d591a8775b64d1867a8cfff124f6a5e3a4f5", "00f9548064f01b9af8868705493a37a037193b48f53b7c7973023f53e6ceff6830ca2f7a14ef51536d453af43b3058d8a9" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "acc4f2afb7f5c10f818175074ef688a643fc5365e38129f86d5e2517feb81b2cd2b8dc4f7821bfd032edc4c0234085d9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0082f37604f66664c2883dba6d98397c281045cbf59f1d16dddb1381126a246553a8b4d2aaea48ad9185a1645f65567d31", "008a4d7b19f1d2e4434c9a8ecad396304abc82221bbab0679935071c72fd975e7b021c04b1d16ea36fc2d051ef5a8e117c" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "83276c0793f0a19742422f8af671ccf965fa7d18d541bef4c05b90e303f891d39008439e0fda4bfad5ee9a6ace7e340c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00f052dfc27bf8a6d36f3739f239b981f5b53fe08d999ec683b01e43e7596156206ba08b8b9f59229e2fbdce05f1e40f99", "0090f0fdfb7029f9b3e8c6144dad0339208b7cdcb3820a554259db9d27afdd18f4a750296c59bad6b62df076f90d53be0d" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "942848586b534105ddd1ca77df72e1251140f412e97b62afbf85d4822309176b5965453dee3fab709e14156b3dfcecca";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00f877bd6e2a9273e322a3298ea3add13d1104b32172283669ca6688f0cb591524a7f15dd41496681eda98939aae729fed", "00e85ca37c81ef19e3dc9ab16908a3720d86875a51a6a6d932e37492a6ec7a344eabc482377f14891fbd1da7faeffa1178" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffed2119d5fc12649fc808af3b6d9037d3a44eb32399970dd0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "14249bbcfeeceab06c75654d361c0df8d56b320ea3bc1d4627ec0a2f4b8fa3577445694664f569a91f480741381e494a", "28479f2186d715a56788f67073056aa0cb0b6a7f7893e77b9a6976ef6663d80226896d7f43bb502e1b4d49558a27dd8b" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "79b95c013b0472de04d8faeec3b779c39fe729ea84fb554cd091c7178c2f054eabbc62c3e1cfbac2c2e69d7aa45d9072";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "50a438c98ee94025ce13e27d36b8280d4843585836eb47011a070cd77729245684a0db31fde980620349c796832b2c6c", "00bdb72dba9f3f9cc878559f50b6bd1290f10a6bccbc1eeef7708b1b72059022987979e35221c51259f337c7288a2f86bc" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "bfd40d0caa4d9d42381f3d72a25683f52b03a1ed96fb72d03f08dcb9a8bc8f23c1a459deab03bcd39396c0d1e9053c81";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4d3fc5dcfaf741113cda3ce2f8dff4c912143e4d36314c361d7ed5656b68448bcca114ba9e8124281234660b7726ddcd", "680ddfef7ea07bfbcede10803d38d7211631ca11466078819eb66e11921ab7ffa3c4560c732e77595fd408e917dd9afc" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "4c7d219db9af94ce7fffffffffffffffffffffffffffffffef15cf1058c8d8ba1e634c4122db95ec1facd4bb13ebf09a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "63d65cdfeb1f1a42000f43bd1ddd130537a7b6f635e8d2bd81a97da168221183da433ca78429fd2b33c5f94895a9c13a", "00a9d1d5ea328725653a5a9d00f85a5516236f3b1428a8629287d3b0487a2e82dd57f93bb2aa3d9783dc74131e13756034" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "d219db9af94ce7ffffffffffffffffffffffffffffffffffd189bdb6d9ef7be8504ca374756ea5b8f15e44067d209b9b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d22c9c348b9745711f57debac3a07df90a527c06bd02a8454f41437d54224e071698f03fdc64b1d652414edc3f2239c4", "009ae9812a4b92f099d6659a659691768d57e530ed3c91d5455781605850997a58221f22a2451c3932470606c23f3ab1b8" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a433b735f299cfffffffffffffffffffffffffffffffffffdbb02debbfa7c9f1487f3936a22ca3f6f5d06ea22d7c0dc3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "31f05c0c29e9da49aa2fbbedee770c68d10f85e7f77e72ac3cfa9c8623a2bb42eeb2f24ac8f2aef7ab0c4b4782314003", "5bb32fc1ec04bbff5eab96e070c938ba1b53fe63970f649ae02e2a4ada420a249b6f7c525e2c4b9b0d5562ae26f2278c" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "b9af94ce7fffffffffffffffffffffffffffffffffffffffd6efeefc876c9f23217b443c80637ef939e911219f96c179";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00bc26eec95e26c980bc0334264cbcfc26b897c3571c96ce9ab2a67b49bb0f26a6272fdc27806d7a4c572ae0f78149f1f3", "00c8af5f41b99d2066018165513fb3b55e4255dcd0659647ed55e1e2602cae4efbd6eae1dfe2ff63e2c748d4acc7430139" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a276276276276276276276276276276276276276276276273d7228d4f84b769be0fd57b97e4c1ebcae9a5f635e80e9df";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6fa0964dd054250af176891c0c822b013b70f059c347172cafc6b36cd16cf3b0f9d19f2598bd0d580ac16c46acb167d4", "375bef701c002dcc040fd54824b14cc2df0154eb20e74464e1fe7b833426dd7d636bf2d79603fdde5ddaab23ab0cf426" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "73333333333333333333333333333333333333333333333316e4d9f42d4eca22df403a0c578b86f0a9a93fe89995c7ed";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00baa4e712ee0786a5ab0e5a5dafdcdcf87b38830ab2ec86faedda9fdf65332f6a9688269412f050356530d4664a7fb8cd", "00ecc46a901b016e6bb8a336ad9aa6f19abf9ada69705d1c905beafb95a44f52af43de4bf80c050cf996b7796dfcee8e1b" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffda4233abf824c93f90115e76db206fa7489d6647332e1ba3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0081e78a52ae0695583f7a601ab9b6fbfaf434f2befa1f8c833d59deb627a927c2f42d48eb617fe042f584e105c23c2317", "00cf22d565f5f3b425ef7937df629b6864dac71264b288c1a987210f523071319ce3f64411910ac23765c4266e615112bc" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "3fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294bb";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "41fa8765b19d3108031e28c9a781a385c9c10b2bfd42e6437e5c4bd711cf2a031750847d17a82f9376a30ae182a6d6e7", "1c20af96324147d4155a4d0c867ca8e36eba204fbed2087e0fcbdc8baabe07bb3123f9f7259e771cd9f1ad17d1a23787" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "dfea06865526cea11c0f9eb9512b41fa9581d0f6cb7db9680336151dce79de818cdf33c879da322740416d1e5ae532fa";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e585a067d6dff37ae7f17f81583119b61291597345f107acffe237a08f4886d4fdf94fe63182e6143c99be25a7b7d86b", "572c1e06dd2c7b94b873f0578fcb2b99d60e246e51245d0804edd44b32f0f000c8f8f88f1d4a65fea51dbbb4ab1e2823" );
            {
                // point duplication during verification
                auto m = "313233343030"_hex;
                bn_t sig_r = "b37699e0d518a4d370dbdaaaea3788850fa03f8186d1f78fdfbae6540aa670b31c8ada0fff3e737bd69520560fe0ce60";
                bn_t sig_s = "64adb4d51a93f96bed4665de2d4e1169cc95819ec6e9333edfd5c07ca134ceef7c95957b719ae349fc439eaa49fbbe34";
                auto r = true; // result = valid - flags: ['PointDuplication']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e585a067d6dff37ae7f17f81583119b61291597345f107acffe237a08f4886d4fdf94fe63182e6143c99be25a7b7d86b", "00a8d3e1f922d3846b478c0fa87034d46629f1db91aedba2f7fb122bb4cd0f0ffe3707076fe2b59a015ae2444c54e1d7dc" );
            {
                // duplication bug
                auto m = "313233343030"_hex;
                bn_t sig_r = "b37699e0d518a4d370dbdaaaea3788850fa03f8186d1f78fdfbae6540aa670b31c8ada0fff3e737bd69520560fe0ce60";
                bn_t sig_s = "64adb4d51a93f96bed4665de2d4e1169cc95819ec6e9333edfd5c07ca134ceef7c95957b719ae349fc439eaa49fbbe34";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b4d78cccbced8065c0ebdc330b4670ec99309273e442b9be341196c1043e4441fc57b914085595bfc755c64fc409f0ba", "01fee31cbbbaed5c1323f09c87df9b0712c12e99733fa23ef91b4e6ca666b09dd7540ebf1068a15155bc069e3d595c8c" );
            {
                // point with x-coordinate 0
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6e3c68be53aade81ef89e096d841e2845a23331e7ec8a6a839d58d07fa016c0973ed75de4f99177bfdc74db566e9d15a", "4972ea08e577ce1f61c13a6ca1bad1deef2982ee01a2826f002b769f2c46098d3baff068a405d09ca3840d2fafe4e46e" );
            {
                // point with x-coordinate 0
                auto m = "313233343030"_hex;
                bn_t sig_r = "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                bn_t sig_s = "0033333333333333333333333333333333333333333333333327e0a919fda4a2c644d202bd41bcee4bc8fc05155c276eb0";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b101cdb3eba20e112adbb4bbd2cb479a69e590a44ea902631832abfab8af2c3041b3df7f1665b2c6eb533f546217100a", "1a61aa9951578ad4f00ae17339a8a6f1359bbd0ac355678ed4df21338f08763c1d3702ec132b634c7bcc0118efb1d0dd" );
            {
                // comparison with point at infinity
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "33333333333333333333333333333333333333333333333327e0a919fda4a2c644d202bd41bcee4bc8fc05155c276eb0";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6761044a040a4979db269b4a377e42f11b4be0ce24611f677674dcf770f5887ca4db565303283809e6d65f7fc6bc2736", "05c7daa403fca53549f75ff3372909642d02b7fdcac1e68242814d6e925ab01a80836cfbb35581960079e2fb44c0d186" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6922c591502f01046fee5617bf16496f58398822e69afa8335308f36c09a8ed437209fefcffbbdf0a4876b35a3c7ab26", "55854db825b94b3f27e5f892d3bbb6c7240ec922894dd3598e91fcc6134a2b8fd154e1790466906206f0f623416e63a1" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00892dac0e700fc29d1802d9a449a6f56b2172cb1b7d881013cd3b31c0edb052f2d340c8995a4477bcb9225fec15667233", "00cc6c34ae17445444516fd8fd22ee83f79eb0771ebff6677ac5d4e089f87a1c72df957acb24492adcd7c3816b8e0c75b1" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "6666666666666666666666666666666666666666666666664fc15233fb49458c89a4057a8379dc9791f80a2ab84edd61";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01634117e6478ce0568b0a2469237bbac6ff096acb7e514072bf77123cb51ba0cc3e8d69284d534d8e6d1e876cecf222", "31e5ef04dc96762ce7d5ef3348ad1e241ac797ae3b630ea249afc5139af49b8ef68b32f812d6b514210363d498efc28c" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "99999999999999999999999999999999999999999999999977a1fb4df8ede852ce760837c536cae35af40f4014764c12";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "675bdc79d8243887fe1b305d12ac10d2e9c0bde070a6e3394cd5f6adfbceda75498b0e7a794c7212f42be93f61674456", "3e96d1bf6f95cdbefa774911ba06463d8a90a0c9d73c9699b061d779dc52496e8ee9b9ae9c5d4d90e89cd1157d811895" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6aae76701acc1950894a89e068772d8b281eef136f8a8fef5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0fd1aab89f47b565b8160dfcc433b6408adeb1473c036b26b7ddec714fb4d0e7dd756c88469e86e218813ead8e8e7676", "00f1cc955c4139e0071c0079ec1d77164e0569bdf453837e8b33c98535a0e7c9c61ef24762067bb46b6116ea7909a69b23" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "0eb10e5ab95f2f26a40700b1300fb8c3e754d5c453d9384ecce1daa38135a48a0a96c24efc2a76d00bde1d7aeedf7f6a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "34d74ec088bab6c6323968d1f468993812f690d6edca5b97604d718e12b8cdfdd96d42e57d33afe312f0ee3c3d0a13f7", "0086f4922bb2c13bdf7752a3ecb69393e997bd65461c46867ebeef6296b23f2c56df63acfde648f3f5002dbc239ffd1582" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4376c9893e9277296c766a83abbe36b34da7a631f8cbfd32a1888de0dd1455a21a153ea2d61cfa5071fc6be12a658f6b", "290ba1a8ee8c78b5dd58f9ffcacb22955682eea02429c3fa8cdcb649fa4d007c8693e3f8f3c0a5f3c4de7a51beaa9809" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "10878fc4807f6732a23c883e838e38c787f7088f94c1824b84673e8b9eab16de1544ae4bf2c6fe3fe4fb343b7487e2b4", "3036ff439533d22f951dae966584bafb23b217dcad2f8f4e0e6999c0c4d0f076634be805f676fd2a59c27f9fe7c5d95b" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "6666666666666666666666666666666666666666666666664fc15233fb49458c89a4057a8379dc9791f80a2ab84edd61";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "036b253e3b4ac88bb8585a2b32b978766a931e5ad0d0e653a2e34b44d6ddcc0d386e20c4def2d8bb3f8da128c1eac69f", "009c8e3b5ff5dde2205af359b3974d52758d7abae812b8b275e1452c4e59cb62e9b6771d347dbd1dea761c70291cc5e0a6" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "99999999999999999999999999999999999999999999999977a1fb4df8ede852ce760837c536cae35af40f4014764c12";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2783c1be922fce155864ecb41d0a316e193a55843e80192f1fe556772f3debd04b9fc93c27bc6f353938886a40441994", "1a352cec336946424fa3c208ea7105f5549edde8688abd305344bf4f66dda7eabcda6f8557c9af88109804d702e9670b" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6aae76701acc1950894a89e068772d8b281eef136f8a8fef5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00fa92538cdc740368caf16480ff1304cebbbe59a46a7a84603726b9592d105be069df1c61b5974f27e7552f797de97cdb", "620e03a46da862e4b089bafbb80df8f055c8f47991b3a3ddb2b089aedb2f15841a6a5b5e14c1dc36b3c155c4f74d3409" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "0eb10e5ab95f2f26a40700b1300fb8c3e754d5c453d9384ecce1daa38135a48a0a96c24efc2a76d00bde1d7aeedf7f6a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "f9b127f0d81ebcd17b7ba0ea131c660d340b05ce557c82160e0f793de07d38179023942871acb7002dfafdfffc8deace";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "064ed80f27e1432e84845f15ece399f2cbf4fa31aa837de9b953d44413b9f5c7c7f67989d703f07abef11b6ad0373ea5";
                sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", "00c9e821b569d9d390a26167406d6d23d6070be242d765eb831625ceec4a0f473ef59f4e30e2817e6285bce2846f15f1a0" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "f9b127f0d81ebcd17b7ba0ea131c660d340b05ce557c82160e0f793de07d38179023942871acb7002dfafdfffc8deace";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "064ed80f27e1432e84845f15ece399f2cbf4fa31aa837de9b953d44413b9f5c7c7f67989d703f07abef11b6ad0373ea5";
                sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "29bdb76d5fa741bfd70233cb3a66cc7d44beb3b0663d92a8136650478bcefb61ef182e155a54345a5e8e5e88f064e5bc", "009a525ab7f764dad3dae1468c2b419f3b62b9ba917d5e8c4fb1ec47404a3fc76474b2713081be9db4c00e043ada9fc4a3" );
            {
                // pseudorandom signature
                auto m = ""_hex;
                bn_t sig_r = "32401249714e9091f05a5e109d5c1216fdc05e98614261aa0dbd9e9cd4415dee29238afbd3b103c1e40ee5c9144aee0f";
                bn_t sig_s = "4326756fb2c4fd726360dd6479b5849478c7a9d054a833a58c1631c33b63c3441336ddf2c7fe0ed129aae6d4ddfeb753";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "4d7367"_hex;
                sig_r = "d7143a836608b25599a7f28dec6635494c2992ad1e2bbeecb7ef601a9c01746e710ce0d9c48accb38a79ede5b9638f34";
                sig_s = "80f9e165e8c61035bf8aa7b5533960e46dd0e211c904a064edb6de41f797c0eae4e327612ee3f816f4157272bb4fabc9";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "313233343030"_hex;
                sig_r = "234503fcca578121986d96be07fbc8da5d894ed8588c6dbcdbe974b4b813b21c52d20a8928f2e2fdac14705b0705498c";
                sig_s = "cd7b9b766b97b53d1a80fc0b760af16a11bf4a59c7c367c6c7275dfb6e18a88091eed3734bf5cf41b3dc6fecd6d3baaf";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "0000000000000000000000000000000000000000"_hex;
                sig_r = "5cad9ae1565f2588f86d821c2cc1b4d0fdf874331326568f5b0e130e4e0c0ec497f8f5f564212bd2a26ecb782cf0a18d";
                sig_s = "bf2e9d0980fbb00696673e7fbb03e1f854b9d7596b759a17bf6e6e67a95ea6c1664f82dc449ae5ea779abd99c78e6840";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ffffffffaa63f1a239ac70197c6ebfcea5756dc012123f82c51fa874d66028be00e976a1080606737cc75c40bdfe4aac", "00acbd85389088a62a6398384c22b52d492f23f46e4a27a4724ad55551da5c483438095a247cb0c3378f1f52c3425ff9f1" );
            {
                // x-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "07648b6660d01ba2520a09d298adf3b1a02c32744bd2877208f5a4162f6c984373139d800a4cdc1ffea15bce4871a0ed";
                bn_t sig_s = "99fd367012cb9e02cde2749455e0d495c52818f3c14f6e6aad105b0925e2a7290ac4a06d9fadf4b15b578556fe332a5f";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "a049dcd96c72e4f36144a51bba30417b451a305dd01c9e30a5e04df94342617dc383f17727708e3277cd7246ca440741";
                sig_s = "3970e264d85b228bf9e9b9c4947c5dd041ea8b5bde30b93aa59fedf2c428d3e2540a54e0530688acccb83ac7b29b79a2";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "441800ea9377c27865be000ad008eb3d7502bdd105824b26d15cf3d06452969a9d0607a915a8fe989215fc4d61af6e05";
                sig_s = "dce29faa5137f75ad77e03918c8ee6747cc7a39b0a69f8b915654cac4cf4bfd9c87cc46ae1631b5c6baebd4fc08ff8fd";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d1827fc6f6f12f21992c5a409a0653b121d2ef02b2b0ab01a9161ce956280740b1e356b255701b0a6ddc9ec2ca8a9422", "00c6ed5d2ced8d8ab7560fa5bb88c738e74541883d8a2b1c0e2ba7e36d030fc4d9bfb8b22f24db897ebac49dd400000000" );
            {
                // y-coordinate of the public key has many trailing 0's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "3244768016457c463b74f2097f216d9670b191f76281c74bc6a1a1971d19f209bf4696468f5eb75d6326a0a43c0a6529";
                bn_t sig_s = "501e0ad985ed9f95697bd17fdbe3f9ca92e0f76426d3664e6896648d9c750bf588d0ce7d011c1a1e8d6c2e082422dc93";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "5e1af40f2480e3d97c4ae4bfd34a9f45269241356f3a46becd86a4a7c9716d73ca5aebdb3db1a7765650666683bc856b";
                sig_s = "7e7c4b473a2baaa4953785be8aa2a10006f6d36b400ab981864d69cecec046718d0404b9647454b159aa5a92d76d7955";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "6688e36a26f15bdc1c3f91367f8a7667f7bb3e30a335d6f0900e9534eb88b260cb29344c723fedfbe7ac9c5a33f4bf0d";
                sig_s = "aa35fddf0fdc9017860b378f801cd806f3e2d754cd2fd94eb7bb36a46ce828cef87e9ebbf447068e630b87fee385ad8f";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1099bb45100f55f5a85cca3de2b3bd5e250f4f6fad6631a3156c2e52a33d7d615dd279f79f8b4baff7c713ac00000000", "00e6c9b736a8929f2ed7be0c753a54cbb48b8469e0411eaf93a4a82459ba0b681bba8f5fb383b4906d4901a3303e2f1557" );
            {
                // x-coordinate of the public key has many trailing 0's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "d4a8f3b0b4d3a5769e3a0bbc644b35f1d509355ed1fe401e170f667b661f693b32598e8c143a817a958982845042bb48";
                bn_t sig_s = "04cc07578bbd1981dbf6e8a97a354c98d41b8b6f6e8a2c2b1763c7c2a29d79e24f8476075c9aed9aec6c64dff50461ae";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "c286d1928e9c79fdd3bebdf22a1dbd37c8105e8ecf41e9e3777fe341b6b8d5a89b9d986827d6d1dbb381cd8239484a22";
                sig_s = "201119ae305b9360aa9b5e5d1567e0674c09e4f025556ebf81b987466b0f421b8d31f72bbe95f3ce2aa9874a84edfd40";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "d9c678550167f10c511e62acb4bd0a3f7f336bc090c94e6c6b02622439c348a2159c5f41f9b5aa4b470590d40dcd7cc2";
                sig_s = "1fd5eaee295abb4081cb626745f4ad279ceb44604062830b58e6c0465c562d41f02ba588fc0db1ebbe339cdc008d7a1b";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2b089edd754169010145f263f334fc167cc19dae8225970ae19cc8cb7ec73593d6a465c370f5478b0e539d69", "00d1951d597b56a67345acb25809581f07cd0eb78d9538a3f8a65f300e68a1eb78507df76de650e8f8ee63a5f0c5687c98" );
            {
                // x-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "20fee7c71b6cb0d1da3641ec6622c055a3b16a1f596c64b34da1b2d0b868b66a8f0a0d0db983b3dc7e53bb7295da8197";
                bn_t sig_s = "8141a931d3579aec1cac9887d2fff9c6f12d47a27e4aab8cf262a9d14a715bca0b2057cbc3f18b6fd3d1df76f7410f16";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "913eecc559b3cf7108a65d6cc3076bfdf36c6f94dcc6693d06690470f34a2e81564241e1de5f5f51421de30af467f10f";
                sig_s = "649bd3717244e8ef3c6b0eda983f84dca5ea86d1bec15386b9c473ec43a8cd0ba558eee819f791d9ff9272b9afd59551";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "23855c46403a97b76cbb316ec3fe7e2c422b818387604bda8c3d91121b4f20179d9107c5f92dedc8b620d7db87fccccd";
                sig_s = "50f57343ab148e50662320c4161e44543c35bc992011ea5b1680b94382cf224ea0ec5da511e102f566cb67201f30a2ee";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00fb01baad5f0b8f79b9cd104d12aab9310146add7d6b4c022d87ae6711178b94d618ca7b3af13854b1c588879e877b336", "208b3f5ad3b3937acc9d606cc5ececab4a701f75ed42957ea4d7858d33f5c26c6ae20a9cccda56996700d6b4" );
            {
                // y-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "d200958d491fcebde667cd736c9dba0961c70db2ecaf573c31dd7fa41ecca32b40b5896f9a0ddf272110e3d21e84593a";
                bn_t sig_s = "c2ecf73943b9adce596bac14fce62495ae93825c5ff6f61c247d1d8afcba52082fc96f63a26e55bccfc3779f88cfd799";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "6ac17d71260c79f81a7566124738cb3ee5d0aa690e73a98ae9e766f1336691e500cad51ba1302366c09cc06b8f7049e0";
                sig_s = "32ca965d6d7012ec187c7cab9544334d66c2a7658ddefa67e4ad40429815518ecc87b1492ddd57333bd2300b4660a835";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "e19a4646f0ed8a271fe86ba533f8be4fd81bbf4674716f668efa89a40cac51eec2a6cfbd92327d25efe91ca4ff712bc5";
                sig_s = "4a86b2e8e12378e633dec2691e3b1eed4e932cc48b28e45fa3d464cc0e948c02cc9decf2bb43b25937fcf37e9ad86ef0";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00fb01baad5f0b8f79b9cd104d12aab9310146add7d6b4c022d87ae6711178b94d618ca7b3af13854b1c588879e877b336", "00ffffffffdf74c0a52c4c6c8533629f933a131354b58fe08a12bd6a815b287a71cc0a3d92951df5633325a96798ff294b" );
            {
                // y-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "15aac6c0f435cb662d110db5cf686caee53c64fe2d6d600a83ebe505a0e6fc62dc5705160477c47528c8c903fa865b5d";
                bn_t sig_s = "7f94ddc01a603f9bec5d10c9f2c89fb23b3ffab6b2b68d0f04336d499085e32d22bf3ab67a49a74c743f72473172b59f";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "90b95a7d194b73498fba5afc95c1aea9be073162a9edc57c4d12f459f0a1730baf2f87d7d6624aea7b931ec53370fe47";
                sig_s = "cbc1ef470e666010604c609384b872db7fa7b8a5a9f20fdefd656be2fcc75db53948102f7ab203ea1860a6a32af246a1";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "dd4391ce7557cbd005e3d5d727cd264399dcc3c6501e4547505b6d57b40bbf0a7fac794dcc8d4233159dd0aa40d4e0b9";
                sig_s = "a77fa1374fd60aa91600912200fc83c6aa447f8171ecea72ae322df32dccd68951dc5caf6c50380e400e45bf5c0e626b";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }
        } // End of Google's Wycheproof tests ecdsa_secp384r1_sha384_p1363_test

        // Test vectors from Google's Wycheproof RSA signature verification tests.
        // Generated from: 'ecdsa_secp384r1_sha3_384_test.json'
        // URL: 'https://raw.githubusercontent.com/google/wycheproof/d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d/testvectors_v1/ecdsa_secp384r1_sha3_384_test.json'
        // Note:
        //     Test vectors with flag(s) 'BER', 'BerEncodedSignature', 'SignatureSize', 'MissingZero', 'InvalidEncoding' were not included.
        //     All test(s) with BER/DER decoding related errors were not included because they're not part of this test scope.
        //
        // Algorithm: ECDSA
        // GeneratorVersion: 0.9rc5
        // Header: Test vectors of type EcdsaVerify are meant for the verification of ASN encoded ECDSA signatures.
        // Notes:   ArithmeticError - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA have arithmetic errors that occur when intermediate results have extreme values. This test vector has been constructed to test such occurences.', 'cves': ['CVE-2017-18146']}
        //   BerEncodedSignature - {'bugType': 'BER_ENCODING', 'description': 'ECDSA signatures are usually DER encoded. This signature contains valid values for r and s, but it uses alternative BER encoding.', 'effect': 'Accepting alternative BER encodings may be benign in some cases, or be an issue if protocol requires signature malleability.', 'cves': ['CVE-2020-14966', 'CVE-2020-13822', 'CVE-2019-14859', 'CVE-2016-1000342']}
        //   EdgeCasePublicKey - {'bugType': 'EDGE_CASE', 'description': 'The test vector uses a special case public key. '}
        //   EdgeCaseShamirMultiplication - {'bugType': 'EDGE_CASE', 'description': "Shamir proposed a fast method for computing the sum of two scalar multiplications efficiently. This test vector has been constructed so that an intermediate result is the point at infinity if Shamir's method is used."}
        //   IntegerOverflow - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified, so that the original value is restored if the implementation ignores the most significant bits.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   InvalidEncoding - {'bugType': 'CAN_OF_WORMS', 'description': 'ECDSA signatures are encoded using ASN.1. This test vector contains an incorrectly encoded signature. The test vector itself was generated from a valid signature by modifying its encoding.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   InvalidSignature - {'bugType': 'AUTH_BYPASS', 'description': 'The signature contains special case values such as r=0 and s=0. Buggy implementations may accept such values, if the implementation does not check boundaries and computes s^(-1) == 0.', 'effect': 'Accepting such signatures can have the effect that an adversary can forge signatures without even knowning the message to sign.', 'cves': ['CVE-2022-21449', 'CVE-2021-43572', 'CVE-2022-24884']}
        //   InvalidTypesInSignature - {'bugType': 'AUTH_BYPASS', 'description': 'The signature contains invalid types. Dynamic typed languages sometime coerce such values of different types into integers. If an implementation is careless and has additional bugs, such as not checking integer boundaries then it may be possible that such signatures are accepted.', 'effect': 'Accepting such signatures can have the effect that an adversary can forge signatures without even knowning the message to sign.', 'cves': ['CVE-2022-21449']}
        //   ModifiedInteger - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. The goal is to check for arithmetic errors.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   ModifiedSignature - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an invalid signature that was generated from a valid signature by modifying it.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   ModularInverse - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where computing the modular inverse of s hits an edge case.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['CVE-2019-0865']}
        //   PointDuplication - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA do not handle duplication and points at infinity correctly. This is a test vector that has been specially crafted to check for such an omission.', 'cves': ['2020-12607', 'CVE-2015-2730']}
        //   RangeCheck - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. By adding or subtracting the order of the group (or other values) the test vector checks whether signature verification verifies the range of r and s.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   SmallRandS - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where both r and s are small integers. Some libraries cannot verify such signatures.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['2020-13895']}
        //   SpecialCaseHash - {'bugType': 'EDGE_CASE', 'description': 'The test vector contains a signature where the hash of the message is a special case, e.g., contains a long run of 0 or 1 bits.'}
        //   ValidSignature - {'bugType': 'BASIC', 'description': 'The test vector contains a valid signature that was generated pseudorandomly. Such signatures should not fail to verify unless some of the parameters (e.g. curve or hash function) are not supported.'}
        {
            auto pubkey = curve.make_point( "29bdb76d5fa741bfd70233cb3a66cc7d44beb3b0663d92a8136650478bcefb61ef182e155a54345a5e8e5e88f064e5bc", "009a525ab7f764dad3dae1468c2b419f3b62b9ba917d5e8c4fb1ec47404a3fc76474b2713081be9db4c00e043ada9fc4a3" );
            {
                // pseudorandom signature
                auto m = ""_hex;
                bn_t sig_r = "9da5c054a9eddabf4753559edd5a862cdf57adc0c2717a6949a43d80cfccd02b14ec06113ccf08081be43552391cfb16";
                bn_t sig_s = "88bb307e9a04f923c70013db3ca716d21b313dde0cd6849435bf3b192d5266589a00b34e9c4c626b1055e7a38ef10853";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "4d7367"_hex;
                sig_r = "22b0ee0e8ce866c48a4400dd8522dd91bd7a13cc8a55f2814123564d039b1d1e3a7df010688dab94878f88a1e34a905e";
                sig_s = "f7668925262da6aad96712f817a9397b79f0fb893aedcd7221f454a60a18abb3b165aae979f29d22cfab18fb61945f87";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "313233343030"_hex;
                sig_r = "3db6c4d7d482fdb0a13470845f5ad2438198776c2a5954b233e24230889f3023ff64e4cbc793c4e3e94318b4e65f8cdb";
                sig_s = "03c22aa010ea7247ae7cc6c7d0f6af76f76ef91ce33a028de49979bdc2cc17d7df4c19c0e4c61c49275bc408697e7846";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "0000000000000000000000000000000000000000"_hex;
                sig_r = "7a36e2c2ebf9bc0165ff75f5906a4806c2a668cb48477f7f105169c9b5a756abcc06b05b4d5ac42ecfd12cdd0f8fc65e";
                sig_s = "96aff9db7873cd2f6aa85c2693e1129b7896340287762854062df8104162a4572bdcbaf673af28a92314ec597f7acfe3";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2da57dda1089276a543f9ffdac0bff0d976cad71eb7280e7d9bfd9fee4bdb2f20f47ff888274389772d98cc5752138aa", "4b6d054d69dcf3e25ec49df870715e34883b1836197d76f8ad962e78f6571bbc7407b0d6091f9e4d88f014274406174f" );
            {
                // signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "34a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c";
                bn_t sig_s = "c0bb0ee1bffc6c7b74609ec20c460ec47f4d068f33d601870778e5e474860d77834d744db219e6abae9c32912907efd2";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // valid
                m = "313233343030"_hex;
                sig_r = "34a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending 0's to r
                m = "313233343030"_hex;
                sig_r = "34a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c0000";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending null value to r
                m = "313233343030"_hex;
                sig_r = "34a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c0500";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying first byte of r
                m = "313233343030"_hex;
                sig_r = "36a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying last byte of r
                m = "313233343030"_hex;
                sig_r = "34a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db4cc";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated r
                m = "313233343030"_hex;
                sig_r = "34a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db4";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated r
                m = "313233343030"_hex;
                sig_r = "a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // leading ff in r
                m = "313233343030"_hex;
                sig_r = "ff34a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replacing r with zero
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending 0's to s
                m = "313233343030"_hex;
                sig_r = "34a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a10000";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending null value to s
                m = "313233343030"_hex;
                sig_r = "34a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a10500";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying first byte of s
                m = "313233343030"_hex;
                sig_r = "34a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c";
                sig_s = "3d44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying last byte of s
                m = "313233343030"_hex;
                sig_r = "34a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd3921";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated s
                m = "313233343030"_hex;
                sig_r = "34a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated s
                m = "313233343030"_hex;
                sig_r = "34a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c";
                sig_s = "44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // leading ff in s
                m = "313233343030"_hex;
                sig_r = "34a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c";
                sig_s = "ff3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replacing s with zero
                m = "313233343030"_hex;
                sig_r = "34a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c";
                sig_s = "00";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + n
                m = "313233343030"_hex;
                sig_r = "0134a42eda6d8a881c6a3369fd89db629c9b61904c86019726b4f0fdd1ba4eeb869ab3182345a88754178a3e92aa12ddbf";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r - n
                m = "313233343030"_hex;
                sig_r = "ff34a42eda6d8a881c6a3369fd89db629c9b61904c86019727262a62cdd1e08fc7ea7efcbeb447385e3db20bbd10888ad9";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 256 * n
                m = "313233343030"_hex;
                sig_r = "010034a42eda6d8a881c6a3369fd89db629c9b61904c860196ee50db3243fd459cff5ca6bcb9ad9f5ac616b78ff4a277274c";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by -r
                m = "313233343030"_hex;
                sig_r = "cb5bd125927577e395cc960276249d63649e6fb379fe68d912724fb039e84258bd66f58f03082026d561dad822b24bb4";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by n - r
                m = "313233343030"_hex;
                sig_r = "cb5bd125927577e395cc960276249d63649e6fb379fe68d8d9d59d322e1f7038158103414bb8c7a1c24df442ef777527";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by -n - r
                m = "313233343030"_hex;
                sig_r = "fecb5bd125927577e395cc960276249d63649e6fb379fe68d94b0f022e45b11479654ce7dcba5778abe875c16d55ed2241";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**384
                m = "313233343030"_hex;
                sig_r = "0134a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**448
                m = "313233343030"_hex;
                sig_r = "01000000000000000034a42eda6d8a881c6a3369fd89db629c9b61904c86019726ed8db04fc617bda742990a70fcf7dfd92a9e2527dd4db44c";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + n
                m = "313233343030"_hex;
                sig_r = "013f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78874db51f73e84e472ce6a716df47684a2b3c004470826314";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s - n
                m = "313233343030"_hex;
                sig_r = "ff3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78f8871a1b8b79f2887cb28bb24de619545163cd6ed6f8102e";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 256 * n
                m = "313233343030"_hex;
                sig_r = "01003f44f11e400393848b9f613df3b9f13b80b2f970cc29fe402337e991b6deffbfeeda4bad473e3bbc2a6951a668e6aca1";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by -s
                m = "313233343030"_hex;
                sig_r = "c0bb0ee1bffc6c7b74609ec20c460ec47f4d068f33d6018740159862804edf982b33669b69693f30c1b019265c42c65f";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by -n - s
                m = "313233343030"_hex;
                sig_r = "fec0bb0ee1bffc6c7b74609ec20c460ec47f4d068f33d6018778b24ae08c17b1b8d31958e920b897b5d4c3ffbb8f7d9cec";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**384
                m = "313233343030"_hex;
                sig_r = "013f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s - 2**384
                m = "313233343030"_hex;
                sig_r = "ff3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**448
                m = "313233343030"_hex;
                sig_r = "0100000000000000003f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                sig_s = "3f44f11e400393848b9f613df3b9f13b80b2f970cc29fe78bfea679d7fb12067d4cc99649696c0cf3e4fe6d9a3bd39a1";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=0
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=-1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=0
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=-1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=0
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=-1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=p
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=0
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=-1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=0
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=0
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=-1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n - 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Edge case for Shamir multiplication
                m = "3337333130"_hex;
                sig_r = "ac042e13ab83394692019170707bc21dd3d7b8d233d11b651757085bdd5767eabbb85322984f14437335de0cdf565684";
                sig_s = "c1045ed26ae9e8aabf5307db317f60e8c2842f67df81da26633d831ae5e061a5ef850d7d49f085d566d92cfd9f152d46";
                r = true; // result = valid - flags: ['EdgeCaseShamirMultiplication']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131353534393035383139"_hex;
                sig_r = "0c0b82be4c36d506063fc963133c14d5014d65c9eb796ee8a8387120119ccc16b57302b6ccb19a846b7762375b3c9718";
                sig_s = "285919259f684f56f89cbaa789ef13e185fd24d09dcd46ce794aedc4e5b4a3820535213abb7c4e605b02200fbeb3227c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32363831393031303832"_hex;
                sig_r = "7da99d7e8bb505cc5f12706d5eb7669336a61a726a5b376ff96d678a621f38681bc78592cd06717cb87753daf0d39b77";
                sig_s = "ca91cdb78f21950877b69db1418a3e9b5799b3464f1fa223c7ac8d6fa9f647f2a08109935ad67477c96bbf1a2a127a1d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333336353438363931"_hex;
                sig_r = "204d322af7178ac20b39a42723fb1f8329b105993e09dbdcabf3e0eaa0a08d54719e06ba704691295a56be7765b5fd74";
                sig_s = "3b526de3e47e69518d4fbc0833a5785074c3f4eef27b9f0fc48481514931e43235b81e51d2b577b1739964ef25d8faad";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33363235303538313232"_hex;
                sig_r = "9d4adb54f52349cc73322ffc946bf44a1a1bb954bd4b58f912be068ce05272a12479bbb0f778a9faf8f9f2e9324bd5e9";
                sig_s = "1eee2f98406c30728da3b2b533c387108cc67fc24abdb6bdab686f207f0a75cc9c3b4d4ea9427d881c47d419ed7a1b95";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323739333237313834"_hex;
                sig_r = "ae50b1aaad54efbe007f1da7d50ec00cf1100f904fd8f4940ef48f364031dc1284ab984e018105e6d368bb5a47c25022";
                sig_s = "a803fb0156a10e42d4294a764a1da9c3e0c8320bd1a83544ff46751a777bbce23985669e43ff63fcdbac34d68f42de56";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383836363432313439"_hex;
                sig_r = "bc65644acb7dcf72bbf937e781d6de7bca052adcad474e3a2b06795a18db7b89d246a485d696b2b8d07c07d2ba2e2929";
                sig_s = "af811cb9772b4b3f1eed358b722a5b28a21617aea7eb6f9371b68a8d1eb7232def267ba56a6220f66a03c3ed7cd322e1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333737393036313539"_hex;
                sig_r = "f6205c154a9cd38a1fc9a18c7bf6350699c95144268ba4ca182a5c8d50b780d468aa9beb8115f8ec489558891ecd6d65";
                sig_s = "863f41412ab418fe037fd688a9f6c509bc5535b2c6b5ad7bf9486fb0e5b02136219aca2cdd9d5d63f9140e6d1d054201";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38303833323436363234"_hex;
                sig_r = "aedf7382965359c9abff67f0fad2be6b84d760ac95da1c656989f19938b046371e101e8bab9a0ae9b9ad2bc242a98201";
                sig_s = "9175511515a01096b4d77cc505c60facfceb1841948442448e5c9f24204f817eb20d12479305e82ee5a34bd73ebb04ad";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343832353634393539"_hex;
                sig_r = "bcc696d8d3445960e00c9f76f277e5fa3267224d0187ad120f9c074597eeafcb6c7f22f51900351848855b20072afdae";
                sig_s = "935dfc4f7b48ac01116e5cf194fd2feed3cb28e72cba8485f1d94e5d20f5f4147a1ca3d6496bbe915913d21c4f5afbaf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303635303732353033"_hex;
                sig_r = "c029e49048921647659a042eb533004ea3487f22a7f2c471c43a5a2326dd03ac24386242c05698194b5c6171f08bb7cc";
                sig_s = "a92ed5f2c736e27711384a131c464f73852a7dd167b27c63020040d8de991a390ad76627d597ccfebed809f2f7f57b26";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343932313138323033"_hex;
                sig_r = "0f5e1771ba1957fe8794c23776832ea40ec4fda999186f6c365f4749f07893cb55e972658c2d3b39a7b485193ff1d719";
                sig_s = "3967983d1da9dcf0105ddc383f599539d4b32b1bb8dae1a6fe0afbc9bff1e0952a32f08d161b3979a60bb6e49b6c7d7a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353535333230313336"_hex;
                sig_r = "0939874c2f67090a900ad7399df78c6005fc4673e23b155df7471b31debd2174fea94e00180ddc1a86609eda8830b449";
                sig_s = "c9d71934a7222e415a01692c7274e5097d580dfe74175dfc0055feddfb414c1ae857051ce12c0ff25d5372751456622a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333331373032303036"_hex;
                sig_r = "c35b9eaa9a03a36ba52b7ab207ff48925a0188d288b1ed25d7de8bc203e8ef912a01891eab8f8e3a7d0a948a26d35ab1";
                sig_s = "cf04105208f10af61240da6073cc39278fdadc0578bf40bbd0b0f601ed791e041a90a09d7c423a83f6cd047d745c4f24";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373531313832333938"_hex;
                sig_r = "6c1fffcc270c9bf108289b42514e57e3f29ea0f1b3fbfc10ea283b3e6d2a4438d591fb7274c9ffee15009cd9e340f106";
                sig_s = "de38043b47c7d5ab21d8ec5a35758f1a69ee59ea6df525884a04210172e7421f2a49f5921a4eac40b278f6e7c49474f4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3737303439353436343831"_hex;
                sig_r = "ecc637f3d32bc9a1ec20f025af72eb03df49f27901fef6b58d226b6eaa9faa6374f87c2aaaecd69946f3777fb9d4581e";
                sig_s = "48f6a06b296a17d84dd26ffded0c5dccf177e6df9a7710b0406fedfd269b2c220f11c1e02cea42c18ccac768c64ba7eb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34323539303733303333"_hex;
                sig_r = "7dcf9ded94532d50e9a2ac971642da0de95a1ca95500621174113c1d554f21bb2d175b5beacdd73443043c6cc8eaf105";
                sig_s = "d4da518de6b8c05c640a3e7a1540482d935c4dfdca7544daf94ac8135804127b93665e1191b66bdb0089c49802c33fb1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343139373133353036"_hex;
                sig_r = "8209054bb408eed6ab65f4bb76223d509ea24d02cbbc5273145bcb40189052540e565fbf50474f83db3da054a793c863";
                sig_s = "b8169b12568ffa03c0e37d4a19911e9f4af7cd256343a36e41cd7b41395524235e86d55c647f288fe5cef2b5401e4413";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3231393238333534363838"_hex;
                sig_r = "9fe969770d630bb938ca2282536f71f3dc461071186216d940eca10fc53c4e7ef067bca237bd6a82eafef0fb8d38050e";
                sig_s = "b23a042178fdea5da86229c08a51227f23e31b1e2345defa12ed7041bec31f87837ba4764721823ea9f1e652d536c5ed";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363235393934383739"_hex;
                sig_r = "459be510bca760f75aca10e41efb7ff64b78fb9711e72f224373b9af14f2c042b68b15bb189b3d7ccaed9318936543c9";
                sig_s = "579c07e99fc9891498ef3109360017052cb20bafb290ca2ffa64a72cf01e38e12770ba0ad5e190d2ef10c2d294e099a2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393538343937303836"_hex;
                sig_r = "2bc3bb18191a5bfe6d13c735104d78dd947854cf1d93017695119c8f04ebb44d7a7fffe71d15b78e0c2c28765bbdfc38";
                sig_s = "a9051dd102b20e3c69a01a36b85a1ccea670da784038989145e3cd9108b064d6d54f7df21164adb91b3850cd005ff68d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32353939333434393638"_hex;
                sig_r = "fe2c0567483ecbc6086a24160200a9ce91e6cf52df6d25b2ab08fedcc4ca95cbb6be68b58870c10169264f3b3e8d552e";
                sig_s = "34b7ef7c580506d29b1ef8223e2131602dad9fbcbce6f846de42519faecfa612a82e999cbfed45f377b77ae5ef0b4835";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36323332343733393531"_hex;
                sig_r = "09296917f12fb3bbe2c69c9bbbccf8a400d7e0b31c453ff7e928a7e4347a185435490790f56a5a819271192d64d612da";
                sig_s = "163860e1f6390c0ada261d2d0346b49f18ec3b17e0389e4c3b2296382bc23d6576bb968120cfd24ce735a14d3167f203";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3737363033313033323137"_hex;
                sig_r = "9bf980d1d91fa0daf73e3bcc02c7773503f291b3378c96700ecd71aed81fb8ff47d4baa8b6782842f227a9314f343e44";
                sig_s = "4342d335dd870f4a1b817b519ab184710c2c79b6329ae3f87b735e48874b6e47950db7c8f0fba59a349112bd2b3d9eba";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38393534383338363735"_hex;
                sig_r = "3f9b09855b47d180d60fe6ac427458a452ad72678d13818d1a28a376b31fd7d1c67e70ec234c40fab7d17719f7caa27c";
                sig_s = "dc1d5765bc5c266a39e1a94085983ccc63cb41556e3733330c98934c329eb7e724e12cadd082da23952b831bcc197f18";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343533383530303035"_hex;
                sig_r = "8c6910c012fb1a5b45032b09f2cfdbc7c3b22b0e18a0cc0ec4adc296cbfca66832379456b867ad1a0184ab1a80af59ee";
                sig_s = "3d87fec6feb833d01e4f77a306441fd27f328d01f6c20eef9b185ad4723c46f5d15e7be0db1c496018b4fa1987ac6b78";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32363934383137303236"_hex;
                sig_r = "8cb0ad263557318156ffde6b45cb6ca8633c3b50b51454605dd01242dda44c9cc5b59b327e919629a9f73720e53a5e63";
                sig_s = "4f2a0cd11c7ac03425e25d84bb44149117903cc4638e2f64450e2a915b14c6d9c74f70c4f85d6036bc604a92f9b97166";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343331323036323937"_hex;
                sig_r = "17d2c9d32253234b36a02e59f99163913a7c11a723f7122c521dba2cdec36bdcd1837c8b60a916aa64ed32b2c400d23a";
                sig_s = "821fb503cb89385bf9a6288ce6559cb69652e8bf940ccd0fa88aae2e72d31ac7d7cf51433ee45889094f51a4cc17272d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323031313936373336"_hex;
                sig_r = "b2e6fbb2a70af41654fb5d632fcbf9dc8a8a362394e42d13e086e7da261aa980b49c4a610a367973f798b9aa9df6d0d1";
                sig_s = "6d237b3161ec602529eecb5c7c706020f82b8040ccf7082576e3caef5e8d6cd87c46a8f3ea9947b18d1a35c83494d849";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383330303038353932"_hex;
                sig_r = "a6927125459e31afc31810117677c6ec2ba27c3ee5cc5fafbbd74153d3d2b2f7c7411e564c09d582dd2d5a201ec2b0fa";
                sig_s = "6e14a3955d24c4ac4f8c035f5edaf74e45ebd95a27954bb1c11fdb00fbc7156e96318d33725c0666006ae0573f7df785";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383834323632353236"_hex;
                sig_r = "d0f8e8a570a0462ea8ccb980789acbf243cbe946522ae4e9e6fa7e5e8e1bc006c8b84915355f00f39a61dbe77d2b4b9a";
                sig_s = "0f1ed97929bd7cd633f835086d2241a7b7d8f857b94f71e30b3e9bd19863a401834d01d29d32399006e8f84e0852e3d3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132333434393638393037"_hex;
                sig_r = "19e5a38c81ae167c70ef4a1879b7dba0dfaf5dc8a841269e82b106c6ea3f9e3f7e162b8c561d8f1b7b4a2cfba4c8a925";
                sig_s = "08c41e654d262ea6e1d2f74cd99ef479cb36476b2dac5bf0f250d87f7115bdcb59ddda54abf3b3b77471348facc0c8de";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353439323433353935"_hex;
                sig_r = "e47a0dd0507717c29d0e482037d7fd001eff3b80013688085ae430d46edb23cab8df8716d078c6503e38a1cf6a9e74f2";
                sig_s = "edaf65e609db0925dff88d252791db4a008d9b46e5e6da98e23a766a8a35b8df79ec189d272429dd64ca60983462daef";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303832383235333337"_hex;
                sig_r = "35d47a723521553ea0440e6dea660439c51b80e896877b03b0c02ffabcecd86e6cfed2e4fcd80d76c97ef945b626b025";
                sig_s = "dd61311a4d0eb024288fae55abef6f0fdaf71a55cd3ccb2f8ba8d43ef36dd5562c07d2b4ef60e04ec4c696fcd052185e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38303337353732353536"_hex;
                sig_r = "5319f4a01c4e88261146de213d65e55c2532d9a535bc8c47cd940fd2b7b5bb363e1932bdacc9a196cde39368d86a14f5";
                sig_s = "8afea330d833a1f3310aafef6bc27b684838ef3e57ac7e36c02e0dbf9e33b934dc7afa7418aabc3e6b0841eff09bc470";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373734343739383034"_hex;
                sig_r = "5c51106927cb275b54a7c90f6ba69902f1b1a19e2ac4b76b8d1e41b86f14ff32bbc66f07d4be610ccde84af4e1401181";
                sig_s = "551d9901408a4d9a1a85fa17de0c7bc49b15bccfae095247fc256a048582610b6ba87bd89dc98859dba2df76d77aff2e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3133333732303536333833"_hex;
                sig_r = "e931ac049c0b7bd9060a58b0f78d8d0b60f57caf647fe6476802c9baae7e06062fe3d1a1f0c6345dc7c530db32cad843";
                sig_s = "b83867f656b9fea099ca0678bd62f2013238bbd6969a2384e0cb2488dad615a4d91dbdf7908426c9ea9ecf17b872a25e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35313832373036353336"_hex;
                sig_r = "d4ccc6e89e85ffcca4b9e32fd45c5be1585d20c35ec83253f3080b0705746f0f5e7e92043b5ae8fd95963e45b4199213";
                sig_s = "48448f45ad0fc8d20fd1dbd088bdf6d51577f79a1e5e55432ea79d84eefe0b9b55ba145d637be5a686477fe00e1fb481";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34303337363939303936"_hex;
                sig_r = "6d3ea919365f9f39fe1f9b8c17415766f4c2b77c8393dc8cef321af5b4aa955646643ac32b2220b7590deadec15b88af";
                sig_s = "4d64a4fb9e26aaeec0d92270becbb5e2f04d812b2bb8b86cb1744437e62e58dc72f98ecafeadae69aef3328953143490";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131343230303039363832"_hex;
                sig_r = "7774080a80e32087c8e923c65522c76648205d9804805bdf05977c4559eeacc518560920e55f626748ae12034745f7bc";
                sig_s = "1bfbb5bcaff2b70298456fd8145bbcc6d150d9f2c3d91d6ed0f3d7eacc16456f698138ab34a546195941a68d7e92f3be";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323037353534303132"_hex;
                sig_r = "b8232417c371ecc56ef6342abecfa42afe479ad1cfcb18f8945ab0e2076621c185c2821a8028c36f1f2a8d3be7fc3442";
                sig_s = "17a0f7c15403a3fba3d8f095cd7eea597df761dc46e5c8122a3fffabb9fe37c52232e7f49af7e7cbaad8ed62dee8a371";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383536323335373531"_hex;
                sig_r = "9a5e7ac2a195f5859a0753087da0a2ac20a8bacc551d4c19b10fffe6b7acdd3ca6543957c9f7be8bedd33e89df7ba594";
                sig_s = "106cb9821f8aadaf7a7c411df6ca3bde9b6d4a267e4a43ffa9d5d29cc973f3ca4d776351b82586be7d6e2c251726b3ec";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32363736343535323539"_hex;
                sig_r = "1cdc96cc7892322075399aac7e0a86d4ffdb6e45153c0afa98bfd912941c22d05f360fba6f8734542eb55375b26d38aa";
                sig_s = "8ec452f8acbbef3ebbff11e6bf349032b610e87946a6221cccb5055c18d1f1188b6254a60113ed8adc6d0b09fb2f3fd4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313832323433303137"_hex;
                sig_r = "937d4df90d09299bd32bf354e1121a311a77ba0274e7b847804a40d5b72ecb8e9e441afc5289e0337ca1195a4951c1e9";
                sig_s = "7e442371b9991905f417e4e67ead31621bc068964097a46d5bda507a804f5b3bb142ff66d07012549fc42cec38754d11";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353232393434373333"_hex;
                sig_r = "65210ed179af3b99c09b9e95dc81f77007a32002ee7d53eed567086a68a62f1c08543c85f7d1e1f081bae477ff3613fa";
                sig_s = "025ce6efa2fe24732fe11f5b1f1232d48fa5dbcfbd62f96776302b1ac52f0d0d40549f2b2f67299569cd14fb7ead4c45";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343535383431313936"_hex;
                sig_r = "e6a4518771467967e264a9b736aa1f8bc6f421de607fec7e93fc62d91082c979930e6a3ffdcc54d5f0f4b4a2f0665d49";
                sig_s = "4c6c625b60ab3230e6d190f37a6f14e574f8dc7595467fe89ce62d6d1f2fd198368769fc84b556a3847be26841351408";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132393134353430363938"_hex;
                sig_r = "6388afc6cae9421ba6c52a640a0ebcb9c547505f500307194c8c1eb41cac959686ffa7b3a2adda65136030cba17d1695";
                sig_s = "cb1e148645580dea5a87c60db7c818942d55f169fc59eda9a2177a001ecc1bcbf2d519d67d79fba44daa2945bd380c52";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323730323132343635"_hex;
                sig_r = "2d7f29f767ba2f21619347bf29494a318eee949e91181ed7d2cf61162b92f0747c308885891b1734e9b6d5d3705475a9";
                sig_s = "1c34c2ce61e3dca2bb3202b6c4320155f764fc58d318ba44df9a7c06a0a453ee43b633353dbcfe129a54ddc8b6a27e13";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35313732353737303635"_hex;
                sig_r = "68a8758fb66c0ee50309490852f214f6bd09dd888f35390163defa70647202983ebabff3791287d016164c945494edf9";
                sig_s = "099a2c1073815916cebd4a41448e1b8dc9bb150465adf99c8a965b5fb327bb879e1b34f8d7c509aa1b018f98c9e13e40";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333835393530373037"_hex;
                sig_r = "7ff134c055bda5bba91fa53da5ff90c501a6264abd8db5ced03e9eb88ee63325f267a8fe483b0f7f129434d2e2114705";
                sig_s = "11649294f067d415681ca6cf6245b0beadcb4095b8e9c9d18bf11ebae41ecafde7529796286ec2efa9073de2f9025e3d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3634333837383033373037"_hex;
                sig_r = "9dfc836f6a993e1aeba9fe4b4e09901b83a5439a0ede150ab583c217fc22154050eb9c4a2f1f0f75c06139549d3013ee";
                sig_s = "ed83ee554777a5086ac90b9654f724507a54e5651b4d38153ac7576cf8dc9487be7d3efca544ff4b4804981efbda10d7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34383637313133303632"_hex;
                sig_r = "fd614924d6325daf270efbff4db11d645ec9b1f903fd36e1543bbd536ee010d07dd154fdc945a57f52f239439279f42f";
                sig_s = "079edf2f7ab361f7542bfd9175dd41ec137bc00d997943720e164e7187585a487a1893cde536b1dc52cdc0baa1fc2183";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3133343239363139303533"_hex;
                sig_r = "eb55101d2d489c0151d991b0e486016222997b917363f8c48386683091297819662ccc34381d5e5ec1c0c43d137232e0";
                sig_s = "d8bd992c2e0ab4fe46a4b43dc3b5103c123ca38e88e3c555385a6fc8ece7d9c957776667f389a950bca4b2ad6503c48b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35303634343932363338"_hex;
                sig_r = "f29aea476f19eacc44749f6057d39c6da903ba5c5b5667694145a6fe053ee08abed1d6869d3830036a29b063b295e67f";
                sig_s = "2decfc3e7d8cf0391f8e21714eeef04fa4f660a404294bcab6cdf23e4fa9e44997694781c49f4539a8d5b0dfa55603f1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3232373339393133"_hex;
                sig_r = "4b55c6c5f0264ddd31b88a92072d3a8f33b28306716d5430c0ff8fbc37d9ddf1e4a60e4e496b355f77ed005b51e352be";
                sig_s = "54d6da5a6385fa10e97c21b5bdb732a9a9c0685883da74f1f8dea0ae497b7609b3aa4ee92f448144ea2c5529ec2fc016";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333932353736393433"_hex;
                sig_r = "6024ed7ee8ef3edc593a9d07856b9aa78972ff33b82608c93e7068bcac05e0c5048889c8d520351047fa80f050abf83a";
                sig_s = "0d221dba3ef2d3c14923a651bd2b803603fbc94634033d52a66d80ea6120976c8fadc7274d05ccd47e1d06a63310b6c6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343435323032373632"_hex;
                sig_r = "fab3f2cf338bd7bf46dada597a4f66cbeb336393e4a289e21f8a02a6428bcd5fe66e87bdd3b5072997f94b76f04d9aa6";
                sig_s = "ad0c0f1d9c4f8a4b5100e183dee6d5d6825296784cb8205d448204237f5d3435f4c8f0a4fef81890c5a5a028405330da";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37353934393639363532"_hex;
                sig_r = "15cd4339b568212b20856d8397e5c5aebf3b4e4eafd8c90adc2dfe93f928e8a8bf17ec307064ba866491d4b44440d116";
                sig_s = "ba9357237d9d6b22be6761f63d91a265d1dc08cc693ae14576200d6aa7322eca439eea414634f5666c22ab29c67fbcdb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303134363536343631"_hex;
                sig_r = "9d2deb753b8e16e6f24e1b718000daa0d4617242225f1b91192b1ea8acdca607b05f1c0da8e3cdbdc52f448a376f13b1";
                sig_s = "8654d2738725423c0934c20b28327f7a5ac53a61f296a5ce562c8684d2f3090d19811fe70dbce71f106c4060740981ec";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39373034363738313139"_hex;
                sig_r = "1c7c8d1c493bdb1f1290f04aed3c4a7cb0a83c36330a4fab50e68f235777579dd06a073a3857f226dae511a2569e928d";
                sig_s = "14e5058d70b7cfb04cfb0c3c1d3d6fe500328340860e4b7cc2b5f11cab09cba0c7b887274453ab30d9164c73fc1f6f36";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343131303338333134"_hex;
                sig_r = "cade486e6a8e78141b15dbe60095e42d8196fafd843c722c8c686a60063e701f30d8a488c2a18a63635a13bc8ff0a787";
                sig_s = "ed7aa0208952d2d452432ffa1bbf7146080911cf7e87aa848ee90314b2afe427a80cd70187b3ac3572a360d4db6b17e5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353437383438353336"_hex;
                sig_r = "2787240e7fd6d895098d1773733727ee5792fe644b0774b8530ddd758b347143d1939bb7c9a3312774cf7126e499f5ab";
                sig_s = "ad215cb6681f287ffb96a6e7c41331a2e773e68791391c658f2e5c95cf82e3871e49c9fff08f7b540848c1a7cee2ab85";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333738363732383631"_hex;
                sig_r = "aa92d0b7d6046210024b962fd79d1a27ee69c25936e5895cd92224b3f560829c11de20e7f52320bba91b87c4c7ef4962";
                sig_s = "816c95ee54c677c4be1ba70317a90aaf1c1d2f233fd480d22cab453d9539657ce695e21952e6157ce3460680dc2fdbf2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313636353734353639"_hex;
                sig_r = "4eda9fc1e0df8ef24f3148f8a737a76eceddfa6057441c877816ac402349f32571c8074611179968e6fe7cfc1f41a80b";
                sig_s = "e0549e78e774377dffb9e742f05f5b1a1a2198571d0f2243fd25703029e0effac2808fad1c82efbdf0063d6032df33dc";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363431343037363435"_hex;
                sig_r = "18a83b96dbd10de3a62fdab7142f201f9f480447bf000f6ee314da64d2351bbc7bb94cd1c551dee4828a603e6a853fca";
                sig_s = "8fbf2a1a7ad4ed76a08748f41f5b3468a9a7cda57503aa71c455292bde2dc88a2580a65a6859d20f924aa7a5cea3743d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303833363036303631"_hex;
                sig_r = "2fb5726226521d1105cdd22e84ff46a36768ee4d71e6f5cfe720ddbd36ad645c05a7207c9f7cae2d8236d965ff64f943";
                sig_s = "ac3f8b7841b31c95f27e99a86413b6aa9086fcdbd176f7de65a696d76edcb0775f2e257db75fa5aa716946f3d80b1cea";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383235303436303231"_hex;
                sig_r = "2a38f4cc1da426f15d8c8dbed58608eec86862554f4d6d503dc6e162e72754b1298ad4508ae2a93d493c836b19548c4c";
                sig_s = "9b51610514136d5dcfda3c4736a839288bc1f043ea362cf6e56dce3f4337204d5bdf92160a034f459b30410872dbeb0d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313432323938323834"_hex;
                sig_r = "3407844641a75ba72ed05f9b7289ea2c8f9015c97e8d7aacec4a88b374a255371b19e7a2e7949f4b78b63334b4984434";
                sig_s = "cee117c6fb8f8e47ce33357d7ed1a82b1ed912be3778eda9de303b2ee910c014eee3cf03e27f16fd94d7ed5a8e8c7b05";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313636343232303939"_hex;
                sig_r = "b98e1313e62ff0155158059e422cb6e8ce70d103f1a95a77e1795ef2ae38a42596732405602299ee730b81e948083adf";
                sig_s = "8a34134e86354d26f343343c05cdb46350b610ad16883f234e847fad97047ee4b8dfecd0bf77479b65643f9c35b74441";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343830313930313632"_hex;
                sig_r = "0ae0a9cbd0de42e6590835374548708df9671208ab72e23bf7aa4329bbd0d4a696e99d04d36534e895737b468cff08ea";
                sig_s = "8c8b6bb101ee844bc75cd2b3b32ea9c3b6c2ac5408c26f6a444335d730af2dce6f4bf1bf4585428e902f901eed10da62";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35323138393734303738"_hex;
                sig_r = "cf0310487690de93d344bba957a1ba380f72c2ae44975f69716b2aa2a866787dfc46629825ef19e5528395d872ff9367";
                sig_s = "ff60a995865b6f5e6ffc15884e5901d55f384ffc62982e54a9c2dccaf7543246673c5bfe710f2a29daca77de766ee9ee";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130343538383435393733"_hex;
                sig_r = "4a0f3d91ef6b9b6e512cd9c996f8e896717ea8c6d685834e4c31bcaf592a93d0f0b169efeb0ea52a5bea6be361d7a7b3";
                sig_s = "c3d429d0daf1ee7c2bf4a0bc8f10cd7ce453b8e2a762b31885d36f5e03cdae3adb693bc2efe8a64d6e7bbc17f23b5500";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343839323235333334"_hex;
                sig_r = "40f82935328e34e31f1966bd0bc1dfc2adf1d71d86fc6dd0f9e9e1930dfc357e30fa67722c562dd84cdb73fb715b622d";
                sig_s = "cf40658591f34527587b0969a45ca5a30f87dbcf0b058f75c158ac883d52119030881c0aeb1f8e12682d06d072705550";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35303433393832313335"_hex;
                sig_r = "a3434df3d065f4b32957077f429bccdaa8875981006ce880585c160fca1f552dc6334583d7698226e650e95d86a896b7";
                sig_s = "54e2eb28c70796e3bea9f2fdc3799f7d6dde5b3cc84de7448296d65fd8a44260b0666cefa416adda5046f45a5b8a9ae7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132393833353030363939"_hex;
                sig_r = "b54b004489e12ec91e875f3062dff1f1bd0407e216162b4913a34f19943c8f967c1f7250ff0ce5f43a0b250bb9fae16b";
                sig_s = "95c13a702ca6269ed8cac69291e01767c0f862648b0961238ef0b6be88cd316973a290bae4f50147816a49ab014a7d69";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131333236373331343032"_hex;
                sig_r = "ea28a6b9158328d0711bfd10019643648e695c1fa9df2a7c2e1a6d3b03b6703bc763f8f0c701d7b925d35075da783f38";
                sig_s = "b4bb6b034288af213ecabdcc2d55610181ba77b26673b1490e7e08a43f6e57fe20618a5adc7fbfcbe255fa79655aaeb1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33353733323839303232"_hex;
                sig_r = "d973f5fa26a7069dac82790097db0d93dfc52a490ac2a84960c6dc52c2e84d2df1917c8d194789fe8981be40fbefb006";
                sig_s = "1dc1ab55752add3952ee3f5d86bb167ed1fdf20e19d5c893c1a6031c1a2b70701ba03cf7d78b89331d524c5dcf38462a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131373339353634333738"_hex;
                sig_r = "3d4ed5e71127a0da4aa63cc1d7ce517a450370dff65ef95b4185a44199181ec5ff70f80f6d7435e6bec4d6e58e73591b";
                sig_s = "27b2d65bf08ab8e745544225181638af5df08b85c9f7a9057e1605f145b3a1389661d9c990d0f4d82636dc6332b6941d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3733383230373935303035"_hex;
                sig_r = "e36ffc2ca7e62c2fe35c7761a78ae2839d1503b437cc7a89eee28ec74d75d2948c7a3148070ad715f7ce8260c160611d";
                sig_s = "0c18edef913d63ac220cd4b28aef1cd43aa9acf7b0fe889c4a28ac22934e46aa2a99a5b803a61471bd5bfeef8c86b17b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34353233333738383430"_hex;
                sig_r = "148906bcfc686aa3f608321d17a425373bd9ce2f47a35a6a01124992cba56e744daef2b00dececff63ed96d5d7c2e158";
                sig_s = "4303a5c7049766956679f204e655301dc16fe9cd85f6ebb1997410e0d2029240181c946d86800cc6ba882f276603db29";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39303239363535323738"_hex;
                sig_r = "5264c26ceb0481b74472f26ecca4459785a2d63c9494d8744e42e9eea5799bfb0fa95ff3c8a5de2868098a025110bbe9";
                sig_s = "e1858d96c814dbd39ca5dbde824be0894b4e418fe51306784a8fd0680850a5b32958714ae9124e9ad6372412212df1be";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363030353238363330"_hex;
                sig_r = "273e229dddfaa7ba5763c8563f3a05c7d2d2471331225e8f26a20e0ae656115c62ddfac3895f10012253ba7bb79a65ca";
                sig_s = "89a6ab6fd5bca31659278ac3f3e79ded9a47a6fd166fc746b79fc3bd9d21e5f332bb1e89a14efcd3647f94aff9715aba";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333639343536343136"_hex;
                sig_r = "f447dcc8ce6573a2da5fd58a3974f46a8d76608e477742b68c2e93245f359567a953cd18dc1d95fa7e3c5d02210cfc0e";
                sig_s = "b273a9ce5a021a66f6a44f2ae94f2f5fab6e3b5016648c9df38756a5b7e71d07aa453240d39bef0d22afab1e19095694";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130303139393230373030"_hex;
                sig_r = "9378874a38f221b27d8b7ab06d827130d0db2e9c43f443e9cdd254ef77a4f7aae589a6c1499970dd5acf516802688aa6";
                sig_s = "f94a6319379598119bddf9f787e74b135ad193b692e44a848ac6d1d0443d49adcdcf1a9f530686e76080840e1b647be2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373032333133323830"_hex;
                sig_r = "a48cc74a1d39a0b8cfcd12768277535389790c9ad2638aca42401a44e80ff0ceb40e193cd9e27e39443a1d2665de485c";
                sig_s = "1569ca82e563df78feb1d704953b8c35b7eda09259fc16ab262304d0c09383f550cfdc97ce549874212e3fc7b83f6d4b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31383038393439383431"_hex;
                sig_r = "e6049a43aa5761ad4193a739da84c734f39f2f79f8d97241982082185fe9cef7747b68c59ef3909f18af6c5df48ee559";
                sig_s = "bb7800436791bae910fbfc6b69c0b7e6972dea1bd5ad82aaf97ebb85d920a15f9f5f280fd813281f36b2ae3c53fd6e41";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373438323839333135"_hex;
                sig_r = "148d734104a52c9d58ca1ad7ba56fd35147e8d324a0923ebc9c5d8b393f492bce1da6c9d1fa68d4faeebf0868e03f171";
                sig_s = "4629809043f228f0f3adfc0696c2e9d800791ee82034c5fac37fc521e40f9bf2250c53036b8286e032959ed5f3a58483";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363232313031303338"_hex;
                sig_r = "16762ba4645c905590e6a3dd4b1e2af693cc4e64153812f93b80ed4d1c07e664e5b22880f24a120d4b48e1400fcd3afb";
                sig_s = "d481c2f9b255bba2ac29fe055536c3c7fa92e4f34cfdc5b5f5227f582736c87c1350bcb760069c4004ac33fbe2ed3549";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132313833363339"_hex;
                sig_r = "830c8c92465fc7f1a654d22eaeadf62b5fa29bebc8e184ca104913eb8bea234d287961900f308d88f9bb7387c8de58b2";
                sig_s = "960eb635db967cd69f80123e0a43501c6161cbd9e8058f5bb7506cc24fba3a3694688b5b0e066bf2ccaecbb5a9eb0c9d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393535323437333036"_hex;
                sig_r = "1377906f42629010e79bc60142234a44c78e8887f6dc4086bdc7e9bf94c92c84aaf48efb0269205b8bd6e324224df178";
                sig_s = "6f430a1937fc0463143c80a0e132074a64acc825c2f4ed8b0de03204a681bf171e9e002a88431fd388c7a906511171a4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393531393636303731"_hex;
                sig_r = "d1d335dca83a7ef4770e68ff82d2bb75341abf72a362c88d8a176020db37bfd5874e14c0cb011cb316bc6e6d1322a893";
                sig_s = "c61fc7dd9f66b8cf2f8c9a780089fe31a20608b458ea12a246a1cba34566c2d833a71bbe09482ad3c26bf9bb6088fd5a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383830303734303635"_hex;
                sig_r = "536183374fa37f210723fe3aabde18997be247be006e20c5d17d8e4c79790ddfe4e6f17f8823d36aceeea22c9e44ba9d";
                sig_s = "b6a0f63b27876d1686b9e601c273c20530c765e506605cea39d9accba9a7007bb10d64333e5e22125f34d1dfc8e60461";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3136373937333631323130"_hex;
                sig_r = "2fa6073fd290a699ff0a4bd425a69d4e151a3ec3faa65c504d5e41b45c2a738d343a99865690bcc22c03230c3949ce3f";
                sig_s = "3989dd2d632007c498ed830d277cc1193590f23fe5e778deeffdbb2c135258327b121a81313a0bcc9f77db206afddd8f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323235353833343239"_hex;
                sig_r = "cf60fb9789b449ac9b9f022dc83481777675e55f09b4cba5d8349c0e16907f8929e3b538cce4d71c01b010a633807997";
                sig_s = "67654a0bebf3a63fa93cf9906c846cf5edbb03968c86eef5e7555a14d606009006f9f9e4569be3375a9a8aa04aa20c45";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3236393238343433343334"_hex;
                sig_r = "6ab23c76784d003ec508233f7f5e6461d6806c66af62c4769d45ec8751d276bdb68b2efc4fcf83f675a3101941f9adec";
                sig_s = "6f306bd6f782aba3c7d0c0d6c0e0e8897f967f0de2a84db1d67e477378ea425dcc6fc6113e5a5f67ac34eca2c69d0bdf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36323734383032323238"_hex;
                sig_r = "526365e36472883664eb011bdf9a1503397f0e3509066665f9c276e367cf2730774d4525125cadccfef0c0cf28949a2b";
                sig_s = "948cbaf1c0e7f0ccca5f5d2a7e4a94f4a7ec43d2cf69ae5ebecb41521daa9e618615208cb62b35809fc40401670ae3b5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31313439323431363433"_hex;
                sig_r = "b1cf39b023502a1aa3daca372c295c1eb3c5fee2a841ef2cfd4087ffdd4e35e8804b8d879a939216d24fae1bd1e7f19a";
                sig_s = "8b8bea55a9625efb9733d1dcfad8d426b81c9e71fb53b246ae54c3196972d284172e6b1911bafe6b631e5e48344c4409";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d7dea8ac1e4b9aea2d3d1ad7d6a877e116a8bcdb87c8463c69ad78f8074f33b2c179ac0580af901d21851cf15b3a5e34", "2a088198c090b9e367695a1c7fa110b66828d8f07bafe6eb2521dd20e517cebd295cc9cce52e0c0081b4cf7fe5ea884e" );
            {
                // k*G has a large x-coordinate
                auto m = "313233343030"_hex;
                bn_t sig_r = "389cb27e0bc8d21fa7e5f24cb74f58851313e696333ad68b";
                bn_t sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52970";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r too large
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffe";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52970";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00cba0cc097c795cd467d835977764b7740fa480c3cad83a726d68bbfe8dbb752934eb4fb6c767dc09bdda6d0d2d057ae8", "00e277c7ad56d6f21099d998e7bfded8c8d2d100c8ebd9f57681a633b91ad0890c020e724689c6b1b4b8f35b49679a4fa3" );
            {
                // r,s are large
                auto m = "313233343030"_hex;
                bn_t sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                bn_t sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52971";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ffc271e311cefc1c133202448e2ee74457bb68951b0e575747cc6ee9c0691720bcf9eba23c18f96e845cda05e06d4f7b", "00dc7c5d17e91f12abf3638fc8e87866f0373f0ffa90c2c759712d3fb163730a184e4707ef424ef833079c0ed5e1498344" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "d1aee55fdc2a716ba2fabcb57020b72e539bf05c7902f98e105bf83d4cc10c2a159a3cf7e01d749d2205f4da6bd8fcf1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "74ae987af3a0ebd9f9a4f57be2d7d1c079c9ec7928a1da8c38ff0c2b9bd9822fa7603decc1becabd3f6ceebb353cb798", "00e0c9ac6f4f575fa1ed2daf36224d09aa569f8b1d25b62fbaeddf766a34b9309000cce2447017a5cd8a3ce76dd5428ff1" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "b6b681dc484f4f020fd3f7e626d88edc6ded1b382ef3e143d60887b51394260832d4d8f2ef70458f9fa90e38c2e19e4f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00dc23280ae627109b86d60be0e70cec0582a5b318fa8254dfcb97045eefdf1aa272937de99c6b3972c4cd108b4fc681cc", "0ec5438a5d44908c479da428e5b2e4f5ae93bf82b427d8dca996e23d930700082828112faac7f710928daa670b7576cb" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009bdf0a7793d0375a896a7f3084d3c45f8dfcd7f73d045484e71128713cab49b4c218af17e048fa6dbe32f2e289ee8395", "0be28a090c2f6769f85e5ff1cfb300bd0ae907b5d5367ede98dfd3e6a81c4b4903289973285a4ef91b790ad12761321c" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "02";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0090770515f27351111e56d3bf14fe392d42186cb870374a8d40870830057bf52da8c2e27691236a0de2876893f9b77ab2", "00fb1cb5dcfd30e3a2a0056a5dbbc1c5d626ba669cbbfe8bdb121de7cc394a61721d5c3c73a3f5dea9388cad7fbca72649" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "03";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e06c663d7324540cfd76aaeeef4fdac904264e30ee9f5c202f7c499d29ab05e895b8b41952df7f80bfc9e7474df9b2ac", "00ae09d908c09ea6333266a15ad74c4e4d051d9aa3f5c93b3027a072ddd20b02f9b25f0a527cd6773e323ac0e04162486b" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "03";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009f31fd6cf46f8db0b46c735ae3b4ece85e4112dddcbdd42981783efaeac6217d4d841189b05ad6e45e4d15a15d4f1651", "687e6da1b56d02d66e4b927f7a1ee00bc578d1799a78764ffe7cbbd611fe233b161f84abd13b346867a0248da4572be5" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "03";
                bn_t sig_s = "03";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "55cf46544ba3665a483875bebe791fb844bc60be3828144f403d3a5f879ff5df907f7f5618927e6dc5fda4d73520323e", "2fe8aa11b033cac53dc3527759d8967e724725f7dbc8b35712ea8ee27366baecbd2c7c81344d889faef99f9d83236f84" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "03";
                bn_t sig_s = "04";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r is larger than n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52976";
                sig_s = "04";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00fde3383d470bee8a6ceab51498e5fd6111576578244188bc01116ca9b1c63c0e74eaab57eb29a293c17ab6d7ab90c6ec", "00bed0a26455351c1672925ca931d8a386df8da101f598487f37e48841fc53d12585d3e1b8458b1fa31e6b4527a339cd51" );
            {
                // s is larger than n
                auto m = "313233343030"_hex;
                bn_t sig_r = "03";
                bn_t sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accd7fffa";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "24f0d59e6bab85cce63823e4b075c91520e0f7090c58dbae24774ef25917cf9fab1030513f4a10b84c59df529bc1d3b1", "2469f23a674bf49a0383d239ca15676704eab86bd3149ea041a274643866643b786bb17c5d0f10dbf2bfc775c7087cc1" );
            {
                // small r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0100";
                bn_t sig_s = "489122448912244891224489122448912244891224489122347ce79bc437f4d071aaa92c7d6c882ae8734dc18cb0d553";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "39833aec7515dacd9546bab8dc740417f14d200bd26041bbf43266a8644628da82dbf53097fe43dca1c92b09832466ec", "67f862c02c8911343a146fddc8246c168376e4166e32bad39db5be2b74e58410b4e9cc4701dd0b97ba544142e66d7715" );
            {
                // smallish r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2d9b4d347952cd";
                bn_t sig_s = "ce751512561b6f57c75342848a3ff98ccf9c3f0219b6b68d00449e6c971a85d2e2ce73554b59219d54d2083b46327351";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6cc5f5640d396de25e6b81331c1d4feba418319f984d8a1e179da59739d0d40971585e7c02d68c9a62d426ca59128e0f", "00feab57963b965302cffe9645cf3ee449846381d82d5814e8ca77167ccf4c20ec54278e874f834725d22e82b910c24c2a" );
            {
                // 100-bit r and small s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "1033e67e37b32b445580bf4efb";
                bn_t sig_s = "2ad52ad52ad52ad52ad52ad52ad52ad52ad52ad52ad52ad5215c51b320e460542f9cc38968ccdf4263684004eb79a452";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "567e0986a89e4a51ff44efdf924e9970cbdaf5796dea617f93e6e513f73cb529e7a666bd4338465c90ddd3f61823d618", "5b252f20921f66a72dfcd4d1e323aa05487abb16c797820f349daa04724f6a0e81423ddf74fdb17f0801d635d7af213d" );
            {
                // small r and 100 bit s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0100";
                bn_t sig_s = "77a172dfe37a2c53f0b92ab60f0a8f085f49dbfd930719d6f9e587ea68ae57cb49cd35a88cf8c6acec02f057a3807a5b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0095512f92e55b5d18003397b822c1173f4e25a2640a4a68bb880a6ca8605cbfb83c75dbddc4937ed822e56acde8f47c73", "48e4ff027a1b0a2d5790f68c69923f3231ac61074caad2a022f6eabf8c258bdb8142be43ffa16a6f2c52f33cba006400" );
            {
                // 100-bit r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "062522bbd3ecbe7c39e93e7c24";
                bn_t sig_s = "77a172dfe37a2c53f0b92ab60f0a8f085f49dbfd930719d6f9e587ea68ae57cb49cd35a88cf8c6acec02f057a3807a5b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "74d5679e10edc41eb06ba54a1de2c9c71820bbac14f3758bb7fb593dddbb2e573e0d7a785344961399da18c8f615ae1d", "00f71e1c0ea892931571da09432ac46f6cbf53129e1e3e74c567180c037df59da84c8374b295b5a0ec6100ce9d800cd05e" );
            {
                // r and s^-1 are close to n
                auto m = "313233343030"_hex;
                bn_t sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc528f3";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6982e9820d0c0078418692a9e017b0e896609970992c62285e825c94980bad199b1cfb45a6314ae1bf35fb8255f3e0ea", "3e63f4c32d828a3e2e1368a0dda0a0491e90a2040084d4d79c2229184afe4f62879822c54779f2136c6a46e7408c753f" );
            {
                // r and s are 64-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "9c44febf31c3594d";
                bn_t sig_s = "839ed28247c2b06b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3b6131ea967f5e3c54cfd0211ba7666d74e119403af55024e2938c774857badbffedb6f4e557d86595e63f8dbb2c4289", "00e89119062a122176d9f57cf66c9c00a442901f110f2d782da7a99a764bf89e21b96d513ce4fa45c6d19dd0a13ca548a5" );
            {
                // r and s are 100-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "09df8b682430beef6f5fd7c7d0";
                bn_t sig_s = "0fd0a62e13778f4222a0d61c8a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "292c15a18011b795a115793af1d6e91bbcd5f2362a68441284307b2d35a77e768f54e6f744211a478f28aef8e80e1003", "432aeb3fba7f2b56976e91995ca2454dcd01416fcbc0385152aa4d5f7ab4b6e7cfd77e34afd8c0a0f9f4dbb0b0587123" );
            {
                // r and s are 128-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "8a598e563a89f526c32ebec8de26367a";
                bn_t sig_s = "84f633e2042630e99dd0f1e16f7a04bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009fdc7e0a73087f2109d6581b0b70f3257cd87982bb2bdd3d2827cf8988dc0e0e88ee691e8a88aa25b979fab3268dccb2", "13959bb97e11c91c698f45d84ae8ca4c5a7c23e92c9e48f05e9bd3710d7c143317c0a890f7411156a12460c26a560af1" );
            {
                // r and s are 160-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa6eeb5823f7fa31b466bb473797f0d0314c0be0";
                bn_t sig_s = "e2977c479e6d25703cebbc6bd561938cc9d1bfb9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1764c83ff4c28f7b690ca1c4b05832d78394f0aa48de452eb7b470526f4099d45de563b506c1570eb9b0f899a5f03f5a", "00ff89e562385d77b2c5d48dbb54501960997566bca5dcdee15848b907ee7457f8e46a221f64091c36f8d3053147c1a628" );
            {
                // s == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // s == 0
                m = "313233343030"_hex;
                sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                sig_s = "00";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a3e044abfe616fa2c0341ffc4326f3367221dba0bf33e56ae09cd3549e61b33364295c1c2747713cea7acd6dc7bb04b6", "49a7a8292ed773b33772d3fd925b77226a79551a436b9738b4577c89955bc3e2c2afbdf75cc751d7f8855298892463fd" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "427f8227a67d9422557647d27945a90ae1d2ec2931f90113cd5b407099e3d8f5a889d62069e64c0e1c4efe29690b0992";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1daa2bbe04e15631da2692da5ce55817430c332263caf13ae5626e9ad75e28938cb2d246b391c9e80ca301040e04df3b", "22b5021bae7d5f5739fd44027d70ae9b44ce82bb638c2d44e660cbbbb493e4499203d750d6c451b0a091f7f363d7c59b" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "369cf68bb2919c11d0f82315e1ee68a7ee8c17858bd334bf84536b2b74756a77e4eee10ecc5a6416a8263b5429afcba4";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4a42f3bce03237811543677df2b8bb9c7034fb6b9eab2e29041d81fc93b11b4d3e6788d57031fff957c9d10ef786249b", "176cffe0e08dfb5cdfae7e330977c7d88bd04e814d2d5fc6bfbafd9dfdd8e59f9b79c5af26d6edef3f6070e59736cfa8" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "2111832a45fc5967f7bf78ccdfe98d4e707484aad43f67cf5ac8aa2afbde0d1d8b7fe5cfc5012feb033dffdec623dfbf";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ada857916b3ae94e2309c4478749e2d43f34702f5da9f6279670fca56d0a4c8b24a96145af01e8d6cdccfdf236f8a026", "00fc246df477514a830748fc713f25ce5d5780b8b253e7dd09a4a41f65af07fe95607faf0a737ba820933a5c77ade053b9" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "20cd002ab7dca06b798fecef3f06a222c2d2a65e9ec92f74659a8d82fe7d75e9af739f0b532e17d6c5f622c4b591442b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "787b21230df5f1036a459a5f81445cc9f07d2bef3f872b33cbf1de8381f026cd943f960f094fdc2e13561af81f3eacd6", "00cc29c6c5b8fbbab21953cc979b0391b3e051d8cd7cd112dccaf487af7e29b415ebc206a33b252b9237ddaa1bb286affc" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "3276fe55314e426a8ed83c4c38dc27c8fe8cbba0b39bad7cfc35e963adf10ab37251ea6829b8d255a77dd0b655cf9ff8";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2d06c9d3eaa9ee5aec68df7c097b36a4a8c2ce6f704d944cbcf4e8f8d45386a2b43a61c9165c2d008975ed2e183f9c63", "611bffb7bc19e852fdfc6767609d41dcb680319378e039743b37b0e9e9c6a686cf9036ab77052a8de1b2ae71c47b6f99" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "1a80b4a3d6c88775821e26784463080eb7de510762ab0d98223e532364c7089b07af73746ae4cf076c5277dcc80cf8c2";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b9d04ce66c8737ec6425f7b458163d44880428ac62858566490c3fe88a56cbf9f57cc76c6726393e39d4ed97fc95b5a5", "008244af490369e7008b68f725345b9c2b91f719c5fa88705ad5d33a986be75873c51856d1afcd99e0e69d687646eb3438" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "74e780e38b3a7cd6cfe17d5c9ac615895bd97dd4076b5f8218ae758b83d195fba64eb9aead39a790ca0f8b8387376265";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b318b005c3b79ae4ed584c2a7dc8aa73cd3b47673940dec5e7acc1d0cba904d20f0f9e00b3dbc66681818fdb32ad706f", "0086eae465fcd5b3b81f3005d60b84ec8becaebc610f6063f432f94816fb586bbc608c579a954c0583a726a13ddcc271d2" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "6ee5f8daae12c862e1f7f8b59294ac90448c4461e29b36ed623a719dd69bb17b3a4b7c29b9eb5c39ca6168bf6b597c6a";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e49cc09972b1134202ccb8ae75156e3aa1ab1cab3c76b948890a1d00bbb619e701106d6d2b89b4a3cb3fee7d7bc1e1d3", "515301ef8e56e263179ee36058fccd4072f8f073e6580114ede2ad5da71b0fa3926aef13715e0f2f5ba53847c66ffac9" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "5426ca20a25b0cfb1ef230c62f91e98005f346e229233f1803e8944bf421fef150a4a109e48cefaa4ea23eea627fca41";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "189ed7ae2c68d2cb2337e8be079594b73fd83044dde91d80b21c14913f48f243d0545239921cd3cafc4da26d872bb27f", "36f1fd8e77aa536e63e8f720a9f6df0ecdb3ef6efd8f8e4b8bae68d36bfcf9f94c2d8538ed85f0e02e573070b37692fd" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "39fd1a0ae3964735554c61daf085c66bcc2e9e5350131086023aa99549fc5f9057c848e75a1b8e58069fe0b9b23fa3c9";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ab69a9010b6a49c6fc70b68d13416e124eab0855e023e729abde0c7c2c39f288b7e978e90fe8aed9117151eddc0cb43a", "0085f1708fa08ef674c9e8f43351e5f60fc33c2e1057bd747dc07e243d9414d2aa14f9f62f475ff08d6a7ec9fe935239dd" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "707a37cfb7367c2e551ea1f0caeac6c0fdd2b562e1bd8f1c7c51a5dd78f21da8cb179bd832cac3d3aee21fda54729e66";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a2c11e8b85862e43d15e1ec7948e24b9e5af9c137e3d3026524822b46290373be52d5311b2b85972c689828e6c7e6766", "4d0596346a35a48ff64a83891e1c54e4a5546fe8e02c0c1bba12a71a60bb9c2a0db73deade44fdd9099e4583dcfa0493" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "15c99e2ae11f429e74fe2e758bc53ffea26eb6368dd60d10daf860f9c79fa8cc6cb98fee9b87dd38353e970539a50a9e";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3a5dea2fd350ee0f71a6df2eaf3371a31563926502261cab0d8fa9766b020c0ee0325564e11e76edf0cd754f5191cb31", "00a5e4f83ff046694b90737a778f1a14fb9ce877949787ee856797069ab8fe0449a07379883eebcbda7cd671d6a86f9c7b" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "148c732596feaabb01be1be3a220740e84bbfabe6d82ad0db1c396fa047603beeb95a1cd37fc708a9451d3cc29a45b32";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7d1c6e405b2f1508abd51f94c2c631453d43c60000195d5616e0140a6c5a273cfd21c2594c4c57b2ce1ccd9de3ece324", "00a77fa6ce730e4bc0342df1c55486ae12404633c67f7c2479c41e847189cd2a400fa6ea48203c8d202ef8019fa87455a5" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "6b3cc62a449ae5ef68bec8672f186d5418cc18d039af91b45f8a8fae4210ef06d3f0d226f89945b314d9df72e01a02bb";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d7b6afe6f56f4a971b0e3c76f21dfbd31d677dfee379a7533de31dd83acfe81232eace1e0346bafe8e9cbe395e2fcfbb", "7780a9132cb9b85bd37965060de6d2baff92e76488bd65e4d3311573c55965b403c9f5874f6d1f8dbbe0009cde1f8e0c" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "7db7901f053b9cefacfda88dd7791c01fd569ed9a5243385eccae12ba992af55832a2e5dc8065e018399a70730035bd8";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "100fd7ac4ae442ab989f94a10a1f310f799d76980d00a14418db067b144bf45fa7639446fad508b76fd3ad9c9fe55810", "693598529b8349a28dd1d0632039ff0897523fed9af2356c0e36612135ed629369448b97d165ae5b2fe5c5ad396d2b06" );
            {
                // point at infinity during verify
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = false; // result = invalid - flags: ['PointDuplication', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d9a08d4f9f8708471e2e6b04ce08750c395b80f4a14169123e2fd97556c1171d82e87165a77b2dfd089ad25382ef4251", "517d0c26bebfce8483bfb089243d82eb0e712a7d2e7f71f9abb82ddf16c2e525146c7dc5686fb7ad334022ad092d32a4" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "68133653284ee7e9a8cccf584a9e4f06bc31a3eb031999f0229db7c2b10630424c7ee7513e40319e3972c1a5152d5d28", "00a547a17df730d86278de44cc099643ebe1f07e48618de255bc672dff63c58f86b2db29c89f109147d8d6be1f03c466e5" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294ba";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "233c399596e090c132c8e8b33c2ed443d73ab9abafaece5e47c6a6dc82d3fcc006ebf8b5b1c5fd028c97097909d5be38", "035f777dffaac0ef909bbe6be4e01ecfae3b36b2ea2095e352c179737980f96124d45b76677274d975eda57436f453de" );
            {
                // u1 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "f8723083bde48fae6e2f3ba5d836c2e954aec113030836fb978c08ab1b5a3dfe54aa2fab2423747e3b4fa70ec744894c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "357931297f6a369df1e1835ae66a97229c2ab63a75a55a9db2cdbf2e8582c7c0d8aa79f2c337e4e01980d7d84fd79917", "06b1de385965ae26fc38ab2b18a8ea60e52faea5c2e27666913858917cb1cf5b5c0bdc9c1498389c1db155e54d3198e2" );
            {
                // u1 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "078dcf7c421b705191d0c45a27c93d16ab513eecfcf7c9042fd744d6d8dcefe1036fde07248d32fcb19c725c0580a027";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b760dcee338ca73c8cc69f0360d87253ef3632d302bdbf743a65f8762ecea207a5c5aff3add177378e133378d2c83a40", "00abcba73c686f35e13d1cb44197bd763b5221d3b17ca7d888bbbc52eb2c33462036dd7a3b569290cb586d9e6514d69b92" );
            {
                // u2 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00fa8f96db8c7c9350d90ab49baaa941a79ebe62f017d54b6f83854f430408926e4a46335e44e1d67f0f18c7db2d70ca93", "00b65df386caa193875fe91740214526a2ed17393d8bb62bdcee9f887802bc2d76ca9a304b94e795032956c8608c0e7f46" );
            {
                // u2 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa84ecde56a2cf73ea3abc092185cb1a51f34810f1ddd8c64d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "69bf123fb0d38b6a1c3f01a811e16ac78f40301332a0a18454fb4bd9b7c9516520f5ace9eddad328b8d283162eed1c75", "009fa36f89c13419404c11c2ac982777cd30aea7e621351d96ba39676c26b36ccd109035d708da63ab9aefee3c82f6d405" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "52d0bad694a1853a24ba6937481240f8718f95b10102bcfe87d95839091e14aa1c38ba8e616126d4be6fe25a426c2dc4";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1e5863f2dafa6a4d1a10a4cb18ebe792c0154aced0c5c2abe33f727335c720693e92749795539350d8503f209da1bea5", "6f0889c25cd0aee834431262177f43b7ddb01a75532dd55086c44c1931cdd3e0312eea51d300050130f6e754aa9f92f8" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "2412cc835da0a4357d1b7a986a76fe42b79542258c02dd7af927b27a9f9352ed3eedb6520a422e876949cb5fd0724090";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0087fc8357860b94528775f3787406b79d7a7d65d23d1d5707e66978be71aabae87bc539c24addf6c55468cea11cfb85bf", "3f881573285dd3742ecf062d5321c3d5f86212ba88ae75dd3945ebb3b44c37a178d440bfd72ca8f2e7c99cf6367da248" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "1a2303bd73ab20717627366a498a23f4afe23f30b93b0f3be65b74e5eb19f2abef049411ba50146a305c5bb98169c597";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00eebe3763025894619173c8b4397deb7febbfe10fe2d283fd303d48691ebc8ba3ab1209278e763199a18f398b9c148405", "0098640539d7ec66d3c43bfed723292c85856f02e020deff4e468bf3bf3c7fd08391d9525a2cb4f85fbebbb7945a5853ad" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "2805e063d315ae83078dcf7c421b705191d0c45a27c93d16a277765a9f34e9a4b2e3bac6291d3ba508e5769fdbc4920b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "41a0504da3995adb7665654b6ef7d0d00f77fcc536fc1cad41b0daca5a60dd88c99c20e698c99d5663eb532a57db08b3", "4d2b0acb79b95b70cb0a5e2eba110061ef87f0d34b5bbfdeaf5184b67103f8a2bdcd20a7b9f09ad11811776659becb75" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "5e063d315ae83078dcf7c421b705191d0c45a27c93d16ab4ff23e510c4a79cd1fa8a24dc1a179d3e092a72bc5c391080";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "45c152c4e642f156b50ef6252f2b0cdd36f20cfacbe389fd79e2fbf19f0810cfbfe5d157d2fcc9b2a649e9675fd86c07", "4eeaab3bec18eff3b702e0e0f5c40ce928ae48161e06833ef3d76fa743c51b2711ca7c06cfc3a20ab804066251d2a115" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "bc0c7a62b5d060f1b9ef88436e0a323a188b44f927a2d569fe47ca21894f39a3f51449b8342f3a7c1254e578b8722100";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5f6849efa9aafd6a4030018579e39d241df4c192e5ba78c6e9b441aabdac8eb8f4b353865c1c9127ecccca468c41a561", "00ec501582456fe6396643c368d2b9735c47384dbdcf2cc16927ab9b327c36350fe7e1f949e7ce14e60b1c1dbec8dff5f0" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "d315ae83078dcf7c421b705191d0c45a27c93d16ab513eecce49d6742e48c5aa2b36ea79df9d9e3277247c3d843d5887";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c3ecd74e383f55b7ec8cf0579e6fedb9863ee0a82cc84cf13854dc1017aecb2a5969f15194a9ccb09e823559fcd7b6f1", "1faa3cd553119de6efd237b9a84dfe520694ba373c8b60d5b2e741b35bbdd9cfa635353a1f0cf47042881684a96fe516" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "e2c087faeed9abb45e3942a10187bd6d2df94757e2584ca7599b3385119bc57f7573f71dfcc9161dd86a91096695d236";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e4efcd7525aa87a1390ca91cd3f0ad38613384377278c4e29b14264ca550e6e57e6c6559df830065caf902a2f8df41ad", "00ff1121276e4228ac454d62994ca1a3cd24d500a90ddaaee2e5203da658504292bd81b62c4024a8fd4d0725e6a07c254a" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "e727c7f2d36924d4f4fb46d5d0c752e8aabb5317b2e59419d1d54ca40b148e12b60908edf846b56e4d64224fb8d7e885";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "54a018053bf8dff69ce32e1f8c0c9ba658dffcfc1200cbd89c16996aece05b84ba945164b4bcdb4d8b6dac967ac78c47", "00edaafea84b25520478e67b328def37e5bdb94f18f3bce507cc24161aa4297477fff23968ae367cf0c3f2f70ed2bc205d" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "ad2f45296b5e7ac5db4596c8b7edbf078e706a4efefd43013f89f548eb1919353be15323e74f80a62e7c37108a58fbaf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "68828912c312ed14280c954102f2d4ab06d58bd9e7abd0afcafa0c349d0f09100bc5c91156cefeb9d3e33721f5d1d5f4", "69cc3a91967d5b964963044ea966e4a3e2488f3be4232f1a8723d2956c687240fb2f92d456bea0b087b1007b444141a9" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "83c6e7be210db828c8e8622d13e49e8b55a89f767e7be481fb9d492c668a0ee02dc4f5dcb69eed3bcf4445e36922e4cd";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1dc3d0da27139b88b61893d1bdee2e5fce3dcd8c4b65e1861ad0886068d32d905d343c4567ab20903f43beb1f5e3059a", "3cb44b0793c790e3f65bf78799755a8f40107cae627b57fbc03181f65b12416ba5f5fed566a95dc4b1b93a1a63550811" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "8d1181deb9d59038bb139b3524c511fa57f11f985c9d879dd6df6133efa89045a38f50e201805df28ea43a9227177785";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0085d1e93894969ef05e85263e3751285abf14ce1fb1a947d99ab869e61249ab515224ab3b0f322be36c90a3a1522f83ab", "0088fcdd8457e34a9e8105d361fb3711b544e4684aac178a3217505bb894e851181033d7c756d572abcea1aa7bb1e10c6e" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffed2119d5fc12649fc808af3b6d9037d3a44eb32399970dd0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "609b7164d1e196a5596bef71b34a8fb4eacbbea10fd41d126c16ea3578d893e898c413805230c7fd7e33ee832be72120", "00c2e379c857c01d95b53daf382fa5c196705c7f927ab3dcd8e6aa6bd4fe6767c56c178dcc1bbde32ea00afdc1a4f59fa6" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "79b95c013b0472de04d8faeec3b779c39fe729ea84fb554cd091c7178c2f054eabbc62c3e1cfbac2c2e69d7aa45d9072";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6f557ef52d480ea476d4e6bb8eb4c5a959eacf2ee66613dc784fff1660f246a1765e916d20ac0dbc4543303294772d12", "00daba49f78c8a65d8946aab0a806140136516cff6725267865e9f93e4052e072ae984f3e975e7792b67b5b1807160d429" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "bfd40d0caa4d9d42381f3d72a25683f52b03a1ed96fb72d03f08dcb9a8bc8f23c1a459deab03bcd39396c0d1e9053c81";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00f07a94c4b1dd878c2b4507549ad7557cf70f7286b95d7b7b48a0491a635379c0032d21d3fbb289bb5b7214e2372d88ee", "38934125ec56253ef4b841373aea5451b6e55b7e8e999922980c0508dc4ffd5df70627c30a2026afbf99ef318e445c78" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "4c7d219db9af94ce7fffffffffffffffffffffffffffffffef15cf1058c8d8ba1e634c4122db95ec1facd4bb13ebf09a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "61f352564999c69ce86c0336c9a9a9baddcf4555b675183ea27f682a7b0661250ff7d2d00672880e7d3fd5329b4d19a3", "1f28c529832d0b336633e3ef2b0bf97007a61b7e427c9d2ca1fc2910b0cc685d409ec423bf2f5211742b8d3b33d2f04a" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "d219db9af94ce7ffffffffffffffffffffffffffffffffffd189bdb6d9ef7be8504ca374756ea5b8f15e44067d209b9b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d23d62e8f8c286da7a8e2aaaad9b759c6852da31639ebddf7b4e4fd1ebe26806caef21c9fdccced05cbe1332bce4bd4d", "00899480daf03c5918b474d9dac0742ed97aa622d18b747c4446191b5639abc708c02ff97147b5092cc1395da611476001" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a433b735f299cfffffffffffffffffffffffffffffffffffdbb02debbfa7c9f1487f3936a22ca3f6f5d06ea22d7c0dc3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d1c1d5980bb20f6622b35b87f020a53d73fe7d148178df52a91964b541311bd88e00b35834238a0bc1401f9c3ea0c3e3", "00a50b861b701099048e0b36ec57b724b781f5c9e9d38eb345dd77eab0cb58b4fdea44e358bc6a6ae4d17476eb444bc61c" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "b9af94ce7fffffffffffffffffffffffffffffffffffffffd6efeefc876c9f23217b443c80637ef939e911219f96c179";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6626339de05be6e5b2e15c47253ad621ae13fd4d5de4e4a038eb2127fe33fd5b898cd059a43ec09d186fbf24ed8c00d1", "009251db17bc71d07b53e8d094c61b8e3049e040da95a885e4e476a445f7bfc3705f8c66a7f7d95f0697b9bf2eff9e4cc0" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a276276276276276276276276276276276276276276276273d7228d4f84b769be0fd57b97e4c1ebcae9a5f635e80e9df";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6288739deb45130ee9d84c5d7a74a64d4e1a829a657c8f06a178438b8657169c486fe7c2610ea1a01b90731edf8e2dd8", "1f2d7a092ecf4a08e381473f70519befd79e3b1484076fb837a9ef8065d05f62df4753a26f72162f8be10d5bdf52a9e7" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "73333333333333333333333333333333333333333333333316e4d9f42d4eca22df403a0c578b86f0a9a93fe89995c7ed";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2bdc91e87927364f316799ffabbfcda6fd15572255b08deb46090cd2ea351c911366b3c55383892cc6b8dd500a2cbaef", "009ffd06e925b733f3f017c92136a6cd096ad6d512866c52fecafc3b2d43a0d62ef1f8709d9bb5d29f595f6dbe3599ad3e" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffda4233abf824c93f90115e76db206fa7489d6647332e1ba3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009aaa6c4c26e55fdece622d4e1b8454a7e4be9470e2e9ecd67479f2b7bb79ac9e28ba363b206ce7af5932a154980c1612", "00cb930ccefbd759befafdb234f72e4f58e0ce770991dac7c25bc3e4c7c0765fcf1dacbc55f4430520db7bf7da401080e1" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "3fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294bb";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009004b1043628506e37308dd0107ba02d809b1504f89948161ab7a580b9e2b6c111688f9a7db9ec1e52c987cbe06f1173", "00f20b953d46c6172a883fb614c788bf860c456b1b08db110b09447ef0176f7222be4120128f8a198f37264efe6256af93" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "dfea06865526cea11c0f9eb9512b41fa9581d0f6cb7db9680336151dce79de818cdf33c879da322740416d1e5ae532fa";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "23c5694ec8556343eaf8e7076de0c810ce26aa96fce9da325a813c4b0462553d679c70a3d9d626deac3160373bf05d11", "00f4e0f85a87d3b08a699d6e83d0c8309e7e1646625f7caa73bed83e78b2e28d8384f2c0555bd1023701c10a2c1726a9dc" );
            {
                // point duplication during verification
                auto m = "313233343030"_hex;
                bn_t sig_r = "b37699e0d518a4d370dbdaaaea3788850fa03f8186d1f78fdfbae6540aa670b31c8ada0fff3e737bd69520560fe0ce60";
                bn_t sig_s = "7cd374eebe35c25ce67aa38baafef7f6e470c9ec311a0bc81636f71b31b09a1c3860f70b53e285eab64133570bd7574f";
                auto r = true; // result = valid - flags: ['PointDuplication']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "23c5694ec8556343eaf8e7076de0c810ce26aa96fce9da325a813c4b0462553d679c70a3d9d626deac3160373bf05d11", "0b1f07a5782c4f759662917c2f37cf6181e9b99da083558c4127c1874d1d727b7b0d3fa9a42efdc8fe3ef5d4e8d95623" );
            {
                // duplication bug
                auto m = "313233343030"_hex;
                bn_t sig_r = "b37699e0d518a4d370dbdaaaea3788850fa03f8186d1f78fdfbae6540aa670b31c8ada0fff3e737bd69520560fe0ce60";
                bn_t sig_s = "7cd374eebe35c25ce67aa38baafef7f6e470c9ec311a0bc81636f71b31b09a1c3860f70b53e285eab64133570bd7574f";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00916e5351bd3efecf755786fa77f6acfecf3b00cd496fbcdecd8d255120dfcf27b70e7fc9de74be9b15f72650b3eedfdd", "5bb6bcbdf478e15f77221d01d6086eae7dae44a16bdeb4afe178eb444600452789889310ad61014a3957436a59a3239a" );
            {
                // point with x-coordinate 0
                auto m = "313233343030"_hex;
                bn_t sig_r = "01";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e79f9ee594e711ae1439a237a0db174abd0b0138c4da3db1a6bc0180280b83020104580528d1030544ee4e7a17341e5c", "393de20f319b72e523b0b9ff9cd10cdc4a5b6b35850be57079e1afd30dbd6d4651139cfe0b16b32b074f81563009f7d9" );
            {
                // point with x-coordinate 0
                auto m = "313233343030"_hex;
                bn_t sig_r = "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                bn_t sig_s = "33333333333333333333333333333333333333333333333327e0a919fda4a2c644d202bd41bcee4bc8fc05155c276eb0";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009d91680bd5ac912ddecc5b609094a8d5fd12b5d5af7c5bbff8f129d9bcedd5dea45df2d09513ec7aead188885fd278bc", "00d968fbaba2bd7d866f6853a6d79661fd53f252ea936573f6bc7a32426c6a379d3d8c1a6b1e1a1aa7faa7ffdf5c4b0fbd" );
            {
                // comparison with point at infinity
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "33333333333333333333333333333333333333333333333327e0a919fda4a2c644d202bd41bcee4bc8fc05155c276eb0";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "66c48ea217602f3e0e77f402dfd386450c3a33f3b9a266d01cfa4d8cb9d58f19e7cc56315a5717ae27f931a8b6401aed", "0f47cc979e0edb9b7970ac66bc66315d3d38594dc933dfb963ccd5676efb57b14be806c0879b3cd28fe6ddeaaaf4ad92" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a03d026431e0f75a9ce6cd459eb268c44d59a00bb6facd5b816a2823845e7f65c48c69cfb4841bc0ab8c981e6c491db2", "488eb2d9321b30ebf3f1f99da618d3311b01928ae9b23764b530e2ad41dd121b6812b7a8a80f669934dd8efb0445a962" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00db12e7908092c195819ea7652a2f923f678f00aa8181f3c2cb0021e268a176737d48a48ea25a48ea2b0cce3c31f1406c", "009c46a9b415ca03d1b309c5f4735b6ce48da4d32a0eab51772dc6bb7e63d835ea7612c92a629c058af638a5bb5354110e" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "6666666666666666666666666666666666666666666666664fc15233fb49458c89a4057a8379dc9791f80a2ab84edd61";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "532b95507ca92950613dcffe7740715af07953e881d133b75989426f9aea6ed1bd22a9eb899441b29882a8e4f53f1db2", "65dda7154f92c561b2b6c9f154af3a589871f5290114a457896fd1e9af235de9f1eb7cfe0911e27cecaa30f90bec73b4" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "99999999999999999999999999999999999999999999999977a1fb4df8ede852ce760837c536cae35af40f4014764c12";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1dd1d7b6b2f677d7e10fa14bb35a74bcf83d6ea0bb308ffeb7d73634f6911e4213752173fa76b2c5be12d752b8176659", "00888325cc90b23ae34fac03a5b9a30cbcb9d24e02923d6d68e8e54066eabbf8a87272827fb2f26392dc45664bb2399e90" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6aae76701acc1950894a89e068772d8b281eef136f8a8fef5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00edc6ddb4a76167f8f7db96dbbbd87b241a2477e60ef21f22d0fb235fdd987adb15a13a9c9f05228ec7e33e39b56baf17", "008397074f1f3b7e1d97a35d135760ff5175da027f521ee1d705b2f03e083536acfef9a9c57efe7655095631c611700542" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "0eb10e5ab95f2f26a40700b1300fb8c3e754d5c453d9384ecce1daa38135a48a0a96c24efc2a76d00bde1d7aeedf7f6a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00febf3b365df31548a5295cda6d7cff00f8ce15b4aa7dc8affe9c573decea9f7b75b64234e2d5da599bf2d1e416a75007", "69205229d1898c7db1d53a6bd11079458cc40da83c16f070e5772b1d2059fef19f0f36d4471ad85ec86cf1cd4e7d90c4" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008373e65ac625a5a4110e350e7f08a0392f8261581c06a88b125a145681687fc5a6c796f16ca48977bbfc7729bba80063", "01d966a2d30fdf2b6dbcc8c9ac3b6b2150431f95fdf49e8ea5fff99f185cbcd2f9631ee3f074d680700fe693b0398583" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d8b5b751bef246a3769682966232b714b05d99a37199223e55cbc4df6941b2529e57965c94f60d88837cfd952d151abf", "009eb51727dc4665f8e74e8f5c79d34ffd11c9eab8b5b773950d1f2c446d84c158aef8bbf93b986d9b374f722d94f59f1b" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "6666666666666666666666666666666666666666666666664fc15233fb49458c89a4057a8379dc9791f80a2ab84edd61";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5f2098bc0eda6a7748fb7d95d5838a66d3f33ae4138767a7d3e221269d5b359b6456043b7a0973cf635e7424aaf1907d", "00b1e767233b18988d95e00bbb2dafbb69f92dcc01e5cb8da0c262cb52924af7976d9ded1d5fe60394035cc5509f45865c" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "99999999999999999999999999999999999999999999999977a1fb4df8ede852ce760837c536cae35af40f4014764c12";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "018cb64da6154801677d34be71e75883f912274036029bb3cf2d5679bca22c9ff10d717e4d9c370d058ddd3f6d38beb2", "5bc92d39b9be3fce5ebc38956044af21220aac3150bd899256e30344cf7caa6820666005ed965d8dc3e678412f39adda" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6aae76701acc1950894a89e068772d8b281eef136f8a8fef5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00aedfc5ce97b01b6201936777b3d01fe19ecee98bfade49ec5936accac3b02ee90bd5af667a233c60c14dac619f110a7a", "00d9b99c30856ef47a57800ea6935e63c0c2dd7ac01dd5c0224231c68ff4b7918ef23f26195467e1d6e1a2767d73817f69" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "0eb10e5ab95f2f26a40700b1300fb8c3e754d5c453d9384ecce1daa38135a48a0a96c24efc2a76d00bde1d7aeedf7f6a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "f8723083bde48fae6e2f3ba5d836c2e954aec113030836fb978c08ab1b5a3dfe54aa2fab2423747e3b4fa70ec744894c";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "078dcf7c421b705191d0c45a27c93d16ab513eecfcf7c9042fd744d6d8dcefe1036fde07248d32fcb19c725c0580a027";
                sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", "00c9e821b569d9d390a26167406d6d23d6070be242d765eb831625ceec4a0f473ef59f4e30e2817e6285bce2846f15f1a0" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "f8723083bde48fae6e2f3ba5d836c2e954aec113030836fb978c08ab1b5a3dfe54aa2fab2423747e3b4fa70ec744894c";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "078dcf7c421b705191d0c45a27c93d16ab513eecfcf7c9042fd744d6d8dcefe1036fde07248d32fcb19c725c0580a027";
                sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ffffffffaa63f1a239ac70197c6ebfcea5756dc012123f82c51fa874d66028be00e976a1080606737cc75c40bdfe4aac", "00acbd85389088a62a6398384c22b52d492f23f46e4a27a4724ad55551da5c483438095a247cb0c3378f1f52c3425ff9f1" );
            {
                // x-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "82b41176571a051a82c18e1ffbf4f3ef7146e0634755ba30fc965efec684d12830ed366acf4759fcce146e867b9108ea";
                bn_t sig_s = "52eaa43df5a95a92aee5f0002f4b4a1c870cdec040c966280be579a15e865bebc1269b084e17e727bae14b8ad6e6c73d";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "b4c1897895e4c214af7ac546230ab6ea733a6353fa11bd5d9892dc89e113dffb50a3581e58d5cac31efee0d56601bc84";
                sig_s = "b1494f4cc17f4baa96aa2c3da9db004f64256c1f28aefd299085e29fe5399517a35ae8e049ec436e7fe1b2743f2a90a0";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "c9b58945eed8b9949bd3e78c8920e0210289c1029cdb22df780b66aee80dca40e0e9142fc6db2269adbc4cb89a425f09";
                sig_s = "d672273cc979c16b3336428a60a3627bf752f9d7f1ba03c5e155cec8fcf523376feab08fe0e768f174828adcd17da0b2";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d1827fc6f6f12f21992c5a409a0653b121d2ef02b2b0ab01a9161ce956280740b1e356b255701b0a6ddc9ec2ca8a9422", "00c6ed5d2ced8d8ab7560fa5bb88c738e74541883d8a2b1c0e2ba7e36d030fc4d9bfb8b22f24db897ebac49dd400000000" );
            {
                // y-coordinate of the public key has many trailing 0's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "9ad0ec81fe78e7433ccfe8d429ffd8cc3792a7ed239104ade9b7c828332a5be57493346c9a4e944eec914acac1ab5a45";
                bn_t sig_s = "cab9be172e51ff52c70176648c6c6285630594330d8ffa5d28a47a1b8e58ec5c32c70769ed28bc553330c9a7e674da8a";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "84ba925242eaedb53cc529e4763d8995aa7315e68a47ef89f291dd29ef138e4810bc1c58a6bcbada3ac83541dc139c79";
                sig_s = "4579278b73adadb63599028b873bf5f7cee2ff01eaf0faf2d529b01211a63e78433011da37fab174607fe90a4c3d81bf";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "56a69cb5b4026268e11631f7fc35830e8a612ed79278f280e7d7e409558c43ef226ab25cf639aae7f435545cc4d8e8e5";
                sig_s = "5066494754680d61c23419273ba030df0f0b8b0a486cb0dd498298a34db478a6c133b4f5e071b6696cdbec63a74d84c2";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1099bb45100f55f5a85cca3de2b3bd5e250f4f6fad6631a3156c2e52a33d7d615dd279f79f8b4baff7c713ac00000000", "00e6c9b736a8929f2ed7be0c753a54cbb48b8469e0411eaf93a4a82459ba0b681bba8f5fb383b4906d4901a3303e2f1557" );
            {
                // x-coordinate of the public key has many trailing 0's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "6328e30a8e218904631d6e8858e1e3841a2f6c0959af1b53ad3515bee16cbb600b5abaa5123c8eeb8cdc9b2da1a8ef39";
                bn_t sig_s = "40e708de5a00178926cdb263afcb12710ae8c03b298eeadbc40522c0479a94e98dfbdce493fcf0cf7f4afb6949d9f95d";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "34b9ce48ad0aac78ff138881f3b13badae7e1cf5da7ff060c5642b22c5ec4c76fd4cd46d564676d4631bd567a7ea9284";
                sig_s = "61dae7993b4500005f45f55924c502f8803455e21a62499db2cbbc80a582c1107c8014afb4619f5d4d37fddbdf2d7bb9";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "e337217405a8457b0e31ae4e909eabe79343331c4dd0623c2b13d0981012e28d1fbf88f0101c1abae8cace1c801dfe16";
                sig_s = "948603710e13fe5b87e96ca87fb17bddb5762b9e4f2fc6e1c4acf4ee20b641518158b32bbd42884bffad25e0171a3462";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2b089edd754169010145f263f334fc167cc19dae8225970ae19cc8cb7ec73593d6a465c370f5478b0e539d69", "00d1951d597b56a67345acb25809581f07cd0eb78d9538a3f8a65f300e68a1eb78507df76de650e8f8ee63a5f0c5687c98" );
            {
                // x-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "b2f22aeb025c40f695850ca8d9243d671557ecdb28ba78ad2f3389e78fe685251a29dfbc2ebc1d7e5e1098b4b286db18";
                bn_t sig_s = "d2ac24a65d1463405bd4bb117e4d1ed7f7d9b457d51dcb1fd8704ad27de5cbc11bea45f8e3cd1ecdb51981962feaa4b6";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "f3b374deaa912309be3a08722fcd0fa17fbad8a0d674a96b1140efe2f9451e373029546b84a565dd88b6816b03c69912";
                sig_s = "f44fcc8e2513a2574e9c88de1960e8d7f6c607fb0aa6400362ccacf86e56cc44bfa6e233a993800fe1385e747312393b";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "de778636b0c8775a48e8f7c2da3ce056ea18c0f7b61a6ceebccdc1db0462a739a9f623b342d82b5cdba9329fd32d4870";
                sig_s = "5f843dc49e8c8642d0ade1fbd635ee1ea6f6da8f980ec1d839de2b37ba7082668179cb80e7c97775e77c7afe8dfb9791";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00fb01baad5f0b8f79b9cd104d12aab9310146add7d6b4c022d87ae6711178b94d618ca7b3af13854b1c588879e877b336", "208b3f5ad3b3937acc9d606cc5ececab4a701f75ed42957ea4d7858d33f5c26c6ae20a9cccda56996700d6b4" );
            {
                // y-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "8f6f35102ebc10571603d65d14d45e2658e36a961d790348df0ed3ee615d55919e1c31d02e48b4c29b724e75094e88e1";
                bn_t sig_s = "1674424d64d3a780b031e928ee3b246a3703868aef1afcc6b50dd217ae6bdcb5fc7f59d2b14dc4dd08f22853abef621b";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "81fdae0b7e18cca48e0bae1a4e2c96f3973b0f661ccae269c1f0535265954e76473f51710fd2eca0b014e0386bdb387e";
                sig_s = "b4fd60411ae7ad836c8b1768bf44fe126d753781628a2b34f21fe1fbc961d21a153d3838e0200ddf8b7c16819230c0e2";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "f6b94cdc2083d5c6b4908063033dbe1817f5187a80fbf21e0155ebc16c3b14b06282171a63d8c6ad173bad8aa40b8406";
                sig_s = "569db82936c0d284c752149034a28e2415b57247c723077d8a5a7c9725ebca7603de5b7a41c53fed2bed8143a9bb8beb";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00fb01baad5f0b8f79b9cd104d12aab9310146add7d6b4c022d87ae6711178b94d618ca7b3af13854b1c588879e877b336", "00ffffffffdf74c0a52c4c6c8533629f933a131354b58fe08a12bd6a815b287a71cc0a3d92951df5633325a96798ff294b" );
            {
                // y-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "89d3d1a5c2ce6b637cc9e30a734ea63d34a7a72630400ee82916b79fa9a9a83b4e2faf765ddcf1fa596a4c026293ea06";
                bn_t sig_s = "9013c5c51bde3c114ae0ce19141c6c72bbf0a8f75885257f202240af212064f0fa9b1409d8c5e195a8db9d996eb1cd67";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "4bb0ddb7af2d58e75b17f7ea81c618ca191efaa374026901fc1914b97b44ed64873404b40c249ee652e9685c67347881";
                sig_s = "af0bc80678b411ce0ea78c57f50bbb9b11678e001d92f2f49ad17af4759c7a013d27668ed17b13bc01e13eb9ee68040f";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "024deac92bccdf77a3fe019fb5d35063c9ad9374bf1e7508218b25776815eb95f51c8c253f88991c3073c67ca8bbd577";
                sig_s = "8da6b6f9fde42f24536413f8c2d3506171c742b6a0883de116b314d559388b41630aa24c485e090fee5f340c79486164";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }
        } // End of Google's Wycheproof tests ecdsa_secp384r1_sha3_384_test

        // Test vectors from Google's Wycheproof RSA signature verification tests.
        // Generated from: 'ecdsa_secp384r1_sha512_p1363_test.json'
        // URL: 'https://raw.githubusercontent.com/google/wycheproof/d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d/testvectors_v1/ecdsa_secp384r1_sha512_p1363_test.json'
        // Note:
        //     Test vectors with flag(s) 'BER', 'BerEncodedSignature', 'SignatureSize', 'MissingZero', 'InvalidEncoding' were not included.
        //     All test(s) with BER/DER decoding related errors were not included because they're not part of this test scope.
        //
        // Algorithm: ECDSA
        // GeneratorVersion: 0.9rc5
        // Header: Test vectors of type EcdsaVerify are meant for the verification of IEEE P1363 encoded ECDSA signatures.
        // Notes:   ArithmeticError - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA have arithmetic errors that occur when intermediate results have extreme values. This test vector has been constructed to test such occurences.', 'cves': ['CVE-2017-18146']}
        //   EdgeCasePublicKey - {'bugType': 'EDGE_CASE', 'description': 'The test vector uses a special case public key. '}
        //   EdgeCaseShamirMultiplication - {'bugType': 'EDGE_CASE', 'description': "Shamir proposed a fast method for computing the sum of two scalar multiplications efficiently. This test vector has been constructed so that an intermediate result is the point at infinity if Shamir's method is used."}
        //   IntegerOverflow - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified, so that the original value is restored if the implementation ignores the most significant bits.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   InvalidSignature - {'bugType': 'AUTH_BYPASS', 'description': 'The signature contains special case values such as r=0 and s=0. Buggy implementations may accept such values, if the implementation does not check boundaries and computes s^(-1) == 0.', 'effect': 'Accepting such signatures can have the effect that an adversary can forge signatures without even knowning the message to sign.', 'cves': ['CVE-2022-21449', 'CVE-2021-43572', 'CVE-2022-24884']}
        //   ModifiedInteger - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. The goal is to check for arithmetic errors.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   ModularInverse - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where computing the modular inverse of s hits an edge case.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['CVE-2019-0865']}
        //   PointDuplication - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA do not handle duplication and points at infinity correctly. This is a test vector that has been specially crafted to check for such an omission.', 'cves': ['2020-12607', 'CVE-2015-2730']}
        //   RangeCheck - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. By adding or subtracting the order of the group (or other values) the test vector checks whether signature verification verifies the range of r and s.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   SignatureSize - {'bugType': 'LEGACY', 'description': 'This test vector contains valid values for r and s. But the values are encoded using a smaller number of bytes. The size of an IEEE P1363 encoded signature should always be twice the number of bytes of the size of the order. Some libraries accept signatures with less bytes. To our knowledge no standard (i.e., IEEE P1363 or RFC 7515) requires any explicit checks of the signature size during signature verification.'}
        //   SmallRandS - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where both r and s are small integers. Some libraries cannot verify such signatures.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['2020-13895']}
        //   SpecialCaseHash - {'bugType': 'EDGE_CASE', 'description': 'The test vector contains a signature where the hash of the message is a special case, e.g., contains a long run of 0 or 1 bits.'}
        //   Untruncatedhash - {'bugType': 'MISSING_STEP', 'description': 'If the size of the digest is longer than the size of the underlying order of the multiplicative subgroup then the hash digest must be truncated during signature generation and verification. This test vector contains a signature where this step has been omitted.'}
        //   ValidSignature - {'bugType': 'BASIC', 'description': 'The test vector contains a valid signature that was generated pseudorandomly. Such signatures should not fail to verify unless some of the parameters (e.g. curve or hash function) are not supported.'}
        {
            auto pubkey = curve.make_point( "2da57dda1089276a543f9ffdac0bff0d976cad71eb7280e7d9bfd9fee4bdb2f20f47ff888274389772d98cc5752138aa", "4b6d054d69dcf3e25ec49df870715e34883b1836197d76f8ad962e78f6571bbc7407b0d6091f9e4d88f014274406174f" );
            {
                // signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "814cc9a70febda342d4ada87fc39426f403d5e89808428460c1eca60c897bfd6728da14673854673d7d297ea944a15e2";
                bn_t sig_s = "7b0a10ee2dd0dd2fab75095af240d095e446faba7a50a19fbb197e4c4250926e30c5303a2c2d34250f17fcf5ab3181a6";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + n
                m = "313233343030"_hex;
                sig_r = "01814cc9a70febda342d4ada87fc39426f403d5e8980842845d38217e2bcceedb5caa7aef8bc35edeec4beb155610f3f55";
                sig_s = "0084f5ef11d22f22d0548af6a50dbf2f6a1bb9054585af5e600c49cf35b1e69b712754dd781c837355ddd41c752193a7cd";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 256 * n
                m = "313233343030"_hex;
                sig_r = "0100814cc9a70febda342d4ada87fc39426f403d5e898084280d6f6c4c54ffc59f2e8c9b538f242cc160c3ec02b7597388e2";
                sig_s = "000084f5ef11d22f22d0548af6a50dbf2f6a1bb9054585af5e600c49cf35b1e69b712754dd781c837355ddd41c752193a7cd";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by n - r
                m = "313233343030"_hex;
                sig_r = "7eb33658f01425cbd2b5257803c6bd90bfc2a1767f7bd7b9bb4483212b9f6e08e58c6c6bd52b610715198180387b1391";
                sig_s = "84f5ef11d22f22d0548af6a50dbf2f6a1bb9054585af5e600c49cf35b1e69b712754dd781c837355ddd41c752193a7cd";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**384
                m = "313233343030"_hex;
                sig_r = "01814cc9a70febda342d4ada87fc39426f403d5e89808428460c1eca60c897bfd6728da14673854673d7d297ea944a15e2";
                sig_s = "0084f5ef11d22f22d0548af6a50dbf2f6a1bb9054585af5e600c49cf35b1e69b712754dd781c837355ddd41c752193a7cd";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**448
                m = "313233343030"_hex;
                sig_r = "010000000000000000814cc9a70febda342d4ada87fc39426f403d5e89808428460c1eca60c897bfd6728da14673854673d7d297ea944a15e2";
                sig_s = "00000000000000000084f5ef11d22f22d0548af6a50dbf2f6a1bb9054585af5e600c49cf35b1e69b712754dd781c837355ddd41c752193a7cd";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + n
                m = "313233343030"_hex;
                sig_r = "0184f5ef11d22f22d0548af6a50dbf2f6a1bb9054585af5e5fd3ad1cb7a61dc9507f6eeb2a65341ad0cac035dfee58d140";
                sig_s = "0084f5ef11d22f22d0548af6a50dbf2f6a1bb9054585af5e600c49cf35b1e69b712754dd781c837355ddd41c752193a7cd";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 256 * n
                m = "313233343030"_hex;
                sig_r = "010084f5ef11d22f22d0548af6a50dbf2f6a1bb9054585af5e276f975129e9147ac941628fc0cd2aee42c9ed8741e6bd1acd";
                sig_s = "000084f5ef11d22f22d0548af6a50dbf2f6a1bb9054585af5e600c49cf35b1e69b712754dd781c837355ddd41c752193a7cd";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**384
                m = "313233343030"_hex;
                sig_r = "0184f5ef11d22f22d0548af6a50dbf2f6a1bb9054585af5e600c49cf35b1e69b712754dd781c837355ddd41c752193a7cd";
                sig_s = "0084f5ef11d22f22d0548af6a50dbf2f6a1bb9054585af5e600c49cf35b1e69b712754dd781c837355ddd41c752193a7cd";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**448
                m = "313233343030"_hex;
                sig_r = "01000000000000000084f5ef11d22f22d0548af6a50dbf2f6a1bb9054585af5e600c49cf35b1e69b712754dd781c837355ddd41c752193a7cd";
                sig_s = "00000000000000000084f5ef11d22f22d0548af6a50dbf2f6a1bb9054585af5e600c49cf35b1e69b712754dd781c837355ddd41c752193a7cd";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=0
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=0
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=0
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=0
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=0
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n - 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Edge case for Shamir multiplication
                m = "3637323636"_hex;
                sig_r = "ac042e13ab83394692019170707bc21dd3d7b8d233d11b651757085bdd5767eabbb85322984f14437335de0cdf565684";
                sig_s = "8f8a277dde5282671af958e3315e795a20e2885157b77663a67a77ef2379020c5d12be6c732fd725402cb9ee8c345284";
                r = true; // result = valid - flags: ['EdgeCaseShamirMultiplication']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33393439313934313732"_hex;
                sig_r = "d51c53fa3e201c440a4e33ea0bbc1d3f3fe18b0cc2a4d6812dd217a9b426e54eb4024113b354441272174549c979857c";
                sig_s = "0992c5442dc6d5d6095a45720f5c5344acb78bc18817ef32c1334e6eba7726246577d4257942bdefe994c1575ed15a6e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35333637363431383737"_hex;
                sig_r = "c8d44c8b70abed9e6ae6bbb9f4b72ed6e8b50a52a8e6e1bd3447c0828dad26fc6f395ba09069b307f040d1e86a42c022";
                sig_s = "01e0af500505bb88b3a2b0f132acb4da64adddc0598318cb7612b5812d29c2d0dde1413d0ce40044b44590e91b97bacd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35363731343831303935"_hex;
                sig_r = "d3513bd06496d8576e01e8c4b284587acafd239acfd739a19a5899f0a00d269f990659a671b2e0e25f935b3a28a1f5fd";
                sig_s = "366b35315ce114bffbb75a969543646ee253f046a8630fbbb121ecc5d62df4a7eb09d2878805d5dab9c9b3880b747b68";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131323037313732393039"_hex;
                sig_r = "b08c4018556ca8833b524504e30c58346e1c0345b678fdf91891c464a33180ed85a99bc8911acf4f22aceb40440afc94";
                sig_s = "4a595f7eed2db9f6bd3e90355d5c0e96486dc64242319e41fc07be00a732354b62ec9c34319720b9ffb24c994b1cf875";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131323938303334323336"_hex;
                sig_r = "2b08f784617fd0707a83d3c2615efa0c45f28d7d928fc45cd8a886e116b45f4686aee97474d091012e27057b6ba8f7e6";
                sig_s = "c440aa6ecb63e0d43c639b37e5810a96def7eec8e90a4c55e5b57971c48dfb4e850232fbb37bd32bb3b0523b815ff985";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39383736303239363833"_hex;
                sig_r = "0609f4ec120c8838bda916f668e9600af7652e1d3f7182734f97f54da5d106bbfd216c32f227b76d583de1c53949b2ee";
                sig_s = "46926dffc766ff90c3b921b3e51a2982a1072314c1fdfb4175de7adea5a6f97bdff587a473504a9c402aac7c05bd4785";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3230323034323936353139"_hex;
                sig_r = "5ae2220e4716e1ef0382afcc39db339e5bd5f05e8a188d4a5daaab71c6c35263ee8820a34558092877449ebb15898c5c";
                sig_s = "c4d38e2e85451c43ee35b0c56196cbf3059acf2b8b529f06dc1de9b281d9b0f3f3983df8936e944ab0b18330a342ee88";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343531363639313830"_hex;
                sig_r = "51fb84ed71d436c737ab24e2a45c68f8f623748be2caebd89e02bfc89309b8350042ab1b97849b9f680f044a58765175";
                sig_s = "d4a8f60791657a8c12985fd896ac77e7d95cb050582f2466471dc2c6dcf90db05ce34beadbfcfe690dc56c0cc9944007";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303933363835393531"_hex;
                sig_r = "40159290d161df6b3f81a92cefb6df56149d588e7b886bf24939f5c8b6bb515d325b3764f0ed284a77fa9081ccfa5237";
                sig_s = "bd55dfb47709287ce7b88dfd96ac7543eeba9bd31b8c91f203d2b90418122406399c80a53539b81f1cb60fa3b23a2563";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36323139353630323031"_hex;
                sig_r = "d7fb9f53865cdf9d4cad6f66981aea35a1454858ceb678d7b851c12a4c6644fe1915a4b219b51389a5ae2c98a433cc3a";
                sig_s = "94ad75c3dea88740205cab41032dfe149341cf4ee94dcd2f0c8bbe5af5860b30b5e1f764b2c767b09fd10761050c989c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35363832343734333033"_hex;
                sig_r = "157ef8f85cdb9257983d06a7f29674752659097364b401e701705b3bd9ead884fd32141320ae76ae05f6fc7ec155d6c2";
                sig_s = "ccadc3851020e41dd91bc28a6c073409136a47f20b8dbf2553fd456a8ed5fa7e73e4ec59dca499e0d082efbb9ad34dc7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33373336353331373836"_hex;
                sig_r = "e763001769c76f6a6d06fad37b584d7f25832501491bec283b3b6836f947dc4e2cef021c6c6e525b0a6a3890d1da122a";
                sig_s = "acbd88729cce3992d14ec99e69ff0712b82a33a1c1e8b90e1399c66fe196f7c99bdb3ff81db77dc25ae6f0c1a025117d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34373935393033373932"_hex;
                sig_r = "c6425b6b046ec91ebc32b9e6de750e5d3d36d4ddc6dffd25ba47817385a9466f6fc52259c7d02c66af5bf12045b5659d";
                sig_s = "84cdc06e35fecc85a3e00b16488eac3584942f663d8b59df111c0650139d7cda20d68dccae569d433170d832147bc94c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39333939363131303037"_hex;
                sig_r = "3061f090e4932133a0e08ac984d1c8d8d4f565e21cf15427671503880341265cd44f35a437ee3c3a8857579dd7af0c35";
                sig_s = "93ae374a0f63dcbe41a1b7b07a50faf2b33f35e0b6600bb36aa5cda05238640fa35c635c0fa78e1410f3a879bbb8a541";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303837343931313835"_hex;
                sig_r = "0ccc627f35454cc84e08a828f5bd5f5e41eeeaa40475bcc2e71ff372e8c718a5e179d3b7f2d7051db9060c4c978eb638";
                sig_s = "b12d0240afbdfc64c60861548c33663b8960316a55f860cc33d1908e89aa6fc9519f23a900e0488fa6a37cfb37856565";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323336363738353030"_hex;
                sig_r = "e72419fb67ebbcc0de9c46ce5475c608f9de7e83fc5e582920b8e9848000d820d393fdac6c96ea35ce941cb149516400";
                sig_s = "6aa19934ef60f4a247bc261ba256283a94857a268f42a0939c95a536fbd4f8e1f1c285a7b164c12213abb9e3393cbe9f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343438393937373033"_hex;
                sig_r = "8b740931f9afa8a04c08cde896b7fdd9aca3177d5e4a3e5a51e54bfa824b66ab11df4e90f49798d644babfede7830224";
                sig_s = "afd91e7ce15059a5b5499e5aef4afa91fd090e4e5029b3f4348f0d4349df11745869f9255117eea405a78af5dd6a646d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35373134363332383037"_hex;
                sig_r = "989024bce204a7539fbd2b185ecf375590d873177c1ff26bbf755838ae5bcde180054663702ac3a4e68fe8b58fd88c70";
                sig_s = "bdbedf64e424dbd7f979f83adef3fc85077fa76f8b1724815b5b8c24fde7fbd72f4b369a415d9bbf565cdc459bdce54c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323236343837343932"_hex;
                sig_r = "22624fc23403955c0c9f5b89871177fa53879c8424de3b4ab1bcbcddc6e57b870b0491b848e19f728722b3163f4aa328";
                sig_s = "5bb82642cdaa84d6977fb95b3ede4ec7f2d54881cf435636d3509816f13ebb7be24fd7d4e1e81fddf07bde685e8d630d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35333533343439343739"_hex;
                sig_r = "da5a2daa7437df4566ebba6ac5ed424655633e354ef4d943dc95ddefb0dae69f3616e506cc8cb5bc433a82ba71f6feb4";
                sig_s = "5107b24041bba45073ce54488a5aef861e7805bbb8f970aedc1c59149cfe72c7025e2d117337e8677c88ef43374e6907";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34373837333033383830"_hex;
                sig_r = "2b0659fb7fa5fc1fce767418c20978de9a6a59941fc54f8380619b2ab2a7d6039de5373fbb503c24f2ce38e9c57995de";
                sig_s = "0d94dba98dd874bfffeac96a9295b6ab667708b8e33252edc029574c484a132135b13e52db6f877987c1be4f51fca193";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323332313935383233"_hex;
                sig_r = "4a5a14f1ecf053bf3ec14843db8c7dd153e9545d20d76345a9e1d1a8fcb49558ca1ee5a9402311c2eaa102e646e57c2c";
                sig_s = "1573b8b4b633496da320e99a85c6f57b7ee543548180a77f7fced2d0665911cb4cde9de21bc1a981b97742c9040a6369";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130373339333931393137"_hex;
                sig_r = "104e66e6e26c36633c0af001f0d9a216236816923ec93b70bea0a8ff053a15aaaef5fe3483e5cc73564e60fe8364ce0e";
                sig_s = "ec2df9100e34875a5dc436da824916487b38e7aeb02944860e257fd982b01782b3bd6b13b376e8a6dbd783dfa0d77169";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31383831303237333135"_hex;
                sig_r = "4b06795da82bda354e8d9422a76c7bc064027fcdd68f95b7bc6177a85b2d822c84dc31cb91fc016afa48816a3a019267";
                sig_s = "18e31018e312d3dd3dd49ec355fdb0def3bb3e44393c26cf1bc110b23a3aacf6c442bfcec5535ce37527d0e068f75c03";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36303631363933393037"_hex;
                sig_r = "ad75ca5a3df34e5a6d3ea4c9df534e8910cfb1d8c605fc398fbee4c05f2b715bd2146221920de8bac86c2b210221bcff";
                sig_s = "a322d3df3bb2cf9e4215adf1ff459e70f2f86bec6dd6af5d04ae307d21ed5955136c8e258fdc0f9cbd6cf89c31aa691f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38383935323237303934"_hex;
                sig_r = "b0fa6289cc61bab335932ea1ac6540462653cc747ef67827825f77689a4398602297835d08aa16e23a76dea9f75404ef";
                sig_s = "278d654a0b50c57d13f9c9c8c7c694001167f8e3b71491772a7427f1410fb6de518740c22e455e58de48846479b300cc";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353830323334303934"_hex;
                sig_r = "c216cb4fe97facb7cd66f02cd751155b94fa2f35f8a62ba565aca575728af533540ff5d769b7c15c1345ab6414e15068";
                sig_s = "278a8a372b75d6eb17a4f7c7f62d5555c7357a1a047026bead52185cbcc01d73b80a1577e86220b2278da2b1ee8c983a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33393635393931353132"_hex;
                sig_r = "9591c80453cffbcd0b8d6d20fce0cbb2a458e54aed7ba1c767e6c017af4c4aa07a76859c0b249f6692a3c9ace893f14e";
                sig_s = "893b567cd2959cd60557d3d6013d6e1741421a6edc5bc18244b3e8d7744e57928ce006a3fbd6e6324cb8ea3e5177e7e3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323838373332313938"_hex;
                sig_r = "350b5515ba9785f149e2a566c14f4178757bb325179888f526f7db11161aedcd752551381316c2713f5de21d3d517af0";
                sig_s = "97d48a90c3bb3444736bec69db0649f82428b39238ada6048a0bead84f2f3b73816b48fed4d57b5f87a194ce4004ed7b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323330383837333139"_hex;
                sig_r = "833210c45d2448d9a4d69622d6f2193e64c65c79d45d62e28f517ca5c68eef05a2e98b1faed4cc87cbdbec6fe6bb8987";
                sig_s = "b777b44cd30e6a049dc56af19a251d955c1bbab0c307fe12e9e5382fd48c173db0292f0b1047da28ee18518e11688eea";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313239303536393337"_hex;
                sig_r = "7728ef10d9d5f3f32132716e6b403926929b05201700658d4b7f25a0692f153b8d666fd0da39888ab6234212659268d0";
                sig_s = "55df9466ee2c98225a2b0c4ff77622f9d11b4e48aa7f9279cdc2e245fdd9b9f4282106e25a458ff618bc3ca9422bea25";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373438363536343338"_hex;
                sig_r = "552040701dba17be3b4d5d6e136ce412b6a4c50ce1ee53415d8100c69a8ee4726652648f50e695f8bb552d0df3e8d1c4";
                sig_s = "1374972b2f35b2fd86d45ed0c9358b394e271575e429ac8aa60eb94b9df7e755d9317fb259269e9d3b1db8d48d91dc7e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37353833353032363034"_hex;
                sig_r = "fe6ef07056ce647128584bec156b68b8005f42d8c85dfb122134c488cc0e72cf8f06700417d7ff694b45e894ec23cbbd";
                sig_s = "7f5e33c5bfa697c144d440b32d06221f630a9ccaa8e9a0489490c04b86e8daae0e41d2466429b4b3cc1d37348e36cc0b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333237373534323739"_hex;
                sig_r = "e009fc1a13d282bd37f10693350a5b421a0039713d29cb9e816e013c173bd1ec2bd6eb6bd88429023ee3d75d9a5ec06f";
                sig_s = "0b8bd481982a6e52355bcde5fe0092abac41f0543c31d1928b9a585e63e9520e24a65f46db2696e1b85a65c4e5240879";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373735353038353834"_hex;
                sig_r = "acee00dfdfcee7343aeffa8514b11020c5435027887529d255bdbd45a90f160c68f05bd4b567daa8fa14e5807f5167a4";
                sig_s = "1c9fdf546190970aa33121a3043280669be694e5f700b52a805aa6101b4c58f0467e7b699641d1d03f6229b2faf4253f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3137393832363438333832"_hex;
                sig_r = "8a4ee1e3bb251982475877d18763fafcf49ccc8b0fec1da63b0edccbb8d3e38608a2e02d0d951031179e12ac899d30c3";
                sig_s = "73cb62ad7632cd42dff829abfbfcb6165207e3708ed10043c0cdee951c7f8012432696e9cf732dcbadb504630648419f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333936373737333635"_hex;
                sig_r = "3903b59f837ff5f41f42cbe3e2fc8e17d859cbb35386c4327d3947fb012b3629fea911c83cefdbd503aebbcc1114afd1";
                sig_s = "0e5be9094b5a22ade00c24644f476baad0f7741dfb2ce9644a1c45769404f8dccc522017c2b8cc630f1a0ef5fee99fe8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35393938313035383031"_hex;
                sig_r = "7717ffc8d0811f357299423c56ec181c58f1981f5c1dd4f346f6a2ad71d3582e203a11e8609c1146ff3247a1820f832c";
                sig_s = "96c89ec707da3cd8b09084b065e3265327a536a974c4285155388011e348f2e7f005ae7e3e502732fc2971ac13fd72c0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3136363737383237303537"_hex;
                sig_r = "a21519ce3533c80826f1e47fa9afde7096151144291134421990285a8d89a8c2d4afdadd547a923dcc17bfcdd0e9ffb9";
                sig_s = "40577245dd2e022c8ed8b5de7b8c26f31307429a7a64e5729311cc4128e3b486867e61b4a8a1cd0731792eb1466d08f3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323036323134333632"_hex;
                sig_r = "a727addad0b2acd2942cb1e3f7b2917ca65453275198b06436a993bfc982d3f54620c395e253d57b8fe026efcf7252f9";
                sig_s = "7a19811aa4c12c45c3c041e7c614d0d98051ca7a0c57a9a107d552793ba1d0debb373525aafcc13ae1acd50a42a89adf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36383432343936303435"_hex;
                sig_r = "22287277872d175d8a3ff5be9818658f845eb9c1b2edc093ae82a75aa31cc26fe1771b4bfbd4c320251388d7279b5245";
                sig_s = "b47d1833867e889fcfd7ac171855293a50aa6db24c6522e374fe87be12bf49b13c8b5e1455a2f25aa7912f799eebe552";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323639383937333231"_hex;
                sig_r = "a0f41362009b8e7e7545d0f7c4127e22d82ac1921eb61bf51e9ea711e41557a84f7bb6ace499a3bc9ebca8e83728787b";
                sig_s = "1f6e0c15a3e402370885e2aceb712280ebc45b63986357765b7e54b06cd00db8308e4715c39d48d246030bf960e6a2ff";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333837333234363932"_hex;
                sig_r = "4144e1c6ad29ad88aa5472d6d1a8d1f15de315f5b281f87cc392d66d7042547e6af7c733b31828f89c8a5dafce5bb9af";
                sig_s = "f5d0d81f92428df2977757c88ba67f9e03abd4c15b1e87fa1dd49e601a9dd479e7c3dc03a8bfea60fcfc1c543931a7de";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34313138383837353336"_hex;
                sig_r = "5f177fc05542be6e09027b7eac5eb34f34fc10ad1429e4daaea75834de48dd22626f2bf653dfcc46234921d19b97406b";
                sig_s = "7def6c993a87560425f2c911046357c4b1c4c376bfa22bb45d533654fea6f565ba722147b2269ea7652f9c4af62ed118";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393838363036353435"_hex;
                sig_r = "bd77a8ff0cd798d8f6e75dfbbb16c3ee5bf3f626dcb5abdfd453b301cb4fd4caee8e84dd650a8b4cf6655dea163788c7";
                sig_s = "ef8f42394469eb8cd7b2ac6942cdb5e70dd54980ad8c0c483099573d75b936880459c9d14f9e73645865a4f24ee2c4ce";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343739313135383435"_hex;
                sig_r = "a02e2196258436da6a35a2f73cf6b08880f27757566ce80c7fc45f5dcbaec62d3fcebb784b4a650e24c1a997e4b971f7";
                sig_s = "f1195d2ba3321b6938e04169d7baf605001b6311f08a5e82157a7675d54993f2fd1e41f8c84fc437a1a139d2e73e8d46";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35303736383837333637"_hex;
                sig_r = "686c5dfe858629125fdee522b77a9b9be5e03a347d79cb4c407f17fd25c97293cd99711f33e77814bd30d2453d3a86c1";
                sig_s = "509ac9b18c1b2b5a2b1b889d994b950743a988c2fcfb683e89211a43da6ee362c2e414d84fe82db1904b81701c257822";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393838353036393637"_hex;
                sig_r = "83ce818ecd276432a8ddfe75406d01329e76d7586cd6f611c1fe1a0913ad80014c2156381942d58dd6356e44ccdc52a8";
                sig_s = "36a35983b97a9ae2a19cf05ba947dd880c973d5c78f9676ebbcb0b40d639124030c137236232f1fad15afd71c52ad8ec";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373231333036313331"_hex;
                sig_r = "7cb78ebb712b5a2e0b0573d28440a5da36bd2338805d90ef3b0c1178ae613be8ae8bf548af4e7403e5a5410462afc2e3";
                sig_s = "8631a82cbdb8c2c7df70f012405f06ad0ab20d6c4fbceb3e736f40fdff1a8e5f6e667a0e77259f277494de84ec0de50d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323034313031363535"_hex;
                sig_r = "85110fe21156b7764b91bcb6cf44da3eb21d162395071c216a13b5920d67a31aaa20dfc4669cf32c04964d0831bcdc29";
                sig_s = "e19187033d8b4e1edf7ab8eaaae1e13c80c0c4db51d921ccf62f424524cbd530d07de2cf902a0ecda5e01206ae61e240";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33313530363830393530"_hex;
                sig_r = "0fd621a892ee5a3eb0bcb80f3184714a6635f568d92f41ad8d523887d5b82d2b930eb5ff2922fda1a3d299f5a045837f";
                sig_s = "1278725a607fa6f2fc7549b0de816fe2f88e3a1ec1ccaf9fb58e70a0f6646c2d7aad6e4f73d116e73096bdef231d0c89";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373237343630313033"_hex;
                sig_r = "802cbe405d3ce9663b0b13c639aa27730b3377ce42521098ae09096b7fc5e7ac998b6994344e89abfb50c05476f9cae8";
                sig_s = "9aa7258c0dc4eff4b2d583575368301e2a7865cfaa3753055a79c8b8e91e94496a5d539181c2fd77941df50fe87453cd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3134353731343631323235"_hex;
                sig_r = "859b0446949d7f78a0301ac4cc02b599a758fd1be006bf1a12570015869e59b9a429ce1c77a750969f49e291f6ab8994";
                sig_s = "99a812a1acc2c646814315cf9b6290d2232236cdf131f9590088e75a55786cdfc9d9027ec70056408ab55445fd79fe60";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34313739353136303930"_hex;
                sig_r = "dbcc7ee9fa620e943193deae3f46b3142779caa2bce2df79a20639c8d01bce414a61f72764c1ec949c945320f5ee2a1d";
                sig_s = "1d9879787b880bd05db39bac07bfe3e7d0792932144e211e81f21da9621b83bff11bc52bcc7cb40cf5093f9bad8650fb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35383932373133303534"_hex;
                sig_r = "7a1f9fbd0f6e776c3e3a3c798f5c0d9e20f0e2f3f4d22e5893dd09e5af69a46abc2f888d3c76834462008069275dfeb9";
                sig_s = "45e6d62a74d3eb81f0a3a62902b8949132821b45d8e6cad9bb3d8660451727cdf7b332a9ac7bb04604991312143f8a6a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33383936313832323937"_hex;
                sig_r = "047962e09e1b61823d23726bf72b4dde380e032b534e3273db157fa60908159ab7ee4cadce14fd06ebe8e08e8d8d5a07";
                sig_s = "1892f65ee09e34ce45dd44b5a172b200ce66b678b0e200c17e424e319f414f8dfbb2769a0259c9cc105191aa924e48d5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38323833333436373332"_hex;
                sig_r = "8f02799390ab861452cd4949942cbbcc25cad7c4334c4bc6146fbef8ad96c86f923fbf376d9ab79073e5fcb663f1ea91";
                sig_s = "ce15d9862d100ff95ad7368922eec3f6d7060ce412c01ff13870aa61626ee49edf39bb27005ecbe406bb6825f74c0438";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333636393734383931"_hex;
                sig_r = "1879c4d6cf7c5425515547575049be2a40c624a928cf281250f8bdcbf47e9f95310d0992c9887dc6318b3197114f358e";
                sig_s = "e1116bf68320bade7d07a1a9651512d60b551af8625b98b5eb8ca222d4073ae5c140a80e5dbe59f073647daa00837aee";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313939313533323239"_hex;
                sig_r = "31dced9a6767f39045472749baec1644ae7d93a810a4b60eb213c02c42de65152ffc669af96089554570801a704e2a2d";
                sig_s = "3022ecfbc88a72b9c50ef65344765b615738f2b3d420ade68cbf3ec40bef0e10c5cc43bcfe003bb6f17ec23802c40569";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35363030333136383232"_hex;
                sig_r = "f4bdf786c61c5f1ce7568638ba9dbc9a134e27fc142003bf9870353980a8f4c2fbd03c8d0171e4048ef30db6fe15388a";
                sig_s = "d0e96768bc6adc91f93ae5704e86888853f479f32a45bfd436dc8a030603d233c56880124b7971362aa11b71315ae304";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383639363531363935"_hex;
                sig_r = "ec0f635b7ce31988a07f41b3df35ca03c70e376bfb3b6ab24831a83be2121b9f9e93928b10a8f5fc0322bdb9edd406fe";
                sig_s = "66618ccb473c6dac3b14cfab6dfb24d219b37aec63425067c2c1c631d64a80b9cab6445f5a5439adb28bb99daa9234a5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36353833393236333732"_hex;
                sig_r = "4f2bea24f7de57901e365d4c332ddb62d294d0c5fd58342a43bdd3ba5cbaf25adaddb5944bfef9dcc88f94d93650bbbb";
                sig_s = "0851b97ddc433e4521c600904970e2bf55aa901e1aaaaf06818377f84a28e033a49eebc21ffe9cff3cbefd0963fbed00";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3133323035303135373235"_hex;
                sig_r = "72a9bab30f8da1437f17115cc37b6ef8cf6591ed934d596675ad7b000c6a74cca5f37210a68228a58023790e3726c357";
                sig_s = "12d697c4e20b18f63a3e0164dca8ca4a5fa0058ad7cd1c571cef356e85fd8f56ab7963d8aba824e8d31efb3e690c27b9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35303835333330373931"_hex;
                sig_r = "33b7105f4cc98a1ea2abad45dbbe3761b4613ddd350e62da91560da694be3e84b1684f9a8ee4b3f556c61d02af544462";
                sig_s = "2c86e3a216dc7dd784cdcbf5084bdf6cdc1c7e67dbd61f9f6ed161fda4d4c26167e5b12731cf2b0cf5d9a5f0b6124939";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37383636383133313139"_hex;
                sig_r = "252e3b5b60b8f80748b83623e30013723115cabcc48770c0ab6e7ee29c429ef1d9da78db3a9a8504133b9bd6feceb825";
                sig_s = "1ba740f87907cf6d450080f7807a50f21c31cd245dd30f95849a168d63b37628e8043c292ab7f130a4468eaf8b47e56d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303832353339343239"_hex;
                sig_r = "b8694dbf8310ccd78398a1cffa51493f95e3317f238291771cb331f8e3a9753774ae3be78df16d22b3fbe9ad45bed793";
                sig_s = "daaead431bbdbf8d82368fbbd2473695683206ee67092c146b266ed32f56b31cb0f033eebf6c75118730eef7b7f96ba7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130303635393536363937"_hex;
                sig_r = "d37ba39cd1b5289e7aa3f33afefa4df6821a07d3e8ee1c11e7df036c37e36214bb90264633d4c395644cd2cc2523833f";
                sig_s = "8b0d58ed75af59e2abbcec9226836f176b27da2d9f3094f2d4a09898136436235025208cf5444265af66fed05b3dc27c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303234313831363034"_hex;
                sig_r = "b4ef419020c0dcbdeeeed76c255560f1ed783c0f9e7fcea4c08a0714b9d1f491fda9ae7bb1eb96d294b02799f8286129";
                sig_s = "8d987611063d2f28cb309a56eaf1ea65f27d95c97b77a5f037f2f914fed728267aaf62a37f3c7b44fc4b15125b349863";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37373637383532383734"_hex;
                sig_r = "b2df7b11cf60ac93c078d19f37f889717aa5d9af1d00d0964f9e9f5257c3b51b3d3e47ca5b5aa72058ed63b52464e582";
                sig_s = "b524968ea8c58d379e38f4cfa9da1527a2acb26d605d22f173fcf1e834db0d7f031cb9245cb62b8458ff499b8d3decbe";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353434313939393734"_hex;
                sig_r = "e0edc08b4122b75ebbd1635d07f0bb55771bda15573a5081da971955f9a63f6decdd4919911dbfea503ea8ed1faad93d";
                sig_s = "ca7850c74ce878587056206c590a1097d197a2090cfe3e057becfa2700c7a531623ae7331e163def693e26a97feb540d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35383433343830333931"_hex;
                sig_r = "68f555eef5a323a929719bfd8cf81d6d8a977ecb35defd86fa54d8e5749c7b5f3e80087fbd39f8aa0cd29d8310bd6578";
                sig_s = "e2c2314a50fc0ad78c1ec02ea77ee2e13dcef1460957c6b573f721d72c209ac5fb529ab20397234c59ed44f60400971a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373138383932363239"_hex;
                sig_r = "9e330e29f18123813e83b9c6abd68de96a57f97a4005b88d5b470a67a541b6d3af12124cf8658b751671c6698fb8b021";
                sig_s = "d210fba9bde6ef077ca06b75e1cf7ce8dd70b08e9dd42d81a215ef9272f1779ae3e9f0dec510571d87237cc6bf3203e8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373433323233343433"_hex;
                sig_r = "483192056f753f64ddf0f21072b73d68893e6fa5432c981c7a1955b6592a6045a5c1c58c383e70023c34e09b7964ec8d";
                sig_s = "94b005d5f98c4fd2ad40ff8e03a8599f45e206082112f834df1d48502d2ac690cd3204f0078913794c9c39077ad6c58b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343036303035393336"_hex;
                sig_r = "2b7ec14fd77c4b33230dd0a4e2710fbd307e469baec54b6f25daac7e196b7b4b5df251cdddba7bdc9836ca1319bb900b";
                sig_s = "590036192586ff66ae9a288199db9d02bbd5b703f8c329a9a1f986001b190f20ae96fe8b63681eda17bac2a57fd40f2e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363134303336393838"_hex;
                sig_r = "2611484e7ff47dfaece4aa883dd73f891869e2786f20c87b980055ddd792070c0d0d9a370878126bab89a402b9ea173c";
                sig_s = "4e0006b8aabe9d6a3c3018d9c87eae7f46461187d3c20b33e975c850599ec1cb52c76e1f507e439afc43f9f682e7a8d2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303935343235363835"_hex;
                sig_r = "2d504e38cdb1bb80bf29e07afbc66aea732accc85a722011069988f21eef685084f55efa30bfe32427eb8636db9171b4";
                sig_s = "883e3d80d766ccb29e73a9e929111930da8353ec69769785633fe1b4505f9051e78d50c79a6b7c885c10b160bbb57fb6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303038303938393833"_hex;
                sig_r = "28dc1b63dc61ecde754ff4913780e486339103178e27d761987dac0b03c9bdf4a4a96b8680fa07fc47ae175b780e896e";
                sig_s = "5a9898eedf8781b9afeb506e0272a12c0c79bb893b8a5893c5a0a1bf4324d46dde71a245be2fd8aa2975fdeb40adf8f3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353734313437393237"_hex;
                sig_r = "4c978a47b9e9449337178aa6413a794c4c9bf182a42062646a469b1d2c2c95621e818e661352b07e63254b6954e14598";
                sig_s = "6997345f05cfc05c0fd4d1dd133e555e5e5002e0929a59f60bbffc354234783ebf4fe5db10a870952cabd453635c1082";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383636373731353232"_hex;
                sig_r = "36d8e2cfc80d0436e1fad3702ec05aa138618cdb745652cb85b0b121ee107bdf1ade0464dc0c6bd16875bcc364044d8c";
                sig_s = "898b8775c9b39aa9fd130b5ab77e6c462ced6114898045b7f606142277d9eb2aa897f24c9ba4c8d112111de04dc57c10";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363934323830373837"_hex;
                sig_r = "ce2bdcf924caaa81e79bd7dd983dfeeee91652e4ea6edd077f8b56ada4953733a22dd3a6336446a648aec4ffc367cb3e";
                sig_s = "08eb09faeef4b0e5c1262eda2127464f7e2981ea1736e80afc7c622461c3d26fe08694fb4914ce9dbba83704e3077b3c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39393231363932353638"_hex;
                sig_r = "e3a1b4b0567d6c664dec02f3ee9cd8581129046944b0e6650f6e6a41b5d9d4bf79d7a6fd54ea5a218492cfa1bb03ca07";
                sig_s = "986206925cbfa186c7d88f7100d87dd3b2d03b8789309a722d582f119eef48cd0ea5460917cf27246c31f90e28540424";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131363039343339373938"_hex;
                sig_r = "95a5e29940e42099c4637f4ae51e7d1ec02be0dcfb0b627030984c35e477e80cc57e7eef970e384dee16a9b9fc8f2bf2";
                sig_s = "0ca166c390339653cde84e79a87e5ceb4f52c1a515a5878542fd82705b9983976fd31a4123b5d0bde95a0818114cf462";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37313836313632313030"_hex;
                sig_r = "c30c49d0ba131944e2075daacb1259d5580a712a08f73d889c4d3d484d73dd9719a439a986f48b072c4595c507a01083";
                sig_s = "a5595c0691bc2d215f981fab513e3a88a452f2a1433367b99b02b6efe507519afedbe1ad0337899944e29c9ccccb2476";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323934333437313737"_hex;
                sig_r = "9fd0585f8740669885c162842bba25323ea12b1d05e524bb945cad4e31538742eda5128f467b3c562c5f0a99019d3406";
                sig_s = "43acfadd03915c2350e1d8e514c47eb36f3c3456169c9a562a6262c1c2d7d33378bf9fec7f220239d5c61e06414414a4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3138353134343535313230"_hex;
                sig_r = "4ecac0cdbf665c584f8a40614cd55d042706c54895b1de02984fe309122566c959a4dd3315e7d3f089879f8f45821336";
                sig_s = "09187da6587a3de90eba41f4e6510e711f4467f3122971566ecc39a4bd53e95b8a19380e20ec2a7c752d29de54fd2e8f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343736303433393330"_hex;
                sig_r = "37a1ba49f11e97ad0ec47e687c6c6e94f794f874720c0dd2da501437b50e5b00fb6ed33adf7cf1f9c870fd3d37165bf7";
                sig_s = "b3ad08c9886b4ca1593a68938b67142c65ed4da1714c22204cba71300c094ccdbdf84c38a3f6d896db72ed5051a19266";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32353637333738373431"_hex;
                sig_r = "a0abe896d2f30207bc9b21e75400eedb88d3498d49806f41aa8e7f9bd815a33382f278db39710c2cb097937790d0236c";
                sig_s = "9a29aded30e8ce4790756208d12044e18c34168608026000a883044dd0d91109d866b422a054c232810ddfbb2ae440bb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35373339393334393935"_hex;
                sig_r = "b024fc3479d0ddde1c9e06b63c9bfb76a00d0f2f555220cb9a1311c2deec32eb3d6d2b648f5e8c104d5f88931754c0c2";
                sig_s = "767950cc149697edbae836f977bd38d89d141ff9774147b13ddd525b7a3f3a14a80d9979856f65b99a6faff173b5d6eb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33343738333636313339"_hex;
                sig_r = "2a0ae7b5d42645051212cafb7339b9c5283d1fd9881d77ad5c18d25ee10907b7809740a510e65aecd61b53ba3a0f660a";
                sig_s = "4c0457dd19ef6e4d6ae65f45417ddf1a58c07663a86737d271becfa3ea5724b6018f1fa9e64fd08601a7dbd3957761d9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363439303532363032"_hex;
                sig_r = "0c1657320faca6668c6e9f06f657a310b01939a7d9640fa0429872fe28bd1667688bc162221285ecfb14e8d80627450a";
                sig_s = "f5272aa08c321aa4f7e520825cc720f6511d635598c648d4d514669b3ad803ad259c799e195a095982f66c176435be21";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34373633383837343936"_hex;
                sig_r = "d821798a7a72bfb483e6e9840e8d921200ef1976b7e514036bf9133a01740ce397c73fa046054438c5806c294a02c680";
                sig_s = "8c5d12887fcd945ba123fc5a5605d13a5a3e7e781ad69c6103577ee9dc47adc3e39a21080dd50304b59e5f5cf3f5a385";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353739303230303830"_hex;
                sig_r = "c996bd6fa63c9586779f27523d5583135a594808514f98cc44cac1fa5cfa03c78c7f12f746c6bd20608ecbe3060eb068";
                sig_s = "27d40a11d52373df3054a28b0ab98a91ad689d1211d69919fc04cadc22ff0367d3ef9433012a760c1d1df3715c8d5cf3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35333434373837383438"_hex;
                sig_r = "42dd6c8d995938701a538909ed6aeae0ba50c995138de84e195bbb9c56180e108d4a6274548c7be6e121c4d218d2d4a0";
                sig_s = "fae8668bb2003f0da1dc90bec67d354ccbb899432599c3198b96c5ca4bd2324c46998f4fb76a123467cf24570b1b6916";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3139323636343130393230"_hex;
                sig_r = "061f185633291b9a768e15ec03a2b7c356c757b023b61e313fdf0c5349d128a78668d20b2561709b3bd8451b920f12ab";
                sig_s = "8fc5edc66410dbf20a7cbc3498e405761756ed39866856e74256ac1f255f62b0edff519762ecdbbc8395d14715c4388e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33373033393135373035"_hex;
                sig_r = "69326e047c62e8bac5c090b76bf73ae652fa9a6aecfa1ccb8702f419094c9727511264fb1aeec00e425c7a0d746793d3";
                sig_s = "9dbddd22db4a77dbe16114bc6fbb981aecba7e82a9cbc1ed385e28a51793561770fb3f9696090efca24f268d8788f2c9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3831353435373730"_hex;
                sig_r = "4ca1df89b23ed5efcdf601d295c45e402d786a14d62f7261104e4cb05b8cae17abb095799e71173841749615c829411b";
                sig_s = "1bb777e0a6fee8a2337a436a6fa26a487de4640ff97d57b44b55305989803863d748c7302f2dfde8b8cedd69bb602e2d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313935353330333737"_hex;
                sig_r = "67be1b06f67172c503a5ac50582235d30bc9079eaa4cdec69a39c096310f8d99186cc9af7c8b4369a291d3e921d60705";
                sig_s = "ab645fc91f06b1ff7cc58fccf6f7cfac74db30d839748a78cb5f3b8fefc7a06f3b5ff0310a8580c6050bebb75eda972c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31323637383130393033"_hex;
                sig_r = "d966442d6c29e5a4cc60e2374eccd373db3ebe405ee7c9664c4273100cd1899a1c58110487528616d8c5321dbf522764";
                sig_s = "9bb0e4a2c041a3b7b672029fe480d155f57671ecd6eb598660d025acce1f613d03cd6cff4a214131c8c7a8ad22df1397";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131313830373230383135"_hex;
                sig_r = "08a84a2bc39b082ab82e6e45f088a36f1cb255f97ec8124eca929d4506d7dab63957c647994be2c2c7344f902de5b38f";
                sig_s = "0c9645e84a304ba0970ca5ce00b8c8a971fa0d0bcbec6a70134894c44d3075030ff04333ea3889f847a1ed769ee618ee";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333831383639323930"_hex;
                sig_r = "83004b034202bbf51a327d32ed3ddf67b46eda9bac695a4422744a4bd99aaac3b3e8ed80ddac6538939c9385d6c8f616";
                sig_s = "7b4e61926cb9afa8cdaaf44909df6dc6449887d59fe2acac05f7684a235fa77179bdbcc69fd8f359e8eda19e5a5d4807";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33313331323837323737"_hex;
                sig_r = "ad93375a1d374c41e5de268a8c08c205ff5652445bfe3ddf4ca77a70f5819f9f06db861d82fc9637946f0fe38457f2bd";
                sig_s = "4bc043acbc6a68d4824ed768af9476ad5b93e4cb3bbac284fb5fbd548ae3b96c265c6d1ef4588a3e2da21b124c0d6b12";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3134333331393236353338"_hex;
                sig_r = "9e0d45d2dc93fd363dc919405818e39922f3f9dd0827bcad86d4ba80a44b45a6f60b8e593b580c91262b32859dbb1e53";
                sig_s = "eb9b8dfe5ba4a055a974f19b488f3a6fa07161006ac94eb1fe1c12dd0e20f3a7be38a37ce96d671183c5871249b2a3c5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333434393038323336"_hex;
                sig_r = "7a5d04cd2fda59d8565c79ea2a7f1289ab79cae9fde060094c805c591a2534e4393e28c3fd858529bf17643846aceb83";
                sig_s = "8de0d8c0092fd02d554afe25f814744beaaa17c6946a6387ec7046b602db8a6c900246c2fb63fcef2ac8d9394444a0fc";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36383239383335393239"_hex;
                sig_r = "a564eea0cdac051a769f8ff1e0c834a288ce514f67d138113727b53a1a6fc95ce237367b91f1b91b2f65d589adc8288e";
                sig_s = "182e5b47b6fbd8e741a04e809487ba5fcb8a5f2f1b9af6ce214128623a4768e38e6ddc958ff39078c36c04a314708427";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33343435313538303233"_hex;
                sig_r = "6758867cd1ca1446cc41043d1625c967a0ae04d9db17bbb42fa9c076b3593125d63cd3e7471ee6cdba5235a21cec2f22";
                sig_s = "563db387adb537e1d89231d935ac790316925aeb29132b9f87bee91116c33bf50943fe39b671ce9535dca0a5d22bbfa4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132363937393837363434"_hex;
                sig_r = "cde033e38d3f791db87d8a6907516bd8021acd47e897df683fda529d48050f8b5688f6361daf1b14bc3f45fc7f76150f";
                sig_s = "e14f4811a667c85335a4709a589ea46bac72055b794eaea92d28e834d5bc459c605fe4f27c1ab18d186d59e7d205cb67";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333939323432353533"_hex;
                sig_r = "f2384468b55553c68f9764d8248cfd7358d604fa377ebb13828c43a8ebdf308fbbbebfa49a9458bfda957d2068d24e3f";
                sig_s = "1fdf4891d56e3e90c02b05c14c27c17f56f8e6aa144f02328c90109e1f70c9e3f582f0d299c44da505c543cc89c6a990";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363031393737393737"_hex;
                sig_r = "b1ccafedcc21ba90b342fa23c0149f3d12a939ab6c3342b36ae61fddbdc753927a7c3e978bd780cf25cd78c8c5efe280";
                sig_s = "4c32a73f3157bbe2384095eb67726b9cd3c2623b98a182a3b4f00e8db933e1113b7ada2695a7d79b471026462b20e289";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130383738373535313435"_hex;
                sig_r = "f3ed170e449758299ae55eb85244745e1876621c1f708e07e55c0d2d9ab5f9af9e0a8b3c7bdf8936ab3c9ebd1908e9dc";
                sig_s = "da62ccdb658868147286d7269bcbd4addb4dec9ea3d5d79fdbe0ccffa40d055170bddeb4ef4c5e0bc99fae5db62b4477";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37303034323532393939"_hex;
                sig_r = "83455fc4629e7693c8e495fec2d29bb23bb6db79180fcfa83a4f9310d9db27e29297dee27ee80a71ab2f7a2d59f48b88";
                sig_s = "7736c056c8f2bb57e9fb6b8de0ab6d09879f6611e737634e7b6337aa5c5a01f515d5e3702dec9a702177c816e32bac67";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353635333235323833"_hex;
                sig_r = "74961587cbe49bbf0a73fea82b8b2242f67b0ea09224774639f437c60378a36b2d511a9145d576b440dffd1f02286a8b";
                sig_s = "8fb95d46c22889085cc1d3e20bcfbcbc52f4532445f76f08efae2de8b56fe8525204643330dfd23cce946687a0aef046";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3233383236333432333530"_hex;
                sig_r = "a3fd322330d0f0efccc54bd7d73c3159eb1bcca08cec369a4a08fd00f9ec6d482ced58eb08a0d7c2113bd5575de4917d";
                sig_s = "164e3232a628c40fbba1de82bfb9627cec78a8040cf325a5a8bb8f864c2ac19e3524ac93f4db5713ce62ba256176e05e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343437383437303635"_hex;
                sig_r = "4c862ff9e4ff88f9a58e9fceaaf9bbb30740d3f6c8c6a69b5627fe234b144f8cdf09520735cfd708f5e341a78cc4873d";
                sig_s = "a861972514a0e975cf2da214125ec93288524cc77492ed63c516424278e5ec8d41724467cb7c3111fa34c69193abb435";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3134323630323035353434"_hex;
                sig_r = "62225e4e492a9773397870336168960a66b9e50391ef7289cb2d3878f32252dc1b904f6682545e14564e415bd93e0117";
                sig_s = "9f4d0327f79e043505c691e361fa2e00f87f41324777eca6966f4bea2fa0858876aa01980b2cad7f66037524de49bf65";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393933383335323835"_hex;
                sig_r = "450c65d2d88ba464eee3a5ce9310b519d5dcf608799fb2275eee987a67c2c4d7ac53716987cc5139c18c67ef07b1e207";
                sig_s = "1ee0439311a7bce1c4fed0a3152d1b354d96536c6ca0c9188ac1f1afcc5cd7305b5611ef0d19d8bd57c5059976dc5e68";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34323932313533353233"_hex;
                sig_r = "aa2575fb5bea0effb5247d20c3d0165d575831840b5c18b0245a99a61b7ad5d7bf8a8cfcc375e095a84e781025bee3ee";
                sig_s = "9c8b7797ad330abc206060b28b6ca1c639d89f59582528bda1527e3ab081697a2ab576f9d09c2ee329dd73231667308d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34343539393031343936"_hex;
                sig_r = "01fc45285aa2c2e50458199ade2ded0dd36b1de03e8969175be4a6f09f9719b195ded8d9eb4ea132d95d19a3528fd6c9";
                sig_s = "59609a358c5919fef4781061804d4d64a067edecdcfd14620161aae3ef2735095a558e4f8ae345040123f093e5f70af2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333933393731313731"_hex;
                sig_r = "d8e1f6b19e5b92e36060e59e53eeb788a4758c2c8ee9519f3949d5f3315abafbe937b8ed44d47e886a07c107aa8ac9f4";
                sig_s = "12550574318371e5168d0a339f20fcacaec87db211bba4d4e7c7e055b63b75fd31790ad285f4cc061378692b0a248e34";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333930363936343935"_hex;
                sig_r = "4815aec44a7a6b86ae87fc2556accd77832fa33a4710e02ec5ef6f41f68a910e6af4d173ae462a759bd98079b371bf5d";
                sig_s = "6e78d562f9e8be65e8d7a74a7305e5d6cf2f3c4c980f2b18dfb8e9c8b0134ec86548053b3d125e56d5872294d2d14ebc";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131343436303536323634"_hex;
                sig_r = "d302f9db6b2d94e194412f0d40a135a554aee014bd939b3d7e45c1221ef7ce45c2aed875f9a2bc43dbc8264d92e444a5";
                sig_s = "04e7247b258c6e7739979c0a07282f62958ac45e52dd76a41d5e1aca31a5cda73d7b026d67b4d609803001cb661d74c6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363835303034373530"_hex;
                sig_r = "889f0e2a6ae2ddcad1cde3f65b61d4dd40985917ba841b47a1f802491f5af5067722b7683df0fca7ee19d2b73724c8fd";
                sig_s = "1f989bac23b51c49e5d7dcc319eed2fc767e9b432bf75af92814d9e67a5d4b3398eb15e98b70527abbc029abc1bea524";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3232323035333630363139"_hex;
                sig_r = "e69c70c679795ca7d2b66e2632529651c120055fa3cf25435fe8bb28987c02412ce73e6ca5ca7e0b42e9670c0a588175";
                sig_s = "edd8513bff40cdca9e22659238fbcea2de2caeef53c5287a515db9168b3008ec446c9b94f28a6e021c69bc6637fc4634";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36323135363635313234"_hex;
                sig_r = "068cbecfd47bfd688f495df05e45fd5fced6d8e240605c5b2be5e69368740b694b9b1ea034af3180e571dd38a86369ef";
                sig_s = "1a1d2976f748d1621128013c61abda5398a3e24f0073d1a6e07a1e96c12be4f1e2e7b144f9b5a350500acfc5cb0698d9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature generated without truncating the hash
                m = "313233343030"_hex;
                sig_r = "0e2c56eb5f6612f0c2b22ab03d57d9a443075a2b7a0b460883e4f4876121e9b6f1ed67de20b79f028f7f66ed0281db71";
                sig_s = "3916b72b12d035a307b7c45a9878333a8c61445aad2330dc49a12b92e2e5dab72e53e5789f40afb90aea0ea4431f2dd1";
                r = false; // result = invalid - flags: ['Untruncatedhash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ca5ee479ad6624ab5870539a56a23b3816eef7bbc67156836dfb58c425fdb7213e31770f12b43152e887d88a3afb4b18", "2aceec92b3139aca8396402a8f81bb5014e748eab2e2059f8656a883e62d78b9dc988b98332627f95232d37df26585d3" );
            {
                // k*G has a large x-coordinate
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000389cb27e0bc8d21fa7e5f24cb74f58851313e696333ad68b";
                bn_t sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52970";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r too large
                m = "313233343030"_hex;
                sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffe";
                sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52970";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "70e6a90b4e076bf51dfa01fa44de49b448f7afa0f3d07677f1682ca776d404b2a0feef66b005ea28ba99b6ce21d0ca12", "424f7d179951fb89156cdf04aed6db056c98592c651b5a881abc34e2401127fb81c64e90cee83269c5141f9a3c7bce78" );
            {
                // r,s are large
                auto m = "313233343030"_hex;
                bn_t sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972";
                bn_t sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52971";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5a568474805fbf9acc1e5756d296696290b73d4d1c3b197f48aff03b919f0111823f90ea024af1c78e7c803e2297662d", "4c1c79edc9c694620c1f5b5cc7dd9ff89a42442747857cace26b6ebc99962ec3a68a8e4072226d6d98a2a866dd97c203" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "d1aee55fdc2a716ba2fabcb57020b72e539bf05c7902f98e105bf83d4cc10c2a159a3cf7e01d749d2205f4da6bd8fcf1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0088531382963bfe4e179f0b457ecd446528b98d349edbd8e7d0f6c1673b4ae2a7629b3345a7eae2e7c48358c13bdbe038", "009375c849dd571d91f2a3bf8994f53f82261f38172806c4d725de2029e887bfe036f38d6985ea5a22c52169db6e4213da" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "b6b681dc484f4f020fd3f7e626d88edc6ded1b382ef3e143d60887b51394260832d4d8f2ef70458f9fa90e38c2e19e4f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "080da57d67dba48eb50eef484cf668d981e1bf30c357c3fd21a43cdc41f267c3f186bf87e3680239bac09930f144263c", "5f28777ad8bcbfc3eb0369e0f7b18392a12397a4fbe15a2a1f6e2e5b4067c82681c89c73db25eca18c6b25768429cef0" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0e74a096d7f6ee1be9b4160d6b79baba4d25b4fb6fbdd38f5a9ed5cc1ac79943be71ede093e504c7dc0832daeb898a05", "00a8d005b30c894686f6ecb2bc696e25effaccd3c9e4b48122db567c0118a0b983b757c2f40082dc374f8f6117a8e76fc0" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a2ad0e27b40410d16077ddc5e415f109d328bf75e73a0f56876fef731285f83188b207a68690a40e76ed23e2c5e49fcf", "604f1c5d7d7df365005d40e209f4da7bb06f310d5a1660ad6236577fbb47955261f507d23b83013ffb951bd76908e76c" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "65825b7c85ee36e98a00fda722a70a7bca2981fb642084f896c1670107ca01f407f146251bf979724f2dcffe2dc425e1", "00bc10124ed3f2a4acd6d1e1f1a9b7bbdc196365f3b90c90d0085246eb0a336ceeef6469619b6a44c6cde3ade84bdcb664" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0097d213d98a6a6b4b1fb3d20533b333b8f3d9d38458e52846ab7893763e08a69464aebecfa64750bbd2736782d5fff413", "20a7c0bfb103d0f13ddc7858c219139de34698b30d19b894269c13ed79842edd91fdda3e94734c79bd4258561ff0890b" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0bfd55e9478130ae3dfaef83c7802a64701c3f3a4112a25de26a24e038036618a603a5cf784163c4f9511aed456a5661", "0098a0eba39541265c29def7f89dc8799599af95bce3006aa0841133d4fd63d06df461e00306f76ac7a64e95a779d9f7cd" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r is larger than n
                m = "313233343030"_hex;
                sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52976";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0b2e5e46bbbe09fe974f71dee41cfb484457edebd47c50022934e248e7713f4d7fcad531a3b71224b482406125a05e2f", "3ecf586ad81c48a8062845cbc1147b61225112c244b1b63d434068cff7712ac4a1375a0d252759c303c522347e062872" );
            {
                // s is larger than n
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                bn_t sig_s = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accd7fffa";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3c9bb63607cdea0585f38d9780c9ac3e9a5a58153e2aacc4bc7a1d638d12e32c4d3a90c0c114b232c6f16e23e4bebb24", "00da2ac2ccedc5494fe534a9abaea3013de0176f1b0e91bcd62154bdf3f604091a5008b2466702d0e2f93e4a4b6c601a54" );
            {
                // small r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100";
                bn_t sig_s = "489122448912244891224489122448912244891224489122347ce79bc437f4d071aaa92c7d6c882ae8734dc18cb0d553";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "559a66ef77752fd856976f36ed315619932204599bd7ef91d1a53ac1e7c90b3969cab8143b7a53c4bf5a3fe39f649eb6", "1f00f86dd8b8556c4815b2a01c59eb6cc03c97b94b6db4318249fe489e36ac9635876b1ca2ec0999caef5e1a6a58a70d" );
            {
                // smallish r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000002d9b4d347952cd";
                bn_t sig_s = "ce751512561b6f57c75342848a3ff98ccf9c3f0219b6b68d00449e6c971a85d2e2ce73554b59219d54d2083b46327351";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0548e79a17fd3a114d830ea88f218ee1ef7aa3f8dc139e0a8b9b60e25049a816ef449e8bd5dae867446495fdf20f4770", "0363a1e8afefb02ebfd59df90b6d23ff7d5f706f9b26daebae1d4657ac342844ee9c2e0e9269f7efe7ab91e0303c115d" );
            {
                // 100-bit r and small s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000001033e67e37b32b445580bf4efb";
                bn_t sig_s = "2ad52ad52ad52ad52ad52ad52ad52ad52ad52ad52ad52ad5215c51b320e460542f9cc38968ccdf4263684004eb79a452";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a0eb670630f9bbbd963c5750de7bcbae4ddfd37b13fe7690eec6861a3c56c8efb87dbbf85ccd953c659d382c3d7df76a", "00fb08840635a16ac7ecf3de2dc28a77c8af9d49e5a832551e3354a2b311e52be86720d9b2fbb78d11a8aec61606a29f0d" );
            {
                // small r and 100 bit s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100";
                bn_t sig_s = "77a172dfe37a2c53f0b92ab60f0a8f085f49dbfd930719d6f9e587ea68ae57cb49cd35a88cf8c6acec02f057a3807a5b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "254bce3041b00468445cb9ae597bc76c1279a8506142ce2427185b1d7f753d1c0aad94156b531a2071aa61c83ec842a3", "710d6c8c96766ae8b63396133e5872805e47d9ba39113e122d676d54dbb2460b59d986bdd33be346c021e8a71bb41ba9" );
            {
                // 100-bit r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000000000000062522bbd3ecbe7c39e93e7c24";
                bn_t sig_s = "77a172dfe37a2c53f0b92ab60f0a8f085f49dbfd930719d6f9e587ea68ae57cb49cd35a88cf8c6acec02f057a3807a5b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009129db4446c2c598c4f81070f70f66c37c39323e01418c095de9902e0e1b20f26bc3e011ba84c10626ffdce836690c9f", "008e4a104fec4aaa4350c238617ee50456accc49efc3b73eb9548e1600c2483f1c4bae9ddf3ff92af17afd19f86274589c" );
            {
                // r and s^-1 are close to n
                auto m = "313233343030"_hex;
                bn_t sig_r = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc528f3";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a5d6896125b332992cdbd8ad948ff1242d5f13a22712715735801acbb8942547f03e3b0afaf8b82c3b5e643b5f17e40b", "00cdfbca7338f6ab3b2e6e9061944063aff32d704cf8aaa0da261b93375a8ea7feb0490c7a1e77199f1b00273c2311c11b" );
            {
                // r and s are 64-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000009c44febf31c3594d";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000839ed28247c2b06b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6a50284270976040d1220218b75ced142e26e820f46c91307f05dfa4ff0972ab8099679623d7e2872d712fde8e9ebfd2", "00b8233055606a0bd53752bcdb43306abdd67839eaaf5b41d585404d2e2b7ac1ee7cab5d4eadc9e592ba73b44095799be0" );
            {
                // r and s are 100-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000009df8b682430beef6f5fd7c7d0";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000fd0a62e13778f4222a0d61c8a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5219117ecd2995d6b740e1b036e73415e131f816584105aebe9d17b870a8b660d64fe90446caff673fdafd54ab93086d", "00b8690fc241f3ec981e77de6761fa8a4fc3bba9b95421011eb7bd736fe1fd2b52fa892793dab7d76bdfde99e7b9882bc9" );
            {
                // r and s are 128-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000008a598e563a89f526c32ebec8de26367a";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000084f633e2042630e99dd0f1e16f7a04bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "733ffd3c9ec93fd00cde0ca95a6ef8be688da4a6db9a3d2eb04626407d24edd0112cda1a3259c526cd09ee1c91481093", "3f58096e7bfc680f0cafc632064be165c315a2fee3dbb0870898c69ad63aebb74b916aaf7cfa1432696a8d6f71eeafbe" );
            {
                // r and s are 160-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000aa6eeb5823f7fa31b466bb473797f0d0314c0be0";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000e2977c479e6d25703cebbc6bd561938cc9d1bfb9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a701a8111cdf97ced74a00a4514b2b526be8113e7df6cf7163aaee465880d26275b833b186d80f1862dc67ff768dde43", "00e5a991f16f8f777311b17eabdc90b6ece3b5da776cfbebbc504382ca1abae1c6aa6a64d9c41110d97950514e99578ed8" );
            {
                // s == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // s == 0
                m = "313233343030"_hex;
                sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e612db39a8729a85c937a41e1fcd770cdd6489e209fdda6ab0630b9c44209d6cb1702f5498aa90e05ac99925426dda32", "7eeaf17d8574e781c091fea1e078fd17f82c2c451a6ac11a137f3a81b763a0a42c9f6905691a9c2fba28cabe670ff8d4" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "427f8227a67d9422557647d27945a90ae1d2ec2931f90113cd5b407099e3d8f5a889d62069e64c0e1c4efe29690b0992";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a90271cd61b20ccbac718c99c175f6383acf6ac89ce4cd548338346d1774ece7ad501b4af6802c08236d7be4a4ea3b37", "4f449063c4e74600828b6f4e372633b5c5ac8493476979a9af58d4111ff2b8ac62e191e415a49d4dc209432e9f5dd507" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "369cf68bb2919c11d0f82315e1ee68a7ee8c17858bd334bf84536b2b74756a77e4eee10ecc5a6416a8263b5429afcba4";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008b326acd923571636a8f4202869ae942407eafc1362d06dcd1b4665b00b1f9a94a4bbd45653443a638d952d70879abbf", "00bd8e6393772edb0d245c008c3fa8ea3af4299bd6c4b073afbac6bb43bf3332855c035492f6608a075ed567ed422582b5" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "2111832a45fc5967f7bf78ccdfe98d4e707484aad43f67cf5ac8aa2afbde0d1d8b7fe5cfc5012feb033dffdec623dfbf";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a1e8b1972502dac2049f0e319b6185d799d08f1e806c162e3fd135c12177008a1aeb9fc5fb81c0ec71dbbfed300a27de", "00e29a49d89b68642e11b83c58a521b761b44f1e41c557919a528e2866fa6a7019365729a8418824592859e7c64e454fc2" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "20cd002ab7dca06b798fecef3f06a222c2d2a65e9ec92f74659a8d82fe7d75e9af739f0b532e17d6c5f622c4b591442b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00870649ff8d3a7a14f6952be825beb0711483bffdceed1f556be0b29c4e62d73238f19507038687a69481b7ae37c4c754", "1de0fbcd8cb50014d338d1c83cb4d2f901450af7f435fa6790bbcb66ea87db25fb8ba878c00bb88e20c379576b6d3e8a" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "3276fe55314e426a8ed83c4c38dc27c8fe8cbba0b39bad7cfc35e963adf10ab37251ea6829b8d255a77dd0b655cf9ff8";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00dee7e74e4eb4b7b064ce3ee571fe8c5b79c12234c63193e8efe4466a07c601dbd260d33d3ed36adde0e8e33aa98f1ae9", "00c4817f36e6b2c98e6807c37d93f4903f65283ef372da1a8cb837d2727e6476513b36e1b2c1aae9a6af4d05666bdbb97a" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "1a80b4a3d6c88775821e26784463080eb7de510762ab0d98223e532364c7089b07af73746ae4cf076c5277dcc80cf8c2";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009a2141e20e0f5f4a2ac77c20115c29d39fe510acceadcd8750bbfae9f9ad68c8671b6505d2baf770d1e4fd5f314d26fd", "27477d03efa31a797e42835f867b89986523ca02063fb1d8854f57dbecb69352834caaeb272bd7d59a42bf08e33998ce" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "74e780e38b3a7cd6cfe17d5c9ac615895bd97dd4076b5f8218ae758b83d195fba64eb9aead39a790ca0f8b8387376265";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e7fbcf59900e281e939172f1ea7a4ac9e5c6bb9f30f15f8379b15d739b302293ba8ec4ceec1a6ddf6605bcb25f2a8e2e", "00c06626028702ee8f45fedb501cbd47e16235e1e4386eadea5661ce71cd200876e7d0a467ce6104eaf8e526ad67a41d51" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "6ee5f8daae12c862e1f7f8b59294ac90448c4461e29b36ed623a719dd69bb17b3a4b7c29b9eb5c39ca6168bf6b597c6a";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7134832af3c609b17b40641039152600d9b318b3a41578f26106a4e97443b0d204bca2dff9aa4ca0d9b86a6192fc2c91", "2407202d2a51192674661b402d8957197c439e65b2b20b6631f5b771696da43099c29a1002b71bf99437eb5413fd9d50" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "5426ca20a25b0cfb1ef230c62f91e98005f346e229233f1803e8944bf421fef150a4a109e48cefaa4ea23eea627fca41";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d3bc62d583ad855a35ae39f4116ba97ab2f25157c55075d177a083912fa749500e9ba7b2801fa8529817c66d9ae8bc33", "4f2db63f152c5795a2aa623a999aed8628ea305161b90bcf0c43c1757534c6472f683c9ec310b3e15c1beb8d4937fb84" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "39fd1a0ae3964735554c61daf085c66bcc2e9e5350131086023aa99549fc5f9057c848e75a1b8e58069fe0b9b23fa3c9";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "26bf1d7f97f412d6e940565a881eddc1b026569265f02cd415e82fbd4190da9a86c79f9ef221f1f95368e57ab0ecd2b3", "76e2ffd121f572c21fc83261361aaa716dfe9b6f1fb48fd7fbbde14d284fcb723b3f6252bf34a3c92171e86ab0c24948" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "707a37cfb7367c2e551ea1f0caeac6c0fdd2b562e1bd8f1c7c51a5dd78f21da8cb179bd832cac3d3aee21fda54729e66";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00f31fdd34ed4e15da354326e13ae48005d0166b1a3db26cd6b9d62c4d7db29c450091d15093828dc4543ff578ca198c84", "1f5f7ceda1a4a3b8dbbc1bc4a60d98d748418c7bfee7cd418243ef5d8c346b0f825d2b1c06084d67b7471167921dec05" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "15c99e2ae11f429e74fe2e758bc53ffea26eb6368dd60d10daf860f9c79fa8cc6cb98fee9b87dd38353e970539a50a9e";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4bb7245b1960c5ef4d9670242b6e0478162644cc3416543b9dd79c04e57a90f981aa48bb110edd54c657056f7fd9cd46", "61524656f1aa505d7f53497165cd63e7ab8727760955f87e66fa627543d156423577109e8e2aace4bd57ad87efd51946" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "148c732596feaabb01be1be3a220740e84bbfabe6d82ad0db1c396fa047603beeb95a1cd37fc708a9451d3cc29a45b32";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009ed91f3bd77cafc98d2152f5a10e947af87c4863359877e178ec977050f5e289322469d439506eed00bad84eaf79f03c", "4956440e4f468ccd298dee1b41aec2829da1b33f33e39624e659b6a831b06593e4365707b8d66fecfad0fc7beab3b15d" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "6b3cc62a449ae5ef68bec8672f186d5418cc18d039af91b45f8a8fae4210ef06d3f0d226f89945b314d9df72e01a02bb";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ea03e9823cc5e5a4891651b2c56fcd7e2e357e21835f559f7a8800dee1cf6b70a7051193b4c00b948444a3f127bd4a3f", "00f7bfd49aa2fa48827364851480d22c92070bed72f1aa9a3d12313b6ec9ba8f028f660e10150e7abb0bdb32fec5f3e4d0" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "7db7901f053b9cefacfda88dd7791c01fd569ed9a5243385eccae12ba992af55832a2e5dc8065e018399a70730035bd8";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b6815ba05413bcf34f4c0704af590c1998d7fcd169541e1efe1567ca1dd71a22e35ac838b20c75281582044a57b58f45", "6cdceb10612062779abadd8742c6e93ed74adf306f3b3a0f96b70dd1134b7558b64b55b200c5732c50f05aa032ae7c00" );
            {
                // point at infinity during verify
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = false; // result = invalid - flags: ['PointDuplication', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1af19841ff3df8bdc4f8cce957e0dab763efe413929b279f1d46dde1c6f2bbc55af1bb1d8011fc587a4d599a4ae7cd8d", "5f663860c43c88e08399f00ef6641123787956a2b7012883b5ff7c46bd156d96d3c02a63ef86e060a2a0fa5b80d0c0e5" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6836084fddfcfd527cb3847fb8b911c0fa002537fa460ca8f5d40f025603a4d89aa6ec640fde0cc4b31c46239a1d0bb7", "6beed7019892e87287e23f0d35093ab14c4d41c0efe8463ede3494230a384eb1bc410de918c5484a25640741acb8cc0d" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294ba";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b4b2d5a8b50ffabd34748e94498c1d4728d084f943fbddd4b3b6ee16eaa4da91613a82c98017132c94cd6fe4b87232f1", "6d612228ed5d7d08bf0c8699677e3b8f3e718073b945a6c108d97a3b1433c79052b2655a18a3b2e621baa88198cb5f3c" );
            {
                // u1 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "43f800fbeaf9238c58af795bcdad04bc49cd850c394d3382953356b023210281757b30e19218a37cbd612086fbc158ca";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00842b3d89e54d9a4b5694d9251bba20ae4854c510dc0b6ef7033e4045ba4e64b6ddcd36299aac554dbac6db3e27c98123", "00868258190297e1d6bae648a6dee2285886233afd1c3d6f196ad1db14262a579d74cf7855fffc65f5abd242b135ae87df" );
            {
                // u1 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "bc07ff041506dc73a75086a43252fb43b6327af3c6b2cc7d322ff6d1d1162b5de29edcd0b69803fe2f8af8e3d103d0a9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009ab73dcfffc820e739a3ed9c316c6f15d27a032f8aa59325f7842cf4a34198ac6ff09eb1a311ce226bf1abb49d808511", "0135f4b0c2b6b195da9bbe1993e985b8607664f1a4b3d499ea1a112b6afc7e6b88357c9348b614ddfdc846a3f38bbdca" );
            {
                // u2 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "28771b137fb7d74c0ed0290416f47c8118997923c7b3b717fbbd5308a4bb0e494714bd3f1ff5e9e368887377284272eb", "00f92e5df476a2fa0906ce4fad121c641abb539ab4ef270cd8f0497cc3e6e05b18561b730670f010741238a5d07b077045" );
            {
                // u2 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa84ecde56a2cf73ea3abc092185cb1a51f34810f1ddd8c64d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009d1baad217829d5f2d7db5bd085e9126232e8c49c58707cb153db1d1e20a109c90f7bcbae4f2c74d6595207cb0e5dd27", "1eea30752a1425905d0811d0f42019e5088142b41945bee03948f206f2e7c3c1081ba9a297180e36b247ee9e70832035" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "c152aafea3a8612ec83a7dc9448f01941899d7041319bbd60bfdfb3c03da74c00c8fc4176128a6263268711edc6e8e90";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008e39e1e44f782b810ea93037c344371c4fb141c8bf196ea618f3a176547139a6d02121d2794cbe6481061694db579315", "00c3184e8cd9b6c16b37699633d87f5600654b44cbcb5ab50ba872dfa001769eb765b2d1902e01d2e8af4e1fd6e9c0f30f" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "4764eeac3e7a08daacfad7d1e1e3696042164b06f77bd78c3213ddea6f9fd449a34c97b9e560a6bf7195da41333c7565";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b96fca0e3f6ebf7326f0a8ce8bdf226a2560c22526bf154f7b467010f3a46baca73414070db0f7ab039f345548452ae2", "6f7b744274e9bd6c791f47513e6b51eb42fea3816b3032b33a81695f04d4e775be06484cf7e6a69cba8bacbcb597b3e3" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "cb4d5c0ff0abe29b2771fe9f179a5614e2e4c3cc1134a7aad08d8ec3fd8fcd07fd34b3473ca65ead1c7bb20bcf3ea5c9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4fd52b11ff747b59ef609e065a462cd85b73172d20f406fdd845d4eaa3ec173e06ee58a58e1810f051b275bbaa47ccb4", "0084d2382b9e72c526dc3764a11a4a962a7a4c7355e6f057fc976ab73cc384f9a29da50769809ecbf37358dd83c74fc25f" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "6e441db253bf798dbc07ff041506dc73a75086a43252fb439dd016110475d8381f65f7f27f9e1cfc9b48f06a2dfa8eb6";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7d123e3dbab9913d698891023e28654cba2a94dc408a0dc386e63d8d22ff0f33358a231860b7c2e4f8429e9e8c9a1c5b", "00e7c95d1875f24ecdfeffc6136cf56f800f5434490f234f14d78505c2d4aea51e2a3a6a5d1693e72c4b1dd2a8746b875a" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "41db253bf798dbc07ff041506dc73a75086a43252fb43b63191efcd0914b6afb4bf8c77d008dbeac04277ef4aa59c394";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "608ce23a383452f8f4dcc5c0085d6793ec518985f0276a3409a23d7b7ca7e7dcb163601aca73840c3bd470aff70250bf", "674005a0be08939339363e314dca7ea67adfb60cd530628fe35f05416da8f20d5fb3b0ccd183a21dbb41c4e195d6303d" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "83b64a77ef31b780ffe082a0db8e74ea10d4864a5f6876c6323df9a12296d5f697f18efa011b7d58084efde954b38728";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "48d23de1869475a1de532399da1240bab560eb74a6c7b0871bf8ac8fb6cc17cf7b34fcd7c79fd99c76c605bdf3fcbe18", "00e15b66ab91d0a03e203c2ff914d4bedc38c1ec5dcd1d12db9b43ef6f44581632683bf785aa4326566227ece3c16be796" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "53bf798dbc07ff041506dc73a75086a43252fb43b6327af3b42da6d3e9a72cde0b5c2de6bf072e780e94ad12dcab270a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5d5eb470f9c6a0bb18e8960b67011acf9f01df405ac5b4bf9f4611d6a8af1a26b11b0790e93ae2361525dde51bacac94", "00d42ce151793b80cee679c848362ec272000316590ebc91547b3b6608dfbade21e04de1548ebb45cc4721eb64a16b8318" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "24c53b0a00cf087a9a20a2b78bc81d5b383d04ba9b55a567405239d224387344c41cceff0f68ffc930dbaa0b3d346f45";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1da34a149ed562c8ec13e84cb067107bc28b50bfa47575d5a9948cde5a3d7357c38ea41fcfcdd1ab1a1bd9b6592b33d9", "00e14aedfd0cfffcfecbdc21276e6a2c78b8729412c48339ae538b799b7d8e61163047a64cfcec9018aa00f99ae740e3f3" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "c600ccb39bb3e2d85d880d76d1d519205f050c4b93deae0c5d63e8898ca8d7a5babbb944debe0f3c44332aae5770cb7b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008b8675211b321f8b318ba60337cde32a6b04243979546383127a068a8749cb5e98c4231b198de62a2b069d3a94d1c7b1", "009d33468a130b4fef66a59d4aee00ca40bdbeaf044b8b22841bb4c8ba419f891b3855f4bddf8dae3577d97120b9d3fa44" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "3ead55015c579ed137c58236bb70fe6be76628fbece64429bb655245f05cb91f4b8a499ae7880154ba83a84bf0569ae3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "442766bdb8b2cf4fef5f65d5d86b61681ec89220c983b51f15bfe12fb0bf9780e0c38bbcc888afb3c55ee828774b86f7", "56b7f399c534c7acd46be4bc8bb38f087b0023b8f5166ab34192ca0b1cad62d663aa474c6f9286c8a054ef94ea42e3c7" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "de03ff820a836e39d3a8435219297da1db193d79e359663e7cc9a229e2a6ac9e9d5c75417fa455bc8e3b89274ee47d0e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "11342b314f31648931abb897c1371dd3a23e91f2405c4a81744be18e753919752208779de2d54e865eeefbb0bfb4998a", "00f533d7a4d6fc6cb5cb98915ce08d0f656e37a502e78f8c1b8baca728c2ecb05a2156f01cff16595b363cdb49c00c1aa2" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "e5a6ae07f855f14d93b8ff4f8bcd2b0a717261e6089a53d54bf86e22f8e37d73aaa7607cc2ab831404b3e5bb4e01e79e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3c96b49ff60ff05951b7b1aca65664f13128b714da620697ef0d90bfc01ef643baa5c608f16ca885038322a443aed3e6", "169a27f2ea7a36376ef92a900e5389a7b441fd051d693ce65250b881cfdd6487370372292c84369742b18106188b05c0" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffed2119d5fc12649fc808af3b6d9037d3a44eb32399970dd0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "388dae49ea48afb558456fdb1d0b04d4f8f1c46f14d22de25862d35069a28ae9284d7a8074546e779ad2c5f17ce9b89b", "00b353298f3c526aa0a10ed23bcb1ed9788812c8a3a6cbea82a3d9d8d465a4cca59dbd3d3d8a36098d644f1b45d36df537" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "79b95c013b0472de04d8faeec3b779c39fe729ea84fb554cd091c7178c2f054eabbc62c3e1cfbac2c2e69d7aa45d9072";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c85200ac6411423573e3ebc1b7aea95e74add5ce3b41282baa885972acc085c8365c05c539ce47e799afc353d6788ce8", "68cfce1eb2bfe009990084fb03c0919ab892313d7a12efc3514e8273685b9071892faefca4306adf7854afcebafffbf4" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "bfd40d0caa4d9d42381f3d72a25683f52b03a1ed96fb72d03f08dcb9a8bc8f23c1a459deab03bcd39396c0d1e9053c81";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e63ae2881ed60884ef1aef52178a297bdfedf67f4e3c1d876ad10b42c03b5e67f7f8cfaf4dfea4def7ab82fde3ed9b91", "0e2be22bc3fa46a2ed094ebd7c86a9512c8c40cd542fb539c34347ef2be4e7f1543af960fd2347354a7a1df71a237d51" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "4c7d219db9af94ce7fffffffffffffffffffffffffffffffef15cf1058c8d8ba1e634c4122db95ec1facd4bb13ebf09a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e9c415f8a72055239570c3c370cf9380cdfabb6ebdbd8058e2fc65193080707895ea1566eeb26149603f4b4d4c1e79d4", "0096ae17a001424d21eae4eaa01067048bcd919625fdd7efd896d980633a0e2ca1f8c9b02c99b69a1e4fa53468a2fe244d" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "d219db9af94ce7ffffffffffffffffffffffffffffffffffd189bdb6d9ef7be8504ca374756ea5b8f15e44067d209b9b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "637223a93dd63af6b348f246e7b3bcb30beaa1dcc888af8e12e5086aa00f7792fbe457463c52422d435f430ad1bb4b21", "00f9a1e01758d1e025b162d09d3df8b403226ed3b35e414c41651740d509d8cf6b5e558118607d10669902abebda3ca28d" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a433b735f299cfffffffffffffffffffffffffffffffffffdbb02debbfa7c9f1487f3936a22ca3f6f5d06ea22d7c0dc3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7f4dc23982ecc8b84f54241715c7e94e950f596ce033237639a15fefa5eb5c37cb2e562d6d5b3051ea15600e3341a565", "00fed2b55b89d2793321374887b78827ee4ca2216eac2993b1b095844db76adc560450135c072ac1a2c4167520237fbc9d" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "b9af94ce7fffffffffffffffffffffffffffffffffffffffd6efeefc876c9f23217b443c80637ef939e911219f96c179";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a0ae8c949f63f1b6a5d024c99e0a296ecd12d196d3b1625d4a76600082a14d455aab267c68f571d89ad0619cb8e476a1", "34634336611e1fd1d728bcea588d0e1b652bbca0e52c1bfbd4387a6337ff41ce13a65c8306915d2a39897b985d909b36" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a276276276276276276276276276276276276276276276273d7228d4f84b769be0fd57b97e4c1ebcae9a5f635e80e9df";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7cad1637721f5988cb7967238b1f47fd0b63f30f207a165951fc6fb74ba868e5b462628595edc80f75182e564a89c7a0", "00fc04c405938aab3d6828e72e86bc59a400719270f8ee3cb5ef929ab53287bb308b51abd2e3ffbc3d93b87471bc2e3730" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "73333333333333333333333333333333333333333333333316e4d9f42d4eca22df403a0c578b86f0a9a93fe89995c7ed";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2024ecde0e61262955b0301ae6b0a4fbd7771762feb2de35eed1823d2636c6e001f7bfcdbc4e65b1ea40224090411906", "00d55362a570e80a2126f01d919b608440294039be03419d518b13cca6a1595414717f1b4ddb842b2c9d4f543e683b86a0" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "7fffffffffffffffffffffffffffffffffffffffffffffffda4233abf824c93f90115e76db206fa7489d6647332e1ba3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "40c5f2608956380c39695c7457ddce0880b5e8fab0a9a3726d0c8535b2ff6ca15814d83ed82c0ab33aba76e05e5c0476", "00c9d15a2a0b2041237ff61c26519d1d74b141d7a4499fbdefc414a900937a8faf6ef560550c73cdb7edfe9314c480bb2b" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "3fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294bb";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "74acdfd2ab763c593bca30d248f2bf26f1843acf9eb89b4dfcb8451d59683812cf3cbe9a264ea435912a8969c53d7cb8", "496dcb0a4efed69b87110fda20e68eb6feed2d5101a4955d43759f10b73e8ffc3131e0c12a765b68bd216ed1ec4f5d2f" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "dfea06865526cea11c0f9eb9512b41fa9581d0f6cb7db9680336151dce79de818cdf33c879da322740416d1e5ae532fa";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00da35d6a82818ae5254cb65fc86ac42a47873ab247a5ca664e9f095e8de9a57fe721860e66cbc6bd499431a48a3991734", "00945baab27ca6383737b7dd45023f997aff5e165f0fd7d8e5c0b5f9c5e731588af2fe5bd8976a0b871c132edf21f363af" );
            {
                // point duplication during verification
                auto m = "313233343030"_hex;
                bn_t sig_r = "b37699e0d518a4d370dbdaaaea3788850fa03f8186d1f78fdfbae6540aa670b31c8ada0fff3e737bd69520560fe0ce60";
                bn_t sig_s = "e16043c2face20228dba6366e19ecc6db71b918bbe8a890b9dad2fcead184e071c9ac4acaee2f831a1e4cc337994f5ec";
                auto r = true; // result = valid - flags: ['PointDuplication']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00da35d6a82818ae5254cb65fc86ac42a47873ab247a5ca664e9f095e8de9a57fe721860e66cbc6bd499431a48a3991734", "6ba4554d8359c7c8c84822bafdc0668500a1e9a0f028271a3f4a063a18cea7740d01a4266895f478e3ecd121de0c9c50" );
            {
                // duplication bug
                auto m = "313233343030"_hex;
                bn_t sig_r = "b37699e0d518a4d370dbdaaaea3788850fa03f8186d1f78fdfbae6540aa670b31c8ada0fff3e737bd69520560fe0ce60";
                bn_t sig_s = "e16043c2face20228dba6366e19ecc6db71b918bbe8a890b9dad2fcead184e071c9ac4acaee2f831a1e4cc337994f5ec";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00820064193c71c7141fe41e711fe843a7474be6b05f50cb0be411cdf7fc78ea7ec96aeb3991ef7646bbde59152d381a32", "631c5adf93d488b45e67cc9890d8e779f63960193dc16bd1cc136b3e28cf499dfa8e7bff482a0115e6083987f7c042fc" );
            {
                // point with x-coordinate 0
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "52fabc58eacfd3a4828f51c413205c20888941ee45ecac076ffc23145d83542034aa01253d6ebf34eeefaa371d6cee11", "009f340712cd78155712746578f5632ded2b2e5afb43b085f81732792108e331a4b50d27f3578252ffb0daa9d78655a0ab" );
            {
                // point with x-coordinate 0
                auto m = "313233343030"_hex;
                bn_t sig_r = "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                bn_t sig_s = "0033333333333333333333333333333333333333333333333327e0a919fda4a2c644d202bd41bcee4bc8fc05155c276eb0";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a8fdb1a022d4e3a7ee29612bb110acbea27daecb827d344cb6c6a7acad61d371ddc7842147b74a18767e618712f04c1c", "64ac6daf8e08cd7b90a0c9d9123884c7a7abb4664a75b0897064c3c8956b0ca9c417237f8d5a7dd8421b0d48c9d52c7c" );
            {
                // comparison with point at infinity
                auto m = "313233343030"_hex;
                bn_t sig_r = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                bn_t sig_s = "33333333333333333333333333333333333333333333333327e0a919fda4a2c644d202bd41bcee4bc8fc05155c276eb0";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00878e414a5d6a0e0d1ab3c5563c44e80c3b2ef265f27a33ed5cac109ad664c1269beae9031d8d178cbfdb1bfa7cc3cc79", "00fabbb2b6f7ce54026863b0f297a4fe3de82d5044dacafede49d5afc60bc875f4b659c06c19bb74c7c27351687f52b411" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008faa8497ae3006b612999b03f91f7884d95543a266598e897b71e44ecfd9abd7908bfd122bb366c016a577cb1b2e2e41", "2bb1a719289c749804ca677d14c0900fab031da8c70724723a0d54e3a0035da7dcddeef6fce80df2f81940817d27b2b5" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c59cc648629e62dc1855f653583da0ace631e0f4b4589b7fe5cc449e12df2dceeb862cae00cd100233b999af657ae16c", "00b138f659dcc8d342fd17664d86c5bddaa866c20b0031f65c8442a0ed62b337d09adb63a443ab14e3587b9299053717f9" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "6666666666666666666666666666666666666666666666664fc15233fb49458c89a4057a8379dc9791f80a2ab84edd61";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "386bdc98fe3c156a790eee6d556e0036a4b84853358bd5ab6856db5985b9e8ea92e8d4c1f8d04ecd1e6de4548bf28821", "5503292c2c570f57b42f2caf5e7ab94d87817a800b2af6ffcd4f13e30edb8caaf23c6d5be22abea18c2f9450ad1a4715" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "99999999999999999999999999999999999999999999999977a1fb4df8ede852ce760837c536cae35af40f4014764c12";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "294c37b3ec91a1b0500042d8b97bc9619d17f784a9ea528c0602d700783bfbac9ac49bff1e527b39bb2a49d1dc3abd47", "1e798679b7c58f4dfa33cfe40bb62e7df6d2f190b0f3804c700fa19eba28ad7fd6edd7e3a754af852921c2705f444f0b" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6aae76701acc1950894a89e068772d8b281eef136f8a8fef5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00bac7cd8a7755a174fab58e5374ec55a5ce5313235ec51c919c6684bd49305b7005393f72bc4d810ca864fb046d2c8341", "5a33b77f4145680bde63b669ea1f10f3ee1836018c11a6f97155d90827c83dbac388402ac8f59368ddaf2c33548611af" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
                bn_t sig_s = "0eb10e5ab95f2f26a40700b1300fb8c3e754d5c453d9384ecce1daa38135a48a0a96c24efc2a76d00bde1d7aeedf7f6a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00984a1c04446a52ad6a54d64f2c6c49b61f23abe7dc6f33714896aefb0befb9a52b95b048561132c28c9850e851a6d00e", "00b4e19f9de59d30ca26801f2789a3330b081e6bf57f84f3c6107defd05a959cef5f298acea5a6b87b38e22c5409ec9f71" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "55555555555555555555555555555555555555555555555542766f2b5167b9f51d5e0490c2e58d28f9a40878eeec6326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00f00d6327b1226eaa1b0897295eeddadf7510249e6f0f811b57d7197eb6e61199a8f1c6665ec4821d3e18675d5399fdf7", "0087bf1e3fb7fee5cb3582a4159808b75e8b1de07eaffd49d3882d15c77443ad83213d21a4be9285223aa44a840e47eb56" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "452b047743346898b087daaac5d982d378752ba534e569f21ac592c09654d0809b94ccf822045f2885cbd3b221453cd6", "68a01f502f551af14aab35c2c30ec7bac0709f525fe7960439b1e9de53cdad245efd8930967cde6caf8d222c8200cd69" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "6666666666666666666666666666666666666666666666664fc15233fb49458c89a4057a8379dc9791f80a2ab84edd61";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "44a8f54795bdb81e00fc84fa8373d125b16da6e2bf4cfa9ee1dc13d7f157394683963c170f4c15e8cf21b5466b49fa72", "00bb5693655b3e0a85e27e3e6d265fba0131f3083bf447f62b6e3e5275496f34daa522e16195d81488a31fe982c2b75f16" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "99999999999999999999999999999999999999999999999977a1fb4df8ede852ce760837c536cae35af40f4014764c12";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "10b336b3afb80c80ff50716e734110fe83cd5b8d41d7f2f94f0dec7ecf1facc663babb8ed94e4bdf3592e37464970afa", "009be144d354e9b456873c6387a12a3eefd3e2feb66f7519ac72ac502c09d20d72cae9d04c88549a285c081023e1c1da08" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6aae76701acc1950894a89e068772d8b281eef136f8a8fef5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0081f92630778777a01781e7924fced35fc09018d9b00820881b14a814c1836a1f73c3641f7a17c821ffd95da902efe132", "221d81323509391f7b61bd796011337e6af36ae0798c17043d79e8efcdae8e724adf96a2309207c2d2cfd88e8c483acb" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
                bn_t sig_s = "0eb10e5ab95f2f26a40700b1300fb8c3e754d5c453d9384ecce1daa38135a48a0a96c24efc2a76d00bde1d7aeedf7f6a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "43f800fbeaf9238c58af795bcdad04bc49cd850c394d3382953356b023210281757b30e19218a37cbd612086fbc158ca";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "bc07ff041506dc73a75086a43252fb43b6327af3c6b2cc7d322ff6d1d1162b5de29edcd0b69803fe2f8af8e3d103d0a9";
                sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", "00c9e821b569d9d390a26167406d6d23d6070be242d765eb831625ceec4a0f473ef59f4e30e2817e6285bce2846f15f1a0" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "43f800fbeaf9238c58af795bcdad04bc49cd850c394d3382953356b023210281757b30e19218a37cbd612086fbc158ca";
                bn_t sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "bc07ff041506dc73a75086a43252fb43b6327af3c6b2cc7d322ff6d1d1162b5de29edcd0b69803fe2f8af8e3d103d0a9";
                sig_s = "2492492492492492492492492492492492492492492492491c7be680477598d6c3716fabc13dcec86afd2833d41c2a7e";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "29bdb76d5fa741bfd70233cb3a66cc7d44beb3b0663d92a8136650478bcefb61ef182e155a54345a5e8e5e88f064e5bc", "009a525ab7f764dad3dae1468c2b419f3b62b9ba917d5e8c4fb1ec47404a3fc76474b2713081be9db4c00e043ada9fc4a3" );
            {
                // pseudorandom signature
                auto m = ""_hex;
                bn_t sig_r = "2290c886bbad8f53089583d543a269a727665626d6b94a3796324c62d08988f66f6011e845811a03589e92abe1f17faf";
                bn_t sig_s = "66e2cb4380997f4e7f85022541adb22d24d1196be68a3db888b03eb3d2d40b0d9a3a6a00a1a4782ee0a00e8410ba2d86";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "4d7367"_hex;
                sig_r = "8071d8cf9df9efef696ebafc59f74db90c1f1ecf5ccde18858de22fe4d7df2a25cb3001695d706dfd7984b39df65a0f4";
                sig_s = "27291e6339c2a7fed7a174bb97ffe41d8cfdc20c1260c6ec85d7259f0cc7781bf2ae7a6e6fb4c08e0d75b7381bb7d9b8";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "313233343030"_hex;
                sig_r = "470014ccd7a1a5e5333d301c8ea528ac3b07b01944af30cec60f4bad94db108509e45ba381818b5bdfaf9daf0d372301";
                sig_s = "e3d49d6a05a755aa871d7cb96fffb79fed7625f83f69498ba07c0d65166a67107c9a17ae6e1028e244377a44096217b2";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "0000000000000000000000000000000000000000"_hex;
                sig_r = "377044d343f900175ac6833071be74964cd636417039e10e837da94b6919bffc3f5a517b945a450852af3259f5cbf108";
                sig_s = "32ea25006375c153581e80c09f53ad585c736f823c70147aba4fb47bb0a224fae4d8819adad80d4c144ecc2380954a9e";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ffffffffaa63f1a239ac70197c6ebfcea5756dc012123f82c51fa874d66028be00e976a1080606737cc75c40bdfe4aac", "00acbd85389088a62a6398384c22b52d492f23f46e4a27a4724ad55551da5c483438095a247cb0c3378f1f52c3425ff9f1" );
            {
                // x-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "ccb13c4dc9805a9b4e06ee25ef8c7593eaff7326c432d4b12b923163cf1cbe5fe1cfd3546c1d0761d8874e83ffd2e15d";
                bn_t sig_s = "db1b0c082ae314b539f05e8a14ad51e5db37f29cacea9b2aab63a04917d58d008cf3f7ba41d5ea280f3b6a67be3ae8f8";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "c79a30e36d2126b348dd9eb2f5db6aa98f79d80214027e51bcf3cabec188a7ebaf25cb7bbe9ec6bfed135e2a3b70e916";
                sig_s = "241338ee2ac931adea9a56e7bfe909947128d54d5122a47b00c278e684e10102740d26e89e343290a5b2fa8b401faec6";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "0df82e4ec2960e3df614f8b49cec9a4ee1054365414241361feec9d9d9b6909d8775f222ec385a14afab46266db390c3";
                sig_s = "0968485e854addba0f8354e677e955e1ef2df973d564c49f65f2562cb2a2b80d75e92f8784042955f7b8765f609ce221";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d1827fc6f6f12f21992c5a409a0653b121d2ef02b2b0ab01a9161ce956280740b1e356b255701b0a6ddc9ec2ca8a9422", "00c6ed5d2ced8d8ab7560fa5bb88c738e74541883d8a2b1c0e2ba7e36d030fc4d9bfb8b22f24db897ebac49dd400000000" );
            {
                // y-coordinate of the public key has many trailing 0's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "1fafd83d728422e1485f1e52e5b631548647cc3c76c109c3177a73751d91a19012fa4628b218f2229fc4d55f105fe001";
                bn_t sig_s = "4474f9af7b4b0bb96fdb05ae918f799024e8d5b864e49ccd047cf97e7b9f8763cce015c11cf1f461c9027cb901055101";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "e6025bb957ab197fb4c080d0a5c647e428afb0d7cc235c605ae97545494fd31a9979790bb2da6e1cf186789422b15c97";
                sig_s = "8ae9872291430d1bb371ef72360dad5afbb6fb001f403d9aaa1445f0326eb1eef775c9dfe1d7ef8bf4e744822108d27e";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "877d5567c18fa568259005a89c2300d1b3825b732fa14964c1477d4b3098afd09384b97d497464adba41e9df8a74d339";
                sig_s = "c40f0760717b4b3bae75742b6dc3dcf04cc22a449cfea19d305e0658cb705fda75163e7399e0b3125ca7d1919c13851e";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1099bb45100f55f5a85cca3de2b3bd5e250f4f6fad6631a3156c2e52a33d7d615dd279f79f8b4baff7c713ac00000000", "00e6c9b736a8929f2ed7be0c753a54cbb48b8469e0411eaf93a4a82459ba0b681bba8f5fb383b4906d4901a3303e2f1557" );
            {
                // x-coordinate of the public key has many trailing 0's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "e706b0045a6f54bd175e2437b48767b0204f93d8a4d9d3d00838278137e5b670de4305c5c55e49059b8b5f6e264654c9";
                bn_t sig_s = "405741adff94afd9a88e08d0b1021911fa4cedb2466b1a8fd302a5b5d96566ada63ccb82b6c5e8452fde860c545e0a19";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "0c57ce2bc579fbd3a759dfbf5e84c3cef2414846a2e300453e1e4c5188f24432b14ca647a733b6ad35c980a880d36145";
                sig_s = "f12a119e22d48b82049df611f1c851fb22795056498a873c730fcb9fd8f314728de0298b9b22c348abc6de2aba97e972";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "9a8f80697ccf2e0617612027d861a3a3a657fb75cc82810b40dd5072d39ff37eca29008390da356137e2c9babd814198";
                sig_s = "a86537a83c3d57da50e4b29b47dcc3717c5a1ed0fff18ade8dcce4220eac63aab60b9bfed5f1bdd241dab655a9bdd75f";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2b089edd754169010145f263f334fc167cc19dae8225970ae19cc8cb7ec73593d6a465c370f5478b0e539d69", "00d1951d597b56a67345acb25809581f07cd0eb78d9538a3f8a65f300e68a1eb78507df76de650e8f8ee63a5f0c5687c98" );
            {
                // x-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "93718f6f8542725f62de7039fc193d3fcc81d622230ccc94e9e265390b385af3a3ba50c91a9d6a5b1e07d79af2bd80b2";
                bn_t sig_s = "d08499f3d298e8afecea122265a36dbf337259020654739783c8ec8ef783d072555b5907285ce83fc8ced9c8398c6269";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "ce26e42c490dec92cf59d6b1ba75c9a1400d6e5c3fd7c47e1eeb1cded30a3a3d18c81cdfdcbad2742a97293369ce21c2";
                sig_s = "94671085d941fd27d495452a4c8559a1fe24f3225f5b8ef75faf9d3fb01372c586e23b82714359d0e47144ff5d946161";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "ffc4738acf71f04a13104c328c138b331fb7202aef66f583ba543ed490d12993c18f724c81ad0f7ea18dae352e5c6480";
                sig_s = "e67d4ccdeb68a9a731f06f77eae00175be076d92529b109a62542692c8749ddfde03bed1c119a5901a4e852f2115578f";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00fb01baad5f0b8f79b9cd104d12aab9310146add7d6b4c022d87ae6711178b94d618ca7b3af13854b1c588879e877b336", "208b3f5ad3b3937acc9d606cc5ececab4a701f75ed42957ea4d7858d33f5c26c6ae20a9cccda56996700d6b4" );
            {
                // y-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "e6fa8455bc14e730e4ca1eb5faf6c8180f2f231069b93a0bb17d33ad5513d93a36214f5ce82ca6bd785ccbacf7249a4c";
                bn_t sig_s = "3979b4b480f496357c25aa3fc850c67ff1c5a2aabd80b6020d2eac3dd7833cf2387d0be64df54a0e9b59f12c3bebf886";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "1b49b037783838867fbaa57305b2aa28df1b0ec40f43140067fafdea63f87c02dfb0e6f41b760fbdf51005e90c0c3715";
                sig_s = "e7d4eb6ee61611264ea8a668a70287e3d63489273da2b30ad0c221f1893feaea3e878c9a81c6cec865899dbda4fa79ae";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "91d9da3d577408189dcaae33d95ed0a0118afd460d5228fa352b6ea671b172eb413816a70621ddaf23c5e2ef79df0c11";
                sig_s = "053dadbfcd564bddbe44e0ecb4d1e608dbd35d4e83b6634cc72afb87a2d61675ee13960c243f6be70519e167b1d3ceb0";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00fb01baad5f0b8f79b9cd104d12aab9310146add7d6b4c022d87ae6711178b94d618ca7b3af13854b1c588879e877b336", "00ffffffffdf74c0a52c4c6c8533629f933a131354b58fe08a12bd6a815b287a71cc0a3d92951df5633325a96798ff294b" );
            {
                // y-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "af0ed6ce6419662db80f02a2b632675445c7bf8a34bbacdc81cc5dd306c657ca4c5a3fb1b05f358d8f36fda8ae238806";
                bn_t sig_s = "46b472c0badb17e089c8f9697fd0b4ce71f0f4471b235483d4c8dd3d00aa282cde990253df38ba733b2ad82a601c7508";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "e2aa9468ccaaadad8b9f43a429c97f0c6a7eedcb4d4af72d639df0fe53f610b953408a8e24e8db138551770750680f7a";
                sig_s = "d81020846d1c50ee9ae23601dd638cb71b38d37fb555268c2fa1ad8a761fa7b27afcab2fa69224d1f976699914e09de2";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "6bf6fa7a663802c3382cc5fd02004ec71e5a031e3d9bfc0858fa994e88497a7782308bc265b8237a6bbbdd38658b36fc";
                sig_s = "3a9d5941a013bf70d99cc3ff255ce85573688dac40344b5db7144b19bf57bb2701e6850a8f819796b67f7d0b6aea7e50";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }
        } // End of Google's Wycheproof tests ecdsa_secp384r1_sha512_p1363_test
    }
    EOSIO_TEST_END // ecdsa_secp384r1_test
}
