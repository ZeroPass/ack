// Copyright © 2021 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros

#pragma once
#include <eosio/tester.hpp>

#include <eosiock/keccak.hpp>
#include <eosiock/utils.hpp>

#include "utils.hpp"

namespace eosiock::test {

    EOSIO_TEST_BEGIN(sha3_256_test)
        // NIST CAVS 19.0
        // "SHA3-256 ShortMsg" information for "SHA3AllBytes1-28-16"
        // Length values represented in bits
        // Generated on Thu Jan 28 13:32:44 2016
        bytes msg;// = 00
        auto md = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "e9"_hex;
        md  = "f0d04dd1e6cfc29a4460d521796852f25d9ef8d28b44ee91ff5b759d72c1e6d6"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "d477"_hex;
        md  = "94279e8f5ccdf6e17f292b59698ab4e614dfe696a46c46da78305fc6a3146ab7"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "b053fa"_hex;
        md  = "9d0ff086cd0ec06a682c51c094dc73abdc492004292344bd41b82a60498ccfdb"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "e7372105"_hex;
        md  = "3a42b68ab079f28c4ca3c752296f279006c4fe78b1eb79d989777f051e4046ae"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "0296f2c40a"_hex;
        md  = "53a018937221081d09ed0497377e32a1fa724025dfdc1871fa503d545df4b40d"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "e6fd42037f80"_hex;
        md  = "2294f8d3834f24aa9037c431f8c233a66a57b23fa3de10530bbb6911f6e1850f"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "37b442385e0538"_hex;
        md  = "cfa55031e716bbd7a83f2157513099e229a88891bb899d9ccd317191819998f8"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "8bca931c8a132d2f"_hex;
        md  = "dbb8be5dec1d715bd117b24566dc3f24f2cc0c799795d0638d9537481ef1e03e"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "fb8dfa3a132f9813ac"_hex;
        md  = "fd09b3501888445ffc8c3bb95d106440ceee469415fce1474743273094306e2e"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "71fbacdbf8541779c24a"_hex;
        md  = "cc4e5a216b01f987f24ab9cad5eb196e89d32ed4aac85acb727e18e40ceef00e"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "7e8f1fd1882e4a7c49e674"_hex;
        md  = "79bef78c78aa71e11a3375394c2562037cd0f82a033b48a6cc932cc43358fd9e"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "5c56a6b18c39e66e1b7a993a"_hex;
        md  = "b697556cb30d6df448ee38b973cb6942559de4c2567b1556240188c55ec0841c"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "9c76ca5b6f8d1212d8e6896ad8"_hex;
        md  = "69dfc3a25865f3535f18b4a7bd9c0c69d78455f1fc1f4bf4e29fc82bf32818ec"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "687ff7485b7eb51fe208f6ff9a1b"_hex;
        md  = "fe7e68ae3e1a91944e4d1d2146d9360e5333c099a256f3711edc372bc6eeb226"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "4149f41be1d265e668c536b85dde41"_hex;
        md  = "229a7702448c640f55dafed08a52aa0b1139657ba9fc4c5eb8587e174ecd9b92"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "d83c721ee51b060c5a41438a8221e040"_hex;
        md  = "b87d9e4722edd3918729ded9a6d03af8256998ee088a1ae662ef4bcaff142a96"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "b32dec58865ab74614ea982efb93c08d9acb1bb0"_hex;
        md  = "6a12e535dbfddab6d374058d92338e760b1a211451a6c09be9b61ee22f3bb467"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "cf549a383c0ac31eae870c40867eeb94fa1b6f3cac4473f2"_hex;
        md  = "cdfd1afa793e48fd0ee5b34dfc53fbcee43e9d2ac21515e4746475453ab3831f"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "938fe6afdbf14d1229e03576e532f078898769e20620ae2164f5abfa"_hex;
        md  = "9511abd13c756772b852114578ef9b96f9dc7d0f2b8dcde6ea7d1bd14c518890"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "66eb5e7396f5b451a02f39699da4dbc50538fb10678ec39a5e28baa3c0"_hex;
        md  = "540acf81810a199996a612e885781308802fe460e9c638cc022e17076be8597a"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "94464e8fafd82f630e6aab9aa339d981db0a372dc5c1efb177305995ae2dc0"_hex;
        md  = "ea7952ad759653cd47a18004ac2dbb9cf4a1e7bba8a530cf070570c711a634ea"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "c178ce0f720a6d73c6cf1caa905ee724d5ba941c2e2628136e3aad7d853733ba"_hex;
        md  = "64537b87892835ff0963ef9ad5145ab4cfce5d303a0cb0415b3b03f9d16e7d6b"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "6ef70a3a21f9f7dc41c553c9b7ef70db82ca6994ac89b3627da4f521f07e1ae263"_hex;
        md  = "0afe03b175a1c9489663d8a6f66d1b24aba5139b996400b8bd3d0e1a79580e4d"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "0c4a931ff7eace5ea7cd8d2a6761940838f30e43c5d1253299abd1bd903fed1e8b36"_hex;
        md  = "dc5bebe05c499496a7ebfe04309cae515e3ea57c5d2a5fe2e6801243dd52c93b"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "b17977aced3a1184b14b0e41a04dd8b513c925ca19211e1abdc6c1b987ac845545fb3b820a083b4f7883c0"_hex;
        md  = "f91b016d013ede8d6a2e1efd4c0dd99417da8b0222d787867ca02b0ea2e80e45"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "6fa6de509719ffbf17759f051453c0ac3cbe13346546bbc17050541074b034af197af06e41142211ee906a476039b3e07d6cb83a76aac6fca8eac307c034"_hex;
        md  = "766630993fbb651fd8d3603e3eebc81931fb1302a46791df259a6e13ca2cba9f"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "67e384d209f1bc449fa67da6ce5fbbe84f4610129f2f0b40f7c0caea7ed5cb69be22ffb7541b2077ec1045356d9db4ee7141f7d3f84d324a5d00b33689f0cb78"_hex;
        md  = "9c9160268608ef09fe0bd3927d3dffa0c73499c528943e837be467b50e5c1f1e"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "4bef1a43faacc3e38412c875360606a8115d9197d59f61a85e0b48b433db27695dc962ed75d191c4013979f401cf3a67c472c99000d3a152227db61de313ab5a1c"_hex;
        md  = "8703a1f7424c3535f1d4f88c9b03d194893499478969fbb0a5dc2808a069ab8f"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "02e238461d0a99d49c4cd16f442edf682c39b93114fc3d79f8546a99e5ead02f0cfc45081561da44b5c70eb48340418707fd6b2614580d5c581868ba32f1ee3ac34bf6224845b32ba7f867e34700d45025"_hex;
        md  = "abef81b33591eedcac0cf32fb5a91c931f2d719c37801409133552170ce50dbf"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "a48950c961438e09f4d054ac66a498e5f1a4f6eabfde9b4bf5776182f0e43bcbce5dd436318f73fa3f92220cee1a0ff07ef132d047a530cbb47e808f90b2cc2a80dc9a1dd1ab2bb274d7a390475a6b8d97dcd4c3e26ffde6e17cf6"_hex;
        md  = "44c00cf622beca0fad08539ea466dcbe4476aef6b277c450ce8282fbc9a49111"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "ca88614828f8acdb5fcffab6bb2fb62d932b7808e4d9cc3139a835b0cef471d9f4d8ffc4b744dffebf4f997e74ce80db662538bceb5d768f0a77077e9700149ea0e6a46a088a62717216a14b60119dd19c31038ed870b4709161c6c339c5cc60945a582263f3be9a40cd1a04c921947900f6e266f2390f3c970f7b69"_hex;
        md  = "fe2d4183ccdaa816b4446a9b6c07d0ba4b42ac743599db5dc482b1941f443c71"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "ab6b92daf83275cb9c1b76cfb59fbcc8ac53188e0b6980918e7ac0c07c836ca9372d19e11251cca664bbb3c3db2e13b412a9820b65e95612042f5db24643cf9340b9808597735a1f92670ba573a2fb2f088d81087d70565574344af7576d35b2ed98318e2ca0067d4fa8e63f28045b83b6887d4ffa0668a10712ed5759"_hex;
        md  = "744538e1ae1cd7357710b56c3bc6f1bd7a8564118a1e0f9acc30fcf0b5396eef"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "84b60cb3720bf29748483cf7abd0d1f1d9380459dfa968460c86e5d1a54f0b19dac6a78bf9509460e29dd466bb8bdf04e5483b782eb74d6448166f897add43d295e946942ad9a814fab95b4aaede6ae4c8108c8edaeff971f58f7cf96566c9dc9b6812586b70d5bc78e2f829ec8e179a6cd81d224b161175fd3a33aacfb1483f"_hex;
        md  = "8814630a39dcb99792cc4e08cae5dd078973d15cd19f17bacf04deda9e62c45f"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "989fc49594afc73405bacee4dbbe7135804f800368de39e2ea3bbec04e59c6c52752927ee3aa233ba0d8aab5410240f4c109d770c8c570777c928fce9a0bec9bc5156c821e204f0f14a9ab547e0319d3e758ae9e28eb2dbc3d9f7acf51bd52f41bf23aeb6d97b5780a35ba08b94965989744edd3b1d6d67ad26c68099af85f98d0f0e4fff9"_hex;
        md  = "b10adeb6a9395a48788931d45a7b4e4f69300a76d8b716c40c614c3113a0f051"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )

        msg = "56ea14d7fcb0db748ff649aaa5d0afdc2357528a9aad6076d73b2805b53d89e73681abfad26bee6c0f3d20215295f354f538ae80990d2281be6de0f6919aa9eb048c26b524f4d91ca87b54c0c54aa9b54ad02171e8bf31e8d158a9f586e92ffce994ecce9a5185cc80364d50a6f7b94849a914242fcb73f33a86ecc83c3403630d20650ddb8cd9c4"_hex;
        md  = "4beae3515ba35ec8cbd1d94567e22b0d7809c466abfbafe9610349597ba15b45"_hex;
        REQUIRE_EQUAL( sha3_256(msg), md )
    EOSIO_TEST_END

    EOSIO_TEST_BEGIN( keccak_test )
        EOSIO_TEST( sha3_256_test )
    EOSIO_TEST_END
}