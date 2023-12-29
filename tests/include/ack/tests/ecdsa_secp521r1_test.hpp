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
    EOSIO_TEST_BEGIN(ecdsa_secp521r1_test)
    {
        using namespace ec_curve;
        using bn_t = ec_fixed_bigint<521>;
        constexpr auto& curve = secp521r1;

        // Verify that the curve parameters are correct
        REQUIRE_EQUAL( secp521r1.p  , "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" )
        REQUIRE_EQUAL( secp521r1.a  , "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc" )
        REQUIRE_EQUAL( secp521r1.b  , "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00" )
        REQUIRE_EQUAL( secp521r1.g.x, "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66" )
        REQUIRE_EQUAL( secp521r1.g.y, "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650" )
        REQUIRE_EQUAL( secp521r1.n  , "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409" )
        REQUIRE_EQUAL( secp521r1.h  , 1 )

        REQUIRE_EQUAL( secp521r1.a_is_minus_3, true  )
        REQUIRE_EQUAL( secp521r1.a_is_zero   , false )
        REQUIRE_EQUAL( secp521r1.p_minus_n   , "5ae79787c40d069948033feb708f65a2fc44a36477663b851449048e16ec79bf6" )
        REQUIRE_EQUAL( secp521r1.verify()    , true )

        // NIST FIPS 186-4 test vectors
        // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
        // CAVS 11.0
        // "SigVer" information
        // Curves/SHAs selected: P-521,SHA-1 P-521,SHA-256 P-521,SHA-512
        // Generated on Wed Mar 16 16:16:55 2011
        {

            // [P-521,SHA-1]
            {
                auto pubkey = curve.make_point( "01939b25d13ee8e04203643ba3709526a92912b0e98f06962fb217ed18d1ba52bff192640f980d3f7f92c116b5d94dfd48c25a26b72acb9425e316b3d2ac130a6943", "0122d0809c5de123c6e5373c1680a4d566c565408b6750d942c024d56c0d6761807adf9dab454b84254671dc68f6917f09a442643e6db1bb35e6796816dd3e5c6a7a" );
                auto m      = "a2b07a8c08cf0bf146cd11882553147831c118d9adae78dbc1700555842c5758c553751b88da75b8c6f45315db85b1d147519bffb49fa5024219054123f0925c7e715a040478aa3a5d24b4ecf1c49033edafa6622dc7e47fcd0311c54b1e3229d9caa9ba3c3dd8ea9501018a7d4a3b45b865696c94a366d818f1285426944f1d"_hex;
                bn_t sig_r  = "0144c1a1e075aced5e10f50ab7ab0f795bac07439c953ca0c749dc12d50a7e4dce21850dac1fd773e46576335a555f20d266842a8bb47fb464fe3fe297e9ee356e48";
                bn_t sig_s  = "0125f3b6f1cf7eb704bd37391a43034df9260c4d5fdccd583bf65dd5ab4b007c8f837a31a0b7c5a0be3743a187b2569841fc4c69f816c8234d8ae845b92fb9263242";
                auto r = false; // Result = F (3 - S changed)
                auto d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "00882e2cfed1286668e62699ab20c6c40068b460917b306e51ce7f72a4d760e19b3f6cb5897de599cfd84ae70c26d1a39144772b90f8ba1ec2d0f09395265f0308cf", "0020b80b99778dcdd3dc47da42b279cc289eaae369b9e2c4b0322d2eee9b1a76eed6b5b70d03d83f1db81a67ad6bea98ce71b120e9f83f0178cd6fa3f109a87b1fa9" );
                m      = "69638c3ce737f19ec3492f5cf0428f0ed411aa86254c0808810b03ffe041b3cfafcefa398de1e965da22739145622378bb439cddd76dbe4d8cc66005bd5acdb819412bd7bc8358eda95f628f431199e0cc400befcf3f518eed60f986c1b710442454a71918a240db6a9b48122bb4ee5fa1f96a916cb640413b26d0f43a32e1f4"_hex;
                sig_r  = "013ec7124331d896832b77440854c043cb605ae9cc7d20cb358513a5bab26371903c6abc6e4860a0b4940bc5429755341a10251195e5f8af42494c002340ccc57bc9";
                sig_s  = "01460bda2fd76ef05dcbe1cd17b9c5663b03551cce586c56e103179069fbef6ecae47f6555db755860f0b06eb1bf247312ae0f9d64c5cf13fbc42b923d6bee151b5f";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "011a5a6f7166fe435c5cc4238daf92a2d1af483543b7f505785ec4e2d93b2ca1d1eed3bccc31761aa60f7dadc97629475d2712998c2eccb82a78d6da7b0524662e9f", "00c66d54768f5daf947cd414a1296a54c90e2b65a14cb94aecf0ba51c280676c160c39539955f2a8194357a983a1311845f8cac51cdca1e209bbac32cc809f0e4e10" );
                m      = "3f1b870323330de661aac0ff50a0426ed28a99b97b2d5221587c15a2ed6203d8a83ecab3d65dca6df1baad2adab24e7a5f71f9180ff2a28a98ade4fc054c3ef4c88aa8a61174e2399c06d336141d17b27d002cfcd34600585b4efa37131fbb80a0d3ebb5878c8bc3ae8e5db9083210d8318302a2e584fbf147a9ef4a3c0315a2"_hex;
                sig_r  = "010f45ccf0b4de7d2af890d65395c715043dc5ca1489c79b820347d51848f599ebd4aa558c62ce8769c5d5a294679f9aa74414ca6a1b82f183f23558b0a8dc6cce68";
                sig_s  = "01adaf876dc35310ac592d1e3ba89f148c3b76417799f43aa1b24c1d2e3f544c018f066ed7baef480f7488820593bcbb25ce08183fc14c6c12fce0c118743f04e281";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "00f3bd2590cbf620991d990b84efee86073f6c789deb07b89a1f278e6cc9ea573d8586ac395958ce4e1b09bda73af1b1e6f2a8c09ecc697c021974c024564ed87165", "00514871935c187e57d1aac376aeb018acf57c4d005d85cc939a6c83256f38b2c9ecb1a0ec8d132e0f5169843faca4ae664459124bf5f30309fa86f87a2604058150" );
                m      = "14ab6196185df9ed556cd0ea664fed60c4e11cd77293497cefeca1973d291727aef380918747e1b986badd1f7835c7cbac2a1260dfd4d3c27c03fa4089dda56806518b60305041c95c78096aff537a5af1e73c674b13b536bc1256810d136530ba49d1dacc0b4d8f2a56b46c1df148673d73635790fb2afd8050a8d8174c6b0a"_hex;
                sig_r  = "0083e6155dd97bf9ba7c60dbcdcba7824b125a73df1433fcb46f57c51f63ae161ce67393d327d174aec7f0b552decb8131a192ae940deb84acc3b45be61917fc580c";
                sig_s  = "001fbfe61d75dc3fd814eeabdececf361a0a066b8c06c40f0e057faf8e4e7b206dfbbd3a99ef55df67234a29fb1a618620d2e27636d35bb98eb7535d1749c4b7e7d2";
                r = false; // Result = F (4 - Q changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "013136c4e5dee983f761955bce7c196a000cb26863a1dea762884bb041e45363a1ab1665c0ca69d1167e555bd63bceba08f6ee14571acd06eea3e1e5d9c11a036984", "011c830e1fd29ee4e10d7c6db7e90d6c1319c9858f87a944542c28679d83680747eaf71a29362ea2c22a89d78e2ce020dfbba74448d2f46b3f84b99f22604075b22e" );
                m      = "22edb41beb81e6f9479f11cf76cc67fd7177e2c452d4672aff8351737829656991e0649f1845c5a4484a81f16afcb96e9571717b2eac63e747b98421147f77a5b60b45437640a57d0fc5ef37d0d4b1fa3c7cb0091d5618f1d188c3d8aa9bcb37cfb9f7925d3b4a5135f43b104833ff1359854103cb391f6352ba9c362d2e8e4f"_hex;
                sig_r  = "0124b3bcdae17413de84721e6ebe64409d80ac07a3b6c9a603ef19c5162566076108d30ec79426d24c72ac12af6fa1caa4830d55b4e6fcee900b0e4b20cdae0eaf70";
                sig_s  = "003e0724d156c3fe5cb799a17972fbb891f0e11cfb650a1c524f6f2aab134c70fb114084a7821e0e12054fe071c516cbfb393fe9d98c840e1cc9e8475d3add81e0c7";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "019eb73393f070160d871cc396cd8d6973d828d6f3c17bcec7168843f0342c1b54f3c02a1b11348da1035833df6fa469d75692ecaa2feddce9210a813bdb0e1f9936", "00e030c5a11e2317ba10a20ec373cf69c96660b434445235efff0a9d23904c5d3ef49efdf0897222e51624f047b567ed61814f3f9e8c62f16ac27160897d5a09f476" );
                m      = "63b738e1619d533997f0e558699c5dfaafe2f5f330c4a12e9d9401db1d8767d044f543214ce9e65b9363702017a114f81f57e3f607a13268282dc4a6ef0e99862008d7da6e8b19807dc0671bb4d36045afacbe1f337663e6c06edea24b16aaccba6119e55ebbaac28cf3fe0082faa9a9e8cb0e038b45b05d7e65bbb92e264caa"_hex;
                sig_r  = "00ca41bcf9e80780687ba70d7f5ffec7da25542dc22144d9f6843889e941cad2fd8d8771755f38c0ef77909416371726b066464d1d41f888efa39456dee859f0ce98";
                sig_s  = "01770961a369ca70f9d73b61aec34662735cf228299a7c668aa24afbc9d7f621cb3acff79cee19d107361614c1e71ff1f32ae4f02b7bf94486f0fcd61b6f76f304e4";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "000c12d47011ed272aaabcb0fb6c12d8627f33bda02b2b3c3ec7b5ed60eaa577add4205d222b8ba0485b1d98ade9df18ee1e1ad9e0a9e78242322201e3c664bf8c9f", "00d1b86d4a1171bc80822e0e1094a96bdf7e031201ec212ab7d0e7b55394cad8335050701327a0a1a17181b586b89ff24a658e4b0ee16b8418dfcac122f2457f67b1" );
                m      = "cf18ce9521ce1c6e99000b03a92fe1b13df5b2b1d37f5f97e83fcc49473fb3188739810e51f85c2cac73294daa80c9f36dd6704cb0e7d14ab21328935f5a5631d5a8172349155a3d945b4b36110cf8bef096120e6dad4164176c6b8d168c83cc5619c764819eb966aeb67a5bdd3a525c3ccd7e6e322e42c7e17ffa27eae91e03"_hex;
                sig_r  = "00e4678311d0c068eab2118fc0a59014ec32c89cfd1e0273b966634b87783011b58a99204d266014d0236bd6f276f49c693a4d62b0601c307c936252cf718e239dfc";
                sig_s  = "0149f5cc02a6aaa126a99a59b83ae34f405f8076b597540625fa76e27dd29a85b6a4b0fc3e73a245a91d64a8f2b13ac345553b7a40835af76a9528cb48ac8d0be364";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "00f50a08703250c15f043c8c46e99783435245cf98f4f2694b0e2f8d029a514dd6f0b086d4ed892000cd5590107aae69c4c0a7a95f7cf74e5770a07d5db55bce4ab4", "00f2c770bab8b9be4cdb6ecd3dc26c698da0d2599cebf3d904f7f9ca3a55e64731810d73cd317264e50baba4bc2860857e16d6cbb79501bc9e3a32bd172ea8a71dee" );
                m      = "9bbbbe8a72130e1f023fb77be4648c80e1722d98bd478882383026c5c4e8748873997c5a38e0a173ed461546422d7691393dc2aceb0c0775068bc7145e33bf6a9e34f7fc6acc8f079a265168e54d3cca8d40aa04c1afd0909aa3df50908d7324aa7861b50f471fbfa5d615b0d718132c81957b178ad936deb89fde37147f8ae6"_hex;
                sig_r  = "001e7cbb20c9a66abf149c79d11859051d35cfddd04f420dd23bd3206c82b29e782453cabfefe792e4e3e68c9bf6bf50d5a00ba5dd73b41378fb46e91ca797dbb250";
                sig_s  = "00f1e9252573c003cb77f22c8c6d56f2149f7e8d88d699983da9250c8edfd4b9f864a46c48819524651886e3fd56492f4b6c75fb50a1d59e8bfc25f9fd42dc4e1d37";
                r = true; // Result = P (0 )
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "00fc6486a5cc9a366b2c25d57f3f1caadf93659223c7eb38c310916cd44bc49d3ecf1cfbd429b57e329e1eab5f552abaf828ad9cfbc2f7534dc8c87f54d252e7b69b", "01c0010af6c5cdfe26b068990cf44b1bcf324d0940bce1e953f7366c757aadaf25ff7dee4947879f305d3deb1e9a849db3cffb83bc1c7e5e82777be140931d58d177" );
                m      = "0e75709c7f795f9dbebd482fb5a71de2c7ef01fa74a64292324491cdcfec7ae6bf315a030b81096eab2fd0142fd3dae77b703554b0fcf0561d8bc2b5ce3a63c31600fa1c5ee469c9cbcd4f16523b1e5c26a24af1ac0fa2920d8c0ce2b9be11a6e818ea7ab1683eabd08e249281ca83f322594c1a47862a226f80bcb75e51e12a"_hex;
                sig_r  = "00a58843085162864b2246c619d6cd38626657eb8f13ed5921b73071b6bddd56640ec9a55e7f2190481ef5e356425749e626a4b988b811cc12dd21c61cea89640095";
                sig_s  = "019fbd1f9b108aad0208d1a27735ead4685f04d01882ed18c217d8e0e0fc71d8a98d3c45c471327e4dfa631cf4b826ead3bd5fd4bc0426fcc95b58bd354d012cfcd2";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "000933ee70d1470acaea66626394023020ed521d5b9a52e068b827d23af283bdbbbf3999b0c2ced0abf607b467fa86ef89bee3852d4e993df3c2c73a49488740cabf", "010231bba67cba896274e7af7f9c65403e48c56356fba772120aa8781611239d0f50b8958ec8709a301078379b59123b47c5edb87bc2327cf607f876154904b93e92" );
                m      = "e2f17dda2941ce1909c33f3e1076f42957d8d9db8cb7f8ef5e2a6a2d7a03d56c5247c08b58727d40009c91458c818687ca060bb724a061b72bdd2e55988094a99d89c618bc099429e9f2bd2b47771fd116d4227e7d368c5fda34597d74f2ccc3bbf618c53f706d761ccb658dcb8434d9c4c11b0e0ee6fed9a0cdbcf308e5a64f"_hex;
                sig_r  = "016f79df89a498ac65bb39d62e1ce82e5578eaf778084ec5926a638d50ee5943c87955c8255340a90f800fd43d4dca125b68dfe957d148533126d5761d711412bcb9";
                sig_s  = "0175198228ce2eb0222d64eeaa403c0571989046e638419ef96612a90094a26fb819ff1addd823f8912e07ff32ac72790c38c601505b45dbb9cafd1b46f352aaea0e";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0007a5694d537eea406d753532b307c5b86e8823d31e81f6e7371e6def61f31c8f706c1b89f8655e54f68e6821096e6b96a7c3752e47d8d3ef5da135f881927ed92a", "005810620b7d83d3e7e48f7338b18e03c2e97dde5dacdd5d54e4c7e75d736f159dc45431d5d3c07153a334fa60567307271bfb85cb0fcae142cbd7baaddcbdfdc018" );
                m      = "f3278fbf2cd7edb7c0667eb911210cf3599d7322b15c053d1a3a8bf3fc6445fd7c6e68cffa765b8911d93eda77c0a3ce8ccdfed6bb07c9aebaac8d1245f0e02c044ca04b12f45670c97d96db7c36b80c0763a4c2fe93bccc6ccffa91e228b095bd2ef25b111c89aaf05d811b4625d343aa787877e8bfde0a9f432719473cee96"_hex;
                sig_r  = "002cba23e78a1f9c6c18bd26321cec0c26db4f1100b986d37a0f24fc42c75ce4731a2876e8865ae21700289734ad5bae3611418ea37a13fae67db2d1a58a86f85422";
                sig_s  = "00c438e76249b5016e0b83ddef5447420fd13aee6f099a0b9ffafcba4e7227f70cc5dd5abba03532ebc50424fefdd4f6d258ffe044573aa51b8a5d1d5c6e5dbf318a";
                r = true; // Result = P (0 )
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "00a00f34f4572450d93607d3ffb1fffe7c86334426ad60fda27aa647e67c34b2cb1f0a12f4707336f1f708b3ba1f3cdd599ae92a2be92f9ae5526eba9d4adc052fa4", "0166808273466ec1ef2865e92b263b897131c5ea97fce1adb1ef88c8ac2e63eab97567d82db9c0825510812db1b2e4cba705ba64d33ffdce676b7f3aa2e343f7834e" );
                m      = "047876e08961d6855a7f11010caa839e506ec89d6e8e007de36a1f3355d0c7bdf90f0ae8586fe73108869d1d0577a9ee0395706f69bfc0c8c3e17f53fc78fda86290cd3fd63a06bbf1255667a33da0ab50100c239de0c036d40835a317dd9f054543b6ce25f84b1df261a92d5415c2f5bd19eef1b1d6eac37117b53939b792b1"_hex;
                sig_r  = "018ada7d95f4d05350ae95494b7c81e233168ec88c5ebffa2d2a3ac74cf90b6d9f80407276f92bd9b3ca949e5d5cd51166e29678aae58a284b9e6ceda3a550b08c15";
                sig_s  = "01ff12f5e9b12efd941e8a445ac036d735e7bf64237972002568e8eeb0dbb887709b53cfa67186f4df215e2a9f7b9feb045270c72196e19335a9c554a19cee0a8397";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0013a5c825a9ffe6179cd106b4a2343fd3318d83cf3be58d971704d0328486738f7536041cc69e6f9548851cf591ba080c4a1c4b4f5d95d216138d72bc56eb63779d", "00e79075f5acb9f52b67f8411f310c02aac5a98dcce0275438e59f8a2a3754ebe57815247a00d3506fd342d3d43607ba67d4cb608da3a9296d57619223c02e0c4f8e" );
                m      = "774c1af085bd44543f933f6db8d8c0cd07a25cd1517e82ee5a0ca3d1c54ac09e0addeb8b32bba2b1d67f86fcddd747a818e693668cf4569d9c25bd69b5e2d350986b1479fa03c1605c4691938e6bd9f505b9995e77469436b8943e9ada77351614314abaa05343f6b5f2a67dfbc0d61606cb97cea5b2277649bc21e5b076b289"_hex;
                sig_r  = "01ad988418099c6483e6a8d62fc16a9fe571ad35c8cf111c3f35e680541a2f5ed96896715efa4943f8b46d20a0abb228852bdd5cfce1787c150d01231abc065718e3";
                sig_s  = "0095c1e7dcd09375d1760700c5351ab23618b1fdf1b2b02e918c0ec341e5156300b602f7960e0eee2c027aa0076b194080e63155dc56a81699e8aea36ddfe703b94f";
                r = false; // Result = F (4 - Q changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0092bf4245f0ece3a8c3a723de152c6413526c333a64f4f2455e7b45396c1614c473460246f49c65e957dcf779af0b675eaf5ed7800539d3619a6fb131f1bc610968", "0047689692e52baa835ee9c49793bca7b01ed3bc4d4c396a54eaefe0520840a31fa3c35cc0d2317ce367881a15a3c06e7c26b192e90fe16c10e84c92233910d7df7d" );
                m      = "bc59b04a384e79b631f0f401ba990b8d48606cd6a1d4aecca8673058b283ee97aea6362b49ad52ffa533fc089a926f7d0c99b56483ecf0618046ce173527c1ce8648d17a45da8c9376bfe081df57ae9fb09c1e7193d41f359b2164b056737cef4b88a256db2939fbb1f143473e45b0976c964b78447abcd85c66c5d8366fc011"_hex;
                sig_r  = "0141f936c6a5ca580e5a18caeb85fc13e9ff57d50d89b8447c8645ff66202e71eff4303d57c28ee6b68915de6767a124f3652c22940656f4227d61ff30b17c2b9aeb";
                sig_s  = "01c7bb4c22e68920bc6b9df0626b09ac79e5b76ba29d0b632c0b892c8661087461c4131771a2b3a9834ea4b3d3bddac9910331774643ae22b613bd0b2464a12cfabb";
                r = false; // Result = F (4 - Q changed)
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0194cc7f51d9caff692137190541f5aea160977bedb0d3b67c3deed6669bff160696a96550934b3dba4129e204f068901c84c821523bec91ec40336dce0d2673e794", "00709279f85ef54164fd7347afcdbfe42d8d14e6808002b3e0b59bcbed80ce0c16e2db1b320c1d98ccdd75efc50fcd6ce91df6baaa99ecbee6df41da9c142a74386c" );
                m      = "2df095b1f48341c352258afc19240c805a72a7662c38362a81fd3f788120bddd86fc10a99cfcb4855a0f64eeb9c6f75d74c145cd6b3d938e325a9f154a36305e1a213165e83e51b0122a48553d26c9352182fba98dfe8fbf1d64a7e0ae637d855084b2ef5117028d8226af607ed6f6e86065cc3715613289976deea128af123d"_hex;
                sig_r  = "00d2542223b0a5322249e8f1af6d559a87c39aa5c3c7e595b07fb7be4d3bd0184a419651f96811f3e8c9c578a4be68188a8a3a1ff0ccba4af5429ef95c64f34d645b";
                sig_s  = "01ee3123fd300cceabe2ad99bd1975c4594005ac9ec31d44ee4b9fe325d39049a5a83b4ac2a7f0b603c82dd88d136507bca2d383c7e8375c36eda82a169b3e4b4034";
                r = true; // Result = P (0 )
                d = eosio::sha1( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );


            }

            // [P-521,SHA-256]
            {
                auto pubkey = curve.make_point( "015bd9bf7a35cc60147b32b64e0e4e54bf9ac2173cc6784b3d4ebd076aa5d45c1e3d0846b20b61d6342341a8801a2f63028c991831318245c2fe31f8acde6bf2003e", "01afb67c9c700ed332b47a2d148e6ddd3571e138f02a81c3cfe6d4dee0f512d92e76574fe5797c5566c05b3239fabb212c735615e719e718fb40fa6783c964357f72" );
                auto m      = "93e6fa311b9cf278babcd49a6739d312e5f12e05bc9dfee9bb37ccfb2f9ce57d2a3c0336674e094834a9fb80143c3c8ca82b34949596ad17ae6fc7592d1d93f143e7e7c842e17a7d230ace2d2be15c757c37ba0b1f34810c6e51786af718136db22c1f8336540cae5e2fc762ca43cd94c4babb1b11f8fd93a2ac9525324bab88"_hex;
                bn_t sig_r  = "01a341d0e8906239faace79554b90d1445bd28f703d7c7cc8eb163337ad3d4bfb3725cb06e618991491534d399866df5c5bdef897c889947b21148d89c657e64124d";
                bn_t sig_s  = "005c5b728837d44b7b6935efb2b721b4f45c1675d803d87f70158e451434176d9682034c9b356b5f9181e07599bdcb55e5bc808fdd36fef9c19ddb6342c975262024";
                auto r = false; // Result = F (1 - Message changed)
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "009f21a6e7295b183656709089b3c647140c81f71b0b3812e6de22c52245335599ade6a3116cb70277dc2485f91c7b1f46d62afb60fc17a110358c9a02e02e010960", "01e914284cea47dd6836e7ce899d0c9a88d67fc9d039ffa9fa5bee58d247e0d0dc9251be8b82afd3add327f98c5570bdcd8ad8827820032774d19db09232aeba190a" );
                m      = "8a3206879e6e463c6d19c4037c12c66ae26e23e09fa96e3b26d32bb41810cb9b02d55333733fad583ca5d24614c23071ee19e4dff9e4d958fc1de573e198eb6964cfc464ce97e69642c19c0ec75aeb01f93361b9df37cd2b1bc2602d967f3f508d1a9f3155a07675e8b1b53e79b608dffd6c4e0f0711fd0b8c6012eacd8e26de"_hex;
                sig_r  = "00ce4b2ac68afd071531027b90d4b92d9b0e1044b824ccebb2c9ab241d5b909ead1ffa2dc3d330f57187efbea7374bc77c4f7ce7ee689aa5a1e27aa78abc3cc1e751";
                sig_s  = "00aa85d84f9c7fecd25064dbae69c16d6fcff38040027bf476c7f913746272b5d4b9bd34d2482e27730522df724895b99253aed86011139928fa9a272892f8c99d8f";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "01098be00de7b2ee7390f26eff82ba5b6de8f04d7f11909193923866d2feefad9b01c5d78b699ce0a6900dc2a3073a03505ae946aa6f384ab0573ec9d17fa775dacd", "0106e122e7148b547a0314da646b6f834e66c2ff7f64f39da9dc7983e80e84063e23c8ce12994e8495b7786c2b3180d7f22bd2d2becf1e1ba2029cbbe8d4801b65b1" );
                m      = "a2555db3870730ffbafd007a8b565e3c79103751b9c634a40e9ce79098fe74bb43b4cd990c50a80a50f8426893f03998e617a74c8997bd7acee599c24770da781502011747fa55b9215c245f5d36edac311640029663b44b01a50c9b8c5e53f09c11fd73609ce665c066dbee92a749847805c26039089b94f80521e1ac94317c"_hex;
                sig_r  = "01092e5ccfc4f966c3281a3924cd527606ce8e64cfd78f57373cfd702f528368beb71eb1a2cd64005bb172cb35b4ea61af88cb06bc8f1a38e2d75b235d23947dc209";
                sig_s  = "01aff29a28d935d0e10bf8015f38ec128e0ec047f04020d1474366807b140e4d4a6d069aefc8dce723fcb4fc803df30b3880cc6d0dfc75c291d848d89e06ab7e24d1";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "001ec67de63455605b31a460d4faa664697cc505885577c0844472842dee78fa6d522e4b942d3c7e2de684e6399f6a44a328ccaab5e678cd99d49f015e35a934cdd9", "019b41da41e7506cbcb7c31d39751669cda166fd045c86e1fac68d39d2ebb0f1ed50b8a923511e1306952888e068092b19130181c2de5f25c5e1fc4fd9ea202258d6" );
                m      = "58a98d6740bcae94d49817a49edcec1bfe9799f22fe7bc7c46933ec74db0679a34dd8057b71c439d00da2dab80711b943a9f4560d4b5e7f58b79a77f84eb7ac3b9e88c8f13b7ea5568b8612c22e4e5ff6f83c36649917e7165be0f3c759b06ba44cfd6b6d54ad996ac2cc9054e8d3d077386f4835cd024116462257907c1b496"_hex;
                sig_r  = "01e1882a3d98c236189a35ffddc9fecdb7cb5fc5e3d0784eabb69d9c37862dbb38eed6c5567a0abc4f74099329681b9a0921515f1df83ba8948b51d3871866a8f7ce";
                sig_s  = "0025ff707889678f7cd05665c941a2bbe13622a1e75ab986cc86778658c62e527f55804ab27d0643f6bb8adaab0614eac47f33f0e1fba109c63b28fa6732a5afbe49";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "00defff5ef7cc5de0e1ac32261e7a74e8c434c0b51f76df7566b612cc5b8201e7b38c51aa6118b6307f436394bf452a72224c977e37e410eae9525df2ee00a8123bf", "00263b7db73558ddc783824f0b19776802aaf5e46ccb1b1d1dda07d2d6c5843f5036ae8d381b235ccd2ed04eb90c5d51e32cbd7acdc7031cae63c06797556fb66fe3" );
                m      = "77bd3d86c52fe8c327649ce44ccb313cf34d6eee9f6074fd60a9ee3dbf3a84dc680c91703632d6f4ff39b8ea3d13090054d186b4a928b1052caee17dc9bee7a5905ca9bcbcd065be4160c4dd25639f2b23d1ce4837598917d7c86425679de1b33e922e331c1f3f748d3cbd8fc6aec68b73978f5d25d730c8a7fde247edd32822"_hex;
                sig_r  = "0089bd129a537840a52ef434d5a8ba4add952f72f22a84ac4523ea0bc02cbfa8b681ab0ed3fa2bca24ae575f23fce7efbb9bfd28e465174158a5ad2b08fd9e0b7132";
                sig_s  = "0004ed533337791e05f8d097eabdf4be96b3fcc9f876d47fb8c5c7a05cbddba398cded2edf5ec9b7dbb4e32c1374b46953d66a193c211ef12de4b9d73adc369d5e95";
                r = false; // Result = F (4 - Q changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0180f1e933054473e81ac82aa458094b7cb95d4b8d399600420cfb082e37980414909a133d5e42ebb7d2defddb34a9fb51fe4ab72e88526fc28608e152aaaba3ee5b", "01c5cee9fd322d1c3af1726366e8a1e3f22099d9246d4bb02708eed89ecef1fc73926dc97a5c263afa235edb39a9e63d9690608846abc482397a2d8673c5d472c970" );
                m      = "12e796e7b92085ce16fcb9f420ee18bb0b5b985cfc47618d7b28a9e2ceae5d526c9dab015c33ccadb05185f8b205875b20323edc7d0a53a6a35f7061ce823244c6c73de20a38650fe6ffad79bfae8a54dbb611eb55a76fa7400ffddc6421e58efad93f43db1b7aedbd63ba94ea12c39c686dc335c7205f05f6b3e1d12fb508ef"_hex;
                sig_r  = "017f1fd4df519ef432f68b5f426ff23a8f36b5729fdf7c8363d73f4e707d9800c7b50174fc3d66d89813a5265f8734602e5c998c2d7b51bdef6e90ee5a527e1357e0";
                sig_s  = "010560ed68f152d649493c02c1e32bf4138aacb5f2d7f449e7685336edde24e5ce1cfaa2c54530f1419593614971896f1a877dda7bc5d56ccdbab18e770647287979";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "006d8c16536b17cab6ff41f5df4038fe416c05ccb601710909708dc561b02ceed9cf020441d9daa075e8fd604531ff58084035b1c19a498b82582f5b20f9cedf61f9", "00e89d71c66e55c4f5bf245413388bfe9de83944b11d1abdb4692db7da8a086442965ee512f7089f89464dda5d7786e52cc26a8a30bc8824cc56a289fefcd42bdfd2" );
                m      = "3c06bb2421c7ebf060b9da78403a3ef87406cbcc73eb350a2e0a33d20f6a59572d282091654f98b5ed4b41411edfd216704c44a3e295bd7174cd51818b021cb37bfc3f644023ba69fdc081dac3e5f6bdd7c7bc1f71549882566fc4cb30114a1f02f9c0e7610feb0fecde666eb94f5e43245473ea56bd6256610b08162dc2eb36"_hex;
                sig_r  = "0087f86cf4bd36e8253097ac1bc8500dedafdbccbe5767ec25e53c73c4f053f3b37acd1d5ea4c16e4058919b61d2a67393220ffefe07535d53923ace6815463c4c31";
                sig_s  = "01def2582fd0df89fa28c9ce882f5c3846135f51bdf7f4b2497b190136ef04618eaa22a8c5a117b0adfc6425eac3111b6558df145a8b14ad39524b98659e01d51c21";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "01c7fb4747a409a3723177c38c9943b81b2d0aee867b8f424e227f3a664f1877c560d37953e7cc09390e05599292bde1ea345073ec365834d99ac59332f6e5bd29d7", "01b7485b454d5ed5d581c7897a7e68f425d8c23cd89b934747d90765a5fda1cfc3d997af61728f328cc8bdfca8a3ae1b3b90be13cf164c343d199b8e16b0400f3e33" );
                m      = "08f3847e8b10f18a2f33abbec099f764215aeec9ce64c33fc1c6ae6e7dcee8eae995885dd91a354ccd2ac9bf8f9924a375b6387696fe415a08f7ee429318f045b9394f4d6e75ad099ebde5ca94e69414155f4dc271cdfe4bdc318122ae469f9a4b5f44550fef6d4e09925eeb579d61299578d6d84d99c4260ccae583e042b0b5"_hex;
                sig_r  = "01552ac2dfbe67c6abad8d3325713c1e28537eae620d805a73dbaa4e5e04acff6ae0498346d6e41df1cbdb20b70d8e548564da8fa239fe6c6f28b6c2a6ef57973097";
                sig_s  = "00cc9e60b694d792f36cbe9adff8dc79f0f75b3ec11ff2d54419227c7566e0bd441655eb30b558c78a55ac613c1bf3c3058ea7a4bb70adbf5b49fcae15e54defd6db";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "016c0e1d1fc81e5069e9c02794fdfe1f5a8ac5008305d9ac2234eb0117e565203acc6777c570f41661c5db1adb26097d7f5f2a1762c4f8039f1b68caad75915baab8", "000b3690995d6d881dc1564f792ab174cdc1a0fc6f12d69a21088d5e82de4a7d56947a2dad0ce64d9ad0675e72b6da755e3ef82c9cc6d532378c23112210236889d6" );
                m      = "a1c88c643303f293bd918e30ac00964e52f78585be9ed920c579c48fa0276f749c04ad73e3a86697e393e7172d2459cdc30e0f1e2830e5e6952fb23c6a6e3eb61cfcb15a59cd6e11c3c2e080e78da3e0dc206ee9e1e5aed87d7b61d14702c59a116473f386faa21dcc97328f966771fc3e5ff72af66535f41e3daa4ebadd5624"_hex;
                sig_r  = "01316e9a934cad1aa0f7dbade1c9ad942d61bbe1bf41b7b95e3b25b761b9899f6125790369277aa09fa57340a2b8c3c609a08ae7be5a3c09dd4d081e6cb54d9f3061";
                sig_s  = "00d6b285f91c3c8d6192af624336caf793ad5300d96262f5e25228dfb60896c4e28e61be22e92ca7d6e11a02f36655441032bf291f895aaa117f6bfdfb422286f255";
                r = false; // Result = F (4 - Q changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "006194b1780a2416dde8c9402e3ddbf310c51ed87fc40530ad5c97931b99336c00098337fcca7b01c634e56a7874309177364e6d4c24c2ab33d6a1a09a84689ad0b5", "00c5bfcdf640c0a7573ecf4a9dc1aa75db298ddf1a679609e0669182a594b9b9a8186ee961b902d84fe998e3b380c304a0be98974514966965bfef9971f05a57c162" );
                m      = "bd980fd69fb9e1344540e5bb12fd0aab8199a16ffec416edfede8084b7cabff5891f8f04fa72a3260403adf5ee286efe9dc128b06466b21915c394b21ded8d468ec1f2ff82d6e4306c61b3315c8b131131c1ee8d093f5aa47b56dbf388cb935900c4d3413dde92cdb7d6b8c35440ed962d5ef036b241f2bc51842fa64496aaff"_hex;
                sig_r  = "018051118c2d8b841c6d78e2e5068c7305039cbae1f8b5a479b9bba559ebc45d8c8ac18d1f6033713871e656fa4eba9c1c0892e7263bb22c46ec3c72aae92afe2c79";
                sig_s  = "00de0db6a6ba5e6a953a126be3b87d6c895f4bc2db27be223109dc67cf115bbc8c566e1c9a1bdf1a87e632f8a0e4b31331a086caeb60793e87f03b404140aba206ae";
                r = false; // Result = F (4 - Q changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "00397714abcc503eaa0c18abd1fd26586d28ec1b1035d37ac710f2823911ec9afa429b41ea89cec13d5bcae9d6d7147794407e409f3b267cf4dd27e8c77e7ccf4d36", "00a3a4b749d19b84708e42b59e9faa5a99ac0f0a01121655fab87785fca38c8cd4277c8c2c9a0024ff608c3cce954596315dfe0e3b133aeab08bb5389eb2a4f1fb42" );
                m      = "961c9451bbb298e17f503680099244d969a0ff3d0ce6cf15b5bcc73d6edc3e8c8535a18531d885664612cad97da174f1daee6aad95220f6e2fd8c734c57747e46db21e169a03dd673df07aff30848e8370c0960d732e74f9b1d8b53847b69d2cad80f346b50e89d7993cb758fc218668c771422f804d3c9162da98cb30821912"_hex;
                sig_r  = "019da96a866db12948e0aec7231f797061f345739d439bdaaba63e4d03e0bb52c3fea2fb593347d983f24a3afa6a77f476e6bb49a5de843b4c4755cddce97b8b909e";
                sig_s  = "001bb442f428b2ca445a75ad88ed49d965d6659d748d02cebf78faa1ecc187b606f284d11d47791d585dc371c2d91848a55ca7b092f06d561efcf64e0de0814e1db4";
                r = true; // Result = P (0 )
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "01af06b10d357fc3c807854b4be235f81d5036da4df1af6a054a03ff800c1aa2d59c2ad5c0e25ed25c002057cae4b4adb92b95c36cf422a46c8833fd8968e0f32441", "018432172be0e535a3f3a5f6d6927dfbf6a00051cc1983ba25410ee3598a60dd1f7c38526de7ee23f8e9ee973ffddff49eb3edb28adc7d094cd95b63d52ba45ecb58" );
                m      = "b9afbe0d18f798d2992740c35217eec0552f0812c607ef823f74dc2eb2ce58a9abe1c683ed193245a81b9f1eeb68d57c721f052f926b1ce3d79751bccf007375715e70b52c9bce92a6ccad24c205d43a4355d084dce3db2f50ab7d4dc3c6c400db8db47a48dabf295801e960232383480f029c7111bf8d5d7a0c9d64c9465644"_hex;
                sig_r  = "01396b4f044919d0ba5ad43004cd37b8bb0626ea5549d57c532339358ee1794988a7c9eab91a9340dc2aa0f18e89b236a6c20d03a6e98f35c011430fc4213cd65dbd";
                sig_s  = "0101e5a788a867d9b5a4444554c9651173f9f8e15c0f39f9adb66c18ef8075243f23b95d5229ccf5f56b87f5c50920b01b22ab7476ecf4c865a3d6d8f2242d422d8d";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0176f1276918fed24a098d6d03077f3c33ae543316df1b6b06ce877e74b69b2cd4131fdf797e77e5f6391b0b32411120d03c0c59ba1721a7187d18708121d6f3a86f", "010f9d38b30a2da1a745840de7c9994578e32bb10f9334b46f533b6eab550aa55048e4ac601889564ac8314e01b61613fc7b8e2bd3f1a188c5c5e869af16a8d61d9b" );
                m      = "a6c421bfcf95f7dc2f3721c56eddd2bf58bd8a2717396441d95e265c8a3c85b031b80e5f90786126f578affecfb4fc2dcfb3adb96a33cd0953b109970d218a6e59a688b6bc7d51e64eebab69929fac48f45fdccd2a27c1e1a48f19bbd36e5f8f8f0d8ab3f4e2cca2301893f8c373794582eda7b700f57d092d1662b929a2d43a"_hex;
                sig_r  = "019cb5639a321e95214c90a612d29c9ffd5ae5aaa2a814ee2d66ac1ce1d2ab3229009129ec9d472061444cbfbf50c7e4cba09aab65299a42740bce7af3fddf2a1f46";
                sig_s  = "00082ce6bf1d809d3bb4f9f09a95590bb64b0c41bcee5fcdd332947a9b59618da5da897fff44968d92635e7833dec1e91d8d99bd8b527609393b446c83d109a32243";
                r = true; // Result = P (0 )
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0089565cf5838658fd36b70cf5246cbe999a394562c46e9d8057928e0aa9e04ade6002cfb83f315e06790e58ea833b3bd64fba8e93c5fdba8319c5d38be7cf25a21a", "008faeff531e683d28d817045a03b2dd22e50e6168f1e5fda5b5abc71859effc5e5c45b88705b62ca090e3362a8313dc472ec2ed970bbb5029200318e7582643d613" );
                m      = "1e8824c203e8915e62f5304b021a3a1cd027f5dfed3366e123ba28273b1a63956006aceb45a03b5995f14ef08e430131fe93123a4f91683cb0074280b525f7342963e98280d63ae179cdc908a191fed000239f1e56b012b7fecffc1d1a5883a29a78149d507205308170460da5a7d5ade323bef2c9ec4b9a336cfb8b1b7ae473"_hex;
                sig_r  = "006b5237ad17da6037aef116532b3aaa70172d0ca0eebdc478c35e6f8bd0f9a6472d052c5a18a23dcced7be6e5e7b6d0bcb5b3cea707000e7d114b6f41084d6f5620";
                sig_s  = "005e2556425b35e6495b137f7dab522c7e7b812004c87a002f6ce4f4b6cc5f967b8f5b7d3786a17d5f717d3ac467b73e176e90cdd8c5151a6e62fc4604cbeab7e717";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "00aa42473f80d9d81f6d41ed05c8ba35c005f90e2690f71dfdb12555b7590c7a8e95b618368c39f4e84d6cba25f522c9bdd256c60d3f8c8425ad313701225a9cc9c4", "01992b7966b925f42c91f810eb05d602b804301849ea278466a68e5b616e3a0bce110fc9250db14f9c8f5929347e1bb8727bcf8072c6aebc26958954fe96df04e139" );
                m      = "aedf4e8089c90d95f870457561df7fe825138073e867fe13c39a0d0bcd77dfa2abcd635ca40bbb71eeae2b674075bfc5d5fc7d489dfd8f34ed30050631238af2122f7d45cc0634ae8a2efca5cbcc4f967ae55c290f77d53f2c03163f532f31097bc34f531823d23de7e5a9e09a1d17cbd9383a4381f3f6986368a6014fba8b96"_hex;
                sig_r  = "00cbb35513420f206bd26b568712503b66e159a54e154c8d4e9c661aa954e0bf425871275fff5e8f368c8ccc77ffe6adf84ba88a84483d8ba5cc862bd408f6a192c1";
                sig_s  = "002ffb4e461e3161c801ad217a0483045181013deed29eec29cca94776139ddf5fe9d7771e5ac7b637a4bf7e5276940489bd8ae36f41ef6be93cff4b96bd0e1f3e59";
                r = true; // Result = P (0 )
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );


            }

            // [P-521,SHA-384]
            {
                auto pubkey = curve.make_point( "00984cf3de2bbaf1b37ad4e9121a1294a0128d8a031ddfac7a8c5d7c9db83699de26c50012d42223d902cbd4be7e6fb611f4502ce8444d43d3eb0685aee07349d0c5", "017165e8feaada26cc599ee394dfb5de7e2201004f755ebecb92ffda0a24be55aba88ab9b3c7a575884ffa7b78b631806f54e01ef875c5819fd2d52dd6369d649615" );
                auto m      = "4db7b4e0b8c91130fef9bd8fc4ca9c1b2970103cd20366371b1f0d4a00885cec613f5aa54d723289f4ce252d446b8c213f9ee207196f88029e66641673b0ed5cc5a2700219ad5dd6c35486c04f637ba15c77dd2a5b53b1bdcc7c5efb194de1e00adc53bf78ee5b7bf69e9efb337d9f24d697838ca5ad56b08903c5891b84c096"_hex;
                bn_t sig_r  = "0036c8554602661d9d8f4bfecbb099f01e9e314136e50c6d026de2297bbaf66213ea72fce13b73bb07e6e333523f19d3910983ea5842a1b634b3e3ec8157d270b496";
                bn_t sig_s  = "0129b439d3ba2d66c89c34be2a674013128dccfcef33f5d3844c4465381453c361ce80e1b52b6a611749bc70933655caa56da2c5dd6b04defcd8baeb2d9be06f3caf";
                auto r = false; // Result = F (4 - Q changed)
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "00f976d58a015d3015a14997fa3f59ca8d762a6541861be923d6110c9e742a0a2a77d59a6a9335c67f13a626d9545b27c072349c3d20b80c35b0a9490f3e6c5c1b3c", "00425c22ac0755c58fe3497c1f1a9f537d5e26127d9b031359c2378fd4b13f83691a854444eac3fa346bb5a63bb9567c122945ce99d2aeb0bb1b956ad348f7c9c461" );
                m      = "66fadb3dc27fe2a0057eb1e0aa3d49cdb93da4a07bb5c4c01719f8deac82fb0066d9c1466ae5ef67d1fee3e2cccf3185a24c8cb58c18df2bf0ca0caadcdc0ed63107b14e3627a9db7efc88544a91774fed34e335dde43a67ca44581bc9757932414a0fc3970b091e94dc52d39a9815a4aed5d27683d8c537c37e140e8f512750"_hex;
                sig_r  = "01ca7346a2efe39e03e627ee9480a9b7c925a6677dc80932ffd67ca52b7e46acd2063402545d678d218ac579a64cf1fa4eff4f32f92d3fa4510eea22472dbd3daa72";
                sig_s  = "00893d86a6502d5973f6c766413e7c7ecbc4583577c58672ef36a76c83755a0ab65af0e0af0ad0f3e6cb8f9ef67669132ce7e996d6122cbbe1dec710a7ba9c9d1ff9";
                r = false; // Result = F (2 - R changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0066ad5c073425bbbe3a1d97ce6e1a9f2c298392c5afb95c60eee1393f7cd5c9a12c283258b1a53f2ed4abd13ba1287f3a1b051a09cb0f337cb6cf616dffd16aacc2", "009d2b2afc181bd82043b13b8222cd206b9264d73b229c71d9abcf74a478a7f7088bc8c7bb1e54882fee693340a3cf1aa56ccc2fb81d2675b19bba754dae0c2f00c3" );
                m      = "f209ba5871f0a05677c7ddfaf93d39dcc69467fb6dd99b09c7685958aa155838779f9df0f2ff04b6b80275d2e9abce8285333c18cac19a42a6227ea1ebac521110d393e4e43bdeefdda0b3f9ceb2f3da6c5364d44d2a18795327668624fb8dd8c9e33dbc810f4c24edbecdfaba6ac632f5b2831f42121f1330930902452fbbc5"_hex;
                sig_r  = "004e6f08380c43f225169acb0e9f3ff61cdd2e9b713d149f63b5b6a4510d381409648fc1d442fa1bbbce2a8fe1ff7d1de0597f72d7681c79d3a876db6d3ef89ed192";
                sig_s  = "011745ab4dec3542cbf37d10090d6038bd1ef9cce8216a4069b21e4a08075e7e8502ec97b99d3b18fd314d6ab6826bbbfaa2343ada1abc7c3b551c0b854dc45ffa75";
                r = false; // Result = F (1 - Message changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0068801cdbb1e07f4b72218c52aa24bda872f1b2ab4e0c13b686cb8b10096ff88018e82196769359227192752a1c4c884f08cfa7f947ac428651f528bd41d1034073", "01aeb335cb89ecae3cbc05681e2170870dcf40d486db4011c4d7bd84c58c6b3204161d9ca3516760b0c42466605077c96c0540939c635bf5d7d11e1407b6da30c094" );
                m      = "978116ee2d7fcbf1f5013fc84153c5fae7c1785a2fee2c7bcacd962aef6dc201ac62b04eab505b6a5288ea21d41b64114ce01a0a01c617ffd20d1e70babf1af1523a285494a3fe5bd8619bcf87370cafe1188d9843ce805db9adad563d0d2832833a8898bca03965a2dde6f94d2be5a653eb389b6539ec78844cff4d4df532a8"_hex;
                sig_r  = "01ce67a3509d59f8a0f171b86559f1d84589ff2693ff7d3ad3ae64b0e5af85db2fd99bfd7eda6e8f984a87f16767231cbd9026bed0a9a49d74ea5047201227c98f41";
                sig_s  = "0032b0e4c043df8e81ff22c9bead36f704c992ec160d6be7764640200e1307002421b5d73154eccde012b463aeefd11138c5b9b705623c2c849736da23c122df06f9";
                r = true; // Result = P (0 )
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "001dd34056fd2ff3009bca2d0bbfa70ea0fb678597d41dc545358263ce2cef9a2efc016622c12099c2a50257609d6a14f3c5ffac8a52661e4a34689a3aebdbe86163", "017926740659acf72f7c7a147a3a320d501efadef8519bb289ebc33e348d6b9efd65fa516048101678548898619d311b8ef2a0d4a6f59f86810e9e6534176a24faf9" );
                m      = "0784227d3d40bf646f7402cef305863d59d904b16535bcfae67e4e2ffd79d26103c4d3f096493ad46c09a0cbeaf61269d49df46494a860b25c8e5cb40227eb8aa76e6307ddc47e5297393bb5afc946fbae5f8de0069ccb62889df88560a0dce85f888f83dcf80ccc6617a51466eb9d9cd450cdfa75acba6f3ea43cba0760dd0b"_hex;
                sig_r  = "019043db42f44b957784a0e1f09d2e0a0dd548b865947f93b516f249ef1757402544ce5dc402cf8c1f180e9a3be01657258a1dfc14b25ef564805651763d6f609d43";
                sig_s  = "01e0b45e00bde9c4e8dfe094f9bcd7af5a19b631db850a69bf0b6291fd3df6e26f4c712e3b5d4b7b8572f637874057d5652fa2bcd1977065a695d26a80669a23f0e9";
                r = false; // Result = F (2 - R changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "016e5b4f4ff81c1b1e7956103c5cde951c56b37259fb8bf735b386e4d8b3d44063ef062d6e179f618a506ec8ad9773cfe99044748e2c8ae229a51bca6262aaefe2f5", "000069bfdb9123885d8ce4ce67c63311055aa9a1a5150197717a853d0549bd17d2683e427fc90a0b78af5dc96465ea3f2862cf98e8f3ee2a07089e8837aa8d09d97f" );
                m      = "c1c9b8b123b5680b07669c285d3cf9e82e96fbf5c9cb7409265b2c57036137ef73460263b7a279f363bd7a0c7f72318b8fdad4a2d5f8f2d74b4964e54a1409554bec5e3e36d7e594b3af9b4f5cf28e59382f56c1c01a9a6c5c12b4abd127726a7fca24f2aa8281d7e86d6e61b460f2436e23493e83bf99acee860ef609ff919b"_hex;
                sig_r  = "011550cb365daec01901b5a5cabe7930c10d79128c5e510d58b7593c88647eee811e6fa736b26351558cbe7f17d7c882bfd1ffa72ca3bf4bc1cf1c05f31f5e8bc057";
                sig_s  = "00d6fc97ad14639a5157c92b39cfd1315d7e940a454f1289c8e95c8cbbce8731ad37180554e7a91565d86cffb3f5caf4ef883184d717e03eb776af714a32234e3f5f";
                r = false; // Result = F (3 - S changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "00202896ccf6710cf780bef8908a2783b3c8d5b8356f1546a1b6b909b0d65ffd7999a16112d8d68c837597656e520a56c2f6578e322df6dd794d2c08bc5d8f9f4c37", "00576152d30218c941e83080a502cdfbf9de7ca2c394969e779b76c359ffcb84902ff89e37125dea7dcdea0ba928ce2305c619b1906955e6be5ce40d087c5245eb45" );
                m      = "8d2f5ad1abb9f5cc9a981e24ecdbc6f2fd50d52b848e872c579465121151341c1ec8e01165a0365a2e36a26f119b283485e3e385141b4c4d03bab2894211595d46839699c36db0551bf32aafa658d819ad8ae0cc013570487f2d4c6de5c4e4df311f4cafdfa47cd6495d99453bc6fbd0ae538917f6f49a961551fb0c6497b15f"_hex;
                sig_r  = "00bc6a7f5d77cb6ebb36a261e80d739f42b67ddc7a6496acc0ba7804d14b4850cf3fe4d8b56cdd8c019ef9f0d33aa26746018fbb4c69f4587b6da1adcf2feee2b438";
                sig_s  = "00f09c6a94a8550a2781e70b4542096407fc07617f537cd27f1a1ddd15c599d5a9e3fa41da57094456277b44b89d40b26f2cc054fbe657788fa9d71659008d0d698c";
                r = true; // Result = P (0 )
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "006ee95783b768c895e2af569bb84b0b1b00c8b72eec022df255892527987ffecdd81bd8afe267408a8912cce80982bad79c30610571a37d2a0e027e73ad23923b8d", "01ca3f60a37b18bd8b08529da1e39f93d518ae3feead5d00e07150d80d641b20e887c62e8e910ca1c2f64cdcfa678c89b2e3012e3d9b96088ae31dd660dfe6369cb6" );
                m      = "abe8ff2cc3397f3a914d6b026ed01dad7dc33fc11a736060a217ed20dd89a4458f8ee0a670a2f489d0e00599f5aab560fed8405496ba51548a07a722a3ff3546b94572b4c0abbd6503a46cbc7a38dfc9322b702c6b17a38a06e3736749801adc08f6200f06d3bc5fefb9ce72f82af2d68f55e1607602ce6670346b93ac1280d0"_hex;
                sig_r  = "006823e8f6514e42e79d50a112f0f320ecd53963729038ef0d66d5fb59e1c664fda493027678a02b139fcf290657fffd7a529f4f38ac73542f316e1b0b25b3b88cfd";
                sig_s  = "01b3bf9e54b0f48bfcc7289d187e831d94d165949db3c660cb63106be1b933e10614e3673bb8078bd8b80ba052c63d566899e618ea31e2a37e0c9c10da111ad11560";
                r = false; // Result = F (2 - R changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "01ba73e2af308df78d4f2a9e552c3b9fd35d35bf20126fdf751d8ad9917cc58d734fb9de27553cd07c02eabc077f16ad4532871a8aeb59bbec82e46ef1581e4abac0", "00cf888c75582fb50bd0de724a9f4834ea127a1eea437b9a05935d1ec06815bace3464c230314b7f796423ba9fa983b2e6d1eb0260a32cf2f163a5ff46a9623ff149" );
                m      = "84508e6d7c687b7425b212230a1754393156c5643b80ac3c4023783938ed972f6644658e0f4538248adbf08533a10f75f21081dce9636611461cf8bafff496b984cb933d337b1b8405cd2e4626cee1cd9fe9acac22efd1c434eeebbeeef02f2a1c4a5083dd8651adee80aeb41d1e45029eac3dfa2967e76589fc5edfad49849a"_hex;
                sig_r  = "01df7e724658f1666aee8d5d75609e3f5215228ac32b978ea53434b7d154dd4edf661c688083d0937e43836c3611526c75f6f26b08f7844a95113ea4a6f1ab824a0b";
                sig_s  = "019d40a7e03bd69ca568f70a066a4a57c0e6ab82dc8c2c8aa52b00c3ee4c327a87eeb7d837b0c4de68e25f7ac7cf6c0d8bbe0393b98dd61ac4961c7f8c70b40082e0";
                r = false; // Result = F (4 - Q changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "01419bc65174998ac21026f81e6807d8b42f0477396e7ff8a330e17c1d84bdc9b39b2a310767b46c41711f3f2fe503504350c86bf3d2b39473b64822ee32dec526e4", "0184c968f6ad79bf0da00520e5339751cd9c50e41e7cd21ef37756bd0e36e23a8071e5f0240988b73acb3bb2b6002002e09bc7ef70ffcfc7cf42d6b7c65110f54ae0" );
                m      = "b4b1372e94253cdcc6af6139b12dd61fa559299e80e24c900416fa79f9eab738512c7c381acdc2fa4d0393c370ff38d371ac96a6bfa47c4b8fde12402cd27c704059cfe1cb7c3b5fd009f415b4827c7ec0ff32501ebf4dfb179b278f013a16746f52cb5005d902c3cdb5a241a462fb9b1c86576c3a18d21793b0f2403c32f793"_hex;
                sig_r  = "00d785b38c5283466f796988242aba08398ed2493aaabf959ed0e8b7b915cbb711d7694f94206db74641a518642d43c843ea7f43b8354a956a3695764021cc5d2774";
                sig_s  = "012c20c6ab988ae911c7cdea0549de2e40e3e68c47cfe58fb777ebc204641bbb44f2c8b6a0196d330ea2ffa1d8cdc1dd9be353f1c657e43f7fe3c094898a569c45b6";
                r = false; // Result = F (3 - S changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "010f3bb1c96a753d278ddf6435e7a79a53bc2855d26d9f8d5c1337b0fd7d70bccf204377a02a1cbe95cb63e21a9e8a3ce8ee7c8d4ade16ff4083dcacbc6c4b2a350e", "01f98a0273c48fa78a91c0f8c1a43f59c7bccb74780fa38b08989d334f2ba0353a3619e6d4a1072e4e052720ed10e4f2c07e12d0c81a062fe912708dc51d4cdba97c" );
                m      = "b96387edb83eab72ea30c323a7871fb0704ea23b21e20cdda697823b33fdfe31ff8b1e7b991b1cad074d4dee15ead4b298b56aa62477167d40350f864f3db57a414e75ba06223ca29b42676cd57cedcd8031e76de66949ffa933f3b8cf717baf0d7fe21b84bcfe7dbeadd99d665d1ae90c8f74cd6050038e32920aa04c0820c9"_hex;
                sig_r  = "014c4b9e23f51df21b4e02ed7611a8530466d1ed799b50b34b5fcac3bd1d63fa345925122414119cca76d22c167c18ad0fa8e1b47b53ab0f201bd4ca7ea25e011965";
                sig_s  = "00ce91a050938119f80b5f584a9d9515c998212f6e122780f1607cebdb9b538dceb2d4039ab5e1b13736f4166e73d86c720516f20ad8f24e4b9fadd459c2988534ed";
                r = false; // Result = F (3 - S changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "00819178ace7bf1e6e942fd6ed69193386f6c90cf65b42e9204d34ec96a0ce8fb92552ca57a7ba658422dc8b53bee150170362e6e74bdda24fb458271602aaa9b832", "014af772624921f61b3d1275591ec2d68702fbf348382e9e552a9b6c110eebf6e93f20c8bff287d504fa08ae3628e611fc1262736916fa9edd87db1c78ed2426cab2" );
                m      = "a56d82d65841bee94ad279a0c9bb3354caf8471ac11bac1e6b445ee0415b9933ebda8d54d8500e132a3f5b3e9aab72c4fdd0048b9e84ab2b1d4acc3df4003481a33cb7243e72005a6fd1e15995d7b3251fa47605d220ddb1e24571187bcbb67392c94f0b308406f5ee4115d5f18227c98124a087bf06c4c31a93a558bfc6d937"_hex;
                sig_r  = "012c45d6ac0b5dbd9647211f770c3cca4411666aa39b6988a968bab345129237597b6c9b3bd788c5f9f39a38463a8afb159ad72f19e7e33e7f9ce8d67d611c3d9b46";
                sig_s  = "01684000b3d7381aded85b18576832c4a89b4faeea0515454677e29e3f072097e786fef11f72f229b63defa1c2fd3c07090b34f9147647035854cf2950c12a8b16d8";
                r = false; // Result = F (1 - Message changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "011f8e50ed6905b029ce4b16c8acb8ed9136b1c5adf6f11bfb5f3dd8bb1e208ca8329a0aff9bf286e3be90e4d61d5147bcaf2293f934862cca6aead51d6e0a083093", "01963e84a2f06a9cb273a424ee5fa1ae5900fef348371cc91c99323f58bbcd8742a4495a4f7ef52677501a4d5d663658c1f6c8f6edef8b7880e6894ff9e52bb617da" );
                m      = "9e49b40d074d5e899060654ff081fc11ea9cbfa5904e00b49d5c0a0166b61e302ea0dac2ab5567b7fb1f5e116abc48305ba3013ce957aec0f239f7538fcf4f26dcb03540837c4bf8a3338700306e3c6aae6b27c73ce8948856f6c2120e96faf0b52a5954d9134a9b4b9d5395bbbfab3505acae48b30fc58e7676b522908b44b7"_hex;
                sig_r  = "012fc3e0c18c4edbcda4f82b5136c893a6307c3f60affa15d0d99fc0e4a3576b7daefa363b3a362014d14f631c35619f6861bdff9a7b503825bf9f027fcb9a31fd8a";
                sig_s  = "01a138d6b02fd2a7ba45f7f952b2f329ba6a8e25697379330dddd91d1d6e865d3df1541bc4717d3e09b10a57cf38dcef587ac31b4a8abedef43e4f6cdf6ec3f49eea";
                r = false; // Result = F (1 - Message changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "01efc81c1efc7a9bc36ed49a5ef6fa1ba641360fa5c0f96cc1e4a3f4d973c95e86935d979fc2101370777637ab210a56fc4173a50a758725d60e9f925f2066d2bc00", "0108225fc94ab33c74aff785dcc68c45cfc3cbbdfa3481fd2a3f97308be671fb32fc8d268c129d97f140210def188dceecc9d712ac397793dbc39c5cac332671ec54" );
                m      = "036fdf92f353c2a55a33f54d4f731db18e56a5339e731bd09d0b8554806cfbfe36d3c43395c70505866a5659c246fb14a845635d73e222bfbdfad011669d2291fdf88461cd888fb32e5d7f63935dc536d390dc9a9d3f4a67ac1435b89002b4348d80a601b61bfb8f95dbfcee4fec34acf0af907819e2be2d3b68d8eaab4789ec"_hex;
                sig_r  = "00480c48a24e7a7ef832547d107769254fcdb4e7982d0e6abd16822837fd4f3b66d81e1d4a018606881abebd220ed8ca865d7e00499ac9651a98c65502baebf34a98";
                sig_s  = "00ccd22d1b44a1701c99f662535aea9abff7e27f73628101f42708737db8b07effdc2b0b05d4ef233c5910b6261ae9d9c540115f27d2af766c0494c33d31bd56b3db";
                r = false; // Result = F (4 - Q changed)
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "00a15c8040f94235b8b444f7a74ca293ed1b718449911eefbdb74332687850a644395394c690aa98e8064f6eca600fc3f659208c0f8a21a1e7113bed0c6e00e3176e", "004bebea7037b731d175043dec3630b2ee85c680a81256921a89407c14507c10ac043deb5d474602211ad58cb569a8b805686bdac3ef7ff62a4d25b27200706b603d" );
                m      = "9ce982c91af08a21d405f96abd6204588bb0ef1c8b78305b06f36a12d1914cae9dce6a1f1a0b4c42b067667c457c3e90e56f34cff0116bbd350d27882dd6e47997c944dcead9cb945f7c691078c1b533960a55f93d241970a1fdf4441107d8bc8af5aa8e088ea3aa82c7f3286e815dbb85d5cfae0aeeeb093468cb55201eeffb"_hex;
                sig_r  = "00c1a70919025aceb29dbabdfc2a43715192cc60fc3d1ceababb40f91e3110b2cdd8f6e9c1bafe7415a26fa4179f8fc261b143ddb094fe61117afb13adae9db8943d";
                sig_s  = "00197d7f87aea8d6ccd2178614b147b290ec780c8075f8439137803c0e9a589e415d84fa23f5f31d61c1674f87142d4ba4f8473fc92d7715c281dcf3f1ee5c2f1390";
                r = true; // Result = P (0 )
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );


            }

            // [P-521,SHA-512]
            {
                auto pubkey = curve.make_point( "012a593f568ca2571e543e00066ecd3a3272a57e1c94fe311e5df96afc1b792e5862720fc730e62052bbf3e118d3a078f0144fc00c9d8baaaa8298ff63981d09d911", "017cea5ae75a74100ee03cdf2468393eef55ddabfe8fd5718e88903eb9fd241e8cbf9c68ae16f4a1db26c6352afcb1894a9812da6d32cb862021c86cd8aa483afc26" );
                auto m      = "a0732a605c785a2cc9a3ff84cbaf29175040f7a0cc35f4ea8eeff267c1f92f06f46d3b35437195185d322cbd775fd24741e86ee9236ba5b374a2ac29803554d715fa4656ac31778f103f88d68434dd2013d4c4e9848a11198b390c3d600d712893513e179cd3d31fb06c6e2a1016fb96ffd970b1489e36a556ab3b537eb29dff"_hex;
                bn_t sig_r  = "01aac7692baf3aa94a97907307010895efc1337cdd686f9ef2fd8404796a74701e55b03ceef41f3e6f50a0eeea11869c4789a3e8ab5b77324961d081e1a3377ccc91";
                bn_t sig_s  = "0009c1e7d93d056b5a97759458d58c49134a45071854b8a6b8272f9fe7e78e1f3d8097e8a6e731f7ab4851eb26d5aa4fdadba6296dc7af835fe3d1b6dba4b031d5f3";
                auto r = false; // Result = F (2 - R changed)
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "01d6aef44370325a8a5882f4667c21172cdc8fa41d712562883ececff53883ac8ee276124e825088c79d6c9d96323cb7b8c0b7ea44d3f0026e2538f4b62d785bb1af", "0027203959a6e944b91fe6306debe74dc5dde9831fd0ec27e8be2d0b56807d63151b15f6495b8632e919e1e6b015f5ae5f2b6fb8cf75b5f848f00cf4ee457cebed3a" );
                m      = "2fc1140a7414e33ab469799f9432b30d29d1e4451b28a756a0f24a7f7f90cb284fb443c074267a7600b370eefffea23078b4016b59cbeb95fab3c6f37a72e92271b29ee2382e1106f8dfd3871ef9bf045f78d378acc8d16c983d54c7bc0b0cb46bba0de78630f6d0796c2c275e46ebc88e6e6c0e675ebd849f02e47f51abd215"_hex;
                sig_r  = "004417ff74889dde6bb1820b5d13da5c81dcf9b0723ee89bb1ff0d3faa90d497685709f315b2cbe55481dee43ebb6d25b1501ae69494dd69e7bffb72f987d1573b93";
                sig_s  = "00fd7aa027c665458c7ac11d54d4f32cb4a1e727b499ce27b08d3d647c636cc3222a4f0a6057732249ddc22574d7cb80c3769c3ea9de3d33db3edd8ea90cb3f8dc8a";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0153eb2be05438e5c1effb41b413efc2843b927cbf19f0bc9cc14b693eee26394a0d8880dc946a06656bcd09871544a5f15c7a1fa68e00cdc728c7cfb9c448034867", "0143ae8eecbce8fcf6b16e6159b2970a9ceb32c17c1d878c09317311b7519ed5ece3374e7929f338ddd0ec0522d81f2fa4fa47033ef0c0872dc049bb89233eef9bc1" );
                m      = "f69417bead3b1e208c4c99236bf84474a00de7f0b9dd23f991b6b60ef0fb3c62073a5a7abb1ef69dbbd8cf61e64200ca086dfd645b641e8d02397782da92d3542fbddf6349ac0b48b1b1d69fe462d1bb492f34dd40d137163843ac11bd099df719212c160cbebcb2ab6f3525e64846c887e1b52b52eced9447a3d31938593a87"_hex;
                sig_r  = "00dd633947446d0d51a96a0173c01125858abb2bece670af922a92dedcec067136c1fa92e5fa73d7116ac9c1a42b9cb642e4ac19310b049e48c53011ffc6e7461c36";
                sig_s  = "00efbdc6a414bb8d663bb5cdb7c586bccfe7589049076f98cee82cdb5d203fddb2e0ffb77954959dfa5ed0de850e42a86f5a63c5a6592e9b9b8bd1b40557b9cd0cc0";
                r = true; // Result = P (0 )
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "01184b27a48e223891cbd1f4a0255747d078f82768157e5adcc8e78355a2ff17d8363dfa39bcdb48e2fae759ea3bd6a8909ce1b2e7c20653915b7cd7b94d8f110349", "003bd6e273ee4278743f1bb71ff7aefe1f2c52954d674c96f268f3985e69727f22adbe31e0dbe01da91e3e6d19baf8efa4dcb4d1cacd06a8efe1b617bd681839e6b9" );
                m      = "3607eaa1db2f696b93d573f67f0359422101cc6ceb526a5ec87b249e5b791ac4df488f4832eb00c6ec94bb52b7dd9d953a9c3ced3fb7171d28c42f81fd9998cd7d35c7030975381e54e071a37eb41d3e419fe93576d141e36a980089db54ebbf3a3ebf8a076daf8e57ce4484d7f7d234e1f6d658da5103a6e1d6ae9641ecac79"_hex;
                sig_r  = "004c1d88d03878f967133eb56714945d3c89c3200fad08bd2d3b930190246bf8d43e453643c94fdab9c646c5a11271c800d5df25c11927c000263e785251d62acd59";
                sig_s  = "012e31766af5c605a1a67834702052e7e56bbd9e2381163a9bf16b579912a98bebabb70587da58bec621c1e779a8a21c193dda0785018fd58034f9a6ac3e297e3790";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "01d9020b8e6717254eebe619d46dd5a9dda7ba5491a7d1b6820fba888e236fafd71179200437f4d61284fb5a3dfbada66bac3e6909ccbeee03c2b93a8bebe41a73f4", "0048a5f09174fda12704acdd8ed560695dec42864b6300a030768a0be7f09d25f82d7b126125e41417a145641937807ed8d1af7a53f5bc3fc3c57427d755dcce3e25" );
                m      = "307bfa6a2764591bc31537fcbc7275e258f158f4b7ac5cb03761aafee8ff0c58a933cd28a38fcd1a29a7c907050c273bffb249303ea0007d16c8c4aaaf145afe9cc97285d33a8bd42f566b1bea7a5ef77844e3d7c3b55132ac7407da04f1a7e85ec7f2d03b667d9c3c52ebeb1d25b392fb4aa210aff2dac00ffd1b14b0e2112f"_hex;
                sig_r  = "0092df2dcb457fc7578eaacc98ffd73ade07d764e9553506f3dc958cdb3f65d37665528cb2f5f8bded0db0a57e6fa73bfad1aaf94718379d1655db4f32d4c505a785";
                sig_s  = "010e0c31479c2b29dc2726fe9f75b397d9e37a17619e96bc631c62e9ece71f05b199804cc803940d43ddee41171dd7787668c7db05049dd5b63e4f63562aa700ca81";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0007067d2cf7b7619b9fcff2c898246ae0950439b8bab92d809624970eda18456cb99953ce1ae45ee5d36ef02fcd5caa4d951de8581f0c21e572caad56d6dce60da3", "01913c59007a309005f226b6a30122828d60b4d0390359e1977f88b5347dacf2056dd362648e8b1d6fc038a3bd3fde6f1140c740efa9075ab8b4a64b334c5cd43f09" );
                m      = "3629ce6137cffaf0a485594cd47049e7866fa81bb56dd66168567542c6b8fdf7dbafe693c919a7288a03f2483b09c9cd2b3f91670264672967e4542d5bb6c87e861115ff3ec2ec2e96535148623e80525abae8d71f296a4e8947b48bb64074ebb7e0c7a586f57b35da910704f44b41151ac6db350c47e81805fc6932f435a98a"_hex;
                sig_r  = "012aa4a532c108aa3cfb1753f95ca626bb72bd96a423d727656d4ebdc3f406d6cc6c44d3718f9abae8a0b46be9b57f8fd3a540326b63d0d4a8a93165715920437787";
                sig_s  = "001badaf38e16efd75915f4806f054d40abd2d11e402039bd48c832f66cbfd145e4dac93357d476b7e608d7b75a017374ae76eee86c505f2cc16eaa19075827ccd60";
                r = false; // Result = F (4 - Q changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "00365388d9589c18ae608124b4cf746ff488183a912e07d26b6e867c5defb552a5a0df5a16b6342014dd1b0b6760072bcd60045d6a9a514fc74d16047c2e8765636d", "01a5319b26fd555f2a12e557418f6aa65a3461aeaea5c0c6d8698ceaa5495eed7a7d2fed0b76e77b5be11834f36e413d5288e47231c0eb0e9007d4b042bb7a1b6014" );
                m      = "27383a923d22292dacff105f00d0433eb719cc5fdf0d555f05a75fef392eb9a2b10aa7984ff8cfcc1425366578d138d193d735706e9689e1f2590374075c3b0143cf2a6f0d2108dcc3d6682c060e036c399774a3bc7800c7f34cba204693a42803df6592165fa19e34b6c1872ea11aa13e7a6648a4f0d56a5bf41dffd8f03aa4"_hex;
                sig_r  = "01d9ef377063a592cf81e27815a2c20789ff9b60f7f125e618b52d90b35abdd41cd7f437cfad337953ab0314fe8e79a2f2d27fa08597d4b28313358f714a737321fb";
                sig_s  = "00f01d4f150e0a174674a6a61a58a4ba781406024f6dd1b5252e04807b8a807a4ff8d52883eaa258286e506ef4b04ca890e6f81a79ed9a0cd5ed585094fea0bc5c43";
                r = true; // Result = P (0 )
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "00fd0cac24aeb75ca50c50a72340256b43649050e0fa155f72342877bf49c3d57ac2b51b828385ee6aea94bae38587e63390f5ef4ac5540a9e6fc6f1c1e79b524693", "0107b227bdd307efd7a8d4034f733d150c41601215e76eea2bac62ad2427dff52f75f46da3d5fe31bfaedf071d2a8bb5e3c82bf6c84ecdf89ca233c92d599d376309" );
                m      = "2235705a18ad2fc1940d6f1641ef3b7019e56e1cad01aa4c6da18150d622551206dd00163e71b9c2b133f29507fdef144c6fa4a1110a30eb309b04b3f3f9d7f5d6649ec3cf9416c8145e12a0934db1e48ff14800b238a4abe1e2b95ae6984a47aba11408b5f4dbc2cba858d52d58022b66ba2721573b83d5b62f07f38c4c58da"_hex;
                sig_r  = "01c00196aa5dcbc4c4404fa76504a5eacbc96aa66c3ba531a3a679f3fb675ce58f863e08b0d2bdeae74d96ad93a39a78ed4bb3749e26567d0ca5c48a71079925b617";
                sig_s  = "00f1188eba4f0943f4003ddad6a54606c13af26014db2eb8e60534fad3dae8f07c021cea0990987f1e02dce03fe53360472c3dee3c305bb3ef4b0b53ea6625bf152a";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0104a96beea09d88ea6789a9925880c8a9ece8d764be931675640c1bf847ac8e7a8b14f408ba6722c2bf6295db9132d6ad2fe287fa6e6855f7c58ed238148a896944", "01b5e8e643fae552261427ea7d521f380adf605579462315c75e9203203ebdc9ee33dd7ba885b6cccccbd2327462988223c4b31485311c935a341ee87ba1ee820ce0" );
                m      = "f1f3b286307569704538c97c680abd5bb892b421463895c74aa8e1c4a46213f21a95941b8629af8117c2a00cbb71f44d79917357d529e486d8d5b8640f809960973fe9e28b34c6e4082f3b3b0689fd44d3afe5b71bf4349d32b7d80ef5e22d58f19a138e1b676addf384b3e54795c6cee53264f883d080630bf48f498761e6aa"_hex;
                sig_r  = "00ba2c57827baae684d2c637590275c782a6db263a5358c8e1a08b5460ca3cf0f5ff8d4119a6b0d55fc68a75c793098e0a5622a0b4e2fcb0f17943440138d751797b";
                sig_s  = "01594beb73b2ebb7c573ff07b5c43e722dc05979df0eef53587e9fe06a920f61d2efcc7671e6cb875df4e4d92cd4d37cc3eadcb9b6aee8f2097790ce24d6dcda8706";
                r = false; // Result = F (4 - Q changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "010d587aa82a4d8e690672c00e3fd71826d892862d14dc4fbad4935aaab86924dc7ee6f7fd3e2bbe86a8652589448494dab83d363d1d623cbae59f6c2670706a0576", "01a9734c99b6ff21267050738937c30971d0f6fe07e29794748a5017ea1036c975c9a52e6d3739ca0e8d70e784529cc1a7437aac5d75c69121b69020a95356137f1d" );
                m      = "b6fd672065774d5c252a6a596d0373b898465af6778c7219011db482fd94a4e260df7fb7bd3703da7293e96e5324c12f5b8e1cd2c27dc3062007b6ea08e1fcc819ca099033eeb0a88ae28fe49be330a1b727d49fbff8f497edb45b8e0fa1553c33e26ff9b4c35b729b85a6e98654ec3f46a2089b6f863033498e1e4aac3690f9"_hex;
                sig_r  = "0188dcb840dfc573a97117009226d58dbb930ba8ec848931786abc770611f3519c8ba73cceb5b489170805bcf04974672fe66c908ba379aca99fa67fec81a994c2d1";
                sig_s  = "000b1a185512dc6a65e454ea2bdb8049ef8f012a53ae87b759fb5d9edba51ea32e254e80545a99eb4b7c58af96b7c433535fa3f009cc644b1c97666d88355af9fc19";
                r = true; // Result = P (0 )
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "0182c957a62e2e27aa28acee2e2f7b1ed6aef81c68001d2648da47d2b621e8b8bd18d991cd1e3fb9afb84f639fbed1050584428cd2a1d50f877532ffdefdd4e6f7ba", "005fadeef58cc0d79362b599e94636f9c70e3e5580c085b7ea52a5fd24fe4a892120b8f28ba53ec249c42d6d3b36268b8ca8464e54b72d37327d7504d9b7ce534d95" );
                m      = "297660ae8a7038969a7f0838cd95ed1885bd20c5a69a24f5fc8a63918c2167868ade4e372390b0c5ff198315ca1ef947d9c85036e38ba1277f1e6146723bd8f9ad1db6de80dce053c4c9e4597630a02dc514683310d3792a4831df7e8fcc77298f2a2fc4c071412219482a6e218c916719c613cd249a336f823632aeccff486f"_hex;
                sig_r  = "01e3a78e973fef6b6de8a0356401e89f435ae5f49c0173f073c4dbb9c91463e420f5265eade8305f11d30fa8d97e5b4c5ab33975f73385aea81fbdde2f7ddf7fdf16";
                sig_s  = "00efeca10b5362e05a8f2e3df6661d0d536b32ca1e0a62515df2d94eb314aadb5eb40468483e24b16efe85c503d6c231ef860aabe674b72ed1ddd93853338e5e4e50";
                r = false; // Result = F (3 - S changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "009911b41f9af525c874e05bfdf050331bf830296911bcb18eec16275027d63fa106c8989b07921c7e58b02711b5b5880cc4e6d9174e0d31060548cf643bf7ed4f0c", "0184fc0fac3c2c80c69c1c0293f4e5e22fa08c267b1f36ac5ad6dfdf4da1754f7942f48cb56f56cba05e22b91508fe4db3703066e8f697aca56f974f3fe530c9640c" );
                m      = "5d058ae533538ad5f6122e8cc4f5c6dbba56c9b9e49d7eac506874683b7b20093552db5ccd2d819ad554eadedb9b2cf613b73429723caa9f21b9fdff20d575f17b02bbedaa9e2c6b788ed90e239d9def9d108df3cc596fc5e975c59f1d78b9be3fa41c4fe86d1dcaa2d4876c494e14bc167736fef07563d2db0506b24da891d1"_hex;
                sig_r  = "017b8a22fd8f73112310867909f234fad6aa82999c28ea5a2e74b4b4bc79b2f89008b4d361ef7e797c7656f7d9317eff3e5a4982799b8cc0db82618bd2aa3959f617";
                sig_s  = "01edacc6d1c0004b2090d2025d615de1fd53a96e826a3930c7cafaf3c87f34b2583997534cfa127485600a7ae04e6af4a2e98c77fd04507195e520e80014aa982a3c";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "006da3b694e3123ef96b3fd2ab964f85a36110590720dc1724a5d50d3050498957211c6a1535032cf1f31240bfab967cc0cf3b442c35a1bfa3e72470df1863d2593a", "017d0a5dc460c85d0365c7bdc2e9300e276b8aa97368af9972744f4422442afc601ecfe7903a33b0354c901c7b61f29d2d3c5610192cd188291c5651754b385b87a8" );
                m      = "c805a07a01e3806dc81454ee64b3afb33f302dbf65062c1c31169bb501fff4c4a1905729a4d0ff463f2349fd74596b7d51414419e3c92767ebc9db52dae4df2a83cee45486dc1296c6422000699c72137178ffd666d2f1d1a105972bef6eef74e704d8c815bea269512a32fb1b8dd82174e04b2d0d5beaa0401284a7e2bfaca5"_hex;
                sig_r  = "01f9cb1f4e2e65282a929acd8b685ab34da176f5c73bcb374fd1b09bc995385ce3902d6c5496b02916fd5a28f6f8bb662828a76aa0ad14b01bc24a63b328c7bb949b";
                sig_s  = "001d6b3a2f34e3b7bf63d06b11ace172ca61ac5a911a4b408d766eb586c9ab820d42f555e546d892643e12a6752465427c213e3839e4f8cb3a7e4fd83642843e8544";
                r = false; // Result = F (1 - Message changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "00b7e03f0d623a0998add5360dfb0bfe836fcb0a46b0d6f697ba6b3766bd8698ac8c7af62f50511c6aa5e613f4a99fa28f70b220ba1cddb22482be74c969953ae6e5", "00d4ee40ee4441dc85356760f87ba32e2e7c269a2e53a2e8425d5ff02f5e4fe8d65cefe20e162c3915d2eb9ad1354bd28595a86dbdc94a5d40c5b44b1e3aa3965455" );
                m      = "05f1b975f4f446a1b8aef50dfca608b03574a83a7c78d5c2efe1660a034994917455b9c8a774ae381cbfdfff162d36b9a17bbc6ddef34517cf8fa54bb6901f42def4b787a83d3285eaf04621c58267ae6d2bdf20b3bb4cb6c4bd8ee5105eb3f049c44df4cca39f6015a3d316f08af97eda47f92a53600cb2304a2724e40a9361"_hex;
                sig_r  = "01fcba4781de6506f7c3f26521f0e036b5225f651e69e115d6784b2176a666edf69d759627468400a73a136f599fb8db4643fcc16bdeeef6384a1875e1c81c36b962";
                sig_s  = "00a21cfaa7e1ee0eff7efc3d7e936378500283b00687363070974483ad474c58c6b55b77f678d78e7cb44d9745f79394659bdd26b72663608384b5ae9cac1c888d13";
                r = false; // Result = F (2 - R changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                pubkey = curve.make_point( "001bb7c623fde41beec7ddfb96f65848c2f52b50b39576bf06de6ccf157b8ec49889528728480928236300447da7171f58c8f0e0ba8fd3e2cf378b88619aa6c1e0bc", "01f8b20a1a7df319bf78c2cee03581a1ffe8ca5107fbfd40760fbd5ef5247e2df1092d5caf504a9ee653ded2995f0cdd841d6af29c9f720770056ebbc128705f68e6" );
                m      = "3a8d8066c0bfc287e1434c2430261110e33d0ebf69d35b65b0a2d70763c7fec993decf883174f216a6c0ff622ef777c078cae5c6724f9a020f8ec07041dfcca3689a8abcce10efae0a2da949b87459586fd012805c54f0807d927d0b64595c6b18705b49d497cc2ee8b867f9e58b1382e25065500d1d7442944283346657a835"_hex;
                sig_r  = "0000db4c31f316912295c5b9506aabc24b0b2dc2b2358e6b023148889d9200bcf44762e88575e359b4868b2d93ba7bdb24800b09fc22eade0744b9832b71ee784e9c";
                sig_s  = "018c84437fac7cd82099a2a4230084ac27ec7ea9c92e1c9d9a71290df9b37dc881f9ba59ed331c22dca4b2cbb837cd916e0a78398d2b7aaf8e88f113a942beac48c0";
                r = false; // Result = F (4 - Q changed)
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }
        }

        // Test vectors from Google's Wycheproof RSA signature verification tests.
        // Generated from: 'ecdsa_secp521r1_sha3_512_test.json'
        // URL: 'https://raw.githubusercontent.com/google/wycheproof/d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d/testvectors_v1/ecdsa_secp521r1_sha3_512_test.json'
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
            auto pubkey = curve.make_point( "012a908bfc5b70e17bdfae74294994808bf2a42dab59af8b0523a026d640a2a3d6d344520b62177e2cfa339ca42fb0883ec425904fbda2833a3b5b0a9a00811365d8", "012333d532f8f8eb1a623c378a3694651192bbda833e3b8d7b8f90b2bfc9b045f8a55e1b6a5fe1512c400c4bc9c86fd7c699d642f5cee9bb827c8b0abc0da01cef1e" );
            {
                // pseudorandom signature
                auto m = ""_hex;
                bn_t sig_r = "01eee90ae46276f5a4d085d97da8d3d73e3aa41e809aeef225fa7e1780128f43ddb99afd82aff727e7dacfa0f59b1023350741fead9de533527aa6ef6a3a3a285a6a";
                bn_t sig_s = "b27e5ab4845f86ed525fac4e9e8500e56dd5a5161c02f0513393f4381a67ee307ef6516405445e931e6aaa3d7d3f969c6dd5f2044362304d112fa78c1956fe845c";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "4d7367"_hex;
                sig_r = "87b41aba38fbc1d3bed442302c6c35080808a772892d8d7cff937316aee26a78589562d6df69459426ddcc22eba2ad7b46f5d837364487d25064577c2350248f06";
                sig_s = "01e22bd1983a6da4b2ffc3002aafe484aef52a2ed9226e27c11a3e31a0f047a848a93e7383489cf305eba232b1f4daedc1db0606c198b95514cb0dd82596d055222f";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "313233343030"_hex;
                sig_r = "40c2378fb645cb6892d3d78f11eba20a97baf8a78be3adadee1abb5d747dbfaea91d83276cd1430278c39bed88d720d6149932b29748a1b0a791048c8ab477601e";
                sig_s = "01866551c42bc508ca0be80cb459e5fc364c77b7cbe3a6cc95af31a10751240fa634ca1507884f9f88393000fabc8983c487e502a7837cb8f8a9140a1370774f8f45";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "0000000000000000000000000000000000000000"_hex;
                sig_r = "01b4a3842c80a39f50a7de3cbd5676f7895a3047c833df0ff965820361ec0c42c3a3d1cc68b469ee43083371d83b49d72a94e525c1223690cef9eb1c5b49a546f92c";
                sig_s = "01a1b6d398ff656a7159b8d3393e14a17e03411d3ec7b409f68c88827b5e19f383843c198599ca4d22d6f81f7774b31baa6e95d5de02a31c7b56dce517460f603235";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5c6457ec088d532f482093965ae53ccd07e556ed59e2af945cd8c7a95c1c644f8a56a8a8a3cd77392ddd861e8a924dac99c69069093bd52a52fa6c56004a074508", "7878d6d42e4b4dd1e9c0696cb3e19f63033c3db4e60d473259b3ebe079aaf0a986ee6177f8217a78c68b813f7e149a4e56fd9562c07fed3d895942d7d101cb83f6" );
            {
                // signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "01ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b2";
                bn_t sig_s = "01abcd9bbc11d77ae8aacb4dc113aa0d5a53ee51b5e4b189befeed4649f35c97fe595e3ee86ba4c3358e80dd91c4e7db45cfd0fa027f18458c30602d7038515558b8";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // valid
                m = "313233343030"_hex;
                sig_r = "01ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b2";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending 0's to r
                m = "313233343030"_hex;
                sig_r = "01ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b20000";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending null value to r
                m = "313233343030"_hex;
                sig_r = "01ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b20500";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying first byte of r
                m = "313233343030"_hex;
                sig_r = "03ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b2";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying last byte of r
                m = "313233343030"_hex;
                sig_r = "01ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a632";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated r
                m = "313233343030"_hex;
                sig_r = "01ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated r
                m = "313233343030"_hex;
                sig_r = "ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b2";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // leading ff in r
                m = "313233343030"_hex;
                sig_r = "ff01ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b2";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replacing r with zero
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending 0's to s
                m = "313233343030"_hex;
                sig_r = "01ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b2";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b510000";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending null value to s
                m = "313233343030"_hex;
                sig_r = "01ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b2";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b510500";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying first byte of s
                m = "313233343030"_hex;
                sig_r = "01ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b2";
                sig_s = "56326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying last byte of s
                m = "313233343030"_hex;
                sig_r = "01ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b2";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30bd1";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated s
                m = "313233343030"_hex;
                sig_r = "01ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b2";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated s
                m = "313233343030"_hex;
                sig_r = "01ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b2";
                sig_s = "326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // leading ff in s
                m = "313233343030"_hex;
                sig_r = "01ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b2";
                sig_s = "ff54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replacing s with zero
                m = "313233343030"_hex;
                sig_r = "01ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b2";
                sig_s = "00";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + n
                m = "313233343030"_hex;
                sig_r = "03ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ecdf778ea1da4001729f30bea5e3cf64b9f4421887e4aa3c3b8ae86129c45cf0abb";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r - n
                m = "313233343030"_hex;
                sig_r = "ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed9546bdb1625a0ea52f373e7cc4ee2fffeccb5f50d376b345b37a6a45f235e42a9";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 256 * n
                m = "313233343030"_hex;
                sig_r = "0201ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a3769252c79e6591466ec3e3f41320c4f92760abe35774f5d4f2ac562cd7a0eecfaafb2";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by -r
                m = "313233343030"_hex;
                sig_r = "fe31e7e8fee8be05ded42c3f10ff14cfc83fc776dca7bf8032c1dd98403fd5c8912c5a0d9d661b2f7f418cc016eaba135a30f794413a3ef883f60ce9a4824b69594e";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by n - r
                m = "313233343030"_hex;
                sig_r = "31e7e8fee8be05ded42c3f10ff14cfc83fc776dca7bf8032c1dd98403fd5c89126ab9424e9da5f15ad0c8c1833b11d0001334a0af2c894cba4c8595ba0dca1bd57";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by -n - r
                m = "313233343030"_hex;
                sig_r = "fc31e7e8fee8be05ded42c3f10ff14cfc83fc776dca7bf8032c1dd98403fd5c89132088715e25bffe8d60cf415a1c309b460bbde7781b55c3c475179ed63ba30f545";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**585
                m = "313233343030"_hex;
                sig_r = "020000000000000001ce1817011741fa212bd3c0ef00eb3037c038892358407fcd3e2267bfc02a376ed3a5f26299e4d080be733fe91545eca5cf086bbec5c1077c09f3165b7db496a6b2";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + n
                m = "313233343030"_hex;
                sig_r = "0254326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca368019b44ce269bd99bf7487eba70cd063805d0a67190f1faf3032d16b1fe04d11b6f5a";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s - n
                m = "313233343030"_hex;
                sig_r = "fe54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a6a1c117945b3cca717f226e3b1824ba302f05fd80e7ba73cf9fd28fc7aeaaa748";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 256 * n
                m = "313233343030"_hex;
                sig_r = "020054326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca367fbf279cf22d74a02cc5ccaefb87b18d4303c20857fc30d9e6a39caf9657778471451";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by -s
                m = "313233343030"_hex;
                sig_r = "abcd9bbc11d77ae8aacb4dc113aa0d5a53ee51b5e4b189befeed4649f35c97fe5f0cb860e7e5939f230111907bf0d19fff954438c68ea94481a4bdb919c01cf4af";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by -n - s
                m = "313233343030"_hex;
                sig_r = "fdabcd9bbc11d77ae8aacb4dc113aa0d5a53ee51b5e4b189befeed4649f35c97fe64bb31d964266408b781458f32f9c7fa2f598e6f0e050cfcd2e94e01fb2ee490a6";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**521
                m = "313233343030"_hex;
                sig_r = "0254326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s - 2**521
                m = "313233343030"_hex;
                sig_r = "fe54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**585
                m = "313233343030"_hex;
                sig_r = "02000000000000000054326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                sig_s = "54326443ee2885175534b23eec55f2a5ac11ae4a1b4e76410112b9b60ca36801a0f3479f181a6c60dcfeee6f840f2e60006abbc7397156bb7e5b4246e63fe30b51";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=0
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=-1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=0
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=-1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=0
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=-1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=p
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=0
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=-1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n - 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n + 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                sig_s = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p + 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                sig_s = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=0
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                sig_s = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                sig_s = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                sig_s = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                sig_s = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=0
                m = "313233343030"_hex;
                sig_r = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=1
                m = "313233343030"_hex;
                sig_r = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=-1
                m = "313233343030"_hex;
                sig_r = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n
                m = "313233343030"_hex;
                sig_r = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n - 1
                m = "313233343030"_hex;
                sig_r = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n + 1
                m = "313233343030"_hex;
                sig_r = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p
                m = "313233343030"_hex;
                sig_r = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                sig_s = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p + 1
                m = "313233343030"_hex;
                sig_r = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                sig_s = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Edge case for Shamir multiplication
                m = "3132313930"_hex;
                sig_r = "b4b10646a668c385e1c4da613eb6592c0976fc4df843fc446f20673be5ac18c7d8608a943f019d96216254b09de5f20f3159402ced88ef805a4154f780e093e044";
                sig_s = "013aed2bb1d92ef16a821bf47203a3a7df2e9d3efdb040f7d6c7b36bac07bf2c1fa1c44ce630e40f38ef1b838b5252cd41d03f974ff2eb6e731cc52a96d789ee1dce";
                r = true; // result = valid - flags: ['EdgeCaseShamirMultiplication']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373239373236343137"_hex;
                sig_r = "61a4212b4a97c71fe13d44d85881cdb999566cb3e0ab3b8dbe19eb493e3ddc93ca482dbf2a2be8b2593405840e8d18b32bd29e6c3227758632abad768f08cece00";
                sig_s = "014e853cf725c53676c4a807e389036302ab4d9a37a3a565d65cc44e51fc10ef8a9358fdcd02f193dd8b6053d1e5a436d79ef89ad7764270da133222f0ccddec0a4e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343331343737363137"_hex;
                sig_r = "0108a2d18a9052bf94b3ad92c0d1dd4e044793d154562394de5d2b87abb96553e27c13551c1c02c96b55654c61067dd38c646a5a22edb74a8b2a9918061f50d046d5";
                sig_s = "010d71d4946272199678f331ad5a1d6be422b5289e05b313a1312380f2b633d03f2f871ec3800c531a95b2c8aed55a18031d229c74a4bf673be46dab46f7db6ea322";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363033343338303333"_hex;
                sig_r = "01d1850d561d65708444e3ecd468d8857cbebac709b128f358257959ea1df83cf0b6511532247ccf4342dd0e45c0e9c41ab0ff00ace007722c223ee973cc60e2d54d";
                sig_s = "0180e7674a0f0120d9922ac3dfe23661fb69eb0b328b307a0b6245ac881c8a198db56f8f6ad0d63c0fa4681cce10ad4421675afed97ea57bb7837f716d9af939904a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383239363231343535"_hex;
                sig_r = "01b46717f9a79cfca7966a09a027288efc065709d7ff2e3e330ea79988ceb766648cdbc824642d95a4bde04d85cd7fbff7150a60369a66e8ca38056dd0a31d7a3074";
                sig_s = "018035d894c0a0f9fe1db8afcdcca4f0b3fc8f36117708f0176b805d276867e339807e408808817d91f99d9c29880c4c162ae8b67d8bdc24d2c5acc3d29e4ed0967e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333131383231373336"_hex;
                sig_r = "016121c9e9c79f6bff0cfcd8dcd22f9be3d87729d9015123b0f497cddb98772790744081bc692f2e99f27ee10bc56239b2783d754b5020999f31a70c76129f730924";
                sig_s = "0143ff0fa6411ed447156cd44e1746d390a59373943c01fbd9457c23df7701022e69b06804165c16ebb9a536d5c28c00e98f7b1cd4ff294f878bc00c034d9f382515";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131373730373734313735"_hex;
                sig_r = "e2d1f70f08770c220fdca23d2301850a332ca31d57edbc65231f4920e9b6e6fbad37a3266e0a01032906d064163e8c549038e9d5e52d32cea30f3e22e4f1c49ae1";
                sig_s = "45216ed90546b8a99ab98be980bf9a1f7f7fd7bd4112f0561a85cf0c13933efbdccb7528f217babec7eb702bb26570feee0885306b3f8c3f86c9665a90a4dabdd6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353938353135353635"_hex;
                sig_r = "dbc9fc7d1b18ae9d5c42c4043fb468660a0bb74e0fd40a8279d0f5b4a37377eed84b07fc1e9b6d5db1ac1c88cb25eb23e3188754e4c7e38aa5f153076e6b1b8e10";
                sig_s = "3424f4b74d7b19e910fd9e6641e8172c03f759aceba300af49f9f7ffa98abd658d512d79f843d1f4421e46532de99496d11640ad1ce376ef31455c8bf4417fe8f0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383831313031363138"_hex;
                sig_r = "0134fe8e5e3625aafc2db789eec8eb1591ac7f5e400664a04aa5e9bb643c795c1506931a8b976dd00c4ec86855db40e24c45c724c57b54494e4fa4261ff77e16e211";
                sig_s = "ff3280b9409c4cbe6ed29ed9bd1221fff69da388531f62952ab05e97cb7b8af69a32bd31043efae743cd00382dcdc13626f0b2c6cef1041ac550a6c1f8d93c27bc";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303034373833333332"_hex;
                sig_r = "017c711b844e59b2699d69c1dc27a3ed505fe686a0e6ff5c1ee674e36964902def9f92f453d10c5b185242ac98c1f65c0433fdc96de39943b31be16314fc9c73db92";
                sig_s = "0170767fd3b8a2bd2d8cb9c8c1a69073a437e3bd07061ef930e47bef09e4033f467e220cedbc7fbfe193c48dee3fd15f51686fb237d8b00874cbeb05c237c5880b97";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39353030323437373837"_hex;
                sig_r = "bf986f02e077a60e9be04a9d7700e3d4ed4b04a9a9d1bef5f04c7eee01c320ccd2fabee38d44d71fa65b4ae15330f989adcab23757a70632f54ce12c37ccb195cf";
                sig_s = "869f9e343033ffbc0f1f05f90fbdf14b7ba525ffaab1d69cf4ca219f6f191db230b1c223125832894b546222cd22ea7b4bf7ec0fa36f1dc2ce51207f1bf38be51d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323039353030303630"_hex;
                sig_r = "014c2f8a18655c6d4e6a54e1c51c9d61edce24ca37e38459621549e653c3fa9b9a0120cad50295d6f885427c2a18b604e6f6c57f7a9cecabea68b9eebc49aaeb623a";
                sig_s = "436e05bab531350aa441e6e7a1042ea4219de3db75752dc263bb14592b5fdb15827b2a4c2f6ae94aedc89eb0e664989fcd573bcc3014274cbec6791982b8f539";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38313933373839323237"_hex;
                sig_r = "0c59126e6eb5932c6a05ee36738100c24141bde74e3675e112d1a9c0134add3e78b3697ea48fc26394761503dfc1cbd444dafd8d0831b4f517b329e37600898c80";
                sig_s = "017c611d7bce811524911c2741f2ead675b9cb7ccc7738fdb7aa47ab01d4fb6690e938a179159b3a2f83393d006c04f0948ceaef9797f6630ee0df7a35559a34b16b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33363530363033323938"_hex;
                sig_r = "7cc7fe18cca28a8c231bd3c7aa2936d02e3906a49dcdc2a30aac9926d8c89cf25bc644f584ab6ef026dc551af6ba32ceb8e3ce2af46178c4de8c7add701314e774";
                sig_s = "34ede164d5d60a69ca905f0c83314a63700024dbefc51ce1cf2bc69447cad76918580d45b93447093f5429170c996f2f7818ba0c51ce96b7526ea969d7c060d225";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3136333833393533353233"_hex;
                sig_r = "0154a680570056cfcae672d5af7e19556298b9ddd3fa162dc2066ceb8910008f304bcfec4faa917c7c8060f2f5c46fcf9b136ee1ea845b93f1e71613c45f22f9d0b3";
                sig_s = "ecdd6293480007e51bb4ab2eb863eed6742e693d160418522c182aa02851593b02a818eb757200f0cfcc1045fd1239c648b9968f2d38c3b98f42f9d21fe8943ae2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303931373638323035"_hex;
                sig_r = "593c8392ac4e7e1b966ae851ccc07940a04c5cd09dcc977b6223a936e849297dcfb01e65b2ee850b8fbaf9e62fd958c6a73a767020d2207cc405f795e77c808078";
                sig_s = "ce6358773088e069648e44976b0f9633e0d7a3fc4f21f568f196a5f4d0ae193b2ace16d765ac8396ec631acb5bdda0ca5fe10dcc6c2e685021e7442b45baa6d343";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39333634373032383235"_hex;
                sig_r = "6226a7101e0fd946778d45dadac793c04dbb4e0aca011eaad718f505ede077115c5f0e8074f30d3fcd04bfa3ffd69607e17dc1dde1047e1ada38d6daae8b45716c";
                sig_s = "bf2a2a249e0873b6894d6f8bd2f4ac64671525762e463a29c0afc86bdbc73223985feece210d360c7631134acc319de6975b3ba98a1cbeb8e37800064b4792c1a8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393236383638373931"_hex;
                sig_r = "d70238ba91fb3261a3baae40852190517d4d75e2e5ee528651399d615990b0d08dc687d7d060ffc91271a37f66a2d89d9d22a80ce4cd1f8c4a4e02def1a070681e";
                sig_s = "01e82c779a915d496a101829012ee2b2cd6b58b9ad902cbcbdba49876b671f9bb9bdd223ca04997b9f946dc441f98068c6a8dc573c69a3db9b6a563a4b7f5a712177";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35313738313334383231"_hex;
                sig_r = "01904b72705dbc8c01a422a34c3b72213ff9385eb56a6cb271c57ae5ee3338a735977d92666f474b670123f589a8b5d2682a685ebc24afce49039fc57b23480b723c";
                sig_s = "0161185a8e41a08b44663d001824c2483a5086e6da36d7140aa1612724de553894662f9eee58735af46c1a80147665a46048393ead5a5478f0ac05a62a02a697fd2d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34373335303130373531"_hex;
                sig_r = "efe4e821d4b26d7114502a72384a16d070e1a87f166bbc4caec10229ee423a0a6edb4d734a641f5411db4c0d218f979bde59b40b516835cb422981af6fe4685674";
                sig_s = "01afdbf5e549255948a5c8188d26af9b6cefad74d5d431d7f7c49f7c2fb27329cd359520e14a9c3d3c6e935d95f12c48d034e387dabd7cec0b7caac64b0551817d53";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3134333533393131363839"_hex;
                sig_r = "c69ff834fd8c2bfd562322fe6c65c25dac7cc08cce12d2a841afe601575b54610cd10c682afc20b782616b38d1e63a24cc9a3a0ff7a861f93cff1d9d9701f98e44";
                sig_s = "acb471793c0367a786366cf6ff4436bc140fa83572b3ad304d0a1073e7d3aa93da8a4952b6b5985e9e6b331dca2b687bf2fdb2e4bfb781cb0fcb44da56f3b5918b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333834353439323034"_hex;
                sig_r = "01f6c06a2f7a6e10338018fc6960f7617ffd3d64302e1f26bfbfa6cc70f472614dda2ea5dbe4dd693ba4679fb23c926050d2b92761c1e84c5f2c222a21b3745eec7f";
                sig_s = "01ed0aa68af7c551ca17d9b0bb99124f996bc663c52f8e5d904717f14a7e7229dc31116769a9185ace5b3563d46edc24e4dccafbeefa7a8e06a08df63cd808da91a6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373632313932373839"_hex;
                sig_r = "018b88509839c9025991bfd154d529860131b66755273f0986aedbd4a9246e91e725d290c3193552ab4544ec8e57520a7c4f23e55d8d52291a8b40a51599a02b4f0b";
                sig_s = "477c1e75aea8be30f2bd7e9551fc5b4105378d5220d094ac09f1ab20a36bbcd3ca7ed27e103527d4f6c564c7604465092c16758faa524d37a04888b90b8ae9b656";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31383331363534333331"_hex;
                sig_r = "0191a669dfe8d305edf8e4b81dc72bae04032b0d93076f7ed54d46d249704cae99ea33cbd960ee22015245f310a56b0c450c8fbeb785e3aa87b968270d21e8de2658";
                sig_s = "01e5455c1bd53acb7d5f4e9c639eeb92ce6615762181d86cf335af8a64a858102ca8de95808f20a408a6cbb7f878b261bae448e0ac4cc17834697d50aedae3b447ff";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343336383939303330"_hex;
                sig_r = "01f19027cb434dbcd1b3a9220854ca1c200b1ed39eda51d2d6643edfb93f7465674644aee2c1c66cbd5cd587841a1c2eaee1178029822c94acab6ee634c0b633dd3a";
                sig_s = "08f6ecc30bab74b51a26d71bacaae18e59a659f9878a58af16bb35cf0fb5855d49f8582cd1be0a3d7dcfba99edaea18cc2be37b109f7c2eb10ec4556f75ba66acf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323034303431323232"_hex;
                sig_r = "4d3103f0c7747f5f7155f5c28b5a7757b10fc648784116438888d6402eb7d35049b240840c15445416d52da0c7bb59f0174d47d666d5ab219d4d821192618f40f4";
                sig_s = "c22413a33604e0bad3459b89cb7a2ad0c023feec18bff9cd6942fa91c78a92610b90d9f494500a3b6552963b07ce6a640b44ebc1dcbec365d715120addc1b4687a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333337313139393735"_hex;
                sig_r = "b2081e6830ebcc22d981fe9cbec81bfe9a4dab9c1ac1bfbd199226e0ffe0c5b9b02a9c710fb219616d741200551c202f538e8ff20b6afef7acca305308a12445c6";
                sig_s = "0aeebc6603a567271ee33c405219cdaf33c6b809d888a0f0c1c22cfbfb6cde33bc6fc5b5af12c952be0b4ca5766a0f9fe7aff69c97507010e2b29cad41f2751905";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363935363230363738"_hex;
                sig_r = "0105a9c72463f7031c7303ebdafaae233e8a0092cf488595124c00d8bd19e6b851c6040186ffd0f3a803b616c9d8fd46000bfb6f62ea86d566cc75725db6790f43ad";
                sig_s = "04a06ca5033dde4b771f78ca3bd74469669124b99bed53359b1ba394640b4459008bfe368ea2ea5c45b7cbfbb6a14d9dc02bf85515ca118ca8302a3b6faa33f548";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303933303137373437"_hex;
                sig_r = "66357c2698c51b89824fafdd9c7df6f75191102e4b59a92f3a91939a236ae1f656c523c2f4c5d25f4d26fef34b73e43505f777bf808e86d29d45b5dc65b2bebac1";
                sig_s = "153498ffdbbf4335cff891ece1cac19d11b5b5b83775976167ae43d52ad905f8dbea9369e8f30b9764ca4bf88e0a67aab97d2db687b22c2c7b313d90c77d641fb2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313233343137393136"_hex;
                sig_r = "80fedb219a9123098db3e48f31b8c850b0ac0c88e47c328e081857f1fa8dc558a30aaa04ccaa2f788cd0b3a5ec6c441ae9e816c7207011d789c334ba916ed81453";
                sig_s = "01c29e1f56aebc705b611a643b839688bdbf6f684faa7efdd2f86cf5a2afcadffc62a35505b421bb5f55f688eebe49b70eb0bf4f40e366a1039cdecfddc58934e576";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373634333530363837"_hex;
                sig_r = "db5b252f41b8139da572de931dc1ef569e49fa9021f66234693d08292922def384acf8a04d044d07fe7c548f1f0bf6388906bfa83b154014f7db2bae29444df37d";
                sig_s = "017e9b0e27ec4c00a7e64467a203e21254dadc0a3dc381be924215af50c80ced936296c0aae57e8ace74c534ea749d061a8b7e1b5c85aa71c6cd36b30e2aaa44a5c9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131343137323431343431"_hex;
                sig_r = "de0b76360a26b366286d0a95fde0ff2ff24adcc63a2d2d45ef8c1bc8030d673cdbc2e274e343f2d6befb603cb8d6a7c739a785dbe4d974c4fd25a226e89bb08abe";
                sig_s = "011a248975f286d128f1bc916829c7c59378459f61ebe7a46acbe3394c71b00e60779a87ee210ca042696b2c6476d1ed83002bc8cb4a72a7c06e62dae167dc8b16ea";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323638323436343933"_hex;
                sig_r = "01250f78140faac9b131e0a85eabdbacf6b999460c918f1eb8ed0154bd64dcd4609d5856f4495b4f428b93c2d58c162c3ed78263d83440b9444197daee103e2e3565";
                sig_s = "be4536433ef008015ddf0badd9464ee873f90a8132ea906e95a5e8d0c0ed9540f6e27490adaab451218d1771dc2745a9ba01ce8d9b008737cda0e4a08c1e69293c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373234373936373737"_hex;
                sig_r = "01e667880aba13b0dfa45e81a8f534c691893150ce1d6fa543f2fb2a14a9dc50eead2f8f45336208637765c61e22732b8375619faac8eccdea37fdf0efa9497162f4";
                sig_s = "0120ed36a00299f68318fa56072cb39a1e9a6fbffeeab047bc315ad6ff5f82dc433126faebef1adc6d2f64339239b248898c963ee42f356fb25bf11fead790d28f0d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393733333935313139"_hex;
                sig_r = "01d7113e1691c415b3c8aa1d662ce75ac9e54c4d5a9af698b338a2f5cdc77a88735ddbdc155192ad0ac8a8f4b46a861d0fd9526f696bfc5c27823aed612d6c80799d";
                sig_s = "01f4a09f3a975ce4d237c0e00fa60ca34e9be2ab2fc7fcde811e49bcbef086654f97a67ddd075f68137ba467560e5f72a4dfd23d123e08004fbafa9dfcb5319f09a5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353037303032373036"_hex;
                sig_r = "01e948d76ca9fca0a7a99cb56c8c24066dfd0577d8cf0f154b7520ea2f97fa94fc791d21f5ad0f56d9adce2bf4c259698a642b03d1115b7f1ecd9804d30124e8c252";
                sig_s = "6d4ed5c27e6ddc80b69802e81f4da4108bf93ca082a61df296f15557dcf12b5d9466fbda02bf5399b175464a7b23866bfba079b1b112bf06b36723fd611135c47f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33373433353638373832"_hex;
                sig_r = "5ef361042a5dfb8057e99968fa8dc5c32e1e6fee6a923e8ca711c4851b1bab8c6dce47631c69a22b6d5744380f92318a38738df7f74d3ba06be2df0fae32d3b9e4";
                sig_s = "019988d998bfc270b68e7bad761e99f9affdd96478fa9d02cf04269ede6d604b7680a9dcd8a3f589b989c06fbe251c490b19f3c297a41367f1f6e2e39e2c4ca19251";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393437363731323438"_hex;
                sig_r = "01b80a6592fa733ce77b3f48febe5b178c287288a976b857a4a020f07516577184a296fe37c3b88d3cf20e00b5c53d5881f2a21980e3ad3e8c0e358e363c4927e323";
                sig_s = "8009c2401db711677867b898225217997005bb458d6c5109c56fd2ae72d3df8b8e4c4d5f5038969230cef0134ce17ba19aaaeaadbb3da7f16ce4700119c8d91ccb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373235343434333234"_hex;
                sig_r = "bc3785bff1e5c9bca6d12d303849487f2d8159ff5df782433f3a616b9fb49280978aa88d940d0428097f82a26ec22246e64f675a5118c7ba67bd69f46fa6852c59";
                sig_s = "52469800e0c50d7a580a67008f07894376c3783395b7f41ef468a29fafcfc4a68b2899669603ad858fed05f232cf39844f2d8606355993dde9a6dac14a6eb70bbd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35353334303231323139"_hex;
                sig_r = "01289d4e5db332d13be1f44462020f3882e0a626814e5a7cf388ec8453ed1f921bdc3dd2bbc614e4f1be52bc0baedc8f662f7769a41aac95d7a1599390fd900d7ef9";
                sig_s = "32d876eae37c73d79073c9ab8e756d2bff616464a733acbc26d474d00caedf091dd4b2e99c0bc060f0d3d393a3272d76949f091e278bf371234832e23df8b15ce3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132333031383133373933"_hex;
                sig_r = "01300817e6783f704b2edddbd4d016bf45a80ff06845058d3fd9a1dc1349ef902bbfb69f55b0141c1f925fea8bc9e35f44d72b6935cc7d49eb2da1f1b3097483a9ca";
                sig_s = "e53573707d4533f65231a6d0539dfe5b885c0126021022de32f3a4199bb1d470cff7fefafa95cf9b31fc43f3326f3e6e64c31498bd71dd8306592cc1d987cc0afa";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39313135333137363130"_hex;
                sig_r = "018571d2e78c0fd3526c44ccf5d13bff203d1d60f8985e977395bdf8a842691b82d035809a071ea8556ae1b71acc415f208f4555165806b13758d8c03a692084c7da";
                sig_s = "015ac3a64b46df043658dce21c333df7acca6d9ce3161469d005b3017c3eb42159333c71161e8576cb0c83184e5c513b13f43ee665d7fa8363d809060246526eea94";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383934333937393632"_hex;
                sig_r = "4c186d723b97360ad18329e4effe6a4ca80c17ed4fa8bc1137ca0d261bdb845c24a018a960c13dcfdfa94c739fa5390b0943335703b7adc0e5c6d97fe0f3231334";
                sig_s = "017a446f9f54ff41cb9bdbd02d236b4d2597689f99528a3a57cd10e5ee38fc9584efa5d80998c29d47796f02d20a9e7b493ce87a60448943bc55134af171c9162a1e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31323333353833303333"_hex;
                sig_r = "016d8f256b29c501aab1f2442c367ee5f64f7e9d8391ad399ce7ad3a84f0656698474e3c7219e35641a9f67efe6d85a7d5e4502011cd61eb6b501007204aa1aaf0eb";
                sig_s = "3ae01795cead8f70af2b225b8b346c6ae0a9ae048b7768dc86c9cec3cf0709f54b29f99fd2eae87f0178dc266b554c779b0e2726753232b185a1efdd9b24dd2319";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323131323639323536"_hex;
                sig_r = "01fd7c9737ab2cfb8044ecf512617fa199a04f4900a0ed8e6113c5d2fd19c7544279a29a1edba9ee6c0aaba2257fe19deb4042935754c78ee17aca930056c18458db";
                sig_s = "400658f9d136e0a994a4219485e2b6a3bf36aadfd6927c14aeada8ec88ca0ce7a169b79860f7dc49b59d9cf629f5fe1d07a4eea0ea61beebb65615736fa3f1ba94";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303035343833383634"_hex;
                sig_r = "01109ce5f94541c60c9748fcb55f83ac9b351576bc92bf21e6a989302b076c869b2300fbd717d6c08b1ed619be256156248ddc33258a7ea58ccdcb223072278ae58d";
                sig_s = "016f9eff4d78ad496290e35710754437ec0a9b30a3be091727dd256802fccfaac8c6f53aab0c39adbb4b34433fcc1f221e8222f3389c0d646eddbc07ddf0450631a5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333536373632373235"_hex;
                sig_r = "0154a404a6cc2a53aca70381b3223396947dd17eed27d6f3c0b9b6da00d82f6ea4f584a522f8ae4c11cdf86f61ad12a431c6c38855402f87b6c37ca278e6cbbc2f83";
                sig_s = "cb11bfefffe6559f084f3ad3fcc9c1513c2657f231847da40d2e5f8b2596a57955360075bc9bb82effa71aa1af9485be669ac4b3fd107c4f81071ad106d8b068e8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333239353030373630"_hex;
                sig_r = "93cbe3fb6d4d3d42428997ab1ee236228878bd91f809b1a00626ce3806480c298ef4d43d2623c2a58d3daeed0a4090d0513ebaee412e852b2479f693da458a94e3";
                sig_s = "0120c5822abe92fcd34c6624d71e98b8712173ac17f3d663eedd1c1e905c300610778abc54ac6f790602df4e2f4b84ca35cf1b5cce08de341b08db82dfdf87ae6650";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393237303834313635"_hex;
                sig_r = "2bff1eb4d4a3ad9676ea4e171ac832b4d1174b46cb4b9c7eb3cc4f8860795d49a1fe3676f085a44232f4f24c1368fa0538d0ef8e64be8cdcb835e2c23d0064a162";
                sig_s = "4b73fd94b41beca21416ce3e451585516713751235e20c04f90e5d6458ae382cd50ccf9523db05c7179d9aea6b7400ae83d28ae920f6701ea0dad7bc364ed59d29";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37333032333538323838"_hex;
                sig_r = "016dbbab105266a78d1df8e195d854a4fffd3d66bf17ec3f96e3c2c5fd26b2c59a156078aeacc5832d81cc6c86396f471cf8d4dc4f2891b43b0b4980469782a4f09a";
                sig_s = "01a9d5d04b820d5be931fde08801d46a27d3e7fe9995aa0970b7acc739c56e94c524e57e5de386fb1002e76d17cc84584e677f92655a0fce71b03703d4474ed477f4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3133343733373337333833"_hex;
                sig_r = "012b83531b8b74c699a3a340cc133b559b0bc4abc0eda717962b7f68eb05f382307279a571760a88b6c11cd0c060a8603eda021038784fe1fbfc199e038a3d8eb26f";
                sig_s = "13228ae6c8e5682cd4ebd1125892dd95bd31bbf50aaef061614c4715a90f1db89d38bc35e4e2529c71acaa26ed5ab1f49c892c6f987015320d29359d2794b86f43";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32353031353533363839"_hex;
                sig_r = "01bc7ce250d5a075177b749d919ca1b08d27d0c34d900f36c7f2ed0bd21adfd0be63c87463d547ed630a351d46615940b3f2acbd4cb8c3fc3a533ae2d0d5bcbe94af";
                sig_s = "b6306e0c0a3bcd7f96c00eed9eb0576bd9c649caf9055607ccc0febdfceabb6a33fe805cb0193fbf8a36dcfd76b4260b280dbac821cbeba5cf594e565f5fddb896";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33353335303430303239"_hex;
                sig_r = "3f3a8f128b0c66454badb41115199c6f2a899d51fc8706c57dcb6a0937015e7e2c404534c0ab9ad4d5ba135f559dbe8ba2b95fa6159ca8e6a11f4470b92d3c7ead";
                sig_s = "01ee116f82c612b2bef7b8882492a8b0779da07768f72b372635af930c18362a2a4aadb19d1297cc8051968588e1fe273970c298ab63ff1a51f4ef458c6642eb5f4d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343230333537323930"_hex;
                sig_r = "bb6fb4f81fe5715bf8219a486dc94f89f685f89b69c026eca73a653910a3ac2401efbbd4c5e5931e03bc5ca3e34cb6b1f9f7e93fcef688c6ffedd0ae8a5372dc04";
                sig_s = "d8bdba9909f7f8199c85e65692fafd9e52091be6dcb98affd42b17c6eca1f60f9fe68ce5e5a3699cf968a1b1c094d7e83b0f9266a04aa3319b459c259ee3bda13c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393035313735303638"_hex;
                sig_r = "0172ff9d99d166998b9d3c752c72435a3c88a6ec6ccb88cf3cc0b67b2c90a635a81ec08bfb9e5213822b23f2a933ce1dcd10b74f962492773046c9a2caa0398a10e3";
                sig_s = "e014f3fd3b0802902c85f5b3ba39453d44b123c4efc3fd3244bdc5a135aedaa758e661d09ebe7af1b725cf3bc656f9a86646512fa6bd5f239574036d285affec4d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363133373734323935"_hex;
                sig_r = "6f96a2eabd62032864758c284f5e691a274aeb5474a96aa183c41d43b6321c985207fb5480c7a6de8d316ff82fd97c9fd710e014c94d6586125e2416a60e710f85";
                sig_s = "01facee5bf81d66206d08349646020ac237970f7f695309cb6b2a16ddb464c21da01317c9074cebfed530250f818e3619740783d007981324d4f3761c72e2ccc2a60";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383733363733343931"_hex;
                sig_r = "018ce4b4738dc0d0206ebf7e804ee800467cd2d174aed6dcf556bcdb2c138cef9bcdd321a94979eaad8b7ff359c8910e7addf06671779aecca0f779f0de148fe4817";
                sig_s = "01b495412395cb659112efc8acd9fd94fb5ae2732a4dc923d641ff96d67d72486e9f963a9cfa680fb55791b7005b7dfc8d7a30072ce5afcbd4213b0a184e8eb05e06";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333535313036343035"_hex;
                sig_r = "605e9fe2651fab3bc3cd356aa1bd6c866114eb14fd0bfe40fb75071247a8e7e5cc8c375a1b32ab99754b200018f964ed34f509612777cc90129a030c670168cc29";
                sig_s = "3c546cc8750c5675b150f4f49303ee22acf38539d6d3ec4acdd30fe57a1f9baeb62a8d8a42f56e5b95ea4908069aa5bb35da7af074c31c450047f8181c181c1454";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34353339353735383736"_hex;
                sig_r = "011023b80c9ce34888acd9f5265b9fbdd18a7c87302d22b64231cbba16578edf53ef4cd7b4ac29f47e13c31444eeff405c89891b462c9ae3de7d1076e1137c613e21";
                sig_s = "010097adf0b6db68a90390247e0b761044d271f9a10fa17b7d1ffb433bda77b0ca4e1fb7cd5b2bbd9a786a82b4b5d2049b520f8b8fc1c5ad6c9bc99aaa4b4ffc37ad";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383933363633323031"_hex;
                sig_r = "b6ae707a764b79c5e532a138c72d2bf6dcadf17d045f722a2b5401e099ad67249cbbd0b2c7103080b0a3c1ccff47b58b526b1cda1a125a62650638cc71ad5424c5";
                sig_s = "0193fbbf26a4d3a37565cbea7096cc57d6c93670eaddbd06956dda8ff8ec5fba338c449176e45baeae515e9bfce4b7323b4e3162a008819c23314a15757831533c7a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33383036303638303338"_hex;
                sig_r = "016c0113463959f1aec914b7694d6228ce5c8208515253f52232b416108bda0b3de7d678175d455694fd66f49ba9ccc9f9a32cc368d38b606dc454dab9fc411ecf20";
                sig_s = "27009c48d3402075e8bb2869065ad83d662594cc9ce4fdee42aba7639080d7e7fc507c04c6dc45e39840a321b74d695b1e6d95411f4909aa98383d5b102831243d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323332383137343937"_hex;
                sig_r = "b6ca0c0e3aa951fe443180120e5e86e958d12d2d0ba40d047b16eaa9cb2c164acecd0cc20e7a6196bc68771b3ac5f82909bff29de560eb9f39e8faf6d7047f8173";
                sig_s = "01c50102f66d6b0255aba2ef758e5d1f148a9a579b2f2bca3ba3d5639f64412c2cc444937c84c69b8dc47885e9967f024e8cbfa7560c730cdaab72eccf93c3035271";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34303734333232353538"_hex;
                sig_r = "1adc5909ccb73ced388d8cbed6aa7535cca6086f52b0dac552e6191eed513a19b0ff5d57d306d0c8b756d700dc96f189cb552d707766eda4cbb855e542a91eb147";
                sig_s = "01a6821d57714bf3805e8a28a65197463c09597b6c2fde00b64521f7cb6cd567b33ee344e9677ba423045ae5f5b47a39260548dabd6f961482dd4fe45fbfdfcb128a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363130363735383237"_hex;
                sig_r = "f6cc5a98e84faa07fd46dcb0d057383d01ea7eac9e3fbd9f7d462bee76da988a0eed44fd59da6cf992c086bcf1092a3f3d0c9d373297bccbc0a1a25d1ef1736fb1";
                sig_s = "684733926ff39e177af57a0a3b4531cdd19b0c5f717f741d82ea493a09c310026a19386cb95c06ea7b346a2d90c01df02c6997c25dc0b89cc578ed4b0bc7cf3d48";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3137343138373339323133"_hex;
                sig_r = "01ea2fdd9e045483942a46017a75cfbcf3e22905b56de335375b6a72443949c3d8a0af587b7dec02f1c61f679205d5c1f76adb3aaffb93a20533caea83284f3032c7";
                sig_s = "017e31471262766142ffaaf2cd9939d96fdb81fab2629b24f394c58966b9df0d464967e8b73cf2030de62d4415ad4c3cb5568d8c4d80ea8fda6a3196d6782338001f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35313237383432323837"_hex;
                sig_r = "01556547667d7bb076541f9ccc96f5d4948bf1a49472e78c949b3cc1024515c2f4e8fb93410dc75f961fc89df82cf7781b58f7803cf8ccd01d3733050c0fd57de1f1";
                sig_s = "01c395c774afcf7cd9138c2f97bc8157ad5eea934ee3e976fc0ae497096c6f7424903a64cae5babb13f25d53ddaf762fa3bf35649b748f86a12992383d9ded2e21dc";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35303338363930383739"_hex;
                sig_r = "01db229a7e00aba5780017a0ee2e579ffd069be31d8358736db31d2881dae942e12d3fa0d2768d5bab095cdc03826211b48bbc2acada67e463da26b685a5e6d8a71c";
                sig_s = "33679983c9b13c3235eca932448d95945b3a16048c1f75708c054c3f36c87babce0e5db864ac5b63061011d2dbd84b2f239e9b3810ec869de2c663164688b0a7b9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33383737303432333937"_hex;
                sig_r = "011cc7f10ba1f52a7d74a20955c7f327b3951acdc4af205d0ae66eaeb1b9f2bc86f98af26c5efc2240951194d4ea77a5d605afed96712556005948b4666d5746c4a3";
                sig_s = "86c3bfd2ec110d4aa0f89f78b9cf93161db88e3777ae0e986ff0248f7eff483bdf4c58ddb5a70863bb0355c3ded63856559cebe87ee71112014bb44f905c699e1c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333231373038313738"_hex;
                sig_r = "5cb5e2b95fa6447a73e57455326571cbc604e9e54b593af792ac4f3add9cab628d8087d2da79c217c808ce000c45b86555beb6f2caa3ee7c86d7bf3c5a4f8f99a2";
                sig_s = "013c057b5a8e2d5c66ed0fe4b059fc9a2c218333835188dec24cd52c1e691a745c087d199f5e08911d798741aa0d716c20ed24baab3cdfe1f5a66403152b0ff31776";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37363637303434323730"_hex;
                sig_r = "a4d6b83cd0b2ec187c7543b5493731a99f5ae83303190f122f893ab7c6d8c6a25b46aae1cc1b4e84a13bf52f3b3a88a6b0d17df6f1e2a83ef68456556a80b46995";
                sig_s = "3ed11506c4638677d48b4ac940504083b4cac13bf53319bb312c24cc9dd85d3d13ee63022cbb8dc123da8fd926e6f0e23181308d00f81eb10c584e9b3f4eab9bb5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31313034373435303432"_hex;
                sig_r = "01a09b6cfb57008a004d719ed63c45e4b0e97622a36ed2d2b22dde5c633fb714f0279108bc44e94614c9956ae9ff22c51cd847e8ce4314e767d33a01fe62e5b1fa1c";
                sig_s = "0acdba06f7227ca1ed8d0365a9ac68962026e33a593ac08df7bca7e596a5d6717667172ce494fcfe3a9dde26f545c86bf11f8d91ca8a410efa342d79217ec7f094";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313533383730313534"_hex;
                sig_r = "9a544548cc696921a3b0e98201400bbeaf37876f45240b508bd193211826a997fc66dca369de89ffc72ad9c1a67cd9b15651fc34807e7dec3043230e65b7cc9882";
                sig_s = "015bf35d1ab035a1fcae2e05b13677ca2dddd95a553d319e71c59a823421ec6b05f659446a026072f2dcb9c3cb62b1fa302d43754af38dc681a6809db16e4c32865c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323631333835303439"_hex;
                sig_r = "db87573f7cbfa341b96ceb4bbc79b959593b55cd8f638ef4b5e589bc1664ea91f7473c9d913a0901330784341a366314b30495a45a88c8774d985b4e5ffa915108";
                sig_s = "c039fabd667c40289f8a065b0b43e807a0f7f51f7767501588031588fc57317a712cb4217dfb45fa905c8c7b5dc9a838ebb974b5a5b456d08ad6b1d79707c54257";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37353538373437363632"_hex;
                sig_r = "29cc57f41ee48f6d222cba402727e0eee262d67f922e4c0488c276960409dad40d7f719175eb009cc7088cb35f3aca9114c71915b1158c78fb5101649497121e5f";
                sig_s = "b1c22f956b33fb228f7dc12e48baa527762ae6f4c229a4162c4753cac39827b959c4b0b7994b877bf0901dff5a6d4e9757cfad14b0e5b7717e1d0f54c335d08a7a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33343939333634313832"_hex;
                sig_r = "598f0072da616419220ac9408daf79cf4feb4d0d09fc48b3defae2e34c66b88aecff56f95b422131c1de20205df2a8d5ba554db78eac388a267a36335964c7776f";
                sig_s = "016f2735e142d4280ce39254a4d0f8fa8f4f7542f88fdb1a08bd7975011950a9166b291de602193ffbc56adfa4e5212e8e8bb24ddf80a94d762d8a671851dc6621b8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333639323733393835"_hex;
                sig_r = "01025c2317f1e414e14a5b41c7645bc1c2d057dcb23b3b6ec5bba84adb50171cca89f806091d1402b61ead88bf1df50af1b97953244e2cb4278639e4bbb74a040d7a";
                sig_s = "d3ec9a1e19ce0fcfd09c65016e96500f95a8a7255191b95e11e2649e2efeecd928d29a1f540935e0528828a49867af990ff941d1765cf868f08504ac12e3b4f6a4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343933383339353635"_hex;
                sig_r = "010d14ed8dea7292f11c33755145fbccaa0d99c79813ca0373e18d4fd11fb653b456392ab09db6087035dc3907617fccc5b040d21a675d0f63f4af74af8c7211655b";
                sig_s = "c76242ece39dd3aee07cf60210a6575a0670b2821a0856ae2d8505b58ea6570a69ec5ee3efcbd38573acaeed2c6ca3d9e69c08e204093cf8f647089632ecaef7e7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32353334333739393337"_hex;
                sig_r = "6196bbfa16cf1d5ac3aec198d097d113453d7df5ea535b6eb61ac387858d179f6981f64d9bcb60a921d6764d3324eb9692542bb18b0b5400d985bdcd940426b4c6";
                sig_s = "01ffb4a363ff951fea35487f32dcbefaf04e89b73f585598de4a4101c7c39804bc787d92d74210acf86f5a6d03e878ba5f5f5d2724abca0c659f343c3d3ea5764577";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383334383031353938"_hex;
                sig_r = "ab2cae0eb0f847e8b17e986f21be7572985e9f037a27f82b7361a7771af68ad2c94e70bc70c051202b00465f8be707957914562c0a350d7b8448867f39b8b7f2c4";
                sig_s = "01d5ab664b4f3b0552bb84a520c9ec94ee8d6be4b8b3369e10bac7cdf4ea7c969310fce183ee855e460053d30c5e2da82d13a06e03c2f961b79d6ec777444b5647b0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343131303537343836"_hex;
                sig_r = "01ffa079d25bbdfc6ea73a3601d834de5c5854f97c3571f10c7727f3142681aacbf14c862206cc02362ab629e3b3e34994a68333d8f6382985b84b5da5984fc9f46d";
                sig_s = "c4b5a3b09d990f51cd33e103e7f77b524319000d2ef08e9a10e532ebaa36d9562b36afffe35c3baba49643f04966d31a9989b25e2cdda65c89c238f083ea4f8c26";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373836343638363335"_hex;
                sig_r = "018706d81d28ee89ff9bee8ae0a13aac7d3922943fab2a8ff8d3df91c396f03197a0ddc002e825b229e39a2ff10529f935d85085fb0a6a8af6eb6f9e10c9d260687e";
                sig_s = "bb9aad24e5a92d7dc3ee6e29ab441efaaa4a6db4e31502ba8e9c9190eae1ee8040198fe8db5fe8b5a0228933fcb309d7dff4ac00dda2152bf3b1f8e3874c9bdc2f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303534373733373638"_hex;
                sig_r = "77b04bdb6f839f14de5ce476af1f26e1e39c8653141e4499149a8b267786917096cbcb7a72b0d21a3894abf165b653bcaf6075974e073214678feacc10557e0f05";
                sig_s = "eda59d6d49bf299d3eeaf5a2b9a232f7de5b08e144bd359d663d49730985584dcc091e86977b77845f4a3e02a01f485f7cdb891968012dbdf4352339abca4966dd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393237303137373338"_hex;
                sig_r = "015de07d01e25e26ed3069809031e96cf318860495c15a244c42bc0c1151c0a2ef7cb2a2841f0841a890c5c7211585fbb63850c09f5b4a8c28f60e764207a00ab0bb";
                sig_s = "ac1abfb9f8f9824a1ef744ba1299d295848cbdc98691984ecce0473899ef3951a91dae6aecca52a8ab9e04d57f77bbc178e26a31abbd8dc3103742ac0414a9db40";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303531333235363334"_hex;
                sig_r = "dfb9098e386dbe6c49b45d834c06bb331912a4015dd2ac81036d8547fbd69a98d55601c97901c417e33b6eed5e499168cc14b34fb120180cb0b6e11f638182ce93";
                sig_s = "50214812721b288d270bdbce361d4c5acbad454521111d2adb1ea4b371df5c380e4cbe19d0e780bb2e268a46957fb496d2719ae9516d41e70dedd8f9a1f7e7478c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34303139383636363832"_hex;
                sig_r = "3a717996fb34063e77e05a8755eb90dc39f637ba6f18e702e8d049e18790338469cb916907cddc404f73abf047175086de9cc512cd46b9510077ddef8ed60456f9";
                sig_s = "3d4067f4dd3941fb46c2e3d1e13998ee7e42d3265255f4a680fec372e57fd269eb843e6441c74e552ca9690b1007c16f339137c48d8e4b321808558907736a589e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130343530323537333530"_hex;
                sig_r = "b915a03331a4ef1bc8129d56865bb5158167666c5539442d96e417884d2a41b330ef63fb13f66fa77cc6a300e29e8535cb09305ab3f49d7c464d7403c54a428ffe";
                sig_s = "01a3b5ff1bf1c0a19fb268a016bc19f8747d2a0ec06acfcb7564e8b673551300dc0c6988a8d57d2e69b90f45caf42f2769ce54691c24f7d4ccb322dcb01525606052";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333236393538353830"_hex;
                sig_r = "77572850ef3a79cd9df6946e1ffd372269f3a50515b9f8f61b82ee6d29af25c5ab17e05394c14620f15c7d047870102a991322baad29b30465d6d1271b3e85efed";
                sig_s = "4e070c594fdb84f678beb2be1de5aa45ec36ea3c9ebb37a25769ce01bf90db3f2458737138afedc21dd51515241e8724e9a49af12154a278d89db898f66aa10c36";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303734363533323431"_hex;
                sig_r = "c71690b845e4ee1e91a8452c65a245860d5c13c13f359896af8b22466901a999b033ba49c4f3d9b2b496bb03d1f44a523d64815f3db29b262cb31889df5680613d";
                sig_s = "561b5957008a469c998197956ae855d77c2c3bebac91d307e9a9d98bcbb25a97bd914165e08b9651fd70e0a8215c50ce941059dd39cdea01b3520337b43e5c8f2e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37373134363833343830"_hex;
                sig_r = "01b8c5100a6021116c8e988c66611acc9da7cc5ec621f95df537d8082ee3f5c07f7171a8150ef45ce3f3dc802a8911205a5106b963a52ea6287588cb0dc1d998ead8";
                sig_s = "01ccb6df7546f4061f14c6a0950e0fd38372e0c42588c6fcb3354247398d19a5c91d86617595c385e93a087b84c7ff1fd6c4ee4fca2fb111662788dbdc1bc5217bcd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373933333831333230"_hex;
                sig_r = "01de9edf9e10b8c65452f8ea07c57f01c2f2ee6828d89bd4bceaec4046645a970e85b41cf7f04f3fcb357e532e0814d0b7c8fbe1e073d555e3fc13a18bdeb8088858";
                sig_s = "01b091f6bf09385dd2d7a2209637332be35e1c7efba0b80a97b268b5e6d50ad2bff662ec74fab0434890a48e39340a494f45a7de4b886513829854de83ad9abbdc9a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34383830363235353636"_hex;
                sig_r = "010ea1fae566aba575e06f2e676777f0f4b832ac65474c00cb4363a7e96762ac557912cf22f737414fc386410d2140a07f2cc604759a4e50ca6d34eff5a9babd1868";
                sig_s = "8711b35d2a5a6dd36630d0bd0b0c1e85a11057583cc87f59bdeab74fcdaf407235d68d24bda26e6b86645ba31301539effe8e51818e6c915b333cb868ec35a62c2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3439343337363438383537"_hex;
                sig_r = "224f2a6797d31f669a725a0be5c48e569f313bf09780aa49c8430b2ed3e28bd82aea9a46fddfdf9ff6d8be9d50dc6edd9021a1aa8a8707d19fbbb164d3f2f2c967";
                sig_s = "aecdd04885de9bddc60d84ebbf9e868d28542cdfccf7b1a306cb188e18986891cb2537a804ca99b8da8b4a8862bcb842161b33477afea8f224f4277db93a4f66d7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34373038363839373836"_hex;
                sig_r = "011e71fbb3bb894f71425475862000567c6f58170fc2b121e1783da56346a46113e1779203fd55f5be57fda0e7a48d46d1908b8033f87b577eba64e604e29ef8693a";
                sig_s = "01ef2a00cc4f978bcf8a0cca6bafa93a3204ca0c9bb4ed684ee89a569638e99d84cb470f51fdc3786e1ad383c5a90ae49bc1e7e7c14f6bedbabf1f09a42567e302a2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303239383732393531"_hex;
                sig_r = "014867d547dfcce3333d412a7e177451c8fc67295ea0a3fe1bb99c1f517e950c4637464a8d746f217e5ea2d2e87676a76b8df889364a993af971410b2a652bbbb18d";
                sig_s = "0429194561d54794f49d752bd42660856de51f473086380ffd33a856cb8cedf6d2af61e9084e1fc7f6b0232ca5b8343d2aeb82ba32c7810af1f1332d06aadae8eb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303137313930333835"_hex;
                sig_r = "01df9b3881756775ec1f0ae5de26f7d6f8d563c1afaf7942f3059ce75ccf75a34a0120955a1e0ebdd89de9b08b143dcb62e40a711a37e6408721f80e560a17f2cbc5";
                sig_s = "012d7eabe9560bc23bd62266ce1bee7ffecda8c39edf7eaf5608338e2b546b689d2102e29bd3064ef670489c8599ff902b098211107edfda5920eed9deeeacb8023c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393536333633393339"_hex;
                sig_r = "019fa4898ac932313efdfca7e720a52748d11df0d00a2a36bd6c12ae037c8921598368141dfc14d9b4d5736b0899774f51142e109c94bfab196eb7b96c2dcb621c98";
                sig_s = "959ff6ea8673daeb5383357d0be542f64a0385bd7ac3a13cb3ab5c30f08f58c16c8b17d25f73298245ae2a6e060af590b4e2ad870d13a3ed14d61376e3c378a32a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35333030373634333530"_hex;
                sig_r = "4953aeccd2b35bcdf7990ca391d394d198ed627de0b4b5783fc12e20967ecc9729fe6c9ae51c54c566d52356ef4fea2d8da4423cbe5fb82d1d2984a2b6f20ef42e";
                sig_s = "01092dfa2b04a5e1b574c1d907f66e2484aa772c936f2ad3c03b61f7d01290ee849d3e3d528593a304bc2f645dbc3ca83cf2119588adc29860e72a30b1eccf895dd1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393334363634383434"_hex;
                sig_r = "01d9a16289b154bc7b341ab5f376df9d09acd1068b67bab090307042962bceae0199696af36bab0f647906ed7e0a5627c961217e53317ca0896bc650df96e9461f5d";
                sig_s = "01ce2b975ecbd5eaa28883ce90560b27b4c66a284c501e57ed4ce589ecda801def1d15106cd8c830ac1c00b529e4f46e188ec5f90ef650f520b1cfdc33c6ea1710a8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3335353435303535393632"_hex;
                sig_r = "0136f562aa082b535fd5657052a62e794eb6e1b81881ee2bfc41832dd7284be075f5e7e369de8f7bf2660c81e690ab9ceff89750032579f2f19715f6faae78b59509";
                sig_s = "784aa162e2ea1ec60811b5e4fa29907210f3af5148f14b35e641e91d09cf580cf0436662118c9edea88a08b7d88d3562294a0c326a44631b4210e6422d01a0ff82";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333031373232313038"_hex;
                sig_r = "e076bb4455463845b37d0ea66560171847d6601df05b00d3ac292df7e3f348b6fed892ca07cb9c9a8a66fb1e33001906e68e73fb4ed223f169447e763183e8e8b9";
                sig_s = "018e69c337db6f330128dfa27e413fa46681741581452989e530b686406581852a62f0281a10cfdcf10287a58617555e54216be5911f2eca50856b416987c112d808";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35363137363931363932"_hex;
                sig_r = "01b5f54a668122d72e4ca9db26c4246dfe4bd9929f196d76daaccf0658e75cf360ffba84be8ec6a8b4454917c921b68f1db202da9152fae152feed4c795172f6e3dc";
                sig_s = "0144c3580c1ac9a80223b2b3f4b67bf224ee7cd2e2f9cc89857bcdfbafd05694208b87a1fa040e33211ec9b8f59dd6e8313d8d9c67292f3f845cfefb197973b1f5c8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33353831393332353334"_hex;
                sig_r = "0115239e7d4efe196c90165cd12f4992c03ac4796adaa6efe282b9dc269a80a27dfc09efa3f3247dd8239de2444c76786bb36967bc6c862778e0088685c6ccdd05f9";
                sig_s = "01c560b07ee45e916dd9d0d7cd03be4ac14183f1725a4757291af193a9cfa44f0b979ef27047915a3c2da505c411491d243de19b604b1d7f610dbfcf50ea79099093";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3135373136363738373434"_hex;
                sig_r = "018ef019e7f54e6475232d253a6af62a0a1079fd74fa0f1c0cab921f09ce07d22a80ef7235255bc8af01d6f487c2f48aaa59052555c66fca89a3d3fd65a5c215d953";
                sig_s = "01fe467d44a3b55133286673417d4d4f9f42b6e5e49fea2550ce98d1b441f57711d8fe4ebe1f6664a023bdff61f8abd7b2eac163dd1e668875055b9a8dccb8537682";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33313939373833333630"_hex;
                sig_r = "aa9c6b87c3de041deb72244fd3b2628f310da41493090a7c1bd9af654b0ca793175e2e32ce623dd7f8671085066cd1cf4e7fb60a573779b142a20704d33831ac52";
                sig_s = "016b84d9f21150dcd439859e714fb23142ef8a16259b520621156fd04052cfd5022bd31fd0dcb4a1b0b790cee745de38f74f3dabf4d63c71ed2147f43851fa747232";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373430343735303832"_hex;
                sig_r = "01bf9a7c27c58f163d27ff91a10093ac5dafa525c39aed530eeca981c578dcc1ee962732e77093aecebddf8d81daa923477941396938f211811dfc34e4a6eff2ed6c";
                sig_s = "eb3f6b2f40f9ce33dc679f1787ff6c00143f946bfd2b6e10f358b88ca9146a4133ad4356efe0bc1863f9f9475d58f99f6aa87f88d0ad2395699c09615c112c12ed";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343137343336353339"_hex;
                sig_r = "3702d9eb114d84ce30b036b068a829e16882e4e73460b1884fd734c0a238239fe2dabf1f623e420c94973d499987d497d38f115767a5205119735c7198f5cd0aa9";
                sig_s = "4e72a80ce8a9fcf312f1a58c6d4bc43a32d30869c5e4c5d8630d547cc22c02eb90ef17d8e9a588355b6666341ff70a24189f9b6d042ff44699f18e7794f61ae590";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31323335363538383839"_hex;
                sig_r = "b981f4cfbc9f8f7123c5a81098b1a2b2b5ebf4cb3ec332a78217d049669f5153802647e3b888199405e84c571c149e5c88eb20e855d2d4511a737baf968d498a60";
                sig_s = "01c75e5da7adc47363e0c10d0097679ac8135624844a54bf838348da350688d775a171c4dfd760c13dd606fc98fc71c9721ae2ba76658f9dae84ee32512d474d4a91";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343239323535343034"_hex;
                sig_r = "015ba3c5c8a7d86775f6445bfd6ac06e4c40323862a8754b1ba092bf3cec10d247b6a2edc599d914bd2a5aa00ab5a1020d4897c068e569dc9f412dcce1a758cab208";
                sig_s = "baba7f93ce5cfba1a28e5e05509d95371cf1466e34e8b8c6befa4bce7e59e6a2253b63c0a7b472a61bd376fdb09700ed0f7348e2187c8fe4ca87644fecc6e3dde4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3531383033303235343636"_hex;
                sig_r = "4ad0d674b3a91adc8324994b3bcf1071a9b39ff1f493f272518623cd09025be1dc0d6c987412e37942c0ad2d0012c51b8dec7b7001681723b8a92daf919f3afb2a";
                sig_s = "01039fe951958b044b84db980853068f645ee68834fdd1ca904b5181bea15e57c18a6859d56a4d12d89a441b47a839b680a0e4a089fbacd1ce6d7d0b3ca7edfd0510";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34343736333938323030"_hex;
                sig_r = "01115c5bd71bd8a15cdae52b23da52080175279e49193c62980e2d2559847a173fc382e50fc63e1fd80a8fc9272319be5f97a2f8567bebb65ae5f5fdbc539071a653";
                sig_s = "57ba29f8107a3e6f737e983abbdeae230341b06d6d865d1c0603c23f319e3f1c6b02b59ca1e263fb3158da29e762846a02cda628e53d41258fae403683863b0684";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39303630303335323132"_hex;
                sig_r = "01dd8801b1ed5f0960ecc399bc9e30d0fd83033d7128ffa3826675625dbaf327e294eaeb7089b5e8a8c307e637c79f749d93f9d8f834d4913e31f27d625711283f5d";
                sig_s = "011e6377d6b68e848ff2a71552d8347859468566cb4896cf79ee5bcf91f75e93637dee313b47e4f9e7c94f8869a81238441b5739f031c9c4d4de5c79340717e369b1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373536303533303938"_hex;
                sig_r = "0197edd550c58d5b3331febe15b9ec78f4f4d2ccf9cba462f341f0f8e73e8372aa6a3d8d2db17f2ff33115754160277701298db543575560d8b11de14836ab043f6a";
                sig_s = "7a5e1749aa35b07ab0ce97d9098f3c89b1a69919f8ac7513991169c07ece47b7e383cda503a5b004f1c6ca85b0a2c134d52c964988cd6b19821faefa35f1fcc3bf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34393830383630303338"_hex;
                sig_r = "01ada24626706c0dd8962db4d745494068506d39a4ae6413e980f02d3c0aa1d66dc8345a767afa1b9cbc0bc6d9f6efa215d4a22f7b1b8094bf835262828a39c226d2";
                sig_s = "01bcb2cc554765df59067a24081f6a2982c37b89025b80f20255421b5bd68b0e1da5b60446640a58e270f7349a9a48681d490307cedf659dcb09cb8962830187fde0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33363231383735333335"_hex;
                sig_r = "a5b4ffa61d97713f9512813ffb68901d216eb649167780ef6fc7b0dab626b8a6beda7b0af3ace07c4281ebc6dc9db4e14a1ce2ef0616d599f8a3e226ba81b7adee";
                sig_s = "b2d7ceb21ce8c72b4a4951104c93df65ea8fe5176f8b3e6dc6063be1fc005f59098b0fbc790e34398b2a5289a5c5e1487d8434e8af0ac9be5477d7f571f5b0afc6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363433333334373231"_hex;
                sig_r = "0107d319831da7f253b044e229a58ef5eb2d7029382bea1a4db8095673e072466e4d69693123ffc06bac6f626612cfe760e53dffce3f643fff7cd85eb3aa2d6d1705";
                sig_s = "012b0acdc6b84489e6832ffb25d3c980b40922959e83e81b7f3998015a6884a7d26fe211108ab050affdfc689f4e82bf98ae777d242030619fbbc38344336ceff3a4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34343534393432373832"_hex;
                sig_r = "d296056a992da1d912dfaf564e49a4ff33946adee320926f606730dd4255dfa941c1bc38059099320525a87e283859d0ba99472a8f59dc4f3d8d4307e567c3e914";
                sig_s = "cf38b5c76aa99b8818f7728be518b5159ba1b8e1037b359fbfd33b2a2da3fc86e4b9600427f1a622bcd8ef9dc3fc916aaa8d81b288ae42496e0155d52347d8ad7a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3230313834343032"_hex;
                sig_r = "ce546b84fd4ed2ca5cc412da1b22ab12a9a6f0cd26119e9400a71437a2551d948627f253e8d805a43c1b53f4e49d4ac88767aa20cae16e4824233ff8f8dfbfb5a7";
                sig_s = "015fc68020d9c71f960d6253eff0a188b4f01cc075883e8a529839b77ac89a6698140537278b0373292c300ebd48a276d5d40a7ec572a397e856bad0b8b6bc3fc4b8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3538313332313733"_hex;
                sig_r = "79c8514c8cdbd8ad3af8d89b46694745282b8d7b26ea4deddd778ea9ce8079e0cbbe2ce6891a138f023053cad1f2d59a8fe5dc0111c0a5091b239d00f02bb97fd6";
                sig_s = "df02700edca68bb6917ec75b0ec106ff89a4c0c74989b058e147cd23aef9e541b951cf4fccf70c110458e7c1c04adb7f082d3170698fc1962668ff6e277f3f3636";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31313833383631383131"_hex;
                sig_r = "019e552fc9bdc4dd34f3a8c902f84668be067137fb013a4911a4ee72dde4291850fa3d82cd841e3cabddcf9a114fcf3eac5b3dbce74a1a23474b360fd0f65e7c28ff";
                sig_s = "f8fb2289cc3b66129ab6cec2decf9431ee781b920e2c3c58897ea1797827b1dc4e0141bdb223ebd5dba00bf603aaf6fb5b7ea8cb36798e97c4bf748cde9ec709c0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393232363032393036"_hex;
                sig_r = "011e97a758b809597aaba432324a361d823c6e0769903db9029c996104ecbc56dc5944d604dcb9f99c24edfa042a49ce8f5cfb163ed177c574a6ca289880174fa9b6";
                sig_s = "013ea7dbb8040c05f761e00abaefd2ea10ae0e998653f77779418c41b3bf58d6d3326d963e14797c002a2651c44c8e578aba9b220af427a033a3b47281653fa953f4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393735313433323037"_hex;
                sig_r = "0167be329c69775e5b9953eb6b1fcfb5c7fe266718692e2319c81bdc03699d49771d4407023496070dfc19d9b766972429be1421b701b2579a773e0fbfaca5958865";
                sig_s = "0122b728309996f36b2300d97ee1214bfaeeebd954e25aca3aca2b985faae6a79f0b5ded50866468160954663c9a7afb4a8a8c327458491554d511b81b8c9e113d32";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333135313136333833"_hex;
                sig_r = "01ba351c69ead837ffb48d958d5f44c4c054f67cf79a4dd55de33fcf81c61b4aebf2f9a0aa3ef3c51b5db42b25ea221372cbd2a95638274fa377de06cdafd7ba86c1";
                sig_s = "013ba85a1343e41677f97b2020233ca419660163188345cd8baffbb39629868237b7c7cb297d4ca6150fe652139af34dd733ca20276d26895af1f1476de2e504c691";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333236333136383132"_hex;
                sig_r = "d444150b1bdb12f9b40a9b4b7368d3f083bba98dd5d580e4df8767159b144f1e3b0825e80b8c2bcac4cd35b8692c31dc001f1bd63c763e4791d95d8bb641003b5d";
                sig_s = "fc06f26a7357b675b39c566a9cb30a99053721fbbd48bcbcebd463e857327b8132842bf55a22b76d4848afc2535d473c8993e49aa2bfdac2344554c4eb0df0c9ec";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34303239363837313336"_hex;
                sig_r = "e06e110f7db2367e9927568838ebc5982e90d5aa09c442e2c1073027fe6237230625bbca2495a765fac5b35ed0f1da59b70ab9af366697618c112ec38cd8546130";
                sig_s = "b1afea64f3612903bc3dcdcba4a2137745b168e8db230fb4a5027c99daca6dfb8b6e40104f82bfad536a5f85c9b43f6b9fc8f4dd7f1119a5eb7b2834bb24cfd80b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36333230383831313931"_hex;
                sig_r = "77bed86ba5729d867876dd8f2de6e6c9bee584505b5d471ccd0a9a54658a7dbd88e6afa938da50cf7e7afac1e06758eb0f999efa46d439bea76dabe0b08fd04a5b";
                sig_s = "d67c25f1ece420b60eb9a60fd9590f84d87af37db4a39a20a6dcc96aabc92aa8197d836e2ccd20e2739674f5f792258593c6009fb02d3e5e348ba27300b5d372b5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35323235333930373830"_hex;
                sig_r = "01a7796c913ae8f43ba70a5a405d3ed87aae144b62ad261f7074a228b440b07375ce41d5a746cd296e1232f185c3be9dc8f275cc3867eae1e80008a880e5581b8b3b";
                sig_s = "4c6d7bb94edff76cfa8a11599a86783ab63304151ffe49985b1c3c39b36d03451da0726ff28be2567ed4cbdcab9b5697d4e6851a624790b3ac6410b0f895339c8a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333439333933363934"_hex;
                sig_r = "adbb3974f657ca2e8e099d898817c62959733b8808b7125f872dc1942bf63e50cffed2d598d70a9b59131da79c55b073d49786724701e6810dc540e2f6760610c0";
                sig_s = "4ed5139909989c18608a2dc05a984b328ae8f92d0baef270ae15b7f97e9e2df780584d08ca285df39352b9631cf8e1866c42f1b4c4c0a67cf4ce7d101a423a21ce";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130333937393630373631"_hex;
                sig_r = "2e537b14ae1f1dbeecb0cae036b2cfd921d78174a020be40d07f29478194f832b8af3915a5be2e67fe54404066bc434e0b4636be86ced86db2315f2ea5f64f15b5";
                sig_s = "42bde34b1f608f3fcd9da30481f8edc863fde24fa1f679833e9fd35281cf78ac42c7f13339a9b798ece954a349b84206fdf811098290dee904c1bd704215c0b1b4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01c22f5cf1065e9501aa40c802a58b944e8747d0dc332cd040fc27f1ef18a1af20caef9d53d6771ac8ab9b9d46799471feec8d651f1bcd120740e7a6218ba2634a72", "018281452c5b0f2aec6eb143891ef7775748c889c03e7712ab2d2c5c614234122ecdf2ed25526e5189fd3a90ebd17825b9ea5edfd7214358e6cd99814a40504e4472" );
            {
                // k*G has a large x-coordinate
                auto m = "313233343030"_hex;
                bn_t sig_r = "05ae79787c40d069948033feb708f65a2fc44a36477663b851449048e16ec79bf5";
                bn_t sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386406";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r too large
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386406";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01f974fbc98b55c4d39797fe6ff8891eab2aa541e8767a1b9e9eaef1f94895cdf6373c90ccb3643d1b2ef3154b126de937e4343f2409b191c262e3ac1e2577606e58", "6ed880d925e876beba3102432752ce237b8682c65ceb59902fd6dc7b6f8c728e5078e8676912ae822fda39cb62023fa4fd85bab6d32f3857914aae2d0b7e04e958" );
            {
                // r,s are large
                auto m = "313233343030"_hex;
                bn_t sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386407";
                bn_t sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386406";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "29de1ba495032fe2f4b03173aa8edede277d064324ff416bd652a123ac40a6ab91e189fb42c5c67ddeba359873ed559652ba2b8378508c69b3eb13d395f11add84", "2ab8b1c49bc1c079d19fab2dcf30f77e1d8e7ed786669149b254d7feb89fad748ce8c9937992fa64ee025f7aeb6aae8c86ca9221a5531c232a70e6bd0c11644e6a" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe";
                bn_t sig_s = "95e19fd2b755d603bf994562d9a11f63cf4eadecbdc0ecb5a394e54529e8da58a527bc6d85725043786362ab4de6cbc7d80e625ae0a98861aea1c7bf7109c91f66";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "016f831fbe722a5b11ea60d4b63c1bb88616bbb2249f3cffaccaf849791e470447a582090e7add34b5031a7d9aaaf64b96e1da83aec7980b2acbbadaf9a145a8f4d1", "010126cce70be1a8204e418788993cfd9da4bd26a799d42184386cdb0bfecccbdbd30f93a1e2ac19c95bbd34347e0d2e2b95c30f31ad5958a3926485f61d6bff2903" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe";
                bn_t sig_s = "15837645583a37a7a665f983c5e347f65dca47647aa80fd2498a791d44d9b2850a151a6e86fce7d7bb814e724ff11b9ef726bf36c6e7548c37f82a24902876ee19";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01d8c20c1248ac77878a328190f9524a770f0c99f0d689adac92da66e097fce8f55d2311c9eca17a01a1140ac4237caa7e99c4ef12b16ed3945d40479a2d74afc5d8", "15d0590ac9c19d4a1ebd458990ce7601b6fed26cc031ea5b39f770a7111044db2ebc3d6fa90aa171155ce9376e215a932be0897e09876af544467de7d5f03124c6" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "01";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "011f1481b54fd859c3d4ba500d2d5d222301c4907479d12bcdf1363007c5632ec51fdd6569ad174f4f9648555e24cc2a47c0753214ffe41fddf874a9a2141c4134b3", "012d283c35b7127fd1d5c5d0a73127f2c1ab9056205cca574ba075189a2da2eb4750f19a97b96f87a58aef96c38f8dd54104a33988b5b988747112596279fc7a612c" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "01";
                bn_t sig_s = "02";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7130346b01cc8256b06c469e974c5d1a73218c7fc76abc73fe49f3c7141d9b3528c856975468cb43ee45461a2ace7ffeec29624d1580be7e75a10dc8fbbded6e98", "01619ff433bcc4c6379306591c3f8fede365e7ad9d4c0cb566aacdf82c92a504f7fbf77a54ce4e7ba6803b9d421230d4f3ae4f2508508e86b182a009cd4d4b861339" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "01";
                bn_t sig_s = "03";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01f4d8885bf9f4ecffb1ff62cb6ca036800136b2aa02325e46786b6a5f4c4ebfbb1307af34bff1ba2332cad41a417cddc0a5ce3149a988c70aec8ed168b9749bb043", "00d7d06746ef7378545cbc6623073bd56b3a1563d853add995c196cbfe7995bb6082f9bac0bfae347b8bf15eed00a64f3ab02eb70174b9e0122179b855523e725f1e" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4155a72953689b0ed5774a6002d6a01b92c56317b69d73d795a5b5c53ea63f10fc047ace93fc4be8502438427afb60518ed8a21ebc4227e37ab8cff0e08d5c759f", "0165850bbe0f9ecfb1ced3db1151efc1cba15c5e41c28ee5b2f1f625cc090448b857479ccf4acd8931a279a2c8a7c49037a17861e0155c579684e65396f49dad8c3f" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "02";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "015df085716909d94739a3e83563b62f4c4048f513ecb1881db106eb1fc22cbc9132f63c8d785687f82fc4d225bcc5d8a7860023166cb6aad4f6b42ab1f5593febe2", "0107dc4b11405bc81e808ce8679c5ae76c9cc0e490c0fbd36bfd4639cfc2915ee2647a13e89de894d01f0c6f4a31ba4675a9d6441d75c5d755dae210717e372fdf96" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "03";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r is larger than n
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640b";
                sig_s = "03";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5da0bf24edc565f86820e7b599997b9bffc4cb570e2ea2c759050bb9eda4aa5f0703732e623881e3edd731948270fbf0c6b8b8173c0160588a09a2958b1fded11a", "01a99959c1072e4928eb4b4420c55a596bf46ebe0e2f7ffe71149031aa4f8e5e2d4463eb19c117500b733bf73f1684c8ae1999771494f2149912e6cf922fc455b17e" );
            {
                // s is larger than n
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e914b3a90";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a72460b47647cf18215020a05ddd57b6b7a1fdb59589ba54572596abafd9413a3645622b78de90f02ed27e6eaa66b88e22d1edf86dffc00945c453bf55d9561be8", "5655d43e58d4dddb71176716492177bb31c673e9ad1d6a68c00f7d7267002d00e3f203cd4e5d882fb4f6a4da4cf1653934940d8adb162fdc6d3863cfbd7da1bea1" );
            {
                // small r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0100";
                bn_t sig_s = "01efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7ef87b4de1fc92dd757639408a50bee10764e326fdd2fa308dfde3e5243fdf4ac5ac";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "015894e001912487ce160912d6e8ac66a8a7449fe56d06c02e1e52a04029e74cecf0655d7257cc73f68f5929ef5a6cb3b0e689cbb12df439d0932dc990696957a0cd", "7f2be8ac8168dd28c429e45f4f3127f17e1b1f081be900e1ca8c72e354d7e11198cc73d6d6f9542170441be58e4eb0ff34356896d8dedda4bd7596b6b2af2040a3" );
            {
                // smallish r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2d9b4d347952cd";
                bn_t sig_s = "0100508d073413de829275e76509fd81cff49adf4c80ed2ddd4a7937d1d918796878fec24cc46570982c3fb8f5e92ccdcb3e677f07e9bd0db0b84814be1c7949b0de";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01a6518eb0c8bc48d8c6dd8deafca4164a6c45cff282fb321365e3082eb49275447f0efde82cd05125524f31a3a3e0b844a489365f33c46b3f86833f4e61ae15fb6c", "2486c01f530c53fba83b76f0d74c6afe83acfd567b17fb13e13d205b28f2a562300e03cc170525eb05b3d9d02f0f69eb9b8551096b67bc2b0a202ef1366d31bb28" );
            {
                // 100-bit r and small s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "1033e67e37b32b445580bf4eff";
                bn_t sig_s = "013cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc3393f632affd3eaa3c8fb64507bd5996497bd588fb9e3947c097ced7546b57c8998";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e75c5dc6fb8f88c1090a0c626ad8cd3800ebbf84a3a7a9ca11f3329bb4ba341890310f2c05c25a604a956abb325aa5053eb3af7886e83c6836e96a02660810b6a4", "50c49bb8c84b748f6aa80d7f69c12315bd77ac4b2b998a5d63af5ac1b1a6b62400017ce6c02cb8e66704d86739bec5c64bbb5e5df782df6ca1ed3c53f13c5b7096" );
            {
                // small r and 100 bit s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0100";
                bn_t sig_s = "86ecbf54ab59a4e195f0be1402edd8657bb94618fab50f2fe20fe5ebbc9ff0e491397ed313cc918d438eedb9b5ecb4d9dfa305303505baf25400ed8c20fc3fc47b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00fe436033507264c0f6a8e0bd76035c56dfcbea4660aeb8865e0845a4e9895e8394b3fff53428bb6e047ad4d53edd47fb10a0d5ffa10a09b31ee45f2e5f370b0da9", "72fdb3001eccec7ed1d32b560f53f00dc7d1d06111e79f98793872e7b15e5ed8ba9e3cf35e9a5521b893485f6b508d6b3524b9f11516240bd2d23efd37de28d720" );
            {
                // 100-bit r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "062522bbd3ecbe7c39e93e7c24";
                bn_t sig_s = "86ecbf54ab59a4e195f0be1402edd8657bb94618fab50f2fe20fe5ebbc9ff0e491397ed313cc918d438eedb9b5ecb4d9dfa305303505baf25400ed8c20fc3fc47b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0e117d46e922faec0482c89f289c8fca8445e77f456261704c567aa012d655301e4ad9975dea5549cfccc69dbf162a56bad4519cd2c32c169aa41b8df366f3fae8", "00e2d8a21fbb54f84fd5395b648996306c8ba7c2d434179ac999f1d46098867975ca2ed83026b96a7a56caaa0dae8e81901eb0db352abc4a34c4ee6a41b26f33fe3f" );
            {
                // r and s^-1 are close to n
                auto m = "313233343030"_hex;
                bn_t sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138638a";
                bn_t sig_s = "015555555555555555555555555555555555555555555555555555555555555555518baf05027f750ef25532ab85fa066e8ad2793125b112da747cf524bf0b7aed5b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "013480c06fdadf5f1479ad7037b6157837f3cf99e537106bb7357889c01d66468f4944256543ade8d8749f33c5a9fddeda53f0f6c3b90716e59027d6cbcee535806d", "2739b1799c3b15c02d2590ebc021ffb7a254faa59f6003c8d3d2589b78f38f1d7ddfb1369527e3335b6047f20185296fda1c1d6d36420613df0f569b68210e9225" );
            {
                // r and s are 64-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "9c44febf31c3594d";
                bn_t sig_s = "839ed28247c2b06b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "016874eadefdc972faf9b4484f1c1e2753f1230c5274f32addbeced69f7249f895e0e5c18ff52f416c5e235a703b8e8e4efeb7d8b3d5732c9800c8a46c18ce1b9165", "01ffd7c9d50a1070ee6d42959ee52a667bf4b611d12d1f2f9f24956741f06a7c40b576f99fb9561502fc712e1cc7c461c698ed3784257c750a2a9f0a77afe291353e" );
            {
                // r and s are 100-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "09df8b682430beef6f5fd7c7cf";
                bn_t sig_s = "0fd0a62e13778f4222a0d61c8a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "015e73535bb1b6d8d9f3b2b18c9c67837775f5cc2b36f9363443f987ce15bd50a77c63e46fd87a6a2662643e312197b72a07d9ff89466d1606e2f40baaa4a6a5ae53", "3a6c94384f0b1ad7f48419f10b82b0585c230b70bb2739a41fa4a1da28c68f2b80ea0c90e332dee8284589c619c88c96c8d668f384da1bec04caed7d54809fd6d2" );
            {
                // r and s are 128-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "8a598e563a89f526c32ebec8de26367a";
                bn_t sig_s = "84f633e2042630e99dd0f1e16f7a04bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00bf68baf7347cbb658b39763fd71db89575cb9907450c65e46bb280f82579e26138b10440cae13fe8fb4e74568484a68ac5e9e648078eea8529e69d94e787437889", "2c887816f2e39acb9c5fa5e1d546319cf54c7b5e0bd18e840ca1ae8eabe776de62ee22bd9b5e1f2bad90b31cdd46a284b2339460fc2743bab35fbaa4f26d5f786c" );
            {
                // r and s are 160-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa6eeb5823f7fa31b466bb473797f0d0314c0bdf";
                bn_t sig_s = "e2977c479e6d25703cebbc6bd561938cc9d1bfb9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0128bdac640b4f6fee289691b4947a598690bb9e6ccf3bfd0782f61def532e290a45d7202bd8424119b5774c4ebceb7a746f884a88f096bb322743e94b28e8aa5b10", "018716996903048af17d152bcdb9a1ff67aa8b148e025b5d4edbd75faf9595712fdcc7cfa483e01f3a6576727bcb35649d482e18b7e4c4b4e41dff4be3de92488f94" );
            {
                // s == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // s == 0
                m = "313233343030"_hex;
                sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                sig_s = "00";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2ef59eb8b0174fdc6188f1a5258a617a2acc937af7323d0ba83f266e0553e51f471da8aa3f45f445e1f6f29eb735b37e2be3c0fc75408cc4bbf61ce8ca83d122a2", "0101cfa1496a3e76016eaf3ac7494cfe91e491d47ec4b38062d417ad4d3c9f2ba83d63b2508f7ac397826a763eb476ae4dc98b71b6a1a5a540707fe65492c82c6c5e" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "3766c66283b12cbccb593f39d32c356cb4ab940931bedf5d8053458cd26d03b1e9ba364d2056a8c3c7fd8b8f47ab8277adee9bc701ffe1fabde72a01dc098f76db";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01874de89fdfc5be598ef232969e133f2394a48c02af2468871d4382f006277c6895f22619f90834a3260f60ecbf00bbceb9b247580a8f7c2670368b7a354df50e2e", "3e3056d6a8c00ae890b92c6ad1d129faafca8eee169d90f489e54ee3b868f27a666b54553928f5e16d300527ec842fb9cc189fe53e6475909bf4214a6922d88383" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "1acee0a06a4b00e9da99cc1d47fcb1158787578728dc13cc74a95e51fe1ac074f88613bcd4d717c3206c2a73c76172416a94110b9141ad243ba87b51a042d45ee8";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00f1569c62e9e0985fb4915f81ddf8ec08385a2664bda729d515170319a99c15a35cc9737142478c63fd89cefcbefac1346a7ffc1cc6ec7ff541e5ba98285ce91f0a", "00eccec98c5aa3295ae18427c09001e0ec370bc8b01e499d6530421fe446ed506736075c520abb739cdc2c7c2f244853f0feb468b86693e8c79f4cf89c53358016ea" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "0ce1ddfffbb3185109966b647419ce8b553a6d70d6c73013af778f7b211aadeac70511ae766f0b74961a1019ffa18b3d42056fd9ed4d5fd982be75291f2532bb02";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "017c7e5f364d8461d93749abc757f6a4094672c7beece89a082b028fe2611765104f014362ecd1ef83b6bf338295e2380edd58c45700e480474e5a425fc1ab7dc092", "7deceb1204031af3e624d764bbb3c276ba7641fe4dee3a02db0f060f703eebc36ac1f7ef38dd20f9c6b55084dd6739f0ee63f55a6921927ebb1136749ea22a5790" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "ded82c833933ca141a3eb8fd1889f2fca4679437d28e9f867afeb37ecaccbb555dbc61ef83b3f7d57c6b4ac8ea27971716e6a1a0534d7f7ea1fb7197d1c4a0d5cb";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0fc19339dfeef2923aae541664d44b672bac1c5b66691ccd1db942417a4f256667de89b3b9465a28ee0d3b0545abbead2e5d3c73576b51dbe21f9fd341b4cfc6c2", "0154c51f5d096e390e1b96052fdfffd964b80b82807e0fed55464ed8760bc512d620292168ed4a26816be3639a29eb0b01d851990a4d6dfed82e3fb7ee07627ca8c0" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "72ceb39ea97d82d3aebd01ee53d32fc02bca5887fc0a5fe373b7a0d3085249684731fd8157b3743d40caa8a7908699bc223d0df57ca11f6225f732119431b86b9a";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "019272b5e17d6fb21d7acc687c43e708f2ff1e2ee86ebac08bc18361efac7e0e16c28b0986685a91268906adb84026168fa7c082356cfcc8bd9ddda9f5b1cc45019d", "010bc845371a869df8825cb38e3379d4cd101e56ec10b0a64ef60154d789b4e1060a647df2d40b9cffc6d77359416b070e2ac7ae07b43bceea38310f286bf766a24c" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "1834d4897e360d3622607611d64c4338039f8f7db00891bf5930711b2cf7d47be557b283d20aa85d9c5d2e472fdc59a35ff4ac0985bb06fa284838026cf0ba8571";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d8d8afe178015ae9cdc7e1f4e44d750110b75db89387fe07c9251c04efa723eac722bbf47727d2cc18ac35d8a67c773cfed33555ab1c4873761edd694f84c788c1", "2670616086a98b3a593c3d9e71de5d783768bd64359b6637f1a1edab2cb687795821f205b45bf7d909be64f8ac5985033f8ddb56e2d340af7d51cd8ff5ca23d545" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "a9c260ead3d423c0e8bd225f41ffaea6ace17b1e157b98ccf912c90865a4bb74169ff49b4b0d62e0772905ca62b0bdbda232955a3952cf3b83f50bc5f6ae33ee4f";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4985a546019b7bc7762d84505ecb7933ae7285b43e667c7f3fe6c60b3c283ab0a74e6ef76459069dbba574e2f7044a5ad35382ed96c6d657f3f98a41a686567cdd", "17aa5585f9959b11ce65b3dd8c5e44ce8984c87efb0d31aacb9f666967502080c3c9ceea205a13559ee10f38f5b860c099987b20feb275791b8f33ddff321a6de5" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "2e67568c48766d91884b0ecdebb8d9a39a359d77bc97063c625d6d3f1dcaae81cdfb198f4655d9853273bcfb60477cd0a1e435fc8bb93f8d05a20fb977e50cc434";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d1831a366bebf000616692e8c3b7ff21a2f7407ef7b1d9c5eda3618e8c4abe8ef634827ef2e8b2819407d4ad95ebb6c3c7806b27913a485151e9cda3e82643526b", "6b520da556ab0230ca5f3c01502f1d5c5f9640f038b7a01bcb917d9ac6548bc9b33e8e7481fd177ee096e0fa2ea1d719ea4bfb77e9aaf3cf26aa1ffacc887aaacd" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "39e6ac133eb88e5b5748ef6806e750175b100ac40e3efaa891ef7ef078c9d3f2cbfe6398dc776f72cd2f904f2067c63df677f3d8162cce1de557a5aa4db6561abe";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "74607f955058ed6319777f331b0b6a3fc2ac2032ae581ad4ad79bc660cf3e3f66a59bd8a1e33a3599ad666a6da6c3211aedfe9b727817864b873b371bed646c896", "01ac3745b4913e52a846c90f3fe20004f98e74ec250facce9ccb986833e85c4ed9c69d0ecb7b696c8649872f2a41114dfca7c72d642f9f75a895d0ebab7c31a3ef7f" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "6531ae6458fa556c74ce671a556e703038afd8f769c398d080be8fe434accae8dd35e8a28545297310992dfc74efdbcfc3335e0b9f9bbf970cf4361213eade27ed";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b1c259c44fb789216d00f11ae050cf9bbeb3fe61ff1999c0cc90f89925fa6c9b53422ed04b26052728001c1ebd9a8a711932dabdd52d708e2726ee050f12c6b898", "010cf9956328a2e2a769745222f794daa253d52438157b26bc06e8eecb3d0fdedb6e2894b65e489ee376b95098bfd4f23f7eccb6072264d880a272f6c5c469cc02da" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "7321260c7e56e586f4a7b9b47a18613f833097c0cdebc6fe488ae05d1c1f37a3a98f2e1af140e7fb1d2318c50b3b984bc4066bfa55fd98db18ac649ee7e47cdec6";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1e582ef2de6a6eadc18a59b269f1c1359f57a64106774fd6e8c3ea9035c89c73d8c03330ff60dfeaa44dfa381d8b39b96f830ee7ead41021f4c188fd31e7c821ee", "01393512582b57f23da9bc8b64420f434aba31668a9dfa7fcff9c7c2e61b710ccbaf72371dabc85cfe297ae18f265797d9f309bfb9ec01b115c9ade396dee39b1b14" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "4f27499640288c52f93a87795bd7a0b83c95dbf69a5a3b6ef62f1308f2b9a817536173b45e687646255958f0cd08e0c469e66495d4e040217af2fbbd1311d21711";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ddac43dc59c4d2df16d5fb1d3776089cea56af522589e63c197688fd7bb30083a773491d8ae2e57455c81bc6d3dfce0c29d0bcecec87401fe4afa60306540ef216", "00cfb6872bab68b90eb73d705696cf8515be016c18719e5fa6f69185d0bf90a2266519e9908c8399e2570f71ce362bd8c548042e590dddcd86c71690700dae40cbb6" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "40484262d596a23936806ef21ba6192c72023a535089ee524e2a32f61c7497e58b4dec0ae58178f7b6dd3587fa3124a4ccccb49de353541f610f7d3c97b63db11a";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d03348d958f78b30cb3bdf20503aaff4aceb5746390484b74b2d3c0c043a0ccd837a93fc1c41955555511e3252d54dd090d74a6928a358397ab5c36e117aef5eee", "09fa5e3a14a7614905177e948cbe8e0c3cd9e36cc62f5abc2e761697c838cd8b00ba7bdfefaf9b768c47ad5b5e4b20f15bbe72b9fd3707b25cab0027f8c3b71a88" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "7fa623ad71573766571b8fd4ae0a5ce82b3805ae151a18515ef607f2228a95bafdbd24acde135cae5f3f899caf0c5efd1a4de2c53878dccc09f2b7a263c2844e3d";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009e84afd4b44689a9830d81d5d65ff7adbcb422e2b51b41c6d75b70f5db9fe596d49aee84b467275c3578db23884fc809f4e9ae57b165bd6dd1069cbf7044937566", "01e38249e834d3a58bed41bf100a0d9a964cdac10f19a9c3d0e43175deeab9595cfe343e008ff0be63d78b3fd1166ad4c4ec66a55638cdd779a7c50571653d618f12" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "54e096bc1b2ee6f5fa7d65ce54077cd07a379a7d1bcbf85651852fcc62037ac50c6e64b8c6c2cf8814653af7b87d2752e6f3af0a3ef75ec7415a58cdf2990ce4c0";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "438f4f62297e21524d237da20c89842c608e319f1ec5260a79f5ced18519bbfac425a4e72fc19fcdb8225ac86f81e29f30d6f5f3ff32afbf0d44191731179095ed", "01e9581d305a505fe6b6142b386aa8fa0eb13f87eded898a173f1a09337487f843e7daa7dc24132ee35942645284239bdfc7feca911e76d10ebc50fc71f4c5cc23e6" );
            {
                // point at infinity during verify
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd28c343c1df97cb35bfe600a47b84d2e81ddae4dc44ce23d75db7db8f489c3204";
                bn_t sig_s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                auto r = false; // result = invalid - flags: ['PointDuplication', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00eef2fd1df18de7e98b0c5b8ad244704c1cc4ab7cb8fa91617dc564e96fffdd91ac15cf0d3b1ee3aa97ef4e1b34f9e33d12ebd96a3b98825244494d5b2d5aaab241", "01e064096439d4e090db8a9facf5c17eb2ec888a8ddc89b72eb16f059c6e2fb05c1d3cdba1bc0dd06ad322c2597fdcd696acd7f09417d76088d82a439babffb9c7d2" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd28c343c1df97cb35bfe600a47b84d2e81ddae4dc44ce23d75db7db8f489c3206";
                bn_t sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd28c343c1df97cb35bfe600a47b84d2e81ddae4dc44ce23d75db7db8f489c3204";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "72aa33a0c180e18b1b0f86579b0109d629a865ff67c68e37c81bcfe3d14401c58b995a90adec3133de53eca49ffca323f1e067546c27b9d7e559fa4c605f20b2b9", "01c2a21f93a82d61c279a0f27875b735a7b702150478c044d4b4c1f6121a4c0b37dd9c75031080798653c1dfc9a66aaeb94b4fcab22113222050a6fe6121bfdf1420" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd28c343c1df97cb35bfe600a47b84d2e81ddae4dc44ce23d75db7db8f489c3206";
                bn_t sig_s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd28c343c1df97cb35bfe600a47b84d2e81ddae4dc44ce23d75db7db8f489c3205";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00cf1dff74307192b773d12b275076ef04b1807e3b774bf2e28dffc1aa5eca395ca525a9dc6cd2d4ae7e93cbf981e074040ffd2d86fc6b82038b850537143847e4ce", "015a9af9c2f60552ad141acc2ea27ab73a1772078616c3017a441f16e417d93d88030d5351fbf1e6ae9b0c243636d3fb74de920b292ec550f232eb90cdbcca174d20" );
            {
                // u1 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "342dae751a63a3ca8189cf342b3b34eaaa2565e2c7e26121c1bfd5435447f1c3a56f87db98089d208c89e902bb50ed289995ee7ccf6d6e6b1cec4aaf832d3734";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01d0435963afc96eac099639a3e23383462e505c83955f29743ed244e6b76bb6fb080118558e63a6c632d3be9ba173dfe46fa7d9c761ce619055ad1c4321e142e8a6", "018065482a1e845183854103d7c97a37f31aa73703aa1eafc5a774d52962041c35b25ef4e98a9c5b48bf0c91bf16df0c2f2d1685aa4b414383e0654a9e43c0c60458" );
            {
                // u1 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "01ffcbd2518ae59c5c357e7630cbd4c4cb1555da9a1d381d9ede3e402abcabb80e36ac16ffa82726f94af34218463bb8b8a7a21fdb3bba2ed9439e836c6f0e0b2cd5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1af6a36318d047a1ed36849109c3a3661235e693dc0a3bbd76ddfeb7cdb13e79e7f36eaf6e412bdd44c4d0f9914b4696137212127913b9c0b3556f808f54710813", "30246a78fc9d73335ce9befc2be236c32e947efde654481bcb7763656bd9c250c2e1f73511811efdf2c01332cffe2498b8b71cf50126fa0f8b34c8ed2d9631894e" );
            {
                // u2 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01cfb15a18fa029408a4dc7e1894df30e263fc428a872d8b1cdc222c4bbb31ebfe7a24897e514c1c51ef4d7a339f7638c2859a00d7d0390ca002a6ed0ba7424fb6bb", "01ed010d62df4069c1020e0be488768879f1e6c67a0136889080c190d0d6930f2c4097d75f89dea3659785c374a91588dd6cfa2f9e296e7084ad60c0b4041a5476b4" );
            {
                // u2 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "015555555555555555555555555555555555555555555555555555555555555555518baf05027f750ef25532ab85fa066e8ad2793125b112da747cf524bf0b7aed5c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "496260a48fd656a3acbd4af6876d5864ea2c8b317f0448c5ae7c74160d64f303aba83cca1160860028c2bf1508b5af1109de5f740dd9e287af8b7b32ac1f2ea905", "00b08409969c1e066f880742b0606469dce29c07ab5c84bd480f57fa701d868fa399a49a4ba1fe4ecee198a648746273129ff7d02cff2abee672f1775d3ae0ec75ba" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "11648f7c5e213698d5d89a66b913bc4e38b721f642a0cb0b40954716716d50968c7a829e8802df0ad9834dab93c5a462dddca4d445247a23b44ec38fd66467bc";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d522117fe95568bf988ae0fbaf5be3d46ef750361f16189becc63283e6939b36869556c7ebd90272dc4f0bd054f8505c3d01dcdccc3f6538830d9c5fca9fc23b07", "01c7a8c0beba04b4d62b01095a220fbb6878c91cd2a56eb7bba569a5fc0b42964117ebd4faad3e52086d505aad8b9f0096e9d67f51d505aea87cf61ed33a5efab4ef" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "426fb6fd3c671a0f7c7d2c3cac25b966e6ac0ea9eab99d07706245e9992d1d12698fe266c59cebc214d545cf57aca1d3bb80cf3946602712411941191134201a9a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3293db60a2a4b219a531caaf860169f52d5ef06d2f3c185fa4d2f6e3e34bd67926948f8397d2b4a98c06ef904f184599dea82da1bb383b9536ba4717849696a3fc", "116bbc57ae85d57a0675eb7fae131afabbca5fd0abfc246bb0373d006c797ed4fcb27ead00574619c3c5622ce123d4cf670fbde3809b8fb20392a03a20c614894f" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "012f3be6555b95d6a3787dca53f1687f9f23cb121b235cf654c7e1631f52dce04eb8e134c875b7bcd817309bbb455457b9a8c96ac395f3828cce52a0d73baa292d7f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "140cf342e8957593fa7ecfd1cf9530574361364e2bd39df5fac1073e938fcd8b87535f42b230515189204f80fc2c16b40c9bbf252dcb8d77fafa81242e929015c3", "01cc5e15c329aedefbd8accb680d12d76ceb74fdaa70a61aeb79cd2211f2baaf85aef7f4099af081aca2a18b5126df36a02728a50d6bb6904ebd3a0591b56206ce9c" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "d0c7db4562c9a527ffcbd2518ae59c5c357e7630cbd4c4cb1555da9a1d381d9edbed2712adcc0e3bf3c0037a7bee1551669c288188cdf5f66be630de62069d0cd6";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00f332fb45734adce50c95527c0ad83fe0965addb1a188a4578737037982b435d175c9e520793e7e8d832b1a2eb3aea271111a4b2b87ce9d1d0cf0eeb7e45a51241b", "01aabda82f880782f9d76480834b12d60c8e5e1c90ef75242d815eac13425cf07ee77354ff707098bb7830444beff8edfb4812c2961279b412e5078ef147db4d490d" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "7db4562c9a527ffcbd2518ae59c5c357e7630cbd4c4cb1555da9a1d381d9ede3e29d92d74fb34ffabc8ad75ce5cc26bd5d0436a30dadeb208853218f027af0cd4a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01dfe31538bfdeb190ab46fc8836c0876897e956d40e6bc3b2c8afaf979f52b5c5d5bee0d2ef386ab0e59c8278b91be12ce437dd0a9dc1f9ac0807cae52fda502669", "016ad42dc451c2cad7d5b840d151de6cceb158f3755f76d496b959400f7b7b4779c167c4c7adf96cf53afc4dcc6f0e9f6012dc484c2014d1e82f09dc2be96ab1dac7" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "fb68ac5934a4fff97a4a315cb38b86afcec6197a989962aabb5343a703b3dbc7c53b25ae9f669ff57915aeb9cb984d7aba086d461b5bd64110a6431e04f5e19a94";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e0e7553de34d89d37da9ae8eea572beb2a20445bfee82d145fae50d5d6fabc37895c47ba09bfb4025ae961e58155ea868c343431fc939161a10192f910385082a5", "01c8c38c30dce71d50844617c42263df60e29694a702b315be202cf5282adf8170b8a94ea78aa9241db17efdb8a2539c2b71da884211b2b4e45b49ab9192a720c734" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "0162c9a527ffcbd2518ae59c5c357e7630cbd4c4cb1555da9a1d381d9ede3e402ab8bbd93e12de2778bb0e38806ea1c2db3bbee7c3b06e36dfb0c192cd9a8e395d4e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01968ec94f16ecd9d5da1eda6db099b3b79ea1e08d39e7748637cb13c96836f64e0f3227a2ec7563ef58b27bbf18807a6e39cbb8092244ff3f4a3ee9297935a2fa1c", "011640f819fe9f6911f0c8a54f972e9444f8df518fa778a0978bc6e64e1d43b24ebb03b4ece0099a125115ecff3279b2cdca15d6e4e7d00f5b1c9db626a0196634de" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "f208d5b19d30a200d6986c210681ef2bbcb3fb0166aa66ab55cd5dac9b50b037f9355386f8cb08743980f42165f567e5d41ad492b7d8c43a7b848fc0f0ed591530";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6c7518061f076c33c62f0a7494b619c08bcc2782cd99ef6ab6f04545fa17d8c545bac600c1f91830225ddad1a71cabbb8afeee7d80cf537f6e391049dd70c32643", "01f6bfbaa4244b80f062ab7a66a1b6a707de567cf119b46aa5364cbe396dd4b749daf156a84c02b2c25a204dd47d7cfbae5ba394a62a82f9390145b898cca14bc0e1" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "42c736a8baabf2b4176c7d010f8fc17ed981ddcbb2b8df40abc9b37b5d251fd3c8eb361449a0c33cb9d5f63851ce3cb76dc1aab684a94417a52883de9bff64fb27";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "013d7ae4676db161db18cf231eded0e3dbc1b23bfa353f1cd6ed8c472d1e6fca9c963d0fe95243ce65323a063386cb173a02c65acf07b3beaf349e89a612a07065c0", "012990485c9033cec789ec67989516b488e5246f27499a26c4f30489f4a287435ff55c638d1d2c7e28aeec1b08233d1a8cbfea9b6762efd34e0d387c512b12966e6d" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "016db3214ef7a2afbd7189087133217bc55cf3d8c1dd84021da2290495569e8d259289d8203c2245f281513eb96ac7a5aea41fadff0d2ee7cfe2df3eeb2dde5be815";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a0c75547630e9ed64cc1e59725a3072b231b28c586080966db67800636e4b4c217162c8d03a7ba0edf49669fdc682a355ef90947d7e394406296b354722636e005", "01df341f469c7e460e87aa96df2c90a7774e7532fae10410e932262937247a2ace6512e0f9a37f9547f4a8fe3247f093018d000003917c195c1d0ce5b36ab613b9f0" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01fff74db841d0ef64b39513b2cca37621d8e3a46f04deaf9a7a5fb55c74c74957af0b4946347b2e26e6130a5a732d26d39eccc7774e670a0a9ce1485556a606302b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01a714661c4d299f540f291a07f2deefe6145d9f7a9ed492f8539b9e0b29a0d24bdfb71a89f53c1620c8ada2e06fe98ccfe11b988077816f0a04cc338d52266632dc", "0193c3b9c6658381eb61e0221e002b15cc622984550cb0289fb99636d926ccba6d6424dc0d39579f39743c821284849527b524a8650a2914cfdf3b11deaee453c8a9" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01ffee9b7083a1dec9672a27659946ec43b1c748de09bd5f34f4bf6ab8e98e92af63c50c04e5372cb760a648b39d6344016d5dd924e44477cd8b0720f38ebad3fc4d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0128f58edf565a7a48e7e40a66dcd17476a609ea0a2768fd3fe64c8d1ae82d236f6704ebe5b64dd03e59d52c4a87aecd342019899e2f06f30b090c862b325273dd12", "00cc34bb7753bc1ed8445b9450262549bab049161d78129bb273ba528eee2c4050040be5d30ecdd65d5fc01866a512de1519a2f60d80ff522760a16bd3f67c03728c" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01ffe5e928c572ce2e1abf3b1865ea62658aaaed4d0e9c0ecf6f1f20155e55dc07187ecec395f32b47db39870cc799612f3beeead27a21e590792cf991c6cfa1c86f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00e0a499117991efa71c57c12cfb2cd253fc5a2f04c30fe247cf3496f41c546b5c36d962a186e4f01135756e4eb0d8021dd06e0e728498e773922900020e8ca191b6", "008ed0c9ef71c85b0d2a2b18d6517ba9fdd4ca5247dd2cdf033720b4c45b6512a3e83d1bb0ccd7167b405b48f548edd67ea1abdfab2969f758f3cdb3f174edcc4552" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01979df32aadcaeb51bc3ee529f8b43fcf91e5890d91ae7b2a63f0b18fa96e702759995da7fcbb7637415833de4725b0afbc829046a73e8f6a3e8708472d1db0c8c4";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01969b92c818d09e66fc0d1dbaff4093b934f72fcb6a45b13a2cca89d6ab4ea9294987ada9dfb8abdbbadbb879b6da74bebd108b9dfbca74ec56cb8ba9d05cfbccfc", "7321b6ea2f1640675e339feec4d93b0bd7f3dfa9c633c7da4ec05295b7b5fbd38d6ae348af87ba99fc7a29e204fe864137f9946efb7702ed34d1bc5e3458a31807" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "5555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555554";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6b6e33ab1fc74e112d5d7d279ac51b67427181454806ff33bdbdc67af37ad704b521c74dce1f9ffe38e253dd152b1c108a37db3b3fbc40a2e76131d0399bc0011e", "00c2d36db9647c3d71d98606698dae0afbc8dbb648c9dfd4e2ca523ddc72a0bd95e7f6abc7e6ce11a2c40123dc1cc985e155887535e2907a905d8d51e9d3ed01330e" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "9f57708fa97eba94c6d4782cdd4e33bb95c1353bde095232e3e2bab277bb5d2b48f55a53ffe928d034c29970a9e5f384a003907d3d9b82a86817cc61fb17f4c59e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01c0a09793e65ca31b1037cdcb9da8f8e0a8dd648a6a4f3d8cb98398dce856cd7a123da290e665a8a12819846e8f3462eef875abc5fadf8af9466ab7cca03ebeb4eb", "01c37331f2290f75ccd68b81f1e30daffb63d2319d8481272a7d65f9e4e3ac8ff34db0c403f86a6ea990436c66f24489f5f39643ac1046e99e11db924978d0e3812f" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "68d98fa90736eff3e90f8fcfe50838b6fa0bf2cde77bc51e3f41019c8006f4e9cbaeadce7dbb44462da6425be9cfdaecb234c41749ce695be1b5ead2e6b1205f35";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "62d009d1eeade4561686275a42e64e26cccd4bb6aa7385a61fa366ad56359a209fb315e738d64a9a88ae81c77bcf585de4ab41f258244e3749b56e6b284047fbd4", "008e58c40bca682bd13221dd61cd18485c1f831c2dd9e22525c127bab56f49741f30f39bae9fd74533662b883df06c15bc673919b36abfcd48f08c90f1b4042908e2" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "e97ae66bcd4cae36fffffffffffffffffffffffffffffffffffffffffffffffffd68bc9726f02dbf8598a98b3e5077eff6f2491eb678ed040fb338c084a9ea8a4c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00bae91802d593acc94727e46d1b777887be8a8291c99689de4bd4b790b5d4f7ab7569f167d6f5d236f13ec04ffa25e8a76723d02a44ab586cb2f4c7433a27269281", "0092d7569c829789ac45f625c72d50ecaf38fc8f7e82e5b89a986dcfc912225609018a6d618df087096b21c67c00db983bed0b0fbeba7a934ad2149cfb275c4d582d" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01ae66bcd4cae36ffffffffffffffffffffffffffffffffffffffffffffffffffffb3954212f8bea578d93e685e5dba329811b2542bb398233e2944bceb19263325d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00bb394e65fc89fabb9b54d97e4f6133a9091a74f0bd66b1fe77b0d7cae16e98beda1907f70c37ab300af9dfcbfe01d9aa433e1855159b663a653d973c92a0a6a01c", "0159494aa3b06f758c0df70d6244e6001543e0092fe2e4d692299fc442a30d37f834c478b84b58dd357830785404a3e0175ccc65e2e77bcd3751d59d7881ea88c077" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "015ccd79a995c6dffffffffffffffffffffffffffffffffffffffffffffffffffffc2121badb58a518afa8010a82c03cad31fa94bbbde96820166d27e644938e00b1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "014e96e622ab11d843ed0df286c2a9fe40f20027ba9ab34c645de827d1867f3ed4045c781ae9d09424e8f77ef57422f52b38caa2b999e6cf1ead157a8834a5655679", "011db6f3c819fed7b71d766b41905304e61d9f19fc9a6c49267bf2181023e667ebe3465f5521cb1a1d55a5e2722e700c1624dc2d4c9653bcdce8b6fe793c568b35b7" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01cd4cae36fffffffffffffffffffffffffffffffffffffffffffffffffffffffffae18dcc11dff7526233d923a0b202cb29e713f22de8bb6ab0a12821c5abbe3f23";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b7950ea9ebf9d05d460d451dd20d2b70916e258f58d0b550e215d160fb23bb5696efc9457ccededd93cff5f49eb2ae1e27e93fe9f463cdc75f12e317bf69935b7b", "252c57f7438c12484feab9e78180588259b17cffe1f613bdef0bfb4dc33584ab3566eecbbb9626d67546b1b246323d3317b7e68273fcc6053eb16fddc0c5de8295" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "22e8ba2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba2e8b9c4c3f73cc816143fac3412b62de4c63db08f8c57e4c58c31f1b457ca5e57e20a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01ababd5abee5cc082c9a4cd04721820998f21303f6fe43566a858563a23d8431bb9cbf5db84b0be4ce95cc962b78c7713374a34435f84fb065984b98fb2b486d78e", "0eb4914193029be32044ed049f06d0fe4d7db7c9938600237dfaee8643ea0f2a157e57198d5cd9020ed7c2ac952a072bd4e82a211ec1e20f22e871b81556db361a" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "010590b21642c8590b21642c8590b21642c8590b21642c8590b21642c8590b2164298eb57e5aff9343597a542d3132f9e734fdc305125e0ec139c5f780ee8e8cb9c2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "03b406bd7905cf188d2e6e3079dc66eac8411fbc6d1092a02cdc5e9b4d3eb5054a1032ff2fffd194413b2dbb95ef78262cad749195465e1a52f1dcfa858df3f90d", "01ca7a0dbffbcf6d74209a0a334d607c39c79aba96152d32ac3693c490b2a83d87b30428f418794b80cde96fb59b5e9030557d2411445c337411047f1d628ac23e2b" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01a4924924924924924924924924924924924924924924924924924924924924924445e10670ed0437c9db4125ac4175fbd70e9bd1799a85f44ca0a8e61a3354e808";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009faf51f370945040e6609734445807a42bfbd11e24455e9c8da44df7e9637c76b39bd84dde33bf2c66e315124f6412fc3390aa2127d1d7c1803e32e10e8f9bd0dd", "0189b5ecb618bfd16cc67c671cc6da9724796e10350f8a15f9e2192d8d32d27e2b69897b5c61d3fb71b1c72146d31dceca0e4204abb2404e81ac664ca731fec6fe80" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01d5555555555555555555555555555555555555555555555555555555555555554fa6dbdcd91484ebc0d521569e4c5efb25910b1f0ddef19d0410c50c73e68db95f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b99ef22bb58cc25edff6c197315f418dd66efe28bde5e25b3b696d6f9db1b1a017b4f269af407b8b609506080f29eaedd4cf7087e00b599dc5e4d2a8388867204a", "01b999ffdc2b3c5819366c9295e1df5c6468e70396c7fa8c9a926caebe6a1145b115c107c87d106f384f283fe2d2aec65b202745115a14ee506920d02a645ebaa7c5" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa4fc31322e69da41162a76abf3a1b4507ae66074633446f259661a61c93be30eb5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01b261cd6f287105804bc2885d5a59e791712ab6b9f14fe6ff712f5f4dd693c7b01c272156f895b84f74c6718926baa5f55a73c235351746ec99f0898bfaa24bb4d0", "014b855367abf6f742976ff49e834612544bc983a842e56e0dc9cff9289c64f40efe350dc6301f848ed7c741d3b9ce824ebc779fd1e6c068cc77edc009aea1666592" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "017ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3f6475303719ae52bbd2bb4606f8dcb862cbf38bb8545b7c0759d6bd8355f260e10459f788b319df203c3d41558fd61a1770bccdafb355861064acb5c19e022165", "011423d9b472d31faaffdfbd6a3e83f7c8e79ef1bed35a6135abe93e3994e17321c2e8ee6268b1767c29671a43e5bb0d99751e137937a1db4958a3b29c3ad76cac59" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01346cc7d4839b77f9f487c7e7f2841c5b7d05f966f3bde28f1fa080ce40037a74e3001a2b00bd39ee4c93072e9963724941383cf0812c02d1c838ad4502a12c619f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ee030cdb40abf70726866681f7b7fedc534190929c05a650bb928b894a5bbfe9577eea83c6331a796fa27ed9fac95d9ecacdfef6d61c925502b0afddc671463549", "0155606dd4cab19330c57c2ee740cd9c7c88bd88d95f840f315d525379dfeb7ea9bd3677b2185b92957f374317cc6124aacc8708075c4c05c95cbbc355bd692c3708" );
            {
                // point duplication during verification
                auto m = "313233343030"_hex;
                bn_t sig_r = "90c8d0d718cb9d8d81094e6d068fb13c16b4df8c77bac676dddfe3e68855bed06b9ba8d0f8a80edce03a9fac7da561e24b1cd22d459239a146695a671f81f73aaf";
                bn_t sig_s = "3ee5a0a544b0842134629640adf5f0637087b04a442b1e6a22555dc1d8b93f8784f1ddd0cf90f75944cc2cd7ae373e5c2bac356a60ff9d08adfcdba3fa1b7a9d1d";
                auto r = true; // result = valid - flags: ['PointDuplication']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ee030cdb40abf70726866681f7b7fedc534190929c05a650bb928b894a5bbfe9577eea83c6331a796fa27ed9fac95d9ecacdfef6d61c925502b0afddc671463549", "00aa9f922b354e6ccf3a83d118bf32638377427726a07bf0cea2adac862014815642c9884de7a46d6a80c8bce8339edb553378f7f8a3b3fa36a3443caa4296d3c8f7" );
            {
                // duplication bug
                auto m = "313233343030"_hex;
                bn_t sig_r = "90c8d0d718cb9d8d81094e6d068fb13c16b4df8c77bac676dddfe3e68855bed06b9ba8d0f8a80edce03a9fac7da561e24b1cd22d459239a146695a671f81f73aaf";
                bn_t sig_s = "3ee5a0a544b0842134629640adf5f0637087b04a442b1e6a22555dc1d8b93f8784f1ddd0cf90f75944cc2cd7ae373e5c2bac356a60ff9d08adfcdba3fa1b7a9d1d";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ff928f93a654fca5db79158bf8a16960b77729b0663eb72f319054d453c171794e66fa10438beb55416bc89663c8a4d23c645417f7a3d23ec88358d674ee7c50a7", "01ea26dd23b0b878125c75e3a524801b4b58d0eb7513b3ae7b8b6080a2f2b9286bfae256b5b6571ec3d72fa814aa1d02f1610529c41a68cbaf78783738bf961e3681" );
            {
                // point with x-coordinate 0
                auto m = "313233343030"_hex;
                bn_t sig_r = "01";
                bn_t sig_s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "19eb6b28ff90f9d4987669186ecfd84ee28325831404d2bf61d31a8fce2f79435e676d2ad09498f813bcf343e929205b4c3941e5d9d1cd18c0f398b1e6dda08891", "0153f6a8b606b96fa0178af70d8d591a2825fed4b6fbd23e37666f8a25df1d37b7d08cd0ed367e23e97112371c8ea0d737b6f2b13a19abf6a2359fd055d10c4e0d89" );
            {
                // point with x-coordinate 0
                auto m = "313233343030"_hex;
                bn_t sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                bn_t sig_s = "66666666666666666666666666666666666666666666666666666666666666666543814e4d8ca31e157ff599db649b87900bf128581b85a7efbf1657d2e9d81401";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c27585d9eebf4e8907b799c96ef0915953b2ad36bf450e018862062c170e2fa5110f4b04f172c3dff5f6bc5d756ca3e91fdc408b579c870df2b02a09f43db7ca16", "008d713c42d9f1d9b7b09e0253bfbc1ce88f7579986210f7a8281009817c163cb36b6e940acc38e53a88efdc34982f39d785054a48d06facf3ebe455dac6833b527c" );
            {
                // comparison with point at infinity
                auto m = "313233343030"_hex;
                bn_t sig_r = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "66666666666666666666666666666666666666666666666666666666666666666543814e4d8ca31e157ff599db649b87900bf128581b85a7efbf1657d2e9d81401";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7da8b570bacaad47b6c1c87934ab4542ed8629303b2fe2167f452fcd0451995619fd175b4b4d03766901be3baad5afb87ba3104584cdebaae6df6503c18af70793", "6b2f42d5f7b3a626d2745cb597ea86c95bf37c0609716e186d3b8882549db5c8476b737421155706d6f8b753323700492cec0c8eb07d1f0edd341aa0a50a5f29d6" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d";
                bn_t sig_s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "21664b32e13f605495abdc32094c61e78370642b4a8e66e316ae850d32107952198ff9e029777066b60b61b8733ea87495644cc790dd7b15ed9e952aa709d49923", "52ca4eea9d84e07ade2ba11b1f7ceb47d6b5bdc6dda6c1a903cc2ccab52c4b2d4311f28744cf6e660ef86775f76fc047ad1c08c10fab72d7ab61f5d83d01eae795" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d";
                bn_t sig_s = "492492492492492492492492492492492492492492492492492492492492492491795c5c808906cc587ff89278234a8566e3f565f5ca840a3d887dac7214bee9b8";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0197988b90bc98d04bfdd1aff24cf20528e22fee172ba943d88b8e1b1cd59e32ec51838fdd22e6cabba0b2e87f1153b9ba521d863050d14d838e3f77568daf73509a", "46a063538fa6eceea045d0f6f2f9ebebd5187e1ebcbb2d762d89764fa17e15991935b57c606d6e0e1473830207ccdce9fc7a5644b9c559ec54f078f4ef53049c3a" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d";
                bn_t sig_s = "019999999999999999999999999999999999999999999999999999999999999999950e053936328c7855ffd6676d926e1e402fc4a1606e169fbefc595f4ba7605007";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "016ac1f5d968be279c2fe892cac70574297758dfe14e177fc5156c726c27a329227adf29ec4df435f68df6680fad993cb8417816406644eda75c0d871d24bc982fee", "01c457ad39b11fd7bab53bfa64019e0464b84300a27e5ad8ad676e0d57f6f4c198c64f9cad7dc9ad64a7e7d34c1f81cb9e11232443561acfe44c7676f8347a438e06" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d";
                bn_t sig_s = "66666666666666666666666666666666666666666666666666666666666666666543814e4d8ca31e157ff599db649b87900bf128581b85a7efbf1657d2e9d81402";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6e11f2d1f855bb6e5c8dacc10256788eea73667362a4ce77a95630a7adebcdfe570c9eeb3d2c4837ec63bd6020426600396922eb210819acdf89c69d3792fe232d", "0096effa4c755ef75147841a90289b63930ea696e28a39278374949e7656f2f76fbb668571e00f81885331b5c9f8ad4e61446d14e2d0cfd584c92e2f9f75575acef2" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d";
                bn_t sig_s = "01b6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db68d82a2b033628ca12ffd36ed0d3bf206957c063c2bf183d7132f20aac7c797a51";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0091454ea00df332bf33fe18dedaa20abaa330d95c4758c785186237f8e69d713563a457b4fa28863c0ea1f822f9ad6f3b678a8544a3c6337997c962f63943c1e1b3", "01e120a9b5aa72a9998901e8db2cedff456071ce1702402d9292041b9ba4ce3bebd4498baa9708b73305eeec4722c9782d5b63259f9a30c821d1eb03513600a45f8f" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d";
                bn_t sig_s = "0eb10e5ab95f2f26a40700b1300fb8c3c8d5384ffbecf1fdb9e11e67cb7fd6a7f503e6e25ac09bb88b6c3983df764d4d72bc2920e233f0f7974a234a21b00bb447";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d8926b405be46226d55f0c50c9fe7982ea9a4ce6dfedb745cd716912c6008bf0ff3705d5640edf04dc71346b6086b7bae476ee702908bb3f9a5815931e3d680189", "0116b45cf3739e7f3d69629e10f19f9f53c2d01f2284b6e98db0cd49f45887170ca0656d1c75d4505836ae3087e3c1187158a2774c46911361a34e5cd1e7dd9e4734" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
                bn_t sig_s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "016559fc4580186d7c1e3e05e75305c6da336bc3c9aa8f999cbafc719d6f4dbf62ef91f1859b2f61463a77e43705208e34d648416349e4741ea8e5e779a37bd4a5be", "00a808ce498afde58cfbbf5dfb77e607ce294ce0d036873ead04c08d5fd1fd5d44fcf67e680d77727aad682a7a418065e26b2aeae17523cfbf50b0c178693eb35373" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
                bn_t sig_s = "492492492492492492492492492492492492492492492492492492492492492491795c5c808906cc587ff89278234a8566e3f565f5ca840a3d887dac7214bee9b8";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1c31a43219d7959db2d48bfc30142d984303ac33b553b61906603916b9e09016ce6764c1816ac3a0ded1c5f160f66c9fe3bfe5fb5220bc4455c4bb2b568608bfbe", "01068731c675aab1443fc937440b6e2db5cca4695db6da63ec2fb94a0aca567b38e555383a0246bd397451b0a902cc147aad143454a1f0c1166286feca2bfc12fb7c" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
                bn_t sig_s = "019999999999999999999999999999999999999999999999999999999999999999950e053936328c7855ffd6676d926e1e402fc4a1606e169fbefc595f4ba7605007";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "014ac0270fb277eb45c8d3d7e49149ed14087c80c91b140e4fb1820ca4ef48b27e4266fdc1ac803c76e5f636fa4d4625bbbdbcf05729fcff600abab20b8d1dbc16b9", "01a29aad56862835b6fff258a228f612a4926fa667587ad2f2ff3f5d63623870121195da66be32427f28a6493355590d7abf033594b2a1dc812a45e6c83c4c45e71b" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
                bn_t sig_s = "66666666666666666666666666666666666666666666666666666666666666666543814e4d8ca31e157ff599db649b87900bf128581b85a7efbf1657d2e9d81402";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01c4984462ae091f6a3f81776997038fc47dece0dfc9abdac89bed4f6dddce8a676e8246cc3d92d8528281ab0c4a7b4f2a4d02327cc59739bb8e8088f2ccbe15034a", "0132bafddbb84aa5b8fb02478ad4c1b4d893224f0357d7dcd4713230baa635637e6b90e5910c128e40a32e88f1707319339db2a1f9774eef4c3de95583b14fdaaf9f" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
                bn_t sig_s = "01b6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db68d82a2b033628ca12ffd36ed0d3bf206957c063c2bf183d7132f20aac7c797a51";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00fa43642508b0547ae7940582bc4baff4a88e26785ce904934b8246569fea474f1c5f91c2fa27a7a4e858089457399a41245ed61ca4c0a402c7ca89d9dc21e2f311", "0154f0d19aa4997cccb211a85f6717b54412179c2331e1f3998da55fb0bb6e2e53470332f6790f2ac036ded0352b2a33f14ea3685682aed64648012940759ccce2e7" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
                bn_t sig_s = "0eb10e5ab95f2f26a40700b1300fb8c3c8d5384ffbecf1fdb9e11e67cb7fd6a7f503e6e25ac09bb88b6c3983df764d4d72bc2920e233f0f7974a234a21b00bb447";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "342dae751a63a3ca8189cf342b3b34eaaa2565e2c7e26121c1bfd5435447f1c3a56f87db98089d208c89e902bb50ed289995ee7ccf6d6e6b1cec4aaf832d3734";
                bn_t sig_s = "492492492492492492492492492492492492492492492492492492492492492491795c5c808906cc587ff89278234a8566e3f565f5ca840a3d887dac7214bee9b8";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "01ffcbd2518ae59c5c357e7630cbd4c4cb1555da9a1d381d9ede3e402abcabb80e36ac16ffa82726f94af34218463bb8b8a7a21fdb3bba2ed9439e836c6f0e0b2cd5";
                sig_s = "492492492492492492492492492492492492492492492492492492492492492491795c5c808906cc587ff89278234a8566e3f565f5ca840a3d887dac7214bee9b8";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", "00e7c6d6958765c43ffba375a04bd382e426670abbb6a864bb97e85042e8d8c199d368118d66a10bd9bf3aaf46fec052f89ecac38f795d8d3dbf77416b89602e99af" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "342dae751a63a3ca8189cf342b3b34eaaa2565e2c7e26121c1bfd5435447f1c3a56f87db98089d208c89e902bb50ed289995ee7ccf6d6e6b1cec4aaf832d3734";
                bn_t sig_s = "492492492492492492492492492492492492492492492492492492492492492491795c5c808906cc587ff89278234a8566e3f565f5ca840a3d887dac7214bee9b8";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "01ffcbd2518ae59c5c357e7630cbd4c4cb1555da9a1d381d9ede3e402abcabb80e36ac16ffa82726f94af34218463bb8b8a7a21fdb3bba2ed9439e836c6f0e0b2cd5";
                sig_s = "492492492492492492492492492492492492492492492492492492492492492491795c5c808906cc587ff89278234a8566e3f565f5ca840a3d887dac7214bee9b8";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "304b3d071ed1ef302391b566af8c9d1cb7afe9aabc141ac39ab39676c63e48c1b2c6451eb460e452bd573e1fb5f15b8e5f9c03f634d8db6897285064b3ce9bd98a", "009b98bfd33398c2cf8606fc0ae468b6d617ccb3e704af3b8506642a775d5b4da9d00209364a9f0a4ad77cbac604a015c97e6b5a18844a589a4f1c7d9625" );
            {
                // y-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "ec15522152bd082e8511a359e9c4fe2ec0e2e9971ad9368a35c3e9a6473c21d9597ef84d7217d38ffb090ebe308b6274deabc760ffd060d19d17e52cceaefd8a6a";
                bn_t sig_s = "0134cf6ed48b9873bf81ca9673aa8b0c06538fa999b59b73f7176339662f399278f3e9c70848c6e8f3ec639c287d21032a285310dfc5e570e861d7986b48139d9c5a";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "44a45dbf0c4d34cd9b7a612e8afcf36cf3ca269d64dc0d84b6f406b7c6781a02e24d5ebcb7d3595ae5a3c9f3a3fe18fba6526581deed81e4d74a1c77a85635a394";
                sig_s = "01e15d5a81aa0fbbb886830939e43fdec62cc3b64819e384663a51a1f193f0e16afdba98e1690f8ebb978a5684bd41e4dba7a74f21f71caab59d88afd0ef20946985";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "01acf1333a1d8860847e0b0f93b7822ad6c380d2aef10d2036294631a3cea154c9d06e980d0586aeb9f72766f50c35f707dedac887c88ce76eaf6b57a628af4e2648";
                sig_s = "0168d686e958d31315313548734de94e45e47e836ac925b83ad0bfd919a87bcc09b3defcefd0c2f10b8ca4d705258f34eed5007ed72fac4c2cccf322d7f6f39fdb51";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "304b3d071ed1ef302391b566af8c9d1cb7afe9aabc141ac39ab39676c63e48c1b2c6451eb460e452bd573e1fb5f15b8e5f9c03f634d8db6897285064b3ce9bd98a", "01ffffffff6467402ccc673d3079f903f51b974929e8334c18fb50c47af99bd588a2a4b2562ffdf6c9b560f5b528834539fb5fea368194a5e77bb5a765b0e38269da" );
            {
                // y-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "a80553a081456c72e432aa6cf46a24571d9978e3af4f88ec8ffb2d5ee804b4128bc124ec1154e1f628f27f0fc3cdbeec39cc5baffb04ab112af1283865ec577908";
                bn_t sig_s = "7d31a19909b1b7a2314dcc5eb82388ef2e4e8acf0dc6de6d40cc3382c7d8b00227eb929b3b7d522438b0c4a652d1ef8eba9e4d4e91e5c7b3d7947fbc9640af1083";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "016ed83a23e3b31ee7591ad101167699e7f8d1c448ac2453ef29ac02928028b2d9119fa12ff5ce27f582642e7ea8fd4e991b5266caa9fd70079f5a23c06be1153f97";
                sig_s = "bca1632542b3ef53951dc45e49c263ed3d09e2afa27a3bdc9f42083056bb3d65b8d4e95507a4f054a3abacf6f6f99234d86b698dd18c5d5bd3e9f86ac1b018a4e5";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "01eedb8deeb89366c66f53730afbce113ad37152691766d3e267c45d7ccd7430ddaa7ee5c870153776fce1deed2b7cb11fb06abf02d6f18c01e0b832bb97d7bb157d";
                sig_s = "d9256266e952989dd515a8c7540049f9f8d66451b4580dedc736f6777e830216cb4c7bd9af029d4046f3ea747d5d104cad16f20e2e65fa15c7feea9c35b9a380af";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "02fba6a061201ea6b1ed4265163568735ebab78600cdf6a71101dc63beaf546d97a214fc6396793b014eb1aa7a728f53deb2ff9999a3808ddfed15e9629b", "01993852dadc39299a5a45b6bd7c8dc8ec67e7adbb359fa8fa5d44977e15e2e5a9acf0c33645f3f2c68c526e07732fb35043719cfafc16063c8e58850a958436a4e5" );
            {
                // x-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "014dda0dcac3d018a298b7d6d76e3c16a0ce01088f126f413c113ee2eafd69baa0c476c84ca0ffa9cb7b28008b5ea117aabf71e5c147ae46a474303a6c5e967c7f01";
                bn_t sig_s = "01696a0251cc9c50b9ca9aed6786ca4f55d5cf866b0300eef84b3edec1c236890e482b942dc0e817fa23258da17e1d5f77d367f0ed1d5b25cdc483fae5863790e6e8";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "4c5b2e5935dc9303c76b6b4cb8f30739b56fa4880f8fa58b5d4573cbd29d4cfa76239efd7d45fff8040b48d93867b8c81862f029c967f46667455ba715f1a5d15a";
                sig_s = "0168672a6fd60214647864a7d2715ce4890a1973c2fba1c02c3c4f3fb86e4eea946c46c09005aa5280f01c9be720ba37abd55c445cc1d9f5c3797fa27246d77e1c1c";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "016f2681a03e8d6cdefe9e3619397c6c951dfb42b04258f0222c36f810933fe04163a2c4cde88ce9c716b105e4d76a4cf8e84a1b0ade010b9943383b58ca4b03be98";
                sig_s = "50fa6b6be2fe3e66627a5091839753566ee40892af040d3840612b83323a0f0350ad22bc9611d41f8d43ed7d26be53220474feb8d34d01c7a51b17f41edbef5694";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01fffffffe1d5d52b31ca52f8947a35593edf164cd324f833b90935846c64db1454df9f028dc8bc36bb04cb7f0cceceba01a3844097f7c35eeaa81428db0cca63331", "01b7c70277d0bf78a3c7b62c937f0cb2cad2565f5514f6205ceb1a193d4fdb45ba6e6cec07827bae0b16b8316c3539a15114d0de6d2de407fd7117551a70826eada6" );
            {
                // x-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "0f90341f535c12fc02021c81ebe2f9de8ca33bfe264c734bc946cfd82bccc7200a8b85cc0e3d31d84a002a962bee609813b486bfada692fd9385daa0af9a6d72d5";
                bn_t sig_s = "01b46889a27e6538ca39d58d1e1a097c8f1b96a3b947dfe28afeb9dfe707370478fa0bea1217e1030a5075582d90e709d752d8a30be0c26ac2b5f429360f5062e82f";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "8a51929349b7d9848df149e203a50d2c35a8a3ab12bfdebdf6fa6c45a05d75112c5d8f7cb60d615ee38eb4b98de1b8becf7e372653338e5db3c227db9edff36d79";
                sig_s = "01de6b675b626f7008bc0334a59bc163e64eaab23d75dc9adca3258bba2dea3cb4e21d062bc835a65f3182d86f1e0b5d3853443e362063d313afb3cabfe0035dd18d";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "019677f00b7d3182b2cd2ea615c6819864e9a37451564190a81d63947a6335059188d4b9a8cf9841500bf3eb49c09c4c4d330a4f32938ef7c7dd1cd4b80b76dcf50d";
                sig_s = "018237771c8f4c00d420bc264078822ef2fba89f8dd65e0f8824cd89318a16c30611cecb0f24f142aa4c51c074dac7422d8cd78dd0ac40856940f81d916a55883784";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c7c8817bf2f0652a4a4b5140c773e261080a0a111395856e8a3350f5eb5612bd63b367b965e92e9538ea3b7908aef1ade4b68e17f9f9148495c167d1c4dd491349", "08bf0be2979abb8111fd0d768adcad774113a822c1bb60887053b5cf8c9563e76705a391ece154b5dfb114b20e351df4014bec19fa87720845801cf06b7fffffff" );
            {
                // y-coordinate of the public key has many trailing 1's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "ebad623d0aee1d3f17a782297155018f848c38398211b0969ca0cc96771417d44e2894e9aacd44516c3188f7278ca6e5a13980ca943b8cbc8b75a5760b1b40de9a";
                bn_t sig_s = "a4dfa438c8b53c33d5600aae164681b791f4e3a49cf82ef253ef2b40f2c361fbb42211cdafc5315f93937b70615e17a0b81960a894e466a17c9322fed55c7d55b4";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "13c33ad4251e52d9e6b12322a1794f4351b135c722b093dda22a1dcc885eaf3473e09af4307fc294db2d3f02649ad325898223be200c65a076d6fec1c4d054b0c8";
                sig_s = "9d78be212bd11cb5d36374a9743c6772196fb7d029462cdae5517a8ac52b42caabc5452de0a4904f05d5db20279e5663ad7cfe8f04efe6485a632458dd4ae1cb7c";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "019c5d65ec2257ece62f146d9c61661789151ccce3a045c60a03f2034eec2e84eb54414825529b9e1bc6c19581e3ab827166ff4e4722bc10447bbff9a5758839b826";
                sig_s = "0191e1bb04a72eac5dec7c021bae1fc37d9bc81e0acdd09ae63464009a01751394a8593084f634c191045a632073aae56eb65d88ac1ac6fb309dcbcf76f22ae652c9";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }
        } // End of Google's Wycheproof tests ecdsa_secp521r1_sha3_512_test

        // Test vectors from Google's Wycheproof RSA signature verification tests.
        // Generated from: 'ecdsa_secp521r1_sha512_p1363_test.json'
        // URL: 'https://raw.githubusercontent.com/google/wycheproof/d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d/testvectors_v1/ecdsa_secp521r1_sha512_p1363_test.json'
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
        //   ValidSignature - {'bugType': 'BASIC', 'description': 'The test vector contains a valid signature that was generated pseudorandomly. Such signatures should not fail to verify unless some of the parameters (e.g. curve or hash function) are not supported.'}
        {
            auto pubkey = curve.make_point( "5c6457ec088d532f482093965ae53ccd07e556ed59e2af945cd8c7a95c1c644f8a56a8a8a3cd77392ddd861e8a924dac99c69069093bd52a52fa6c56004a074508", "7878d6d42e4b4dd1e9c0696cb3e19f63033c3db4e60d473259b3ebe079aaf0a986ee6177f8217a78c68b813f7e149a4e56fd9562c07fed3d895942d7d101cb83f6" );
            {
                // signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "004e4223ee43e8cb89de3b1339ffc279e582f82c7ab0f71bbde43dbe374ac75ffbef29acdf8e70750b9a04f66fda48351de7bbfd515720b0ec5cd736f9b73bdf8645";
                bn_t sig_s = "01d74a2f6d95be8d4cb64f02d16d6b785a1246b4ebd206dc596818bb953253245f5a27a24a1aae1e218fdccd8cd7d4990b666d4bf4902b84fdad123f941fe906d948";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + n
                m = "313233343030"_hex;
                sig_r = "024e4223ee43e8cb89de3b1339ffc279e582f82c7ab0f71bbde43dbe374ac75ffbe97b3367122fa4a20584c271233f3ec3b7f7b31b0faa4d340b92a6b0d5cd17ea4e";
                sig_s = "0028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba2fe747122709a69ce69d5285e174a01a93022fea8318ac1";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 256 * n
                m = "313233343030"_hex;
                sig_r = "02004e4223ee43e8cb89de3b1339ffc279e582f82c7ab0f71bbde43dbe374ac75ff640b034634da00b7719d0f7b8d151daee2371c709e0bcf89b1846ee184874438f45";
                sig_s = "000028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba2fe747122709a69ce69d5285e174a01a93022fea8318ac1";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by n - r
                m = "313233343030"_hex;
                sig_r = "01b1bddc11bc17347621c4ecc6003d861a7d07d3854f08e4421bc241c8b538a0040b27d9a7f54eba8ad17ad5916eaed487e87fb8786168eb5b51e438bd675558ddc4";
                sig_s = "0028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba2fe747122709a69ce69d5285e174a01a93022fea8318ac1";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**521
                m = "313233343030"_hex;
                sig_r = "024e4223ee43e8cb89de3b1339ffc279e582f82c7ab0f71bbde43dbe374ac75ffbef29acdf8e70750b9a04f66fda48351de7bbfd515720b0ec5cd736f9b73bdf8645";
                sig_s = "0028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba2fe747122709a69ce69d5285e174a01a93022fea8318ac1";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**585
                m = "313233343030"_hex;
                sig_r = "0200000000000000004e4223ee43e8cb89de3b1339ffc279e582f82c7ab0f71bbde43dbe374ac75ffbef29acdf8e70750b9a04f66fda48351de7bbfd515720b0ec5cd736f9b73bdf8645";
                sig_s = "00000000000000000028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba2fe747122709a69ce69d5285e174a01a93022fea8318ac1";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + n
                m = "313233343030"_hex;
                sig_r = "0228b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba09a7b6ac4ecd0410b4722ca75ba197a403a0a1f9ee0e7b391b0649fda1d3969eeca";
                sig_s = "0028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba2fe747122709a69ce69d5285e174a01a93022fea8318ac1";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 256 * n
                m = "313233343030"_hex;
                sig_r = "020028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdb9af1b06bc12840a7e05b6effbd682c166aa584338db1fa5ef8bd18e7418fe09593c1";
                sig_s = "000028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba2fe747122709a69ce69d5285e174a01a93022fea8318ac1";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**521
                m = "313233343030"_hex;
                sig_r = "0228b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba2fe747122709a69ce69d5285e174a01a93022fea8318ac1";
                sig_s = "0028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba2fe747122709a69ce69d5285e174a01a93022fea8318ac1";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**585
                m = "313233343030"_hex;
                sig_r = "02000000000000000028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba2fe747122709a69ce69d5285e174a01a93022fea8318ac1";
                sig_s = "00000000000000000028b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba2fe747122709a69ce69d5285e174a01a93022fea8318ac1";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=0
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=0
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=0
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n - 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n + 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                sig_s = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p + 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                sig_s = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=0
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                sig_s = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                sig_s = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                sig_s = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                sig_s = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=0
                m = "313233343030"_hex;
                sig_r = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=1
                m = "313233343030"_hex;
                sig_r = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n
                m = "313233343030"_hex;
                sig_r = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n - 1
                m = "313233343030"_hex;
                sig_r = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n + 1
                m = "313233343030"_hex;
                sig_r = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p
                m = "313233343030"_hex;
                sig_r = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                sig_s = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p + 1
                m = "313233343030"_hex;
                sig_r = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                sig_s = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Edge case for Shamir multiplication
                m = "39353032"_hex;
                sig_r = "00b4b10646a668c385e1c4da613eb6592c0976fc4df843fc446f20673be5ac18c7d8608a943f019d96216254b09de5f20f3159402ced88ef805a4154f780e093e044";
                sig_s = "0065cd4e7f2d8b752c35a62fc11a4ab745a91ca80698a226b41f156fb764b79f4d76548140eb94d2c477c0a9be3e1d4d1acbf9cf449701c10bd47c2e3698b3287934";
                r = true; // result = valid - flags: ['EdgeCaseShamirMultiplication']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33393439313934313732"_hex;
                sig_r = "01209e6f7b6f2f764261766d4106c3e4a43ac615f645f3ef5c7139651e86e4a177f9c2ab68027afbc6784ccb78d05c258a8b9b18fb1c0f28be4d024da90738fbd374";
                sig_s = "01ade5d2cb6bf79d80583aeb11ac3254fc151fa363305508a0f121457d00911f8f5ef6d4ec27460d26f3b56f4447f434ff9abe6a91e5055e7fe7707345e562983d64";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35333637363431383737"_hex;
                sig_r = "01c0832c973a455cac48a4439659aa21146036c52ec1514121c66714348a1c0e2c7099a2466d9acb49325a0cb509e5dff2efbcd90369d3027cbb7dca58a134278d05";
                sig_s = "00a426c063ab5cc6af20dd1ba8a519fac910183561598e67c0929e25f9c3aaeb245c5647fba21e30c103304dc6f49e6dec68a7833533e4e5448240bde023fe201eb9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35363731343831303935"_hex;
                sig_r = "000d01cde64dda4dbcef1a9b924779598217b97eb688d9b4a4fd20d1b81ff0bb870abff1b0db6dfc3762f27c3954f230a7933d9ea397a972caac5ed2183ec72716c7";
                sig_s = "01c6530fb6b913005f81e156be89b3847701829fbb310d8a4c761212c6d2f8750174f2bf81c238fdde4370fa87de320f57dbed96691af45cb99f3daa865edcdda59e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131323037313732393039"_hex;
                sig_r = "00c009c74ec707252325d78f4e7f14be28f56272be17c0c18c90ad4c07322cef4eea444c8feabf41a213e3e846f8ac8bb7750d49143069cd01877d530bb981f1a85b";
                sig_s = "001f1c27ef97f434a8c2ff315dd39d909709775bb3c7588243bdfd8f7c866c49b3369719d5b74a47924bbce57301675e2baadcec438e07e6d532aba664253ab09550";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131323938303334323336"_hex;
                sig_r = "01d3b17a34b19d134773988c434a9fb7f22a57dfb4c4bcca031e213e1b9a56db0ecb2f3c54cf9b1b6e5981369652de37337a7a7d7ddb54d67b067bbce01fd7fd2808";
                sig_s = "00c90317dfa061122557eb3899939924a8ea3cdd886e0f2e5f2c384b65b1a40de5f00fd9fce889fc313a6a9d5f0a9cd3a7b89b7ba8e97807031f3d1e3f9c103f0a10";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39383736303239363833"_hex;
                sig_r = "00cdca5299e788600a3ca5938d4a4c5f42b5eea3cefc990e67af95a4449aac0ab50e8fc4778efa497223cdca07c0e5a5920110f3a87afaaf265beadbb91c00d13464";
                sig_s = "01a92b9a5570b42f91ebc3d8ba272db9241468154783548d3fcfb6ef46c9e037bb6217af0a31ef952c27604629ad5775e7695c63efa138cee8326a51c1b04d0c658f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3230323034323936353139"_hex;
                sig_r = "01660b0ed15d5f63044cb189e1a405bcb591c37217d0e000008614b152665d5bb9353a3826854a8bc6ebed423b15680e4340a00701b17bae24bd399bcff7e0438bfb";
                sig_s = "01c47f2f5c6143d2eef063757114aaeb27827b6a8f675d1825dac7f4548cbf78a37eb9621a29e9b14cf61fc6ae49e7e6e15350a4b90a4a897ff69b0c59b69508ebc7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343531363639313830"_hex;
                sig_r = "00364684856c7c02bfb2ad2de603d10883ca93c122d4cebef276467a9b7620fb530e4d05d07c15ab948b9ce7682561307913b64ea6896ece1095dc64369f1a9d5c0d";
                sig_s = "009e6db2ff96d9d71150440fd44992656ca118fcaf6bd04499314e8ba61a55a8790aac023ddb68600fbd7ed4cd4decb176e8bd7822ea31d75adcbdaccafcf510c26c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303933363835393531"_hex;
                sig_r = "01a317e49014f1bf3afc09cc048531010e2144b662cac657e51b32bb432d274a730b535fb2de66fa8ddd26faa3f46e004389d25517c56e7d8a1d39563b0e8c9c215b";
                sig_s = "01ad2e1212e1680b660a1c07f54addff575c8c8298e26a14c516f517fb5f966a2b383aa46a483fdbfa72711d60c0f67a2c03d63d2626ffe271e0ce353a4d4b09bd5e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36323139353630323031"_hex;
                sig_r = "01c09b29fc4da04e9b86097bd6d6806aa969ceb37ce52eeac5e9518d27541c3f30c00f113d9dd3b007dae6f381896d43fc6ddfb3fa256a36529b054e416ed6380599";
                sig_s = "0113e5622cb1e4c4bb0842f3d396d7e660241116e94e8120a602e3d2952701b1a11415a3d8c503adced160450fd13157ad147d2d65d77449458659350e20a545602e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35363832343734333033"_hex;
                sig_r = "0078f4a2968460ea8f64a938b3a97c914eb0ccfa94eb08636efee9d5ad8668ce1c9099573abd146df9e7b2ccaaa1a25de903f85962849356a872e88e545babc28974";
                sig_s = "00f2729e9593c9fcdf5971b21e367ffdc87aa7520393527c6f68ab512b88b839003c1c9952b04f2dc74010a31071ee20a9fb1c7e1187d04de71b3f4327df128ccd43";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33373336353331373836"_hex;
                sig_r = "019faed147a76b65779d0989e1300802844c9ba09f338c5e31a24d9ebf8f0b0b4c21f59d369ac10e315fa2b7605b0f17a9c07cf6ce4c83838e58333a3390142d79d0";
                sig_s = "005f4de71fdaced1e8da86efd47ecbdac6a6ffc6d69df71da7ceb5596475cdfecea3d00f074d2de89e0fcc05e3231d531f0d38f2b7c6fe4ecf67a0cdddc21d0867b8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34373935393033373932"_hex;
                sig_r = "00d0b144350a2128f042bc1a27f6c021dad1ec031be8f1d8304797f9ddcb742974aae209f014980174b9d4e434e3f53247889d2da4b767593179cb4eda47e7996430";
                sig_s = "0184d3416dee35ba8807703a91ac927096c10959a05cbffd8103a93a9f20a11537bed7a645f32295e4abce493579caa4e2242060cc4d58b2414870e98b9336795787";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39333939363131303037"_hex;
                sig_r = "0005257a0f45ee2ae5cc30283d23c47c96f6deaa3ac1473e8e8a40eaf61bc4b0ef8bd18d11983f257ec4b1d8d04e76a122b5bbe1d31065159072c58fd9bc3e983768";
                sig_s = "0122dba50d0eb71bdbf092a94a7ea280412906e1f849e91dbd5d8158e3fc6cd12e20461b77653e3df2e45b86883f81071b33651ae1b84cc8e7c365ab8d6a36d1cfa6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303837343931313835"_hex;
                sig_r = "014f624af9d8096fe7a290651d23ab260da64e44b886fef4f3881d0d984d3b387fddcf65b1fa1dbb239028fbab4a1de6ad150cc8a4e4db0a971bb8bcf01c4728ff98";
                sig_s = "0105e3b55db0141c06d9854096cc0f73415dd2b85a331da50cfea3bbf648bbf8651f61f2cd09386b62fbb8ce67248683c260894d9ed54d6667ae02978e38ab99320a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323336363738353030"_hex;
                sig_r = "002c952d7e61e1097cd7f709e62ec486879b380b63791c146b545c064e65b3060250d00af279cf15eade67384b28594db542845fcc6574ef5d8d5bb8a162e0350a00";
                sig_s = "0135ac6d1cc05b095fbae28b652fe5386b8689e21a14990236d3ada7ceeb0c12a4f774bff7b81c8d07572b0c7985364c5d31f33271f0ac3a2afb88b46bfeefbaeaa8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343438393937373033"_hex;
                sig_r = "017919eff78225e1937a921f98f5d153cbffa03929819f228ee013f8e59549b04b9867006a8df25a93a6a25dd1d3f540239a8ed14047ea00811da9305ec515ad000d";
                sig_s = "011fb873bdae1757801e575c5df62cf82a1881af3cd6ed17dc50edbe6c5fd0f4d31766670b2aa572a9e6547b36142afa8464d0be4bf41930629dc04c85e01b2ee8e2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35373134363332383037"_hex;
                sig_r = "006ac9b370067b13ac2b57f35d6d9b1faa93b9b068ef5ddf8bde3a54024810aa2226560065b0cb7501df96b4756ce1e1fa607f86a942367894a1f7728bd5f22cf177";
                sig_s = "008b47a9e1370c9f5bf4677d554c00e9ac3ea7cdfc78836ac53ac710b7f3bff8c2297780c69a9fddb80e03a605e5e48a52e52fd35f41668cd9064886366fda206086";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323236343837343932"_hex;
                sig_r = "00c4bcfff265cd32442220976ffc7e4ec09181d694696eb89af0cb2d5a2dfc3876deb3c6adea168965200c355c3bff5e47ab17ecc44c8434333280796d3a183449ea";
                sig_s = "0062debe91550f8a760eaea309f48483c65a52c7e88a83867c31730cbc6b0a64d4c564bde67e6539af787ecfd18016cde46ddf91740f58f6ea6ec80b173fd1c47ad0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35333533343439343739"_hex;
                sig_r = "0174d744ddc631fcf8202fca0ab10f6d96d3f7552bb2a9ae5ac573634133f61c59a120fedbc39cfb521ab0cd572afbd5147981090d1dcbfe902e03f0c0579967b581";
                sig_s = "012f59ca927c4ae331d2f667fcd9ec01b0b5514e2ab5da0561ea614431dc1fcb761c351cd1211092720ebb7074a5128f8019b7c18e048d5ed3573ed61686e9713f72";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34373837333033383830"_hex;
                sig_r = "019a513cfaf871287340d8a51d2f4348ab4096c5fe244b22add38ce433e3178e8ff5b2df0fe74a1ba40fe8341f734c71f9a1177b41035777e2da6b082e0b566690de";
                sig_s = "00d0c43eb33a817c3aab30281c593c74517ee84e958b114395ce0b31fcf30bb8f5dfe60dbc7f6f14698977d8e0516a9274a5bd71847057e006fa315fae6922eaaa55";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323332313935383233"_hex;
                sig_r = "013204800efcb40ab09ae4137325a3e8c468edae91880a51616ba61f3ef1f72fd89feb956bfb39818d827468bb4475110a04779fd6bb3def25c61c4ba60889ed0ff7";
                sig_s = "00704b7394687698c8841f4875d40e5b3c914f154ccb2b54466ae163ed3410f20d0a07ac5f90c0c31271ec8a524ca2dae4b8bc4f6e1ece173ea907890693c5f2190c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130373339333931393137"_hex;
                sig_r = "0180241cd2e6163158a39599890dabee99c2c86b88accd2b04b5a72874fbdfbde0d18143c4d78e0da1abf3796b238738840d60e34775a8ff810d58a9bb3559a3997c";
                sig_s = "00bc396c2ef28b244fb8e004bf5361572ba1fef6fbe081ed1dedba4d9af78deee126599f75a0a9d0f1b1618ded7a0c5e672e40917fdd30582460da3aeb1e9c4477d7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31383831303237333135"_hex;
                sig_r = "01485fc03fcd629fd4c564775ab6969bbc696b5b0f38141b69f86e052e7fe8849a64af2dd37a2adf64672f20bd6f97cd32f0efea51aa22064c5f10a3911177e1979d";
                sig_s = "0180fab473ff9d726db6d266541a0bddff8610e4026d26b6c9abf972eaef477d50670bdd3067c9d711a8346e16869147751e89b4ea75bb00ece71300cc3b80cf8899";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36303631363933393037"_hex;
                sig_r = "01bea49b150a27026fdf848297b0491019f76abf90f3e6d782e3d3fa6caddb81b7ef58b27f1b2b3f7898889b4e2b6cdda7b5636177a27eb9a67b2055b6f21d262c26";
                sig_s = "00dffb13c2d5f746c8573aa444afc8baf8bf881cc4d0fca8169f6cb304f400eb3932666cd3758c437c9cad79abfd89c72a788505763aabdfabf8903ad4a70d9ec9f7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38383935323237303934"_hex;
                sig_r = "01d56bf6f3758f627f470706d1d28c28fbfcad6dc30465cb285a274fc057f791de73ac30baccde044473fa9e3dce6d395eadf98d1f97259bd851a1eb6f3d31d2d756";
                sig_s = "0033704b4ad37300a96682569f4f7fea3e14d6e1f65864663f39aa67f40b5c949f198d5de9f2ac2369bbb9111c89b393199537c6c08ed7c02709c733ef7660113d53";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353830323334303934"_hex;
                sig_r = "01554035ba84b051d50901c622b98be4de0123a02928dffa7eb13b0403fd5e255f226505e15694956a66a878ff581173d123d1b24eaa85c5fe46d8973a55040ff405";
                sig_s = "01b016dd6b5176ad8347eb9802dd7727e06a29db33cc946f809a42f9193040692b0f82ebbd04eff9f099b7f75f8e45e74ac00a51a9cd4f2cbf5f03f4d2bee99c24eb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33393635393931353132"_hex;
                sig_r = "00293e8d6775f3c14183aecc22f608e9013d7b15dad167bb38a1dfef6b373619f1ba2751d77b43f643f68643cfdb5c04a8ed858bfcf3858a681ae93bfc7cd7e31438";
                sig_s = "002c7d96db7dbbe347bab9f6f7b88f48cb32ab963248737d2c901b90d64591cbdb0f0ca7a14557f8a50fd80d402f929dad141141f1f0c85d9414b32d1fd4d796e6e7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323838373332313938"_hex;
                sig_r = "00b16a9b3aceece85908125f96f6cb6b1afd0ef04171936b3766f8e43beb340d382084b33439f775a29a83945da8efc4190db1343e87d8c0ffb97aeb3be159d90f59";
                sig_s = "00e5c2bbd98e449bd0bb4f75a07f1a88dd63c0602a7660f4acd33937c4913a9c16ba44dc5808892ec88a4255109a7bc5b221c07e6a278888a9712fc2a25b374427e3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323330383837333139"_hex;
                sig_r = "003b47a8ed52f5b0566365313520bc0b6e4e4efb3ea4176ed7a352c4b2f8bffbdb0148ff44f3f13d9e5e31b1cdeae097574aad8bf393c54a5c842e749ee87a74c6b0";
                sig_s = "01d3f484e9e224bda9c8f10fbb74bbb62d7a18245707f4eb52f17dde793892c16e4bdf504960fba55da487f542d412b1b833f6f46336118618fcff69469c83963777";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313239303536393337"_hex;
                sig_r = "0128b8988bfe9287f82ac97be507a544b823e85cc2813b6929e63699cff85a40283076028e7bf8d24330f89adb96bf24a4e183a898e679b36768909574e7d4733d61";
                sig_s = "00c18aae44e6801fc2e3d9c7a20ff9d42b46e4a31ca37772f8c46ce65219b195ca23717f816e1fed51e5b6f9a0ca12c3cf81ae7fc9cc6946a88330b2011ddd160930";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373438363536343338"_hex;
                sig_r = "015edf1fa95b17159f762d68c1736101309e80fe5b2c4415609a5ac0837fe5901f3c2d3d826a43b1f8cd1babf494ffd96cca1267950188a924d4e1bf7f68189f27d3";
                sig_s = "002e8697efbbf53adb7cb1b904718fc71eb2561f331c209c50848b5bc50bef77c5c3487d285bfaa3caa14025cbb71bdbaea6911e3610335641d2799c3fd75019f716";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37353833353032363034"_hex;
                sig_r = "0161f64bbe93fdc0e61134cfd4c453ab740233b436179351aa68a3e38a83400d86ff464d7ceb7a51f541b86eb2f12e32a879b3a29bcb92e08cd50e74f86a0ed52ae9";
                sig_s = "008f6fef49ba12ced6696f4f6d24e6c68057a84496d42eede630199e9bd06d91363542a9776bfcd6d77fbae422e80fe466edd2c2c5e1f5cc79bedd1a7becc1a12660";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333237373534323739"_hex;
                sig_r = "013a6faccc1c06cb5dadb2cf083cb94a7181fd5cbf3954fdc430c2691248fcfcd13767e32491f00269b549cae93777ced0f7b069440726adde7605d4038d7b5ea4cc";
                sig_s = "007622c9065f4c49a6f8649073dfc6a827b897b6984176b1a09d151b9733a68f6da746c47427cdeb3be075da4a351ab78dd5e472cd98d1586edd6ff2a11c6c169fbb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373735353038353834"_hex;
                sig_r = "01899609e7f7cd2ef14bfbb1cb9ba9283ae11a9346a34bef23b1c249da2e76a7708e0f2f97f819e4e25b0d5227eeb85aa593c3fae9398a7020f61ae1606945d13841";
                sig_s = "01b8d5e9c4f030295447106d2b5c80cc2e7d4e36b458a90a08f505df62d2234e59d08187385ba5501049b34e12ec92f7839a18361a52a9a0b6f6a664b118680b53d7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3137393832363438333832"_hex;
                sig_r = "01ddc69d1508021eb560db39f3add8a28dd7fbce417e5fa1f4f626705caaad72b634868d01dfc474e926c97927c56ac51f9bdcfd0e7627be35cc300a0cdc083b00d4";
                sig_s = "006e862caf9f2df11b0a46104e78865fbbabe30bfac0b1fe7f99badc11746a288c1ff27f6fa2aaba6441bab0372af906eef083ff03ba466b896c9344cd396dd46dbd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333936373737333635"_hex;
                sig_r = "0117fe2c21f282c7e4a8415e9c53c254514eeeb0adadc771adbc6d21a09add4f17ea0c597469488238be795f2e187fa016d590535b4ff10c62d2246aa17bb013f9ee";
                sig_s = "003c9f1590ce7a68fc84c617f478188e71aefe8c74c4b9979b8c9196bcc262205aecce5fd2bb80c360d3e20da20e36c5ab70d810d4ba97d13858199d3a1c9c140c63";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35393938313035383031"_hex;
                sig_r = "00be6b47254a3cf93e2e276adfb072256404744070d6dec83ef34e3e6c119206422bb275e61fc47053ef7b2af9e33aca8f8b2e4938057070eb6ebbcf82fabb44a5fe";
                sig_s = "01061ef80935ff6d0e9f87f3537b639945acf50c5d97d30b4b9c347e3f5f5ec02b15a376ae754d64b2efaa811b3d12a0fff0bc689022025dd2f69f2f4b40dda8687a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3136363737383237303537"_hex;
                sig_r = "0130b6fd7dec5cb6f90a8b54ce7b58c61b013d0aed7c4a26639de80aeac3d9e3388e9f87e1e6419d3f0339af324e1421b5d130317ffd9d8be36500a84bb41d026cea";
                sig_s = "0176b460a3eae01d8aa8ccffb0d6cf4d1595aa697c65510a1197b97343c1a6234552ce9d6d318c5f20f48bec0dc311dd62eb40058f3cb22fa958edaf9ddded191a08";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323036323134333632"_hex;
                sig_r = "00a87de42d827ae1f55d6fab3277c7a9fdfac3af22fe47e52bfee34fa1ee3e765095fff20175becbdc94b4a5ad3a149ea7c1bebf4d45370e6b4404a0437d8fae264f";
                sig_s = "01a3c1c5186d8aa491b4623f5765a388930f37bb8f3e1c0db508983585b9090b3aaf22bb846e0fb6d915b5811ac55e4d6cb08f605cb84deb55ab7fba2dde8736b1c4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36383432343936303435"_hex;
                sig_r = "010e46055d9aa087f1c4b6056319cbf17a0694fe073266a3f30363030e345a4bd461acbd99d1261fc05ef3c9a1c37afba6e21c2d513ea3d4709de5586810d7d29ec6";
                sig_s = "00d0c95c7e97a94efb44aa717cd6ebe82de0644e32676d197351f128ee8d2b223ab476d3e66014ecc003081f7040c578b8984628d6ec80733f713e26b2c98cb4ede1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323639383937333231"_hex;
                sig_r = "012c04d08a7a2d07403aba604ea85ec23a52b52786e7fce04170e867be6146eea75a7180f5d4f3b82a204a3c996811a1e61a3e76ed209c22428b35c51fe60f3bee1e";
                sig_s = "016f2feabc25733b0a460463b9933e6e4ae9f4124cd0ad3785c77755dbf0848ec1cfd2ab08b960b556870fa00388d23d9a9fa3112ac3e62a0f342d58fb1f0aa81748";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333837333234363932"_hex;
                sig_r = "01ca9532c9daeb80d0dbc07a4138ba62a6bab8c88b9e1e2edf2675132eb97cfb26f4c395f3b9d1d1275694956b34c3ef72cd00bab86777465b9edba29a41b0114c62";
                sig_s = "0140eb6dddff253a7ff5b032d82fbd18e481a376fe242f6405b81b57165665c9bfe61e25cd3358245bdfb8de7632de72ed20cdacf384764096c8fe3a376563a348af";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34313138383837353336"_hex;
                sig_r = "00d609e1f1cc1adf5889dc6deda441682e760be08932b31592fef3ada143fb4940e4ea75ae519e4fb0769c4fbd33a52b183a21d0bba1ffa3fe50fd11f75c6ac58ff6";
                sig_s = "012400cc4ddc24ddcd47a6d639a2abdef29a65d4fe9175f51b316f4bf918bc918879495c572f8e98364e2e1aa0d4d53ad29e803a4470d94dd06a982a1d041bf2b5dd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393838363036353435"_hex;
                sig_r = "003775a7e61bdda9a3a990ba9fde98f9d81d4b03195547bbd0658e1059daa00da9270671b2fada1bbbf13982f87c9f3f26dda5cd4f24de63bceb5fd9390163c58d26";
                sig_s = "010a03e4ba08f9e2b6915a6c0b83156b00f59efc5417394c51ca7616b58cf91ab7166d8459eb4eeb0d57146ed6560e173faf354b4390817e0aafb38294df25992cbd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343739313135383435"_hex;
                sig_r = "017ab00a30c88faeced3e4a10f9c63785bc29e9af4499466bd8880827cfa580b6171f4a20f36487f7b94592946bca4162faf65872af6bfb1919e6b026c14e51e2740";
                sig_s = "01927515f6489e9b7d9cbf61e103295857c8131320217e7a86d3f2fdcb350da5b42c2dbe173fcb025d14da239d7d610de8475914748573429c9590d3594f4fa3aab3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35303736383837333637"_hex;
                sig_r = "003b2ba1509aea9d42d400400033952a022fe7e00c7ad65c39a2f76d41130aada99c3cdfb9cf44575a2163de29f097beb9bd3aef9334e6fd0813dde2a087f938c5f6";
                sig_s = "001afb56087dfd5cb4fff6679a114c340f3a59f6b3e1813373bf3ebe30cb5e8b285a5875d1b5a9120db80f70310201559f89bb1df147961d1ca4fcdb5e8e84cae082";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393838353036393637"_hex;
                sig_r = "010efb321a347625343f5126ed8545017d799eb103c75558922eabe44211e8fd834655dc2ec5bee9bb3e44350eb6885e0ab974730222e55f13ad27c066722fecaa25";
                sig_s = "00d62e3d7ff9215369aa7da818db302e49033875010b2f9b73d25ca5b9bf2c62ed756686230cd5f4a37c1fa881c97e623919fab827de5995ab456a1fd7ac7b85b1f8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373231333036313331"_hex;
                sig_r = "002f778cd552f54da5f567f47e6979872ba130dc0890172bf3b3bb952f03c64bc8783abe9f056d60e1667780f5ea88f59ef33c735d540561a197d31fe34853a60a52";
                sig_s = "00bd2816f06372f2e3f2582d53e583e133a551aaec04ddc2fdb7b8131787e73e4295ac28a9604a2402ed5b272cc03be57dd4a7df84d9ee24cb0c2bf124ed927defee";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323034313031363535"_hex;
                sig_r = "012a459fffea70d3bfc13e9ea0abb10aae3910df604997cb5e4bb0548abd852abac6b9a32418c3b5ed4e7951ae88eecc0a2f1065caf24c6a814674e95682d9b493f2";
                sig_s = "00e2abd05c585e0c213a219a7e7d38b810d252ffea67650d4d1994a41c2ca325bb964920c6c2545381c45ca3e1eca05e00514b366cb0e1e49b8c236d383b260b9cbd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33313530363830393530"_hex;
                sig_r = "010f2653d94aa28bcbd667a5013f9b283d8487c44d093ee47660329398caa550ca9c9388c7aadeceacac1507e76590afb736adb3583f54f31ae25c9c717ec9f89b5e";
                sig_s = "00494448a7ffe4a4eed84b4602781ecef77a23fed116b1b791b8d2e4231b7ca2a7b6f06d132705932d446e61d344714ee24014fa5bb144a96572b3d48d038a55ad68";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373237343630313033"_hex;
                sig_r = "00c2da48552c39d94f5a45427ae9dcd891b65cca33e624ad2532ffa333666b241d873336fab7bbd7b4c193db4d865cd50f0c1d8cb5c14cf3f089ad42dd43cfff634e";
                sig_s = "014f2070dcf860b96a45f2a6061e4ec2a6ad64d7d0e9fbdb25aa93b99941be280f5c70c0e32b6234df545bace7341af94c140c865d44fa8ea7ebe0fe53bda44645df";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3134353731343631323235"_hex;
                sig_r = "009bc6e74549b48a1e7c181b179687fb27d6e9acac47ec34b1b8bd044d329320544e4e568e67d17f4cda2f0a3fe303d561a11fc0c981ed9be2fcc6d397a43ad49e10";
                sig_s = "00ff295e43fec5b68b00ce8044434bcd17af1ba04a74556353e258d017ba26bed67f458fad5dd8e7d2734d56f59928c2419441a9e8c0573db3586ca056951ca935e0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34313739353136303930"_hex;
                sig_r = "0020963638d0b058494254efce57778ac65e5f23491f7adfa72e4713b7c03946b543c014d9660d855246f308085eeee495cd831b7dbece47aea48e90433bd0fe8184";
                sig_s = "0161a4f4977fecae92d4f67e56f3338c7a9b820b5e05db1f28d05d71f7e5f36bc63f6edda4d3c1b2d73bb8a30c4d745b73e634ef574cf47656a372e3eb42cc038850";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35383932373133303534"_hex;
                sig_r = "01bcc5858597ce8d4dc5ffa6be33f7d804f2f8ef59c5db9301785e0cceb7ed57462f455a465710c7414570c9a35a3100bd15fa40e3ec350d1f75406c2a25885e9d76";
                sig_s = "0043757d282fd1d44c253f9a05d8142c29a6d63c0a1f5508431bc9fb9b60a38b7f414e730e0d59b7b709706a67022e1922fe88b182a57443c58bd06a69ee7814bcab";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33383936313832323937"_hex;
                sig_r = "01240120b97ea67bcbd0e412d87137a13e347a870a2249375fccf8c004da35e592620774160e7b82aed1f57997fb015a764d014d4be1f389e5499777054576e7bf00";
                sig_s = "019f157ec3a2410853274bc4d8e7565e9eaa5dc47d5e515abc86c22fa6dc215482df5c0e2b885f37baef3a6ae83daac930617a5fb37bb03ce40f06fa4ece26cbb11c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38323833333436373332"_hex;
                sig_r = "01a7536d55876f8392a6eba18f075118c273015844eb3536c727c004c1bf23067d57e8fe31872f8bf839640e80e06aba3c0a365a268cabc2da96d84550a569f17f9c";
                sig_s = "00e840b6a7cba718d91103faa134c2f63763f3b6b91db7ecbd3b10f10171a875712cb9384325411beca9a3aa87aaae3902c282d2dedaa1cbddd40ccf0d29975df22a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333636393734383931"_hex;
                sig_r = "013f72be1c331214f45007ff72ce54afce1c910a90e4ff3d176620ff3ca976c2b62d0cdf5d1134290ee97440715531455dc29818828094d366f959e1adc7d7e98ea4";
                sig_s = "01e80ac38ba69f3e53116e5432fbdb3b1e7ea1b43e5f86d1c0e3d1c469442dbb406ffe524f0685f71e811d94a9efa9ed38ccd9213f983983035f2add0b8f2fa4ae23";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313939313533323239"_hex;
                sig_r = "01aceaa6d567ddb39ba52d297e60e4a814c9b476cab568c09d8ace878d846218dd2b5d2a2461f0d5a56c12f0bd803e3253dc5b387b94e86589cb1d0cb809c7071125";
                sig_s = "01b1fb021b10b593cf9e793cf22a88bde9a4b92f9e218094f270b093e8c6c95aced43d097bfa3354e6b98d195c599c2e6f13351c63c28967e08b7e497e120665c663";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35363030333136383232"_hex;
                sig_r = "00f6ffb5dd786326041e74564b719d38924a28329868177c13463cff90c4b09d3d2dbc011281cc78aa0e5e8656123bc50605601a547bb4b1761f852a120ea46df9df";
                sig_s = "01a407fdd445614a16a5ebd4ba075c6c1d7564f3cfd477d6b2620abf18a5bf78311282ea45b9bff813f24c3c7854e6091c8055144f9592fbf2e456421a41c555d7a9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383639363531363935"_hex;
                sig_r = "01a15af4d5ca3deadecd75ec1baec31c8d43fbc889466475e6c23106db4e63ab69003f56d819ddfc5a673c8289f9e6df806b07af57a2541af694e6489734c8eec837";
                sig_s = "0069c35433a3217fcd738a65b7da9e81cd81f04f0ef060050b9c843e9e808d8b8175f3adaefa105d215ea9a46bf415fe2ac180958fcdd878d54f8d19d23e11b76d1a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36353833393236333732"_hex;
                sig_r = "00ba899f94841db6c33b850867c8906b436be3853640dbfc863197fa1e5a55ce25240f2be498b9bdcfc0a89dbdca192d8f84ca3c44e5e0ee6f83e7900e085e1bd481";
                sig_s = "0086e6d558de8d8f014a85cb4a5f6908627e7a1acd70581d9d9c7d14df44d437aa09e5a10a0b760e98d46731f2512ca1b0240c602b5f0a2030485e34de9c6cd08e7e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3133323035303135373235"_hex;
                sig_r = "008eb5c92dbf5e00888b85e6bf6617017e97c04ae950dd731856b9dfb20e0c0e5c54284f411231fed1d071b321f78618d2a75c139663fb9db3435214cbac5a0dcb4f";
                sig_s = "01da0dd29d4728fe6331c8e2ade5045b1237664aed157db2a6cbdeaf5abea81324e28920a1c49c334b1226441f88e1a7f2c7e01d63e950d4378f08973db16b2e6161";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35303835333330373931"_hex;
                sig_r = "0130779f943df098ddb5315cdca4b731c83472d589f4ba4d32c172faf6b3a9e4154c0517fcc5c432eb269b0152297f6df490ece59496bea8047e2f32d0b5f91e85ef";
                sig_s = "00c9eb0b56273114ce2e553341247da86b813bfd65f143a5562bb1c874ff970523836bcdf390dc196e67dd75cd28112ef74afd51b1fb35333be0505a012efebd4e22";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37383636383133313139"_hex;
                sig_r = "00593f0132f7b5c282355978a2cba73fd3bd5ce3272066d4ad9bd8bd8b3e2be0990071b3509ea445dd155cf97e294e2b8d1355809d880e10700eeab0eb8ebbaa4f09";
                sig_s = "0107eb3d5ed75cbb9bcb9278f2266c14c57cf703cbd8f7c7de45c51f0f3baf1dff6bb92f1cbf89ba649677bcdca776fc57f587ce714e2e43e6cc523f0d0a286d38fb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303832353339343239"_hex;
                sig_r = "016ded17fad10f945e3d953b4fd3b72898c370f15164bb7712673385c10bf3929bea293e08bfc30029a465138ad47abe604df807b31707fef55adf3e104920038e3b";
                sig_s = "00b76b212d74e4b6eb994d926e9e796975235fad90e339a21a329e6eed3fe96b6d3c0d5426e8464c4a9ed5cbe08eeb5e490f72e9e0406c0d76ad076b476d07c0144a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130303635393536363937"_hex;
                sig_r = "01f8624ffa5a6aa8d9d04ed1c2272ea55f5271ca2cfc9aa6a3778a0b8a230f611e5d65af18d8251a0cc4ace663878c33205239ee7e8388cc0a040ea51515072e3f61";
                sig_s = "002c1e61197229f40e840ea37325f3bd87a6cd32d080bd61bbde4b072cf7a0c8a89d402cd9235c26f19a084ddceb1cc0bae4006251ccbe10de3954e85a8c5efaf6cc";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303234313831363034"_hex;
                sig_r = "012b01c6601ceca9e58e8abb85d1f6663df70cee761a756b77e45294f09ae609a6b76cfcd67f60e47a3494cb85511e33d92a8d297a1b89e9a9038c0c5b78c3a3d4ca";
                sig_s = "010ef5d2fab59bd42e2e92a2fca7a975b959dfb372519330defc8fa8954bfcfb397ba939edb6a944a2ce9f6fafbfcda6092cddf628801f6dd8cd40cad4d809d5c1bf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37373637383532383734"_hex;
                sig_r = "01c54a330b9dc47eb88dbf60c9ee49f2c7518c0a78baf642c74105fe283fa4c357ff22931ef42f92d16d6a0b806ef718539d21cad71955a530e21cab49a56f561673";
                sig_s = "01c2cc32c5a4d335c48d0cbb0407fb7e4729c57251afbf9534c5309b94e6aae13614a1f2514252f48cc7f143ee761782f8dcebf2fb490e08fdeaf570a7ed9d287da2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353434313939393734"_hex;
                sig_r = "01467b4511b9d6601da3557b8ed432c14a80e5999847be136c756a88dd5134689b5ab70d0a2e8fd8d6141e2b143282f98afb93b7e17609522dd9e64c9e4a31c7c34f";
                sig_s = "00f50ee66a1dfbf86167ba5968d4ee3506a7cffe0f521c1bf830d0867241e345d319e77eeca45858bb3062acbf8d100bc6bfd3127d57a7e91a8199e05052b8ccf304";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35383433343830333931"_hex;
                sig_r = "007af90f6227750f917d65b1c60200c755158bb783a479be6877c59ed89ff595fea3f3a4137591aab23826ed385bd6156277364b5d603ca272259083e6e9ab5db3f9";
                sig_s = "0070842eb62c894935b82da15ca611d9d754ef57859e0c912c0358d0820f4940cdf5360f116a7547a81bf65617f182e597eb1007e26c62838487ca021c3829a590db";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373138383932363239"_hex;
                sig_r = "00b0169e68062caa79f99ec0c72d83c4d0fc2a1c818665cfed1aba3e684392b9a95afb82ddd1de49e3fc3cb3889b4f5a86a7bdf944361db2cfa57021a7643fcfce95";
                sig_s = "0115ec784e042436892c6cc1bede0f4b7b6eb24b300b1f0c674999a6da816dbefb2d53f90b0dedb962a085e5209fcea50311130800d2a9249d279c7bde2f88622512";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373433323233343433"_hex;
                sig_r = "01de4ed1ee81d5cffcf8256a06858cba5eb925ee68e3ed848ac98071b6e30c3b44b102a2de8117cce5b4f9e42603225e0dbcb3fcc171d1492e7ed8bcb6ec286c7de0";
                sig_s = "00fd1e93bbc8b8adeb7864a2bf8e29d6f9c0966fe3d543525bf268b57cd6fa8852bfe0d2750726d5445560f2fc211aa7859dd3ee10078ef907e49cd64326b397e01c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343036303035393336"_hex;
                sig_r = "01fcafa62ee6275443d7277fc46e4c30b4db845ba45b5d6b54faf47bbf921f825f6fd0f23a38c0c7f4debc33add282afad1154c8707b6e18cd65adcb07d32915b462";
                sig_s = "0087a27b2bf3c35d18fd397e0cd7159516cf563b98441e030bfde93ceacd2c4e41228b7b33443ef0a351ce553d6d1d71c12092df796276175cd779b8090c4958b391";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363134303336393838"_hex;
                sig_r = "0078989628acfba86d4bf28beeb9f44001fb8f2d8e245320a19efdede31eae3ec8b496faec30c85e8f63f8ae06046fe1d1575321fa04953e460f6b1386dd5df94edb";
                sig_s = "012aba3349732e21a5bb27d7d6facd8c7688b9d0d0271d6a077f9d6d82db45b5456b767f4b9f1a80f487031f9c0b3ea833c63fdf9c6a25e6b424c19c2e55305d7a0f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303935343235363835"_hex;
                sig_r = "0014a5a46a3ba415f6e8c566ca1b15fa2055649687b1a9fc84cc0fa8631296898fe014e0d45927e4271396baa4cfb3675669b16e76c339db3c0edaf61337e8bebe91";
                sig_s = "01fb313129757f76754b60fdb1e4077f9fe3dd62c8bce52190cfeb9c03021cc92f6d7d1302b8a84733486bf769ae94d3db4b60b6df28fed481d3d7c510299f0c319f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303038303938393833"_hex;
                sig_r = "008a3250eb5f28b598c4a42890d25f6af84082d4376f84f1717e5112a76623e6fe0d207c39463d20bb86341bc26c9f68bcdf794671a01f90465025f87a8c52137edf";
                sig_s = "001ddd317f6622d9b032223f76765ba6c9116ae4b43a1bd357bc9db6fa62f0867dc5d8f781f08c1cbd49b4424fe8c22cfd1dcd07cfde7b3598342442589825aa67f7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353734313437393237"_hex;
                sig_r = "0060ee161741d5cb2dd0ff2cf9924aca0376b1544681627a31688e4d8b3b63a01adbb417ee113b9ba8d4d13b7b4e1b14b51a24dbc3f099b068d916aa94862ee081b4";
                sig_s = "015caff8d30141e1c163e3ec62b7e14874da624a6d8e0252d8e829860e5a49d3732321b625262e5c9b1ef348c3e7cbb1de8227513f320637866785e97e1931d35ccb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383636373731353232"_hex;
                sig_r = "00a1ef8229db9f45da38ae3b6d601110611e209878bbd03ac2a6de65e8402957c669a115e3f02d085fe2d031c61324b77052ab346b4b1a437b58062fb36f9d56cf45";
                sig_s = "00cc5c0a3b68970279ae16880f6ca579d0171a827e99a46aa82b9242dcc09cb0b22a44ebcfca84293e6d21aeea492f00ba3157c5b6e2e4caea6a1c09c824720552f2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363934323830373837"_hex;
                sig_r = "005aa0c8a378c4e02bcc2f56c2c365ccee424e2973c28f0daae8f4c3f0d90b421fefd456e749087e0c667c2a7147bc67b90c696244f216b4d9d7418eadc7d06ef1d2";
                sig_s = "01e28914bd341f526b041128f2d251131d8b2c65847e541d65adca3442962cddb2a71c64fae39fdd56e41686ad632f99c6038d8de0b3aac4045e0a961efdbf4c6a22";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39393231363932353638"_hex;
                sig_r = "005a05f5366c8b8be28654bc39a6671d1b1593495e445c07c995c3be3e168ffdec92e44288802fd455007f8746570d93b5683e4d40e9d9e59de539f0e62bc40d92bc";
                sig_s = "0187a47d8f70adcc5e10267b8fec89d7011d9985427645aed19a8efa2d1189b469cb7aab1998e0c1d2fcac5a5054d79d2ec1c9a00b183dc9af20f555a1140be2dcef";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131363039343339373938"_hex;
                sig_r = "01e213bcb8b960b1296ae176993b2449bae556b6d90df2f07fb08ad8fd60e3b7fe6c73f9c8a7364417611d60119c550261c54bbca8d61e264130ab90187e27d22dbd";
                sig_s = "0034f519382cfacfd07b0a6f3aca117c13d2be725d2f9ee4e5f88739c99121e63ed7358046bfb1575fc73e1ede8339e46c5139843e52e9184bb8c579061a154a0b8f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37313836313632313030"_hex;
                sig_r = "00ed11ac7efb1f29ee64108a5e2606fa9af3bbc12d1a952e47240d5236df64f5b2b77a0f7a0a73d30d0708b5b23ac6d584bf6997d8851623793655dee8774549b829";
                sig_s = "01e1602a2cae7d3212df47eebd12e2fe404851201101bbde702be9d74d040ed998e79a09ebf6d055f94473b1f8d87c99aa165bdaf0a5f270d46caabb8e88bfa54103";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323934333437313737"_hex;
                sig_r = "0007123c45e6e9338bc9fe225cdd96c5ab36cad5c06163f44f6bd903c7594e8068ba9bc89f652ec31b6e1298766b246c1f10877f1e3ec9829b0937b8d36e3c1ab2b5";
                sig_s = "01688bbaeb188b5047be6e8023b14fb121eb1451dcb19f814f5f4dca55ff95128011e3bae505a4d22166d00cb7cf14130590335ee923dc5db3e736832a128a067aa4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3138353134343535313230"_hex;
                sig_r = "01264e3cc4fb802aa221d0787cd0cdf44eb6568982a00a6639f15238af36e894b14f45f06f8c2180fdeaaac77f674e056d1928cbbdfc4b2ceca0b35345ca07bfff7f";
                sig_s = "005c2dedee6b3aa096fc47ba0991a077ef4d5df20d8eff1bf8354412b171f08a98cea1704c8189a7951b0e7a8270ccb285b8db8e35285ed926b19c1eef07fdc05ee5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343736303433393330"_hex;
                sig_r = "00ca3814747888751794b0488955e2aee07e5fab4b9872074aa7432698e7c83b8079773734df1bc752548a218fa59a362e0657b77ae7798ef4a7a3873256ea59ec67";
                sig_s = "015df8f1f16611c960d56647424b97936c8a06f62dc3a95d66bf4aa378d7a9e17d2afb53565780025927e6928f5313428f1d6708339787c8f460ba18457d4c0f521f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32353637333738373431"_hex;
                sig_r = "017ba871aee34a893c4ded7a2a546da0d6867d428497b80fca7eea6e51b73d6411aff7609743e6242b6d4d3736ddcc9ee1aa12c8b62de5382e5c33d1fc4853e3e47d";
                sig_s = "005feb9d9f8fdd44622e4f9effe73fd9b467d355fd6b8de205527f722ee2f5a15eebd59ccdd7b57da26cf953f78886db5a6e5bdd0d56c9bd47ba2271f77687a64b63";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35373339393334393935"_hex;
                sig_r = "01840793684765410baf26b66cbcf7c36658d6c18a2f750c1225520e9f3a7c1b890583f321d4e48752c3b3116dfef733ee386c52a53402acea77cfad1db9380110e6";
                sig_s = "01b51985a306fcdbe3692181106d7d6308873912d003946992098bc98b4261fd78869ed8218849459780b6079f6899a47fcb9ea4874d1c08fab82c6f1e9c9aaae245";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33343738333636313339"_hex;
                sig_r = "012276720b2725ba556d06be39cd16ca0a0351d8f530913c4f0cfb71fdda74b83f02febddc8da0a1f0f910d37d3f5332c027d7bd4c38fd08ebc770bf125207864954";
                sig_s = "00637e70b06045a86e2f329f907e079a785d7f8649541860322fb8b64b9736363f90156b9a5532d808cf2af33b87ff970c02e648dc4f1c90ff0704028ec2c2d9a82d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363439303532363032"_hex;
                sig_r = "007aade608b22c77245734fc5c4be8737ba24dc2ed4321b58124ae46a77ea7befaa5bcf166cb966aad007911623af10925a324bc3c6d06f24d0e2e7b2c7b8468b8ee";
                sig_s = "01e9913a412300b3980719148de0bb03826184aabd58f19659aa8ca18045f36c73c97df3d12b921de510ffa96ceac5454b801c86c55a06b2d771fa77bca784332c39";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34373633383837343936"_hex;
                sig_r = "01eefc7b6c1468ffa7d60b8408bd44c64a3ffaff298168c5016c6f504031867ea14ae48c661b8124418b4ed6ccc32df6bac6d0a485b1990236e15676268b7868d276";
                sig_s = "00515d48436afffdb65caed737116a861974b734bd1903e37dbbc231a9db37464ed762e364cac8b32f1546d6de37979fa05f8b80159a0f747d9470291af6569d6d94";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353739303230303830"_hex;
                sig_r = "01271b912ca055040c227955df729757654aa9bbdb73c61ba14155220e4e7132319f6fb0ee94f2fbe160738f1dce2ad690845c38d962db4fda1598e93270da84a2bb";
                sig_s = "00b8907f041c3b19b9234ab555d0b48325b0cd330889a53276a1e913bab892b9c05cfa889005b14ee2730220746aecf12af911c5baea4be377ee76c0eeaf47b7a712";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35333434373837383438"_hex;
                sig_r = "016a813db0f75f9047fb11f3e19fc1688c29328a54f56ae30c1c9d9378537bfc40c5719d084e49a3b4aea255f5b7f6cc775492b5371e6b67b2d6abd5743e10fac709";
                sig_s = "01c258ffd830151bfd41ccdabb86b24af846612788b361c196d24e997ccf3f17d4452f63d32851a483072e6908095e5c49bbc241a0417749b097bc1ca0e4d127779b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3139323636343130393230"_hex;
                sig_r = "00156a04c22ea5bdb7871124f1117301d781113ac4c9d4da05fea536e983d9261d25dc97006f8c78de23c788718557cf6f98863994af2086f0be3e8aa8812dc3a11d";
                sig_s = "00ffca96b04c56a4a6ce5d22b36e44d3b974d520e7f7c0f9d69034f9e59e0bbdc43236b3e4bfb0f6bde8802cc5cd6022cff166f4c488d64f38d44e3c563da31cf6fe";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33373033393135373035"_hex;
                sig_r = "010913540ad73ceef7314d1758264e1d1525a371a7b9b3086971599a6b749be4d6ba69269b089508f6500dd925aa89a7c7cb7185e0cca7d2ee5664f22845d961e317";
                sig_s = "0135256c79ea5e5768fb3a55e2899b12219b8f68953ccd98c710b6a13de0f59786f4331845e65c7dd6340023a5e280206ca31416058f395fff4bb5de411ff66fc018";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3831353435373730"_hex;
                sig_r = "01b5051ca0dd3b20df7d8c5b92cb42b8a204f92fb4e58c612f43d3800de8c0683c427e832ce622156747052b81bfbf6ed5fa177b6d47858ec8478f6c9ca7948fd511";
                sig_s = "01fe5710fac0e9d3e2b3b83081b28b194b822d0c13397bf1516140cbe3faa52e908848f69789a741b9cd54d703a94577fa813e2f2c75834807401ca010fde5328317";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313935353330333737"_hex;
                sig_r = "008d3c8f8e7ab74d49e16a4c7db3a393fa9567777e373313667f9ce32b1b5e648debffedfd2ff5345ca1b8154c18c8b883957d911e41336285f86261c3ee225fdedd";
                sig_s = "003c51b84c2c9a3feb76a6518634b6f09c0dde8a9d08dec0b3d66135cc1bdb0a80fd69636104af69de8f4062646b29fa3af685ec82704cef706a18c59ca7eca0fb56";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31323637383130393033"_hex;
                sig_r = "01195625a64ac11c4fc1fc479ef80430eb85c1af77f8a197a17e009569ef6c41ac6f35850755379f478d8928b154e3baaa29e92b481ac04dc72f3728b4f088ff37dc";
                sig_s = "000d55c7067877dd1302fdc6bb69b7b7c024e4cf3a0e924102d744ac52366d9d76d5855d3da228c4b67bc7bc4b2a14e7999962cc9bbdc517fc24a823abf584b8f56e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131313830373230383135"_hex;
                sig_r = "0026eb68bc0fb7664c35bf5762cd532dce33b0e396e97d6f4143dc6e1e766c836e27c069da9ea1e74e0b03d030cf8a81490508c1c728f86e59282df94de8d8a0dcaf";
                sig_s = "00a9fb584b712986f19ab7568693df278cafa43272dba400ff333cf48b5556e6e78353a665605c70b6fd0f18f30b850e1a47cda42c4c924bca80102e6793be9a8698";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333831383639323930"_hex;
                sig_r = "00f3d34e36f9754dfa8eafab160ca96d91c7f4f388ec82ac33784026bb6c6a035719eaeec3ee511fffb22dd5d6ab819e6c6387192d6c3a6e9249ead565157e323f62";
                sig_s = "01b5786b1d662d26fe9f69c370d2bc18882abef693c8f17100a02725de7c9f03602fd53a9208b573b3b7b0b66db971767bde835f9e8f42ada201e7b7391b86fe0294";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33313331323837323737"_hex;
                sig_r = "00e69c833b604075e9b28a2ff73a56a32e1a247ef9ae01e7a0e471f6015c2b86eb864c281c8c93d2acf5653ad05bafab2f58027f37513eb8569f50bd475e770e9a81";
                sig_s = "00b9c9d6ce09b53025bfcaa7d172ae41a9b636aa4b80a930931fc99e5e2aa23306f19dc57399b0431e72440a1f4ec7d5ca902f0f7b81c91de85e469f992fdfd4c52e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3134333331393236353338"_hex;
                sig_r = "01c6b8b5cf3c4dd3d62391f18e97eef3aa6ace0ae2c6fc97a561cb8e49c087dbcf8135fa433b566b3385cb57202f1b12164fe62765ef73b72a94e7a57870989a4981";
                sig_s = "0185944434b83a0d0fb4bcdce8ddaadb30a1e440815e7674562df9c8bf711222208cc346b9665d90abedb437912391505dd5d26f0178e7c063790f5518f47d1b05c7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333434393038323336"_hex;
                sig_r = "009f351a41d5375b8993e90b8d8a65bf01d52d14aba1dbe49cbb4ea823804f2b533e0c167903c8bbc593297c18f309798a544787d598074cbf56ef0e5022520912ad";
                sig_s = "01b892740a57204186bd5f434f72d1534b4289f8f7114cb7b1c9cf4541d754f314448cc32deaf35608263488fdc7596f7481ec098b36f8e440829194becc746c77f5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36383239383335393239"_hex;
                sig_r = "01fe24ea831199e31cc68ef23980c4babd3773040870af8823a19708bd0229adc1ce99d02e4d95224101e3e974236f54df86051fa1e9fd21380432633b2495ab782a";
                sig_s = "000efd1f2a281f967e7b09d721581356a714c499f9b14f781992eb9ae7a19f6825045fdc6d9d763f44e1e7c91480a678a1d8ecf6d66e76cea3505f65ff78cff15cbd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33343435313538303233"_hex;
                sig_r = "014c6ee9de0a2a0b60c981831e0acd6636b46ae134fedce61b0488112663b24e1d7e74e227fea883d26b68f21e4135ba0e2069bbe0d9c6433c3908fd5b00182894b0";
                sig_s = "006a180a493182c6bc2a09d7e17ff5d62015293f1e8ae205a16fa09042b0a9af6794cb377f4b8b1175fcee5137c234900f735c484feb7da4cbb405cf9e5370fe4f49";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132363937393837363434"_hex;
                sig_r = "01044a45853ada17ca761acc7df6d1d380252cb0fa66124d9278a5ed8a4a60453bc71de1dbe32b0261165948823c461c7c1eb1714ec1dbf66fd602c7a47446d1dae1";
                sig_s = "00f8b27f7c71e37e4b440d2c86f1c1d50bf7c53d3878ed27e7bcfbeb902f769f86d6c3e8820b99f890050f0dbebd2132e84626c5b16a8c7ffffc3a30ace69dd15a11";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333939323432353533"_hex;
                sig_r = "00676a381b18d05207cddd73b44e4dd71449985c0fa7de1fff43ca5155139a1a09e5e3fd754d86ebbe32f6609f6e906d48d24790e494343c61faa90bfdaa4f49fdc7";
                sig_s = "00fbc1c891bf6e368fccad51cc9b2c29e8e92b658e88c0d23285af269aff6702a55a0ab16807e5523b6637bbb004727f6f55c51ad4cec8c924f9c1feb24601aeddef";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363031393737393737"_hex;
                sig_r = "013c9a575382ff6881c908fb5184be7baf38edb0b06008592558efd57dd8fb9993c893800a6ac8c6d2e34ebfbeff43e63263f133868d0ac7a838f69aff26d60a3849";
                sig_s = "009d22ae7bca8a75a53214c3eece437fb28e05b076ec704d751a28a7ed7e529d5c5338be8c724afa547574a17f70510b2462748a53678e39752a688dc8cf39e886c2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130383738373535313435"_hex;
                sig_r = "01071ce5a19a09aacd43c7cacd58a439dcca4e85f94ea1d48a60f298ee01bb3eeb11d5daf545e7086486f8e4b518a15be69620ab920cf95c5c15ff178c903124fac3";
                sig_s = "01ad6eaeedece9a7592bd21508b2720f1b8c4bf55637b1e8a5ce5359775b980b21eb1d33e8ebf5c0b3d7829152a295b8a9a1343c25350e35f709936accc8ce08b0b1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37303034323532393939"_hex;
                sig_r = "01bdae499160f4cc6cd163cf110bb1f9b421e8786a8ef9297e4b98fd508a1d14c50617c8d1a3de94fc8bd6c38055e4906b20fdcab6ef7bf9e7e5c98ef3e83e38ec3b";
                sig_s = "01ba867b8ee72bb7304ff83fc2d734749447420791d5609e0515de4e05fa70a83385a853cac6c47a075c8c61e4b65b9774574101cf4e081770f83ae1b7e727010ba3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353635333235323833"_hex;
                sig_r = "0000269fc7ed89e554aa52b3875dc00bc140c1937d4f1b32e29da41ff241cdb9bd3058fc148f905982b8717b035e0db00ded7ebcb08572ec76bf0128411145d73091";
                sig_s = "01b4bd6bc4ba7befd5c305e018448a771b71fa1a11b3a2c6185dd6b8477c35eaeb4733fecd90f38ecba628f27c02f809191e993e1e7ff590383e2ec2afd08020b267";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3233383236333432333530"_hex;
                sig_r = "01a5cecc0e572f5ee4eed6755d3230ec5a933c1fb0e35ae771a1fcf0dc880e1c159dd5b6d192dc377505048b7188de3feb815a81a4f30d9226cdc85f751dec1a0410";
                sig_s = "01ef4a743e1e16f0a60201cc1060625ede6f0936e7af90b42736281e89fe7f2de6aa3f25c68576da705d8b3f6d5d8a34d3073307ea198d1cc8d72a18ef25e90f31af";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343437383437303635"_hex;
                sig_r = "01a92b43f57421e54d2528d305e7d5aac9a708e75a7d6fedb47908a4e3edcabdd836a2c4e8436f3b7b64895254536174d88c6dca143699522bc2dfdeebcbf38eb905";
                sig_s = "0093b0b99a89de72aca0c03e12724c2be323577a4629cb47fdda5b12b61ace0b9fdb97549d3d2a1dac15da66ba6389ee54cbc82c995b9f3aa3ae8474f4bb4b52da8a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3134323630323035353434"_hex;
                sig_r = "00a0400f255174ffb8548c29f5faa70e806bb6f6ca08a08753c85c5d145a555cc8e2df285af9985f2e729d4a99a734b7e7fc95560d546a067fda03529f56b2fe66bc";
                sig_s = "00d7fb60271d22ecb5d8ec904a9df1a416be706ce539e34650b8fc514d1dd7afebc1344c0c68c533c5b20ee249a77c075293b2d7efc8731c2e3619be59da871bb083";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393933383335323835"_hex;
                sig_r = "019207c7b645aa45c2722331f46e094f2eb0052075b8ac9414ad77baafd01d4d1fdc68344136fbce01edfa5627bfb8f3c128abb61072c74802192e89137c68d0cc31";
                sig_s = "00ff15b0218f81f0a848742f683cb4d1b7c517efdb8fcf8ac6a35e4971b35536851ed68de40a6e1a4a23bddb5b42efca23b91e91959a4f7e2afa196779c96c6c654c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34323932313533353233"_hex;
                sig_r = "00aaf119702b9985354bbe3f6b6cda8c46151af4202546dfbe04d5f0ffd18ebe7b29d616f1c40376a412a52f4204b5a13e7f3e4304ead566fc41bf4b5fc0b84c8a2d";
                sig_s = "00d599deafd4fa2368cd072b854a3d53425d06adf3573e886b81248a7328a546ddc41caed38c6b1ffeaec9a98c940905cbffa87b936da980d4a9003da41e0c59c92f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34343539393031343936"_hex;
                sig_r = "006c09a59e71cf34f983f75dbb4724c4828a93021cee8fd7d92af6941ca8efc9c5ddda7c49a0e1777225782e09313e3091f056122e585c4eaa689fb2fdb1cb7848d8";
                sig_s = "019f0c5ff6b4638f4c33916db76f9d078bfa8f9e25ae00348e46bb32d777aa26155b82ea73a9e4e2f21f6a65c73ed6c6ab2101cef3524d45b9fc6ea1292f1986acad";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333933393731313731"_hex;
                sig_r = "014e791c42f3998458c5e17f895d25c85cb419195d65e5a0b9a42cf13ddd36959c73460f54aa840d2254355c6ac626f440cb3a84fba632262c9dc5cab31be7da106b";
                sig_s = "00abb97b682f01f45168403613a7e2ff82bb4a9fc20952a35d935428f71ddcc799c6d9085fe3230d72261d73cd082e8108523da7ba0b1691ad6ea63f5f4e8e8909f4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333930363936343935"_hex;
                sig_r = "013ded35ddff2f97780bbc60b8cec89855a35183a48f8fa6bbdc183994bf89021118cc019629df72112b2c529c023e7a5cfce253f7fdb49105d238680b64275a213c";
                sig_s = "009c92e7a0f71608e8d8cfab3f850f7fda1a1a1d056e72254469afe5ceec3c718e6a462e1346941eb08c105501647502c1a810a29df8b208da6a5b296b2bd1e98137";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131343436303536323634"_hex;
                sig_r = "01d0d29756ebff02b71674fa4eae37557ccd51a036fb1eb0b7121b405e7fabd60592927d805b75815af1bca6e9d6c5484225bdd0ec7a40735da972fd5ff645d86f1d";
                sig_s = "008b9fe55357dc118070cf898973a64e7554b734e900c675541e20332a260ca51a23248d9b8f47ded811cfce556a06a71ba5dc5b873075f264a6843e675caf06a534";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363835303034373530"_hex;
                sig_r = "0165fb993f39d350ed60c8483dd6e4e6736591dea974ecd8ab027d3839b752322ee220d40bb6fc0b0d5a8c42928bde50f659b18f51f42fb2b1aa4583892a9114a0c3";
                sig_s = "00a8816c09d47138bf662da4ba25caf44e24185696d4914a7de2b2535f73b9afbd3ffa9cb0a86a115e4d9ac5be48cf7e8fe276466abdf17127bcc7aaf4d096008ca4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3232323035333630363139"_hex;
                sig_r = "000b901c88ea699e715f6db864e23a676e7f7f2415ac1f850f2dde1ad0d3f9c92e8c5de66d45174d619955fae4b0dfebe49c583506481d28d30cbf58e2ac49f370c2";
                sig_s = "0144c97b688b9ecc07b84c68095267e17e48232922756609e9859d18d2eb7844ec925150c39f2b3a255c882be705e0a8e30e68e49fe7914dbcc3ccfbc1d467050f80";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36323135363635313234"_hex;
                sig_r = "00abbd9e77ef1e2a36c6b06f063d93effb8e852387a94bfdf8359b5c18708f90d9f4e9749fd45347f637546b08733789c988fda4f0309551bde813a0bb1a232adee1";
                sig_s = "0191165d58d153fec68f5cc83bcf5891e2e0ca9681204876e872453e9ebd45870b6878ee437e4d833c6ec54337b779acbf9f8202df510d269a710d0c43e4e07b040d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "491cd6c5f93b7414d6d45cfe3d264bd077fc4427a4b0afede76cac537a7ca5ee2c44564258260f7691b81fdfecebfd03ba672277875c5b311ea920e74fb3978af5", "0144a353a251b4297894161bae12d16a89c33b719f904cfccc277df78cea5379198642fd549df919904dc0cf3662eeab01ef11b8e3cb49b51b853d98f042600c0997" );
            {
                // k*G has a large x-coordinate
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000005ae79787c40d069948033feb708f65a2fc44a36477663b851449048e16ec79bf5";
                bn_t sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386406";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r too large
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe";
                sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386406";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "015f281dcdc976641ce024dca1eac8ddd7f949e3290d3b2de11c4873f3676a06ff9f704c24813bd8d63528b2e813f78b869ff38112527e79b383a3bd527badb929ff", "01502e4cc7032d3ec35b0f8d05409438a86966d623f7a2f432bf712f76dc6345405dfcfcdc36d477831d38eec64ede7f4d39aa91bffcc56ec4241cb06735b2809fbe" );
            {
                // r,s are large
                auto m = "313233343030"_hex;
                bn_t sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386407";
                bn_t sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386406";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "336d5d08fe75c50946e6dddd36c550bb054d9925c8f254cfe1c3388f720b1d6500a90412b020b3db592b92ab9f68f1c693b8d1365371635e21bc43eaadf89e4e74", "01d48d60319dfd06f935fc46488c229b611eecd038804ae9f681a078dde8ed8f8e20ad9504bcf3c24a0b566b1e85b2d3ed0a1273292ff5f87bae5b3c87857e67ed81" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe";
                bn_t sig_s = "0095e19fd2b755d603bf994562d9a11f63cf4eadecbdc0ecb5a394e54529e8da58a527bc6d85725043786362ab4de6cbc7d80e625ae0a98861aea1c7bf7109c91f66";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6f8fadedbae63701072c287c633f9c0052ea1e6cd00a84342cc0f626210071576abfd0875664b0746cdaf2745effc18d94905b0fc9d2cad4ba375c0ea2298c8d1c", "0150d128cb62a527ae6df3e92f1f280ea33248711ffe4b35c1b162a9508576860165e0ddc361d96fafcd2ff82776c743b9cd6845db61eb56739f5c4ef561e6c20d8c" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe";
                bn_t sig_s = "0015837645583a37a7a665f983c5e347f65dca47647aa80fd2498a791d44d9b2850a151a6e86fce7d7bb814e724ff11b9ef726bf36c6e7548c37f82a24902876ee19";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5e7eb6c4f481830abaad8a60ddb09891164ee418ea4cd2995062e227d33c229fb737bf330703097d6b3b69a3f09e79c9de0b402bf846dd26b5bb1191cff801355d", "01789c9afda567e61de414437b0e93a17611e6e76853762bc0aff1e2bc9e46ce1285b931651d7129b85aef2c1fab1728e7eb4449b2956dec33e6cd7c9ba125c5cd9d" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b420fb1fecdd9cc5ea7d7c7617e70538db32e6d7a0ad722c63580f1f6a1f5537eb50930b90fd6fdd9abd40015f746d2fd8adf945a75621407edb6863588e41979e", "295108a7e9d2191a287fd160bd24f498055dc9badbd61c6a89fede27b4f9d479d86a20b6dc07c90f008ebe68a0e0cc15a4a03b8cf990e4ff7ed6e3892b21c52153" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "32b9a17c201aec34d29b8c2764e7c7f6aeef10fb61bf9837117fad879f8c6a22a300006d2018cf42b25898ffc9a1bf507352e59e6a52e627cda160e17ea2f46005", "317a89899b7cb3a0d33eafa02b0137a0fb1b05102b22b676f35b9ff6c050ddee9f185609ffb7f5165a769e440792b75044a43e838690d13f884aaae888bf5f86f0" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "10b17d53711f5157f79062c0e034a43b63a8b9893e6032961a2914b78a63658579c6c069d3e03f47017f45d1c883724fa3d492aad8cb7f445b4a3d14926be29c24", "00a83583cf3b5b4e9e1bbfa0004feaf743d7294d6cf4bde726c0ce013db32cffeceb7d01d1af3fd2f214e98e6fc2e40e27bbf675d766f2ecfda075f260cb530b3a29" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "19b553db7e685e34f50662436258a16cc2fc08bcdc5b44755aa24f1e9948e1da4d15e2bb14a2612c1990a43a7b8b81c0be2f614daba72abd551f78ab998f4ff541", "010a807a820f580b3b1f824c664d7d94f6850c167b2c867e7ac7b8b4b8b6905e2c09df4479ce2073f0bc83b73fd9de254aba29f6b5485385d9f647b3e57d475c6502" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01daa911a9f08107cc86a60ae577b1e8a6d898d5a8714610fa5630b5096748c87ff3de68fd1c29695bb632380c335564afc1e82dac15c790775dc6d3a27e0f5ed97d", "0094869cf902444247d35dabc6ea924953d859a0b2e74b303c3a02def7ed51cb52e9aae611b6d6c9a488c561957cc5dcd652b42c121387d164fe57af38111226282e" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r is larger than n
                m = "313233343030"_hex;
                sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640b";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01be3fd44e342b0a202a55ee167c4a98ae61cd5f7a02eb138774bf48075e966edc15054cb1e378ceb836fc648f3038243ed250f515dc8e7a6a129ec413aeb983963a", "0197a4055e496aa30e5233141c16ad5342cc9cc4fde6c4982ab6d20aa6b0124b76f16267bf40e0f14e87aff05720cd20e3c4f9b201252d61b4d64f3a3fd61cb186b4" );
            {
                // s is larger than n
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e914b3a90";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "68d7b518214766ac734a7461d499352444377d50af42a1bbdb7f0032065ee6dc341ccf231af65250e7d13a80733abebff559891d4211d6c28cf952c9222303b53b", "00a2f3d7e14d9d8fabe1939d664e4615c6e24f5490c815c7651ccf6cc65252f88bcfd3b07fbdbaa0ba00441e590ccbcea00658f388f22c42d8a6d0f781ae5bb4d78b" );
            {
                // small r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100";
                bn_t sig_s = "01efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7ef87b4de1fc92dd757639408a50bee10764e326fdd2fa308dfde3e5243fdf4ac5ac";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "011edc3b22b20f9a188b32b1e827d6e46b2ed61b9be6f4ada0b2c95835bee2738ec4dc5313831cce5f927210a7bc2f13abc02fa90e716fc1bd2f63c429a760ed2363", "0118daad88fe9b9d66e66e71ce05d74137d277a9ca81c7d7aef1e74550890564103cc0d95d30f6205c9124829192e15d66fb1f4033032a42ba606e3edca6ec065c50" );
            {
                // smallish r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002d9b4d347952cd";
                bn_t sig_s = "0100508d073413de829275e76509fd81cff49adf4c80ed2ddd4a7937d1d918796878fec24cc46570982c3fb8f5e92ccdcb3e677f07e9bd0db0b84814be1c7949b0de";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "012f8b9863a1887eca6827ad4accc2ba607f8592e5be15d9692b697a4061fcc81560c8feb2ae3851d00e06df3e0091f1f1ca5ec64761f4f8bd6d0c2cab2a12102444", "0174b4e34aec517a0d2ceb2fd152ed1736bc330efca5e6d530ea170802fb6af031425903fa6a378405be5e47d1e52f62f859f537df9c0f6a4a6479a0aadafe219821" );
            {
                // 100-bit r and small s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001033e67e37b32b445580bf4eff";
                bn_t sig_s = "013cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc3393f632affd3eaa3c8fb64507bd5996497bd588fb9e3947c097ced7546b57c8998";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008aed779a32b9bf56ea7ab46e4b914e55c65301cdbe9ea6e7ed44f7e978c0365989a19a5e48282fb1158f481c556505d66ff414a07003ebf82fca1698c33f2884c6", "00a62426993ed5b177b6045e60b5fa1a1f8ce1ad5d70e7bc7b5af811dbf86e651f9ea02ec796ab991e1439bf07ffe2ac6052a8a0b0174d78a9441aaf4d8fc757d80f" );
            {
                // small r and 100 bit s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100";
                bn_t sig_s = "0086ecbf54ab59a4e195f0be1402edd8657bb94618fab50f2fe20fe5ebbc9ff0e491397ed313cc918d438eedb9b5ecb4d9dfa305303505baf25400ed8c20fc3fc47b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0093697b0378312b38c31deae073f24a8163f086ac2116b7c37c99157cfae7970ab4201f5a7e06ec39eedbf7d87f3021ca439e3ff7c5988b84679937bab786dbe12e", "01c6987c86077c05423ac281de6d23f6a685870e12855463770eccabc9f3a1d23cb2a0c15479420b5dd40fbdc9886c463b62ee23239df3a8b861c3291d28224f6057" );
            {
                // 100-bit r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000062522bbd3ecbe7c39e93e7c24";
                bn_t sig_s = "0086ecbf54ab59a4e195f0be1402edd8657bb94618fab50f2fe20fe5ebbc9ff0e491397ed313cc918d438eedb9b5ecb4d9dfa305303505baf25400ed8c20fc3fc47b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "019a9f1b7b7f574a021fedd8679a4e998b48524854eefbaae4104a3973d693e02104fa119243256e3d986f8b4966c286ab8cb1f5267c0bbd6bc182aeb57493a5d5b6", "0158b97eb74862fbca41763e8d3a7beb5fccd05565b75a3a43c2b38b96eb2ccff149c23ef1ac09fc455d808ff28081e985f9e172fc62d0900585172cfbff87383595" );
            {
                // r and s^-1 are close to n
                auto m = "313233343030"_hex;
                bn_t sig_r = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138638a";
                bn_t sig_s = "015555555555555555555555555555555555555555555555555555555555555555518baf05027f750ef25532ab85fa066e8ad2793125b112da747cf524bf0b7aed5b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009b0ce9009af6a1acfa001901a4e94738d222ac7d140321cbcf029f9460f336dfd0655af02c3b98c421eee88648629e205c8a7b55fa41f51ec8cf855be632ba5ae0", "5304f9db29a81c82379f9e48d5ee47a469a450af8b737fbd93a6b9d813afef84ad3b92d5a5d06d96c90c05145d3fa8fcd335b2e17b1673534474cf9ed1c62ccd2f" );
            {
                // r and s are 64-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009c44febf31c3594d";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000839ed28247c2b06b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "56f677b935021e01f7ea71842c2b76479e807cd3fe2705b85ffb9e103788201282f4faf503502e85c695df022cf4ecafedb361751ada93f161c8e00a26f4bb988f", "7886ff30b81ffe355ecf0961f0e0deb775c1002758c6217e02d7b6c6eaee67a7d0f94c40c8607308eaaea840e4dfb57cd0539a4f2885d1475d43429b8cabda559d" );
            {
                // r and s are 100-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009df8b682430beef6f5fd7c7cf";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fd0a62e13778f4222a0d61c8a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00dea73c158a271a3474eea33025778112f45a8251be96ae8c01f832b7e4e241fd74249cbed4486183cd9f622f5436f8d7aa6967bf93ed9dd8e12831f82c1939cb5e", "011ed960d670a15c33e4b0e77a54383bc3d475bc48ca7686b8f0d2dbef972a840ca2b9d03073e3cae697710a98cf5adbf243c72382ac237693f11a713c2a5772327b" );
            {
                // r and s are 128-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008a598e563a89f526c32ebec8de26367a";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000084f633e2042630e99dd0f1e16f7a04bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "011e78c7a24d477c1887ce80021d2db7c93b00b362d60e33926b2e872fda9619b4c5bb024d84412c959277445d21a6929041dcfb9467fa0dadb3a01a26a1a1ea99", "00802d13be68fa3360b1ea81f9319f2c861ebe336a3138e4f2e8ded1a3a8ba7d6c7064dcf84ca29e1e64125f375123737455eee95c9a5c2e4eb543124f58399c3813" );
            {
                // r and s are 160-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000aa6eeb5823f7fa31b466bb473797f0d0314c0bdf";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e2977c479e6d25703cebbc6bd561938cc9d1bfb9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01aa9f3a894b727d7a01b09c4f051b469d661de1e06915b599e211463319ac1b7ca8a6097f1be401d70a71d0b53655cdf9bef748d886e08ee7de2fa781e93ec41a26", "01ba9ea67385e19894fc9cd4b0173ab215f7b96f23bc420665d46c75447bf200ae3ac7b42bd9b857fd1c85cce8ea9c8d2345e4687dd70df59f5149510735bb9c7b64" );
            {
                // s == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // s == 0
                m = "313233343030"_hex;
                sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3877bf6711c3c088da9b4a18e6e9f5d2d6611fa56d67b5664a142a744aebd31ab4b85672fce0eed8006fec114afcd1f6eeced0c9751ac62a684840f7e0ba2928a1", "4055ce08f42ce5aeeac80a2536e75dd936785e6e38691092b030cd2261f5ebd9d1529a8cb85657d95e30febd37a7f5e523fda7780d56e27570ecb626a2570661ba" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "003766c66283b12cbccb593f39d32c356cb4ab940931bedf5d8053458cd26d03b1e9ba364d2056a8c3c7fd8b8f47ab8277adee9bc701ffe1fabde72a01dc098f76db";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "013527482d58bebec6847877dcc18fa7e60c5fb2461b10a2907bb2bcba14ebdc4e708044387a80b194a03c6be62062f4a6cb8d2f33df3071d227ef1e875d8974ae4c", "012b5396dead33bc276ad1fe88709448aadde543d70b644acc5766de7e98ef91b766430e0a809a9ccd1ce859317d477ffedb7b10b788de8ca2cd9f0ab6b4a6db0e0e" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "001acee0a06a4b00e9da99cc1d47fcb1158787578728dc13cc74a95e51fe1ac074f88613bcd4d717c3206c2a73c76172416a94110b9141ad243ba87b51a042d45ee8";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0f1a645168cb60d2de1a58ef3ec87d79dd60c3771cc6d5323e76caa7cb8f326aa38571c74c6c45830d3bcf00517680200e1af7afe0ea69e7a4930e51f67a9a30ff", "015141c86ff3e6cd8dcd3556974fe45dc0fcf6a9b6ef1e3635b0f444628ae8dd09d7ed7897701163a012ac37057f911673e8eb662431907859731850abaca59d82af" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "000ce1ddfffbb3185109966b647419ce8b553a6d70d6c73013af778f7b211aadeac70511ae766f0b74961a1019ffa18b3d42056fd9ed4d5fd982be75291f2532bb02";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a2a67b569a113f13754483464a249b28f588cd71b87bb70373d8c6661cc862a3ed4293aca92386742248783492d524a429f404fceb3dc88711a79040b48b80a173", "0171075214d4547e37f94f674747a995046a8b8a6d7b307ebad9adcb03eba7f63daf925f02c7220da107eef3e4f19e668fea2718aa5c9d2deba1347a8128bdac670f" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "00ded82c833933ca141a3eb8fd1889f2fca4679437d28e9f867afeb37ecaccbb555dbc61ef83b3f7d57c6b4ac8ea27971716e6a1a0534d7f7ea1fb7197d1c4a0d5cb";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a2ee867f515fe3a4cc539711d9539e0db9e85a49c9a6cd65634a4eb0824da585a353e25e04a3d7bade0a676622c078f7422f38cfb1e9d5b2bf031a63d2d037b4d2", "01fd9cc1f25c07963d3b246c016a3e4f260a9b5894f5fd9261beae302ee64250385dcafedddf9871072f8d94c9a654ea364bc6c15115ac38ad3694303f2cba014f59" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "0072ceb39ea97d82d3aebd01ee53d32fc02bca5887fc0a5fe373b7a0d3085249684731fd8157b3743d40caa8a7908699bc223d0df57ca11f6225f732119431b86b9a";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008a0a0f504a308b80289ad4b9e8b741525bfdeab4732286b291c9e3228ae8ab60c1381462f5569f65cd770f5e9b395229445ea5e23622e9abbc6de460db98703dbb", "2290f4d20ba24e3d9279dc0f3e5a5e104d6b5d44731dc5180fc04afebb8a805c752afd022cbb8952f3cff2795f778298713ba1b76e6b78e5c0ffac44ca8b3c769f" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "001834d4897e360d3622607611d64c4338039f8f7db00891bf5930711b2cf7d47be557b283d20aa85d9c5d2e472fdc59a35ff4ac0985bb06fa284838026cf0ba8571";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008903f9a991de771e52ed5e5936626a5510f0b412a5b76156950ac545192105e03bae9bee413b5dafa9f7460934fba63470c992a63817db1dc9d853a6794c12264d", "011f50d0e1b644e47e02863a28233ca5528bbb56b97f25d87f2e1c9edd3c7e8b5f60b600d0e6fa901ba76b2fa4c66f5b03c9e96b774940a09e01ae17cb2885173e71" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "00a9c260ead3d423c0e8bd225f41ffaea6ace17b1e157b98ccf912c90865a4bb74169ff49b4b0d62e0772905ca62b0bdbda232955a3952cf3b83f50bc5f6ae33ee4f";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "010ec0b19ae35ee4eac34047eb1f13cc442c31457d28e025e3f75308916ebd7b8c0592481c39825e6988833f8e953ac47da830e8f49c0980963daa93c2d753df865f", "00bb702a4aa002162a1c7a7142404c159f7243a1ac809b59d6e420080f358861ce0d8af52d3d376f27ab7d778da4c74b1f8641bdccaa0f44e33695e022e9e5bb9641" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "002e67568c48766d91884b0ecdebb8d9a39a359d77bc97063c625d6d3f1dcaae81cdfb198f4655d9853273bcfb60477cd0a1e435fc8bb93f8d05a20fb977e50cc434";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d3f0cf50e9a4a6f1bc5468754c74bb6e7a7198c010ff73d37d36533c2ac55e46e736def95eed3c51a7ef357c14ef1ab7f4a3caccdc38d5368b9664bf952583e6c0", "0160c26745748b22e5cb748348e5dd522099bb4b31d047d451fa492a2ae7c8adf349d4e5ef0738093f5099a6a334722c87cbc65fe5318d97ae0fc30459aff21cd306" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "0039e6ac133eb88e5b5748ef6806e750175b100ac40e3efaa891ef7ef078c9d3f2cbfe6398dc776f72cd2f904f2067c63df677f3d8162cce1de557a5aa4db6561abe";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00f1dbdff93371aefcdb1ce696e46be28cfce9dca1b1ce220930612c0d9f64b32405a5abdde91bd19effa929e62791a3c9feaf73d6d707cbe25bff9aa1e0a438d52d", "00b789a0920d47787e795895ad9fd4c6752d521ce33fd19248e415c19c54cce95d54bffc3e55165104bdc9b0810f67ae1666b3e6ef5286ae897afdba2be4342d7e3f" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "006531ae6458fa556c74ce671a556e703038afd8f769c398d080be8fe434accae8dd35e8a28545297310992dfc74efdbcfc3335e0b9f9bbf970cf4361213eade27ed";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5c9bc016ef6611449a430392918c530d8308d4e628275a5d2e140bc82e3e02a36d03031fbbc62e0109f107564df27c5c47e868bbf92edb3a3d1080aa0b6997a13b", "159b04a43519ef8148d3832f76ae3d0d6bd5828759b8a64f0f365053c15473d61df1634e80f4e0023cfa97d71882289d9d86a32ae5380d21289d453599490b142b" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "007321260c7e56e586f4a7b9b47a18613f833097c0cdebc6fe488ae05d1c1f37a3a98f2e1af140e7fb1d2318c50b3b984bc4066bfa55fd98db18ac649ee7e47cdec6";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "019dabc758b8c0f680fd1c9757ae0e54a9bac35fe0d3666a4a5838cf551f78cf152e5a98d1f36bf533c15b478d292d084e42137b5c32b9cb1220745df41fde5da0a3", "4f3da3ae65b24eb8f61e934a35b3726ba4d71cd2b2c0692f58c24f96ea75193dea76bf88574c0c70a1ce6eb490aa69a9d5bbd299f53dd1e25ef7f2bef8779c3a52" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "004f27499640288c52f93a87795bd7a0b83c95dbf69a5a3b6ef62f1308f2b9a817536173b45e687646255958f0cd08e0c469e66495d4e040217af2fbbd1311d21711";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "35016d85e577a5bdafaaf2880d2d28daeebd64607c5246741fd952f78fc05a4c290fc689a78f09c0fd36fa3521bb1fa67445b559cffb0e59d65f5830222ad40ed1", "200cc3f2c981daea884444669a6036a1caa85a3bf7420beee18c65a33c11f32d31cd9e356f712af3800ffeee331e741d319daab97d9280b173a6869b94740d8d36" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "0040484262d596a23936806ef21ba6192c72023a535089ee524e2a32f61c7497e58b4dec0ae58178f7b6dd3587fa3124a4ccccb49de353541f610f7d3c97b63db11a";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7d2b510d12496dd5cbb1a14b74f8b671c7ad6180d2154dc0a0334178b054105418639965c70251c28b831ebceae05d8da4239b80ec91f807a301800b709cae6ea8", "0145d7f61e14b464e6014ac14c9ab71754e5ff41b569ec9e469368010ef7fb7aaa20c859f9c138a79969c46f0c20c7ea205585bb513d79fd5ae6017797d930f74c97" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "007fa623ad71573766571b8fd4ae0a5ce82b3805ae151a18515ef607f2228a95bafdbd24acde135cae5f3f899caf0c5efd1a4de2c53878dccc09f2b7a263c2844e3d";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a41ad2be45772bdce5f3872f654e9320026726d3642fd8edc560363fef9ea1c12d1a5067ef236fbf4e22772e2066a818ed0de0976721ddd18446283506b8ea6e1e", "01a65ff3118f6c27595a01b387c6486a24ff38d59a757cb0a06cb0a8b8e1fd5adc2d1c6a3d4047ec2fc3f8d4e61f23a10c1bc87280692073cbb6d4774722e658f815" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "0054e096bc1b2ee6f5fa7d65ce54077cd07a379a7d1bcbf85651852fcc62037ac50c6e64b8c6c2cf8814653af7b87d2752e6f3af0a3ef75ec7415a58cdf2990ce4c0";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2a07f13f3e8df382145b7942fe6f91c12ff3064b314b4e3476bf3afbb982070f17f63b2de5fbe8c91a87ae632869facf17d5ce9d139b37ed557581bb9a7e4b8fa3", "24b904c5fc536ae53b323a7fd0b7b8e420302406ade84ea8a10ca7c5c934bad5489db6e3a8cc3064602cc83f309e9d247aae72afca08336bc8919e15f4be5ad77a" );
            {
                // point at infinity during verify
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd28c343c1df97cb35bfe600a47b84d2e81ddae4dc44ce23d75db7db8f489c3204";
                bn_t sig_s = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                auto r = false; // result = invalid - flags: ['PointDuplication', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4bb904073cb6da9e5028df54fc22cf5a9d5ca73a01feedd2b4ce43b87bfd4300a72bdf26b146b2e7b506c03c7a0ad4a7e3e67204dddca9b65d43560ffaf9bfd540", "012b8895632e0406b78463fe1bc5360a3cf796fddda9db2b18ca9171558e6158fa4b0b1d0461d9a46b9b958d629bd62a29ee3942238e0fa83e932a66abb1b50c5f37" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd28c343c1df97cb35bfe600a47b84d2e81ddae4dc44ce23d75db7db8f489c3206";
                bn_t sig_s = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd28c343c1df97cb35bfe600a47b84d2e81ddae4dc44ce23d75db7db8f489c3204";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "016454afca385eb53eaeaab711537d95c50e01268b100a22656adf5cedf68b4a78a6c14a70245df707f6565ce15948c2e38e3d90e05dda3188ab43a73f30dbc6bda8", "0151dca6dc5aec84fa35c79f21365993f0b267ca486ea66c2186a52a3fb62b53501ce2822d4691fbc25cf27adb70734071be523b9231dd8d33a401dea00cf0ae30a1" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd28c343c1df97cb35bfe600a47b84d2e81ddae4dc44ce23d75db7db8f489c3206";
                bn_t sig_s = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd28c343c1df97cb35bfe600a47b84d2e81ddae4dc44ce23d75db7db8f489c3205";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "60daf59638158ed9d3d7e8428501334764162f9be239e168fae9af348c30a7be1cfa4d9636c3bb621d7e0aa71446f8d4a37f2d43274a4255b226f612382f63152e", "016e48300124a636b206fad4d0355862a852623799afee941e864d96dcbf55b801cabd6249b6f567506d5a503e7d03b4764c70fc44c5365f32c3603678476d62b09d" );
            {
                // u1 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "000043f800fbeaf9238c58af795bcdad04bc49cd850c394d3382953356b023210281757b30e19218a37cbd612086fbc158caa8b4e1acb2ec00837e5d941f342fb3cc";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "51fe6a35a85070c7c29502a87672a38153d799aef734226b64d8fd3398621701117f0af9d9afaf6dbb8ca3007255dc79b0f41ed552512cb29207b15a01cdfdfaae", "01a16c61277586356efadcb24764f21f574ef96f2caabc3f47fa66fb8719d7785824061c2d6d7a4bcb851540e62b2f00960b283eac7808d1813ef51b46e1149d3e4d" );
            {
                // u1 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "01ffbc07ff041506dc73a75086a43252fb43b6327af3c6b2cc7d6acca94fdcdefd78dc0b56a22d16f2eec26ae0c1fb484d059300e80bd6b0472b3d1222ff5d08b03d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b4ffc0fff087607ad26c4b23d6d31ae5f904cc064e350f47131ce2784fbb359867988a559d4386752e56277bef34e26544dedda88cc20a3411fa98834eeae869ad", "009d6e8ca99949b7b34fd06a789744ecac3356247317c4d7aa9296676dd623594f3684bc13064cab8d2db7edbca91f1c8beb542bc97978a3f31f3610a03f46a982d2" );
            {
                // u2 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00809fba320fe96ded24611b72a2a5428fe46049ff080d6e0813ab7a35897018fe6418613abd860d1eb484959059a01af7d68cba69d1c52ea64ad0f28a18a41fc78a", "01108acc5577e9e8962e2a7cea0bb37df1d0ca4050fb6cfeba41a7f868d988dbbcebc962986748fa485183f6b60f453ec8606f8c33d43767dddbbef8c412b2c37939" );
            {
                // u2 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "015555555555555555555555555555555555555555555555555555555555555555518baf05027f750ef25532ab85fa066e8ad2793125b112da747cf524bf0b7aed5c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0145130dca77d9674dfceffa851b4a2672e490e8fba8277622b0020e2fe9101e76933b0c01d248071f854e9bc523733936dc0b9930cbe154b9a402f681ee3c6cef6b", "0d0c94b2ad28556643aa3d27523048d227a1de82f8a664707e75394d21da181bec82e1afb0e627539531affa849a2409bcac83fb786c351c88bac2fb2e4322e54a" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01556bfd55a94e530bd972e52873ef39ac3ec34481aebdc46680dc66723ab66056275d82bff85ad29ac694530bb2f89c36ce600ad1b49761854afc69ab741ce0294a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ed3e09809fe5985818f90592fd06e71d2c493d9a781714c9157cbafa5ba196b987fd49ae24274c76251c70b9f7970f1f713ad274590a702f463c73a0704831ce5d", "00cac278297093bd9f9ac2d00bef3d67a01b43b28b9f829407264c738117438300c7704772976916ea102a776262ccf4222cc348c34aac683d8f00179a348323babd" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "00dcf9e7f441448a125b96d72b989d9f4dac7508c7e036f6080d4758e736f5e0636b0ff503f128a98d08e0ae189921065219d2cc3aa83e3c660ca0cb85e7c11a24d0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0ac2c5a4c79309a5132d5d7494befb3905d33fda5f80eeaf63775183aae7af108a3d97f3a441532cf6fac47f6c898329d69182e1fa07ce45997ebec3781c9ad741", "0173a5b6b80a8b73d30ac97e1a4aacb773c1ad692c5ea63f68e373842782bd677864ff656cf8d1e6ec1e58e9a83856ef92677555916749fb95e800ae2e011618ca3a" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "0066eb57733c19a7003cf8253279fce41907bc4f127153c4576dd4814f8b335a0b51560b4447f0382c69b3fe509522c891f0eec3999ad2526835f33ae22a642843af";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01eb2a353dec6b460fbda49c67f431190fff6f195639c226ef8fefcbf191d72529a12cc5485b282a52704c1fd84529a1aa0ad794f96493e299718d2618a1b83a526c", "01f704604d5b2b94a42bfc3ab93317d66a54de15258337433fc96a965d8e2d056fd1134b7989d7b3f709adc28227bdabc11fe2f359c6a6e5111ab43379ca25b66f2f" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "017106d1131b3300d7ffbc07ff041506dc73a75086a43252fb43b6327af3c6b2cc79527ac09f0a3f0a8aa38285585b6afceac5ff6692842232d106d15d4df1b66aa8";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01e43dfecc7e6caad03d17b407322c878f701c5add6eb2afcd786ff3803622dfbb6baa01246e1ea059f7b78842919b2507daa9e3434efa7e8d3ae6c35499f82d0ac8", "018b0e4d6378222a07ccdb4214001f97b1a503d1aac3ab925ea64faa9c739ba04ee3480b147cb07f93edf40b6856a22f4159c3f5cd6c9e7165452907c8d02fab201e" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "006d1131b3300d7ffbc07ff041506dc73a75086a43252fb43b6327af3c6b2cc7d6ab94bf496f53ea229e7fe6b456088ea32f6e2b104f5112798bb59d46a0d468f838";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0141a4d714628c192b8ace1a42854da06e0e1ddb82a07618e4efb05d7095cd1eb65425078160594715eaf59fcb41c9e573fe10298c75c9e9135c775ca73f63d13aac", "0089524b475170d4391cc032a0543ea22dab60ea07538f3a37607f0d4ed516634fde545e2f0a6ba8d0d2fe6aded0a771b4b134a5a280e54799fa476ef0ec87d44e1c" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "00da226366601afff780ffe082a0db8e74ea10d4864a5f6876c64f5e78d6598fad57297e92dea7d4453cffcd68ac111d465edc56209ea224f3176b3a8d41a8d1f070";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0147fbcc65d4818e029e0a3af13a1f7c90f0605a00cd0781200eb656a591d669a787620e6fc8cc594aa28a0b0f2939ec73472c494e09cecaf5f331dafd32d5ac31c3", "75432bdaeecaa0bec7feddc298c565723fb669ee76e38a4c5ff1701f1b38cda9dc9ac43bff18da2047e4dcd80c05a7bb7e7464829d608b68176b04c87f409f46d6" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "011b3300d7ffbc07ff041506dc73a75086a43252fb43b6327af3c6b2cc7d6acca94cb85df5e6c1125394fcd34f6521ffdaddd98f88a99fedcedd9384288bb793cf2f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b5b1c3998589b25c96a700bbd450d04da1f273df8053767a3b03ed1a763ed089c0de99bcf54d49c1520d3a09b845296f0445b3bd5b87918d3752cf651e0ff3007b", "00e896380876b9419c56096914ff6eec01aee247eefef0741895f14ee280f360e11508c37826af82cd915b9002f046cb51008d9ead21124c591bd8265d1492b35ffb" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "0161be37ed5f748e06a89d72c4b7051cae809d9567848b1d8d7ed019221efb06ae81e1264ce49c5d29ee5fe22ccf70899002643aca7b99f57756f2639b6d459ae410";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01aadb41fadc35cf6d11a7c7d01d049b74b37677f04e1bd3dc08450fabae28adcd2d135f966616d283fb18a5e69eabfe7ec41e1a0edb3682f1d39f2af64a94d602b9", "014ae81ebf5e3d2d0529479d4ae8eb05f4b42e519608466ad69e7662d6e9b236765f9be535c058f00f0866bbb4b172ef47a03cb97c58dde5750344bb293035f8e97e" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01e9bbbd64270b9668f7623ef7cbead5483eb07b883cf39fb6884aab67dac7958b0e03144357b9433e69adc696c86c63a23d35724cbd749b7c34f8e34232d21ea420";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01b706fc3f4aae5b86da261a66fbce47eb3b3e1e91544a40a9989fccf74154bbecac042dbbbf411a39090058b62c46fccd1d5eaba0c4879a688ea5fd0a7b4f9a0b4f", "01eda01930c6b22745a97f2d59e182598dfdfbfdb463335293901de7fc9d49cf55ed7fcf5d767d4c22f89f171b4137c8415c3ed438089270c41f88eadef3018140e1" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "00924449b6c96f3758e3b085c079714f11f28d039b11699f0e9b3e7c553c8fc6c8f5212fec5eac3068713b8ec72fc6e2a90872b94e161a89822887f4a9bd5c9efd74";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "58a1fa96111bf30be76c3b8ba4435666677b6dd05031b5c4a840e1ea81f6025f70e1d395ef63cb59fa71e3674cb678f7250887f5d734e3ec377dbe3ae637d24f82", "7a4eaf02cc57e658b5b9fa08ee30e0ef5b3429bb5a10438b0e05bacaebc60317010a334d7f896028aef620f5d9c7cabc38306e032b1b91c2376c3fef3e455a10df" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01554a01552b58d67a13468d6bc6086329e09e5dbf28a11dccbf91ccc6e2a4cfd4e6a2c5278791c6490835a27b6f7abb8a690bb060de3deb85093d3ae16482c84f64";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "303ba5ef90b05110002fdf74d2b8d4c7ab189c64004859c69d7c4730fcacb5f4d9b761ae987d1f3b63bb3ecb78aeecf4a04ff60f5f367a96ac2da8da27a3687a3e", "6673d0d4ccd4c3ce1abc9980fd1885002c3e7b86078214caf7f0962fa51e116363032d7a1b93c92a4d62827549d5a33e4e6b9b6c2ab6ad9c2a15e410c5b1a846b2" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "00aa9402aa56b1acf4268d1ad78c10c653c13cbb7e51423b997f23998dc5499fa9d2f403c78b645cfba4eb78f595fe6d6f01dbaaf803f23ac263bf060baa74583abf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a94eea843a5c49637041598e30c381f7173bf8cd127f3caf5c16cbc728aa4d99173fb38d6a1b1ec21e40336e8d802249272b0ccbf4f8c3636ef66290a81b58fa5b", "01116c23464fad61df8d2d5d1250a5a4c427e9c58e2cf1d059cdd88a7c34984fdd22a4cf18411e1b0224d444a5bd39d5fc97fc0b3648600f19d6ab80aa6a7c083a17" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01ffde03ff820a836e39d3a8435219297da1db193d79e359663eb56654a7ee6f7eb996c8ef12f62344ad211b71057928f96ae75b58e23026476cfc40ed0ef7208a23";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "014f71d2ca5bd2051336854657f09a1fab14c7f2f7865d71bd3fa354bf27b69dc8738972140553b525658b6fd203cc05ca0822e0904bad21b632e0de74a2ad3f0e72", "4525f90519f9497425460b31cbb69ab3701a9ea68aaab72c6d65d364d0f0ed4d0524280f113bd69ef1ba9825202b10287a088c4bf30debecb720ac0739ec67434d" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "013375abb99e0cd3801e7c12993cfe720c83de278938a9e22bb6ea40a7c599ad05a5d3c8e5e5d7b3e16a99e528ef0ce91be0953cb1a9adf757f257554ca47ab053dc";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01d2ecad921dd100a8dc1a7b824b0ac6c9b654ab179833c2881ce237f1b8497ade851302cf50ea5ea169c2a50c0c09cb6ea539a7290a0f3437044b7a2e9ca8d40500", "3fd5651535dcba1f331981c216a1c7d9842f65c5f38ca43dd71c41e19efcac384617656fd0afdd83c50c5e524e9b672b7aa8a66b289afa688e45ca6edb3477a8b0" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "005555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555554";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0165d67972a48fddc2f41c03f79ab5e0d42fd0992c013ead135c3394049645e26ad7c7be96510df59ba677dc94f1146e8e8e8fbe56debcb66920639581956b92b4d1", "008aeb66ee0be18abaa909a973c70b5749d688f8e2cd2e6e1613af93d0033492d26a6e82cfb80ac6925ac6bc79b984f73e3ebbff2f223a38676891c1ecd784a8a789" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "009f57708fa97eba94c6d4782cdd4e33bb95c1353bde095232e3e2bab277bb5d2b48f55a53ffe928d034c29970a9e5f384a003907d3d9b82a86817cc61fb17f4c59e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "018cd11252f0a434f446d3af18518c6b84cb0b7bf33758b4d83b97c2a56e0037b54d57d2b0b842e9c17d70504e01896389c066db8f2bfec025259a51dff514668308", "01cca54365156c59e2c73c17664f09fcdcfd5b910f9ab48d0899b6a7064de8b80fc7a992e47ee7f23ec82fd80179a19f4cf89b4c02b7218f435298da5d322a982c1e" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "0068d98fa90736eff3e90f8fcfe50838b6fa0bf2cde77bc51e3f41019c8006f4e9cbaeadce7dbb44462da6425be9cfdaecb234c41749ce695be1b5ead2e6b1205f35";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01d6329a8afdea27cf1028a44d19c3c72927590d64628775f324514c81de301aa9be9c775c53a6349d1cbd5ecfc7bd39b373e613a10c1439441b141430fdadac168c", "071342d63dba901b93bdc444a1fe2ec6a15108bdf49eb1dfd218373884520d84bce03c5012f5837051cb8abf6a0be78dfdfeeb3a5872dff75b3f874faa6d2243bf" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "00e97ae66bcd4cae36fffffffffffffffffffffffffffffffffffffffffffffffffd68bc9726f02dbf8598a98b3e5077eff6f2491eb678ed040fb338c084a9ea8a4c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01c963b64cdc3ecb1c35cda5ced9419ac146b060adb04c638cf6b66658013cb25e915a6ad0055668342881ed27f438b50ae4bb86ae3c7c02b727a130c77bad698008", "481bfffaead856b4137fd4268ecd74a6c2d4bd6cd13998ce7f0e828b220135d8df23253e681dc90673e0537e7590769a2a441aaaaa3a9901c4fbe44fa9513951ef" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01ae66bcd4cae36ffffffffffffffffffffffffffffffffffffffffffffffffffffb3954212f8bea578d93e685e5dba329811b2542bb398233e2944bceb19263325d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5dfbc867d53c57b2945502b8e56d96ca2d4d485aa33452200a2f4ba16042357976afeecf3e63b2fdcd5cdd76076c1a73e496caf9d6de3e8831d955d138e05884ae", "01e04aa0b5360a0d3badd0120fbb8cc42a38bf1c61755d00858e40e4b10da4ea2575830dc92e312c20af2b8b167d7a58d178661d48cd932fe47a4bc7145e620ae22c" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "015ccd79a995c6dffffffffffffffffffffffffffffffffffffffffffffffffffffc2121badb58a518afa8010a82c03cad31fa94bbbde96820166d27e644938e00b1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "78be6c43e366cf63ddc4235e8b969386e95012fbca5cebf1b0a6fe3c03c1257df7cf47b002eb6c4497f310bff6131b5ccb54fd0e8ee7fcf6b49d487e1b54508f68", "009b61a547104c8516e0dc35d3d17659ca098d023b0593908fe979c29e62373738a3c30094ba47105a49edbc6e1d37cce317b49d2701470eeb53d9b24dce9d809166" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01cd4cae36fffffffffffffffffffffffffffffffffffffffffffffffffffffffffae18dcc11dff7526233d923a0b202cb29e713f22de8bb6ab0a12821c5abbe3f23";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0093f68961005f3040dc1a8ff1416c917bdcc77f1dfa85506c3bb62dac47f7be9529b4cbe57dd2c19e860bd2a0db71d47ef1eca8a20bfc3e0bc5e05c8303001c1960", "2b9a3d45f2f5120fee06445f0d34e6138e3ac5b16d2a22f0460cea258c368ca9e478eb7b8253e7c6f2f7250fdc7dcd7243761f8d56f2350ac51e47ee063f41da31" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "0022e8ba2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba2e8b9c4c3f73cc816143fac3412b62de4c63db08f8c57e4c58c31f1b457ca5e57e20a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2d2d7d40bf17c4e8b18757e451ddded95e6b1007cd144809d21af31353b03038372c4af204d4414b71060b48b3a8439c632809bd33c4736263044405a1ad766e36", "00bb0c5a8848f93fa3e85376b012bf064e303746529a673b852bb5a969c24c0156a8dd26242d0aad4bae43e23631b01fb9d050f9744b59f3b52b1c572217a1d70588" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "010590b21642c8590b21642c8590b21642c8590b21642c8590b21642c8590b2164298eb57e5aff9343597a542d3132f9e734fdc305125e0ec139c5f780ee8e8cb9c2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "018ac11dfe62d1f2a8202732c79b423d29f43bec4db6080a220796a10f2685f92c71c7f72d9da0a8acb22680cca018eba2e8ba3bfde1db9a4ef3b97da16474364e96", "5aad3b286707bd3ad07a060cabca49c53de4f56c05a0a8de40fd969d7d4f995f7c6701fe5c5321f85318b98be66251fa490088fd727da2454e00b3b94dc6e1241b" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01a4924924924924924924924924924924924924924924924924924924924924924445e10670ed0437c9db4125ac4175fbd70e9bd1799a85f44ca0a8e61a3354e808";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "51b2c3e0494564ed48ed3479b596ea4078240550a3c28da33d71d259e8e623e37ab43f396c49363f31c8de8a4644d37e94ed80e0dd4f92c3df2106e2795c2798b8", "00a530d5e961f0696bbeb962aca8e71f65956ae04cdc22a4ac65146943e99a4a2fdb477df75aa069c8dd37a5daaea3848079a6a7bc03e0faa3d65d42f8053db2078b" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01d5555555555555555555555555555555555555555555555555555555555555554fa6dbdcd91484ebc0d521569e4c5efb25910b1f0ddef19d0410c50c73e68db95f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01ba31a6f9c2d227da57de00759e2e844d607bc9bd92bcdf282006884dc347c9284f0dc0623af1e9db22117364a7a80a5b067efa19b204dac8faf2230d80b704addc", "00d88b761cd3a4b0947bfc17e204b4d751f76880a82c9b7c6fd93ded55883c995002d8b8bfff1e021189c08d829d16b088f4fb39ad9456eafbc77c20353bc0f3c038" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa4fc31322e69da41162a76abf3a1b4507ae66074633446f259661a61c93be30eb5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0137bbb48ef281133849ed723f5662a19fff9cc7389a0170d311bd34f4dbdc656246db695ea0712d8aceff9d1d0ef7921ec2e3f8b533e4ca122f9f7f446073889334", "0163e4500d998095f60fa3fed4149d2d9b5b018e03eb5344efe8ffcc1c7d276e7401a4df639c4ab108820062495471be7b29398aadbae440a9bdcd55cf0bb5d96f79" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "017ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "726dda8b7b6ed25f97f1fc6c3ccf554d60fc71e4fab2a578286d32612e7f3e669faed0b97619aef2d5aff9c8ffd987feddc0d6c38b7eec028191400874803f498b", "00c0b8870c612e06c13c57ed6f7ef3d53b5e5fa2db62707b034b5ec13fb47018e31da7ecc991d575943468d701e118eca33122cf6d394b8a6ec0f45bc09701603a26" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01346cc7d4839b77f9f487c7e7f2841c5b7d05f966f3bde28f1fa080ce40037a74e3001a2b00bd39ee4c93072e9963724941383cf0812c02d1c838ad4502a12c619f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "016fce9f375bbd2968adaaf3575595129ef3e721c3b7c83d5a4a79f4b5dfbbdb1f66da7243e5120c5dbd7be1ca073e04b4cc58ca8ce2f34ff6a3d02a929bf2fc2797", "0083f130792d6c45c8f2a67471e51246e2b8781465b8291cbda66d22719cd536bf801e0076030919d5701732ce7678bf472846ed0777937ed77caad74d05664614a2" );
            {
                // point duplication during verification
                auto m = "313233343030"_hex;
                bn_t sig_r = "0090c8d0d718cb9d8d81094e6d068fb13c16b4df8c77bac676dddfe3e68855bed06b9ba8d0f8a80edce03a9fac7da561e24b1cd22d459239a146695a671f81f73aaf";
                bn_t sig_s = "01150b0fe9f0dff27fa180cc9442c3bfc9e395232898607b110a51bcb1086cb9726e251a07c9557808df32460715950a3dc446ae4229b9ed59fe241b389aee3a6963";
                auto r = true; // result = valid - flags: ['PointDuplication']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "016fce9f375bbd2968adaaf3575595129ef3e721c3b7c83d5a4a79f4b5dfbbdb1f66da7243e5120c5dbd7be1ca073e04b4cc58ca8ce2f34ff6a3d02a929bf2fc2797", "017c0ecf86d293ba370d598b8e1aedb91d4787eb9a47d6e3425992dd8e632ac9407fe1ff89fcf6e62a8fe8cd31898740b8d7b912f8886c8128835528b2fa99b9eb5d" );
            {
                // duplication bug
                auto m = "313233343030"_hex;
                bn_t sig_r = "0090c8d0d718cb9d8d81094e6d068fb13c16b4df8c77bac676dddfe3e68855bed06b9ba8d0f8a80edce03a9fac7da561e24b1cd22d459239a146695a671f81f73aaf";
                bn_t sig_s = "01150b0fe9f0dff27fa180cc9442c3bfc9e395232898607b110a51bcb1086cb9726e251a07c9557808df32460715950a3dc446ae4229b9ed59fe241b389aee3a6963";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0110fb89aff135edb801a1cb5bc49525b81dc74da45090d228122871814f489fdcb02ebee46b703e6b4e6af56c5024422b31fd4252c44d0bfd29d945de782d98543f", "01ec425b4c4928e12b619227f1da6d0a9675070d9c5b49ca523050acb718e62643b0e5801543b76dc11f8d694ba09436d8391b477ad2c143ec50c2384c4f688512dc" );
            {
                // point with x-coordinate 0
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                bn_t sig_s = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01c693a3fccbc9f625284239c2725f2a5c90b29b7ce3d07730f7de6031c9e74446d217888ae023aae23df6a4aa153f58c79597d57f42ce5c1354e5dc43a5eb311e13", "015f99658443b2e39c3edcbcda70707fc5a4d39545eabe354816d09284a6265e47ebf0a47355828e818a767f8452a6d18451e0e3817a896ff404cb1611bfc4c4b4a3" );
            {
                // point with x-coordinate 0
                auto m = "313233343030"_hex;
                bn_t sig_r = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                bn_t sig_s = "0066666666666666666666666666666666666666666666666666666666666666666543814e4d8ca31e157ff599db649b87900bf128581b85a7efbf1657d2e9d81401";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "017d7bf723678df574ce4366741e1d3787f834af9997b41c8260a074cb1f325d2bae9f8565dc6b51b6cb02dceeb5a1b774ee8dd7057c99e2d94c3c71299a9ce0f1b0", "0162c65632fff88bdbb17ce2525ccac8df37c501ab0e6626e273fb6cf99000424344c0ac539c9fd6c4f3d28876b257c010d347a45bb010cc058443843a758328d491" );
            {
                // comparison with point at infinity
                auto m = "313233343030"_hex;
                bn_t sig_r = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                bn_t sig_s = "0066666666666666666666666666666666666666666666666666666666666666666543814e4d8ca31e157ff599db649b87900bf128581b85a7efbf1657d2e9d81401";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01e06db423a902e239b97340ab052534ead37e79412c675bf0eb823999e6b731040bff2b0e4fa64edf3962a328921ea5ae4e8f4079eab439e12f92335dfc4863c07f", "7ee9f0ecb409cb133c0cd08b85e840b076f3d615e1ef1393b5222338b227d768003da5f3ba1f72f6654ca54ac11c2ba91a6cb5883d6d1a82304ad2b79de09215f3" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "00433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d";
                bn_t sig_s = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "015053744d53811dbed8880f38d3a34578a7f1c172ec65bd8ad8183ba0ae10093416107f3c942742bde60719949b2c4f026f43582125c99ed48cbc7c5a051a5a7448", "00b36d4c91a2b0367c566b2c12981ce0fdbc3beb983717403f69bf4264fc6182478af0b236ff120bcfca116924c552abef6663b6023be1986b70206d9bb89b5ed298" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d";
                bn_t sig_s = "00492492492492492492492492492492492492492492492492492492492492492491795c5c808906cc587ff89278234a8566e3f565f5ca840a3d887dac7214bee9b8";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01fb2e26596cc80473917dd46b4a1d14bd9a1ca9769dd12bfac1bff17cdc282e74c73a801ec1be83edfe4bfe9813ec943ac151678f0a9a0bf27d9ef308177eb0400f", "019e03a5da3da67e6b8d068dbdacf091b9d5efadaf63f4a7e9c6b6ed0a1c9a5d3cbc3e0244d481066018fba7674a2b59139a5656780563bb4618014f176752e177e0" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d";
                bn_t sig_s = "019999999999999999999999999999999999999999999999999999999999999999950e053936328c7855ffd6676d926e1e402fc4a1606e169fbefc595f4ba7605007";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008422cea9dcf8ae01f7a157888f018a40a66461d3566ec4a4dfc89ecb3c2404be734d329137d630387b012d033221857d5bfb290fa8027640b4063072a3e5b14c86", "25a219e724b81814901a677a8bee9b716b33b16a5b65f2272956a46b5e8683dc896984309ac79449657a1895c9f62bde99c7f5e24ed2defbc9f8dde35ebd0bddc1" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d";
                bn_t sig_s = "0066666666666666666666666666666666666666666666666666666666666666666543814e4d8ca31e157ff599db649b87900bf128581b85a7efbf1657d2e9d81402";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01bc19cf4b94bcd34114ce83c5f1a7e048e2fc4fd457d57e39b3da29f4766acbaef1c10cb13c796a6fffb56d6a392e47b6c74522df7fa02754c33d95b1a9a3c92a15", "00f5744c2bed308cb4f41b512e632cd01d270ef1a0d3f47ea780e73c6a6c9ea6a996faef4d282896c64fa50f5b04e204c56b504bc122ffba7aea4574d7d7ab6303c0" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d";
                bn_t sig_s = "01b6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db68d82a2b033628ca12ffd36ed0d3bf206957c063c2bf183d7132f20aac7c797a51";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "017b0ebce08b09f21e30d15e0edd9fcdf24ab4831ec8a65a3d1e38f72b15f0115da6ed1885e42fcfae31c0914b71e9df2cd106adc039a82810a92924dd154dc05da3", "00c614d1afc4f63de3803bb5490a34e1e2fab9eb78422b21d377fc0d7f991b938c22f4d7dd665f8dd21fadde43172a55f80d05cc4557b6663f9e7a3fe490d25c5531" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "00433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d";
                bn_t sig_s = "000eb10e5ab95f2f26a40700b1300fb8c3c8d5384ffbecf1fdb9e11e67cb7fd6a7f503e6e25ac09bb88b6c3983df764d4d72bc2920e233f0f7974a234a21b00bb447";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "04c3ec8d7d23ce74be8b9c7c27be869c23bafc6874ebc44f47e107422ab1e75ed09bebd7cb1ec4626e442bcf512a25c5ddde26eb08ba37506461830cf9241cbe9c", "50a1bc08f4ba8da1d641ac3891823ab519facd4159768b1c0738f0e23450f374e4d6de55cceed95722be635c5dc0023a1498862f87bfe61d77e20e592cc20bb2ca" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
                bn_t sig_s = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8c5d782813fba87792a9955c2fd033745693c9892d8896d3a3e7a925f85bd76ad";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a7c8204f2864dcef089165c3914dcc2c0896075870ca0bc1ce37856f80f23815b0c8f2ec05145c421049e80ec1e7694f9f04174bbef21bc0972e559cf222de7e1a", "01ff1108c28f01b703820e1c0187912962ab23109618dfcb0c062ccee339002222a3f7dd8dd21675b0e20908fe5855ea876d6a9e02c5f5b793d38fdf79fb83603ea9" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
                bn_t sig_s = "00492492492492492492492492492492492492492492492492492492492492492491795c5c808906cc587ff89278234a8566e3f565f5ca840a3d887dac7214bee9b8";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01802fc79fc8e55bce50a581632b51d6eec04a3c74ac2bf4fae16ce6c7efef1701d69f9c00a91ad521d75ac7539d54bf464caeec871456103dc974354460898a19c6", "722fc1f528506618b1da9f8b2edbdbdaf7eec02e8fb9203d2b277735a1d867911b131f453f52ccc4ced05c3b1bc29e4d20f1e6d34979faa688ce8003f79d8e0c95" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
                bn_t sig_s = "019999999999999999999999999999999999999999999999999999999999999999950e053936328c7855ffd6676d926e1e402fc4a1606e169fbefc595f4ba7605007";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01beb0b4c2e494226404fca4ad505ebfed13d184b1572683215b16173c29a4475aede47f266e0c9c4143137d3e0001f9f0148b689286a7c64e229458b824ed765836", "0130205169783ed9ada9f3a193027ae4e21829ad4a71d05d969605c04f3231dabab03beb2fab07dd8323d7132755734f4e6d1fb43fc8a63bfd244160c23efb6c1429" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
                bn_t sig_s = "0066666666666666666666666666666666666666666666666666666666666666666543814e4d8ca31e157ff599db649b87900bf128581b85a7efbf1657d2e9d81402";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0121e59aaf26b8301f4fcc3e0a563c4104ae00b47c55b8945ce749116fdf6761d768bd50ed431e2b51e646fe4fe7dc2985b6aefa7f9441ea11840d2ace2f34293cb1", "0cf1e1a46d4d637216e28abd124cc641ae7a673445d573856bc2fec58d86e5ed63bc2a7f2049234e335a7bee95bb2724fb1480c97c38cd0d296cbcc113de3f135f" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
                bn_t sig_s = "01b6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db68d82a2b033628ca12ffd36ed0d3bf206957c063c2bf183d7132f20aac7c797a51";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008e859e66d1237fdc928a4b954954fef565d203a0731d065d9df41a4fd3812b1cc2487053ea19ce839d200845952f80d80698771d83ccc1fc7f236dbee4c76b2bb4", "5a04b24c88cd40233fb43c59ea5cf2cb9510d16b1168bc126db64aaf9ab07a7453208fde079095966272bf03bc3312c9b9bab8c795ae375e8a0e8dd81c924e7c27" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
                bn_t sig_s = "000eb10e5ab95f2f26a40700b1300fb8c3c8d5384ffbecf1fdb9e11e67cb7fd6a7f503e6e25ac09bb88b6c3983df764d4d72bc2920e233f0f7974a234a21b00bb447";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "000043f800fbeaf9238c58af795bcdad04bc49cd850c394d3382953356b023210281757b30e19218a37cbd612086fbc158caa8b4e1acb2ec00837e5d941f342fb3cc";
                bn_t sig_s = "00492492492492492492492492492492492492492492492492492492492492492491795c5c808906cc587ff89278234a8566e3f565f5ca840a3d887dac7214bee9b8";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "01ffbc07ff041506dc73a75086a43252fb43b6327af3c6b2cc7d6acca94fdcdefd78dc0b56a22d16f2eec26ae0c1fb484d059300e80bd6b0472b3d1222ff5d08b03d";
                sig_s = "00492492492492492492492492492492492492492492492492492492492492492491795c5c808906cc587ff89278234a8566e3f565f5ca840a3d887dac7214bee9b8";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", "00e7c6d6958765c43ffba375a04bd382e426670abbb6a864bb97e85042e8d8c199d368118d66a10bd9bf3aaf46fec052f89ecac38f795d8d3dbf77416b89602e99af" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "000043f800fbeaf9238c58af795bcdad04bc49cd850c394d3382953356b023210281757b30e19218a37cbd612086fbc158caa8b4e1acb2ec00837e5d941f342fb3cc";
                bn_t sig_s = "00492492492492492492492492492492492492492492492492492492492492492491795c5c808906cc587ff89278234a8566e3f565f5ca840a3d887dac7214bee9b8";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "01ffbc07ff041506dc73a75086a43252fb43b6327af3c6b2cc7d6acca94fdcdefd78dc0b56a22d16f2eec26ae0c1fb484d059300e80bd6b0472b3d1222ff5d08b03d";
                sig_s = "00492492492492492492492492492492492492492492492492492492492492492491795c5c808906cc587ff89278234a8566e3f565f5ca840a3d887dac7214bee9b8";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "012a908bfc5b70e17bdfae74294994808bf2a42dab59af8b0523a026d640a2a3d6d344520b62177e2cfa339ca42fb0883ec425904fbda2833a3b5b0a9a00811365d8", "012333d532f8f8eb1a623c378a3694651192bbda833e3b8d7b8f90b2bfc9b045f8a55e1b6a5fe1512c400c4bc9c86fd7c699d642f5cee9bb827c8b0abc0da01cef1e" );
            {
                // pseudorandom signature
                auto m = ""_hex;
                bn_t sig_r = "01625d6115092a8e2ee21b9f8a425aa73814dec8b2335e86150ab4229f5a3421d2e6256d632c7a4365a1ee01dd2a936921bbb4551a512d1d4b5a56c314e4a02534c5";
                bn_t sig_s = "01b792d23f2649862595451055777bda1b02dc6cc8fef23231e44b921b16155cd42257441d75a790371e91819f0a9b1fd0ebd02c90b5b774527746ed9bfe743dbe2f";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "4d7367"_hex;
                sig_r = "005adc833cbc1d6141ced457bab2b01b0814054d7a28fa8bb2925d1e7525b7cf7d5c938a17abfb33426dcc05ce8d44db02f53a75ea04017dca51e1fbb14ce3311b14";
                sig_s = "005f69b2a6de129147a8437b79c72315d35173d88c2d6119085c90dae8ec05c55e067e7dfa4f681035e3dccab099291c0ecf4428332a9cb0736d16e79111ac76d766";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "313233343030"_hex;
                sig_r = "014141e4d94a58c1e747cbd9ee6670a41eac3c26fb4db3248e45d583179076e6b19a8e2003657a108f91f9a103157edff9b37df2b436a77dc112927d907ac9ba2587";
                sig_s = "0108afa91b34bd904c680471e943af336fb90c5fb2b91401a58c9b1f467bf81af8049965dd8b45f12e152f4f7fd3780e3492f31ed2680d4777fbe655fe779ad897ab";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "0000000000000000000000000000000000000000"_hex;
                sig_r = "0008135d3f1ae9e26fba825643ed8a29d63d7843720e93566aa09db2bdf5aaa69afbcc0c51e5295c298f305ba7b870f0a85bb5699cdf40764aab59418f77c6ffb452";
                sig_s = "011d345256887fb351f5700961a7d47572e0d669056cb1d5619345c0c987f3331c2fe2c6df848a5c610422defd6212b64346161aa871ae55b1fe4add5f68836eb181";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "304b3d071ed1ef302391b566af8c9d1cb7afe9aabc141ac39ab39676c63e48c1b2c6451eb460e452bd573e1fb5f15b8e5f9c03f634d8db6897285064b3ce9bd98a", "009b98bfd33398c2cf8606fc0ae468b6d617ccb3e704af3b8506642a775d5b4da9d00209364a9f0a4ad77cbac604a015c97e6b5a18844a589a4f1c7d9625" );
            {
                // y-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "011c9684af6dc52728410473c63053b01c358d67e81f8a1324ad711c60481a4a86dd3e75de20ca55ce7a9a39b1f82fd5da4fadf26a5bb8edd467af8825efe4746218";
                bn_t sig_s = "0034c058aba6488d6943e11e0d1348429449ea17ac5edf8bcaf654106b98b2ddf346c537b8a9a3f9b3174b77637d220ef5318dbbc33d0aac0fe2ddeda17b23cb2de6";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "007c47a668625648cd8a31ac92174cf3d61041f7ad292588def6ed143b1ff9a288fd20cf36f58d4bfe4b2cd4a381d4da50c8eda5674f020449ae1d3dd77e44ed485e";
                sig_s = "01058e86b327d284e35bab49fc7c335417573f310afa9e1a53566e0fae516e099007965030f6f46b077116353f26cb466d1cf3f35300d744d2d8f883c8a31b43c20d";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "01e4e9f3a7b800de63407b8703ac545226541c97a673566711f70e2b9ccb21a145ad4637825b023d1ea9f18e60897413711611a85c1179bff9c107368f1c1b61c24c";
                sig_s = "01de948ee577c3d4e4122a52ecccac59abb6fa937dfb3e4b988cb243efe98740309452ba013112b225b3b1b1384d5f68796845199a2602a8d4505a331b07d101188e";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "304b3d071ed1ef302391b566af8c9d1cb7afe9aabc141ac39ab39676c63e48c1b2c6451eb460e452bd573e1fb5f15b8e5f9c03f634d8db6897285064b3ce9bd98a", "01ffffffff6467402ccc673d3079f903f51b974929e8334c18fb50c47af99bd588a2a4b2562ffdf6c9b560f5b528834539fb5fea368194a5e77bb5a765b0e38269da" );
            {
                // y-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "00b6cf64861a2b16e33976095dbf45a592c7c24228c4a1dd727f303d5eeb87e5388ad05c328f824c40abd3e6ce003fef5cd59dee0069ad6348ea6e57f90f6bdc0a82";
                bn_t sig_s = "00228181c180366e5451dfef3593ce664804cb42d5a8d5046b816b3daf6602fafd9ac2dc24b8c93a10024480882558b6ad3d9e905923dcd0fd2a11964754a9b46b8f";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "0093c8f766827d6dc15c810fa30433153a5e742859205ee8389fbf695c8840dc917440870acc5b160087ffd0cd9a6081029c60a7c26d5e8aa9a0570f4efdeb13dea2";
                sig_s = "012ec3bbf75a0ad3df40310266648a36db820217ed7fa94e9c8313e03293ef4f6a40e736fb8f208ad8fb883ca509d48046910523645459c27829d54431463b2548c7";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "0152388c6da66164b706b41dd4dd48176d6eaf6525f876ef0ff2d147f6966ebfadf1767fa66d04203d3ec9c937a1f0c945aed953e34be444c219fd3b94d3277aa652";
                sig_s = "01658c1e5b2e563a49d11c883d05c491d628f0a92c3e3dc8db9a4c8d5f0dc846ac22af8b3c5fb5bbe2cfa98614dcffd87de1cee2c5912a5899505a0c5bcaa513e2c6";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "02fba6a061201ea6b1ed4265163568735ebab78600cdf6a71101dc63beaf546d97a214fc6396793b014eb1aa7a728f53deb2ff9999a3808ddfed15e9629b", "01993852dadc39299a5a45b6bd7c8dc8ec67e7adbb359fa8fa5d44977e15e2e5a9acf0c33645f3f2c68c526e07732fb35043719cfafc16063c8e58850a958436a4e5" );
            {
                // x-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "010e89470f981d2c7c5c96587121a67323bb96ff2427739d0d885ea277293efa3b25c0bda04d81466198a3cbfc441f1b1b98f6bcdc2589d9d91a17a7899f70d0461e";
                bn_t sig_s = "017351b0da8c8d0e4aa0974669d190fa2f90aa50227160594dfb55755002365441de17ea42902128a6f81e554177ed509c0cec31fd5053fae03f62ff76579ba92bda";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "011094ac23ca46a3e2b4ac3baae6504f1bfb3ddf2db9ab40eda32d8e0a05727998f8552a033bb05241e826a86a1d03014eae3aa5fe1a45caac1db3e8138b9cf59068";
                sig_s = "0147edb15a5080ee2f929f78b6ac86604aae51b674fa46eaae7fdfd90bf64d6189341155f4eba937eae74c9e480eb4fb7e6aafd4285e7fc503ee6ec20f0b1415be06";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "01d876ae174da31e128babff9f1d15507660bdc7958750844dc4f4291f75a882a22f177f704be6067bf7ce8f06b8626d971e6ef5dcb666fa975c1e11126e04fccce2";
                sig_s = "01abb12630a68b669e6ad2d8d62654d75dfbc6b54a8e3a9c915be663e080ddcc348e57a10e2b1dd9f03e1b897796ad889b075e5919dc5bf37a112d92c693456e6457";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01fffffffe1d5d52b31ca52f8947a35593edf164cd324f833b90935846c64db1454df9f028dc8bc36bb04cb7f0cceceba01a3844097f7c35eeaa81428db0cca63331", "01b7c70277d0bf78a3c7b62c937f0cb2cad2565f5514f6205ceb1a193d4fdb45ba6e6cec07827bae0b16b8316c3539a15114d0de6d2de407fd7117551a70826eada6" );
            {
                // x-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "004ed692af1ed1b4bd5cea3aa8ddc6f3f15d8a6ee0016fa0e8eb958580e7421832ecc0e387c34aafac6380bac419ea45c42ae6426af503847f22c49c2f456338c1a7";
                bn_t sig_s = "007aceadde02ace1668bc1a3360d34e125afde230f536c154d91e6c876bee1d34ae06edcbbca0c7cd17646840913164740b12e2e224fe3ef3dec6fd84a81b581c188";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "00e01094048fcf7a1e2ec66faedffc40f48c9c93514325bde6b4958d80f0413efde7eec1dc6de65f96009c069397e51da2eb1729efa287afd5552b25a9e427a6d836";
                sig_s = "01489e7e124f66942e642de992e60b3a86fcce576767719390c3a312fcdeaa560a7fbb0cabb35e05a6d6f3499160fd2dba12d29b613b16dec7494c950d65fdf11fa3";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "01d296292213380de133dc66eceb8bd857a5c468afe855c05da9db937373b51f9020ca11353415da76bb6af997a486d2370e31adcc0a4531952a3b59428678ee5943";
                sig_s = "015979a3c609c2c2099ae1b290da3d613b248e3a10de7ad770dffc82fb33e74fc3207533f97285cf4557a6407e9a775e59efeaee4264b2634933a6baf8c406f0c4a9";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c7c8817bf2f0652a4a4b5140c773e261080a0a111395856e8a3350f5eb5612bd63b367b965e92e9538ea3b7908aef1ade4b68e17f9f9148495c167d1c4dd491349", "08bf0be2979abb8111fd0d768adcad774113a822c1bb60887053b5cf8c9563e76705a391ece154b5dfb114b20e351df4014bec19fa87720845801cf06b7fffffff" );
            {
                // y-coordinate of the public key has many trailing 1's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "01ef8f785c51a25ae2cd93487b5c848d4af133217a91f51359c966e7538e68743578122df5830002f96f6fadb5bc44480e3b3b2c804e4c51cf95d059d5646c5cef21";
                bn_t sig_s = "01ba2276cc003e87bea37c3724e58a0ab885f56d09b8b5718f674f9c70f3b5ecfb4ad1f3417b420ec40810e08826efa7d8ad6ca7c6a7840348097f92b2de8d6e080b";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "0155978adc4b570d897511f5ecfb65a31947e6e989da17dea716625bb3fa7b92b853623eb0cd9ce2a5e2b4d8c1c2a90ec04fe79d012576ec728a45c5ce47c6d500c0";
                sig_s = "00f79fa8b94ee282a3d1815892cbf15d7ebdf62cb042c76bb3c710c23e32b75992cc249d84072198e4ed63d72435a07d2ed76f278d7399f61a5b5c997f45692fed22";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "01a2af29c58184ca861e7cd931f39cea064b199eee563f241cd5ecf6ebb2ade728f1be23cf007ebe8ef0c42d99f9f5190f6815446afc3043a820d7daf27e86b83b8a";
                sig_s = "01a2acd1822eb539383defff8769aad8bacd50cd24ca7aa6670671418110177808c3f4fbe6041b9cb898359ee61e04824adedd62b39fe5791907a20586333bd3c76d";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }
        } // End of Google's Wycheproof tests ecdsa_secp521r1_sha512_p1363_test
    }
    EOSIO_TEST_END // ecdsa_secp521r1_test
}
