#include <chrono>
#include <gtest/gtest.h>
#include <net/quic_utils.h>
#include <net/tls.h>
#include <quiche.h>
#include <thread>

static int parse_hex_char(int c) {
    if (c >= '0' && c <= '9') {
        return c - 0x30;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 0x57;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 0x37;
    }
    return -1;
}

static std::vector<uint8_t> decode_from_hex(std::string_view hex) {
    if (hex.size() & 1) {
        return {};
    }
    std::vector<uint8_t> result;
    result.reserve(hex.size() >> 1);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = parse_hex_char(hex[i]);
        int lo = parse_hex_char(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return {};
        }
        result.push_back((uint8_t) (hi << 4 | lo));
    }
    return result;
}

TEST(QuicUtilsTest, ExtractClientHello) {
    std::vector<uint8_t> draft28_pkt =
            decode_from_hex("c5ff00001d088394c8f03e5157080000449e4a95245bfb66bc5f93032b7ddd89"
                            "fe0ff15d9c4f7050fccdb71c1cd80512d4431643a53aafa1b0b518b44968b18b"
                            "8d3e7a4d04c30b3ed9410325b2abb2dafb1c12f8b70479eb8df98abcaf95dd8f"
                            "3d1c78660fbc719f88b23c8aef6771f3d50e10fdfb4c9d92386d44481b6c52d5"
                            "9e5538d3d3942de9f13a7f8b702dc31724180da9df22714d01003fc5e3d165c9"
                            "50e630b8540fbd81c9df0ee63f94997026c4f2e1887a2def79050ac2d86ba318"
                            "e0b3adc4c5aa18bcf63c7cf8e85f569249813a2236a7e72269447cd1c755e451"
                            "f5e77470eb3de64c8849d292820698029cfa18e5d66176fe6e5ba4ed18026f90"
                            "900a5b4980e2f58e39151d5cd685b10929636d4f02e7fad2a5a458249f5c0298"
                            "a6d53acbe41a7fc83fa7cc01973f7a74d1237a51974e097636b6203997f921d0"
                            "7bc1940a6f2d0de9f5a11432946159ed6cc21df65c4ddd1115f86427259a196c"
                            "7148b25b6478b0dc7766e1c4d1b1f5159f90eabc61636226244642ee148b464c"
                            "9e619ee50a5e3ddc836227cad938987c4ea3c1fa7c75bbf88d89e9ada642b2b8"
                            "8fe8107b7ea375b1b64889a4e9e5c38a1c896ce275a5658d250e2d76e1ed3a34"
                            "ce7e3a3f383d0c996d0bed106c2899ca6fc263ef0455e74bb6ac1640ea7bfedc"
                            "59f03fee0e1725ea150ff4d69a7660c5542119c71de270ae7c3ecfd1af2c4ce5"
                            "51986949cc34a66b3e216bfe18b347e6c05fd050f85912db303a8f054ec23e38"
                            "f44d1c725ab641ae929fecc8e3cefa5619df4231f5b4c009fa0c0bbc60bc75f7"
                            "6d06ef154fc8577077d9d6a1d2bd9bf081dc783ece60111bea7da9e5a9748069"
                            "d078b2bef48de04cabe3755b197d52b32046949ecaa310274b4aac0d008b1948"
                            "c1082cdfe2083e386d4fd84c0ed0666d3ee26c4515c4fee73433ac703b690a9f"
                            "7bf278a77486ace44c489a0c7ac8dfe4d1a58fb3a730b993ff0f0d61b4d89557"
                            "831eb4c752ffd39c10f6b9f46d8db278da624fd800e4af85548a294c1518893a"
                            "8778c4f6d6d73c93df200960104e062b388ea97dcf4016bced7f62b4f062cb6c"
                            "04c20693d9a0e3b74ba8fe74cc01237884f40d765ae56a51688d985cf0ceaef4"
                            "3045ed8c3f0c33bced08537f6882613acd3b08d665fce9dd8aa73171e2d3771a"
                            "61dba2790e491d413d93d987e2745af29418e428be34941485c93447520ffe23"
                            "1da2304d6a0fd5d07d0837220236966159bef3cf904d722324dd852513df39ae"
                            "030d8173908da6364786d3c1bfcb19ea77a63b25f1e7fc661def480c5d00d444"
                            "56269ebd84efd8e3a8b2c257eec76060682848cbf5194bc99e49ee75e4d0d254"
                            "bad4bfd74970c30e44b65511d4ad0e6ec7398e08e01307eeeea14e46ccd87cf3"
                            "6b285221254d8fc6a6765c524ded0085dca5bd688ddf722e2c0faf9d0fb2ce7a"
                            "0c3f2cee19ca0ffba461ca8dc5d2c8178b0762cf67135558494d2a96f1a139f0"
                            "edb42d2af89a9c9122b07acbc29e5e722df8615c343702491098478a389c9872"
                            "a10b0c9875125e257c7bfdf27eef4060bd3d00f4c14fd3e3496c38d3c5d1a566"
                            "8c39350effbc2d16ca17be4ce29f02ed969504dda2a8c6b9ff919e693ee79e09"
                            "089316e7d1d89ec099db3b2b268725d888536a4b8bf9aee8fb43e82a4d919d48"
                            "43b1ca70a2d8d3f725ead1391377dcc0");
    std::vector<uint8_t> draft34_pkt =
            decode_from_hex("c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11"
                            "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399"
                            "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c"
                            "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212"
                            "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5"
                            "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208"
                            "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec"
                            "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3"
                            "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db"
                            "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c"
                            "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8"
                            "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556"
                            "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74"
                            "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a"
                            "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00"
                            "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632"
                            "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964"
                            "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd"
                            "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff"
                            "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198"
                            "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd"
                            "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73"
                            "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f"
                            "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e"
                            "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade"
                            "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047"
                            "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2"
                            "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4"
                            "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0"
                            "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e"
                            "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0"
                            "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400"
                            "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab"
                            "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9"
                            "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4"
                            "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064"
                            "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241"
                            "e221af44860018ab0856972e194cd934");
    std::vector<uint8_t> google_mangled_pkt =
            decode_from_hex("c300000001089714ce4dc712435c000045349815f4232d1334276442f35"
                            "fa3505fa9fbbafc0d57c8e502d00ff976b3acc29aeaecb9ac05f9861fc75cf6c"
                            "4656b818abecce1475d238c7caef9d0a88c9bc8b45663d79972659808ec72f8e"
                            "e85dc903c3bcbf37267a7e3a96ab3d454ba77585dc39b90bdd19c76beee20cfb"
                            "dd929fb7c7da5664326811139e9dc891af87f19c497cf18b4b4de4c6fe2b4e96"
                            "270c9e2ec0822837a47228e3832677249e30b0f592333d7f7a4becbf74dc461e"
                            "2acf6f1278f7da5b804a951dae714382e7cbfde731213c92c59b2220d3911d7f"
                            "2daa31cc60779e9971e4a9814d510d83a79a66f1a9731cd8df40f01012c629a8"
                            "97e392c83bb2464c2c54141a5310868d00ae0a60ea95232769681c64c95d5599"
                            "00542dbe0bbacc242952fd5cbe42ba69689b4e9e3c1fe639f6e1e2d50e7b13f4"
                            "295c56eaec82bb14eb1bc9390c045e4e0e97b8ebe93cd5a20dd7cd83c6de5cd5"
                            "9210f9c33f7ee874e450c478ea4a359ff00a8286f7ac1f18a4b2af0ffc942725"
                            "af362a817dd92a1dbc9fddeb2c1d5c7dff05a4c985c78b02e35466d3b36a28d5"
                            "a9ce1eea14f215f431051663e88e7cd7e6c36f90d45a21a97c3b8e7705c95f72"
                            "f99c6dc4af04690582a57ff50bc3762f15dfa71322db1ce1aabe8c298455aec9"
                            "a644bccaa9347a9d186ec2801512ed827818cf3eba0781bdf09114d677acdbd0"
                            "665f5e5cbb79219488b742d37085de9079e51e92ffec7d2c7fcb2d3e02303dad"
                            "4eda0154cdd3c9f5f95c1533358d3299d7255c16e862276c4dea10667522c771"
                            "d5dca113fe03421e7e89ccddf44c3926163f5a40685b8f85b6f139b334b1f40e"
                            "d42235b9d9df77070f40ff9d8382e3338249a86c799e7748dc8ac74035584d23"
                            "e6c487fb3c5a36bdaae76fd2929a7ca43c064bfdcde5cd1b51f32cca66f27f19"
                            "b79dbf76d888afc47d313b476f5d4765f92f81becd996b36c5845eaef3f2b602"
                            "296ff7885cba127fcb2c161ffd87e4c32229c8e287de99699500ac2f8a8484a5"
                            "2b6f143cb429f36f73a2499f32896730da7b2c816256142daf623d28199ba9a6"
                            "4619205d6bca37e2fa2c201690607039589a314c305fe1d543647dacd252c8b9"
                            "d0c19cbf12d35157159d56da33c4c78925fcd4c516eb98b35ea80ad96198cc35"
                            "cdf817e917b99a82dc0e72482ca213c249b928017ccf73d3322ee021b84d6275"
                            "04312eae53d899bf6c5db3a4e9565428be6256e11c1e03fa2b603c810687f8cc"
                            "5a473d97bae95c82b26645d8e6e5b207545e6709ed649f6782626a61d48e2c6c"
                            "9d3c167f95fcf15596278fb5b715d6e6e7f50bee7af25580ff36fd174d9d2b61"
                            "e23c1a59bcd4509d6d169d12304c08827e298b5d3fdd85b8af0a7658e5c480b7"
                            "2ba20b79a09e5667091e52d587d44b1987e2c0c78f99ab5d4cbba87ba02eaaf7"
                            "aa9aa344c98163b6d11373a88c999737b29fbe8647077000903097417366c615"
                            "30802b1ee8224ea343c686226277300c446bc7266c70c9c66aba23764d7387d4"
                            "5241d3981854f6d97d3a7ab49c271e28128b13fa5f4a38647056a18ba6b2f90f"
                            "4432fd58e5d4fd5233a4c5087e5f904ba7dfb2b5074ee27578f78d24f180be5a"
                            "b4f480e0e93f5d20e594730eae7fd2a1fab7c306530d4c6b590a52ae15f270a0"
                            "b6e65075e63b0b6d1f6ca7770caa1ce698e15e9b2867292ddeb820c1fa926028"
                            "92d0469126e5a2f7d4e5c99f6b6afcc3097f06e47acc93454ba83e3250741860"
                            "3cbdb338b39c35b4703dfb016aeb2d57dce036e6261999e28778b89089b9370d"
                            "699046673647ed84f9a5271cd5ef73c09870d955b37b464ef6a8d79e8d7bb301"
                            "5f17e869fa064dde2cbc9f38e58a0116a9b148b6ef56796d72e1994d1bfc1060"
                            "44d00d350ffb602fc");

    for (auto *p : {&draft28_pkt, &draft34_pkt, &google_mangled_pkt}) {
        std::vector<uint8_t> &pkt = *p;

        ag::quic_utils::QuicPacketHeader hd;
        // Extract data needed for decryption of initial packet
        int result = quiche_header_info(pkt.data(), pkt.size(), QUICHE_MAX_CONN_ID_LEN, &hd.version, &hd.type,
                hd.scid.data(), &hd.scid_len, hd.dcid.data(), &hd.dcid_len, hd.token.data(), &hd.token_len);
        ASSERT_EQ(result, 0);
        auto payload = ag::quic_utils::decrypt_initial({pkt.data(), pkt.size()}, hd);

        ASSERT_TRUE(payload);
        ASSERT_GT(payload->size(), 0);
        ASSERT_LE(payload->size(), pkt.size());

        auto crypto_frames = ag::quic_utils::reassemble_initial_crypto_frames({payload->data(), payload->size()});
        ASSERT_TRUE(crypto_frames);
        ASSERT_GT(crypto_frames->size(), 6);

        ASSERT_EQ(0x01, crypto_frames.value()[0]);
        uint32_t crypto_frames_len =
                crypto_frames.value()[1] << 16 | crypto_frames.value()[2] << 8 | crypto_frames.value()[3];
        ASSERT_EQ(crypto_frames->size() - 4, crypto_frames_len);
        ASSERT_EQ(0x03, crypto_frames.value()[4]);
        ASSERT_EQ(0x03, crypto_frames.value()[5]);

        ag::TlsReader tls{};
        tls_input_hshake(&tls, crypto_frames->data(), crypto_frames->size());

        bool got_sni = false;
        bool stop = false;
        while (!stop) {
            switch (tls_parse(&tls)) {
            case ag::TlsParseResult::TLS_RCLIENT_HELLO_SNI:
                got_sni = true;
                [[fallthrough]];
            case ag::TlsParseResult::TLS_RERR:
            case ag::TlsParseResult::TLS_RMORE:
            case ag::TlsParseResult::TLS_RDONE:
                stop = true;
                break;
            default:
                continue;
            }
        }
        std::cout << "Hostname: " << tls.tls_hostname << std::endl;
        ASSERT_TRUE(got_sni);
    }
}
