// Copyright © 2022 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <algorithm>
#include <cstdint>
#include <span>

#include <eosio/eosio.hpp>
#include <eosiock/types.hpp>

namespace eosiock {
    template<typename Hash>
    void mgf1(const Hash& hashf, const bytes_view mgf_seed, const std::span<byte_t> mask)
    {
        eosio::check( mask.size() <= std::numeric_limits<uint32_t>::max(), "MGF1 mask too long" );

        uint32_t counter          = 0;
        std::size_t out_len       = mask.size();
        byte_t* p_out_cur         = mask.data();
        const std::size_t buf_len = mgf_seed.size() + sizeof(counter);
        byte_t buf[buf_len];
        while (out_len)
        {
            memcpy( buf, mgf_seed.data(), mgf_seed.size() );

            // mgf_seed || I2OS(counter)
            buf[mgf_seed.size()]     = ((counter) >> 24) & 0xff;
            buf[mgf_seed.size() + 1] = ((counter) >> 16) & 0xff;
            buf[mgf_seed.size() + 2] = ((counter) >> 8) & 0xff;
            buf[mgf_seed.size() + 3] = (counter) & 0xff;

            auto hash = hashf( reinterpret_cast<const char*>( buf ), buf_len )
                .extract_as_byte_array();

            const size_t copied = std::min<std::size_t>( hash.size(), out_len );
            memcpy( p_out_cur, hash.data(), copied );

            p_out_cur += copied;
            out_len   -= copied;
            counter++;
        }
    }
}