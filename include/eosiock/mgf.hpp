// Copyright © 2022 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <algorithm>
#include <cstdint>
#include <span>

#include <eosiock/types.hpp>

namespace eosiock {
    /**
    * Mask generation function - MGF1.
    * Implementation based on RFC 8017 appendix-B.2.1: https://datatracker.ietf.org/doc/html/rfc8017#appendix-B.2.1
    * @param hash     - ref to t the hash function to use in the process
    * @param mgf_seed - the bytes view of MGF seed
    * @param mask     - the output mask
    * @param copy     - ref to the function which is used for copying final data to `mask`
    */
    template<typename HashF, typename CopyF = void(*)(std::span<byte_t>, const bytes_view, size_t) >
    void mgf1(HashF&& hash, const bytes_view mgf_seed, std::span<byte_t> mask,
              CopyF copy = [](auto dst, auto src, auto len) { memcpy( dst.data(), src.data(), len ); })
    {
        uint32_t counter          = 0;
        std::size_t out_len       = mask.size();
        const std::size_t buf_len = mgf_seed.size() + sizeof(counter);
        byte_t buf[buf_len];
        while ( out_len )
        {
            memcpy( buf, mgf_seed.data(), mgf_seed.size() );

            // mgf_seed || I2OS(counter)
            buf[mgf_seed.size()]     = ((counter) >> 24) & 0xff;
            buf[mgf_seed.size() + 1] = ((counter) >> 16) & 0xff;
            buf[mgf_seed.size() + 2] = ((counter) >> 8) & 0xff;
            buf[mgf_seed.size() + 3] = (counter) & 0xff;

            auto digest = hash( reinterpret_cast<const char*>( buf ), buf_len )
                .extract_as_byte_array();

            const size_t copied = std::min<std::size_t>( digest.size(), out_len );
            copy( mask, digest, copied );

            mask     = mask.subspan( copied );
            out_len -= copied;
            counter++;
        }
    }
}