/**
 * This file is part of ack library.
 * Copyright © 2023 ZeroPass <zeropass@pm.me>
 * Author: Crt Vavros
 *
 *  File contains parts of modified code from mcl library licensed as BSD-3 license and copyright (c) 2015 MITSUNARI Shigeo.
 *  Library repo: https://github.com/herumi
 *
 *  Code taken from files: vint.hpp, array.hpp, bint.hpp. bint_impl.hpp, bint_proto.hpp, conversion.hpp, util.hpp
 *
 *   The mcl library original copyright notice
 *   @file
 *    @brief tiny vector class
 *   @author MITSUNARI Shigeo(@herumi)
 *   @license modified new BSD license
 *  http://opensource.org/licenses/BSD-3-Clause
 *
*/

#pragma once
#include <ack/buffer.hpp>
#include <ack/type_traits.hpp>
#include <ack/types.hpp>
#include <ack/utils.hpp>

#include <eosio/eosio.hpp>

#include <assert.h>
#include <bit>
#include <cstdlib>
#include <cstddef>
#include <type_traits>

namespace ack {
    namespace detail {
        inline constexpr word_t bswap_word(word_t x) {
            constexpr auto wsize = sizeof(word_t);
            static_assert(wsize == 4 || wsize == 8, "size of word_t is not 4 or 8 bytes");

            // TODO: maybe use __builtin_bswap32 && __builtin_bswap64;
            if constexpr (wsize == 4) {
                return (word_t)(
                    (((word_t)(x) & (word_t)0x000000ffUL) << 24)  |
                    (((word_t)(x) & (word_t)0x0000ff00UL) << 8)   |
                    (((word_t)(x) & (word_t)0x00ff0000UL) >> 8)   |
                    (((word_t)(x) & (word_t)0xff000000UL) >> 24));
            }
            else { // 8 bytes
                return ((x << 56) & (word_t)0xff00000000000000ULL) |
                    ((x << 40) & (word_t)0x00ff000000000000ULL)    |
                    ((x << 24) & (word_t)0x0000ff0000000000ULL)    |
                    ((x << 8)  & (word_t)0x000000ff00000000ULL)    |
                    ((x >> 8)  & (word_t)0x00000000ff000000ULL)    |
                    ((x >> 24) & (word_t)0x0000000000ff0000ULL)    |
                    ((x >> 40) & (word_t)0x000000000000ff00ULL)    |
                    ((x >> 56) & (word_t)0x00000000000000ffULL);
            }
        }

        // constexpr 32bit abs
        inline constexpr uint32_t cabs(int32_t x)
        {
            if (x >= 0) return uint32_t(x);
            // avoid undefined behavior
            if (x == -2147483647 - 1) return 2147483648u;
            return uint32_t(-x);
        }

        // constexpr 64bit abs
        inline constexpr uint64_t cabs(int64_t x)
        {
            if (x >= 0) return uint64_t(x);
            // avoid undefined behavior
            if (x == -9223372036854775807ll - 1) return 9223372036854775808ull;
            return uint64_t(-x);
        }

        // true if x[n] >= y[n]
        template<typename T>
        inline constexpr bool cmp_ge_n(const T *px, const T *py, size_t n)
        {
            for (size_t i = 0; i < n; i++) {
                const T x = px[n - 1 - i];
                const T y = py[n - 1 - i];
                if (x > y) return true;
                if (x < y) return false;
            }
            return true;
        }

        // true if x[n] < y[n]
        template<typename T>
        inline constexpr bool cmp_lt_n(const T *px, const T *py, size_t n)
        {
            return !cmp_ge_n(px, py, n);
        }

        template<typename T>
        inline constexpr int cmp_n(const T *px, const T *py, size_t n)
        {
            for (size_t i = 0; i < n; i++) {
                const T x = px[n - 1 - i];
                const T y = py[n - 1 - i];
                if (x != y) return x > y ? 1 : -1;
            }
            return 0;
        }

        template<size_t N, typename T>
        inline constexpr int cmp_t(const T *px, const T *py)
        {
            for (size_t i = 0; i < N; i++) {
                const T x = px[N - 1 - i];
                const T y = py[N - 1 - i];
                if (x != y) return x > y ? 1 : -1;
            }
            return 0;
        }

        // return the real size of x
        // return 1 if x[n] == 0
        template<typename T>
        inline constexpr size_t get_real_size(const T *x, size_t n)
        {
            while (n > 0) {
                if (x[n - 1]) break;
                n--;
            }
            return n > 0 ? n : 1;
        }

        template<class T>
        inline constexpr int bsr(T x)
        {
            constexpr auto tsize = sizeof(T);
            static_assert(tsize == 4 || tsize == 8);
            // Note: UB for x == 0

            if constexpr (tsize == 4) {
                // return __builtin_clz(x) ^ 0x1f;
                return std::countl_zero(x) ^ 0x1f;
            }
            else { // 8
                //return __builtin_clzll(x) ^ 0x3f;
                return std::countl_zero(x) ^ 0x3f;
            }
        }

        /*
            [H:L] <= x * y
            @return L
        */
        inline constexpr uint32_t mul_word1(uint32_t* pH, uint32_t x, uint32_t y)
        {
            uint64_t t = uint64_t(x) * y;
            *pH = uint32_t(t >> 32);
            return uint32_t(t);
        }

        inline constexpr uint64_t mul_word1(uint64_t *pH, uint64_t x, uint64_t y)
        {
        #if 1
            uint128_t t = uint128_t(x) * y;
            *pH = uint64_t(t >> 64);
            return uint64_t(t);
        #else
            return _umul128(x, y, pH);
        #endif
        }

        inline constexpr auto get_add(size_t n)
        {
            return [n=n](word_t* z, const word_t* x, const word_t* y) {
                // wasm32 supports 64-bit add
                uint64_t c = 0;
                for (size_t i = 0; i < n; i++) {
                    uint64_t v = uint64_t(x[i]) + y[i] + c;
                    z[i] = uint32_t(v);
                    c = v >> 32;
                }
                return uint32_t(c);

                // word_t c = 0;
                // for (size_t i = 0; i < n; i++) {
                //     word_t xc = x[i] + c;
                //     c = xc < c;
                //     word_t yi = y[i];
                //     xc += yi;
                //     c += xc < yi;
                //     z[i] = xc;
                // }
                // return c;
            };
        }

        inline constexpr word_t add_n(word_t* z, const word_t* x, const word_t* y, size_t n)
        {
            return get_add(n)(z, x, y);
        }

        inline constexpr auto get_sub(size_t n)
        {
            return [n=n](word_t* z, const word_t* x, const word_t* y) {
                // wasm32 supports 64-bit sub
                uint64_t c = 0;
                for (size_t i = 0; i < n; i++) {
                    uint64_t v = uint64_t(x[i]) - y[i] - c;
                    z[i] = uint32_t(v);
                    c = v >> 63;
                }
                return c;

                // word_t c = 0;
                // for (size_t i = 0; i < n; i++) {
                //     word_t yi = y[i];
                //     yi += c;
                //     c = yi < c;
                //     word_t xi = x[i];
                //     c += xi < yi;
                //     z[i] = xi - yi;
                // }
                // return c;
            };
        }

        inline constexpr word_t sub_n(word_t* z, const word_t* x, const word_t* y, size_t n)
        {
            return get_sub(n)(z, x, y);
        }

        inline constexpr auto get_mul_word(size_t n)
        {
            return [n=n](word_t* z, const word_t* x, word_t y) {
                uint64_t H = 0;
                uint64_t y_ = y;
                for (size_t i = 0; i < n; i++) {
                    uint64_t v = x[i] * y_;
                    v += H;
                    z[i] = uint32_t(v);
                    H = v >> 32;
                }
                return uint32_t(H);
            };
        }

        inline constexpr word_t mul_word_n(word_t* z, const word_t* x, word_t y, size_t n)
        {
            return get_mul_word(n)(z, x, y);
        }

        inline constexpr auto get_mul_word_add(size_t n)
        {
            return [n=n](word_t* z, const word_t* x, word_t y) {
                // reduce cast operation
                uint64_t H = 0;
                uint64_t y_ = y;
                for (size_t i = 0; i < n; i++) {
                    uint64_t v = x[i] * y_;
                    v += H;
                    v += z[i];
                    z[i] = uint32_t(v);
                    H = v >> 32;
                }
                return H;
            };
        }

        inline constexpr word_t mul_word_add_n(word_t* z, const word_t* x, word_t y, std::size_t n)
        {
            return get_mul_word_add(n)(z, x, y);
        }

        // z[2n] = x[n] * y[n]
        static constexpr void mul_n(word_t *pz, const word_t *px, const word_t *py, std::size_t n)
        {
            pz[n] = mul_word_n(pz, px, py[0], n);
            auto mul_word_add = get_mul_word(n);
            for (size_t i = 1; i < n; i++) {
                pz[n + i] = mul_word_add(&pz[i], px, py[i]);
            }
        }

        // y[2N] = x[N] * x[N]
        inline constexpr void sqr_n(word_t *py, const word_t *px, std::size_t n)
        {
            // QQQ : optimize this later
            mul_n(py, px, px, n);
        }

        // y[n] = x[n]
        template<typename T>
        inline constexpr void copy_n(T *y, const T *x, size_t n)
        {
            for (size_t i = 0; i < n; i++) y[i] = x[i];
        }

        // x[n] = 0
        template<typename T>
        inline constexpr void clear_n(T *x, size_t n)
        {
            for (size_t i = 0; i < n; i++) x[i] = 0;
        }

        // [return:z[N]] = x[N] << y
        // 0 < y < word_bit_size
        inline constexpr word_t shl_n(word_t* pz, const word_t* px, word_t bit, size_t n)
        {
            assert(0 < bit && bit < word_bit_size);
            size_t bitRev = word_bit_size - bit;
            word_t prev = px[n - 1];
            word_t keep = prev;
            for (size_t i = n - 1; i > 0; i--) {
                word_t t = px[i - 1];
                pz[i] = (prev << bit) | (t >> bitRev);
                prev = t;
            }
            pz[0] = prev << bit;
            return keep >> bitRev;
        }

        // z[n] = x[n] >> bit
        // 0 < bit < word_bit_size
        inline constexpr void shr_n(word_t* pz, const word_t* px, size_t bit, size_t n)
        {
            assert(0 < bit && bit < word_bit_size);
            size_t bitRev = word_bit_size - bit;
            word_t prev = px[0];
            for (size_t i = 1; i < n; i++) {
                word_t t = px[i];
                pz[i - 1] = (prev >> bit) | (t << bitRev);
                prev = t;
            }
            pz[n - 1] = prev >> bit;
        }

        /*
            generic version
            y[yn] = x[xn] << bit
            yn = xn + roundUp(bit, word_bit_size)
            accept y == x
            return yn
        */
        inline constexpr size_t shift_left(word_t* y, const word_t* x, size_t bit, size_t xn)
        {
            assert(xn > 0);
            size_t q = bit / word_bit_size;
            size_t r = bit % word_bit_size;
            size_t yn = xn + q;
            if (r == 0) {
                // don't use copy_n(y + q, x, xn); if overlaped
                for (size_t i = 0; i < xn; i++) {
                    y[q + xn - 1 - i] = x[xn - 1 - i];
                }
            } else {
                y[q + xn] = shl_n(y + q, x, r, xn);
                yn++;
            }

            clear_n(y, q);
            return yn;
        }

        /*
            generic version
            y[yn] = x[xn] >> bit
            yn = xn - bit / word_bit_size
            return yn
        */
        inline constexpr size_t shift_right(word_t* y, const word_t* x, size_t bit, size_t xn)
        {
            assert(bit <= word_bit_size * xn);
            assert(xn > 0);

            size_t q = bit / word_bit_size;
            size_t r = bit % word_bit_size;
            assert(xn >= q);

            if (r == 0) {
                copy_n(y, x + q, xn - q);
            } else {
                shr_n(y, x + q, r, xn - q);
            }
            return xn - q;
        }

        // [return:y[n]] += x
        inline constexpr word_t add_word(word_t* y, size_t n, word_t x)
        {
            if (n == 0) return 0;

            word_t t = y[0] + x;
            y[0] = t;

            if (t >= x) return 0;
            for (size_t i = 1; i < n; i++) {
                t = y[i] + 1;
                y[i] = t;
                if (t != 0) return 0;
            }
            return 1;
        }

        // y[n] -= x, return CF
        inline constexpr word_t sub_word(word_t* y, size_t n, word_t x)
        {
            if (n == 0) return 0;

            word_t t = y[0];
            y[0] = t - x;

            if (t >= x) return 0;
            for (size_t i = 1; i < n; i++) {
                t = y[i];
                y[i] = t - 1;
                if (t != 0) return 0;
            }
            return 1;
        }

        inline constexpr uint32_t div_word1(uint32_t* pr, uint32_t H, uint32_t L, uint32_t y)
        {
            assert(H < y);
            uint64_t t = (uint64_t(H) << 32) | L;
            uint32_t q = uint32_t(t / y);
            *pr = uint32_t(t % y);
            return q;
        }

        inline constexpr uint64_t div_word1(uint64_t *pr, uint64_t H, uint64_t L, uint64_t y)
        {
            assert(H < y);
            uint128_t t = (uint128_t(H) << 64) | L;
            uint64_t q = uint64_t(t / y);
            *pr = uint64_t(t % y);
            return q;
        }

        /*
            q[] = x[] / y
            @retval r = x[] % y
            accept q == x
        */
        inline constexpr word_t div_word(word_t* q, const word_t* x, size_t n, word_t y)
        {
            check( y != 0, "division by zero" );
            //if (n == 0) return 0;

            word_t r = 0;
            for (int i = (int)n - 1; i >= 0; i--) {
                q[i] = div_word1(&r, r, x[i], y);
            }
            return r;
        }

        /*
            q[] = x[] / y
            @retval r = x[] % y
        */
        inline constexpr word_t mod_word(const word_t* x, size_t n, word_t y)
        {
            check( y != 0, "mod by zero" );
            //if (n == 0) return 0;

            word_t r = 0;
            for (int i = (int)n - 1; i >= 0; i--) {
                div_word1(&r, r, x[i], y);
            }
            return r;
        }

        // TODO: make constexpr when VL array is replaced with constexpr solution
        static word_t div_small(word_t* q, const size_t qn, word_t* x, const size_t xn, const word_t* y, const size_t yn)
        {
            word_t qv = 0;
            const auto clear_q_get_real_size = [&]() -> size_t {
                if (q) {
                    q[0] = qv;
                    clear_n(q + 1, qn - 1);
                }
                return get_real_size(x, xn);
            };

            if (xn > yn) {
                return 0;
            }

            assert(yn > 0);
            const word_t yTop = y[yn - 1];
            assert(yTop > 0);

            int ret = xn < yn ? -1 : cmp_n(x, y, yn);
            if (ret < 0) { // q = 0, r = x if x < y
                return clear_q_get_real_size();
            }

            if (ret == 0) { // q = 1, r = 0 if x == y
                clear_n(x, xn);
                qv = 1;
                return clear_q_get_real_size();
            }

            assert(xn == yn);
            if (yTop >= word_t(1) << (word_bit_size / 2)) {
                auto sub = get_sub(yn);
                if (yTop == word_t(-1)) {
                    sub(x, x, y);
                    qv = 1;
                }
                else {
                    //word_t* t = (word_t*)__builtin_alloca(sizeof(word_t) * yn);
                    word_t t[sizeof(word_t) * yn];
                    qv = x[yn - 1] / (yTop + 1);
                    mul_word_n(t, y, qv, yn);
                    sub(x, x, t);
                }

                // expect that loop is at most once
                while (cmp_ge_n(x, y, yn)) {
                    sub(x, x, y);
                    qv++;
                }
                return clear_q_get_real_size();
            }

            return 0;
        }

        // TODO: Make constexpr when __builtin_alloca is replaced
        static size_t div_full_bit(word_t* q, size_t qn, word_t* x, size_t xn, const word_t* y, size_t yn)
        {
            assert(xn > 0);
            assert(q != x && q != y && x != y);
            const word_t yTop = y[yn - 1];

            assert(yTop >> (word_bit_size - 1));
            if (q) {
                clear_n(q, qn);
            }

            //word_t* t = (word_t*)__builtin_alloca(sizeof(word_t) * yn);
            word_t t[sizeof(word_t) * yn];
            //word_t* t = (word_t*)alloca(sizeof(word_t) * yn);
            word_t rev = 0;
            // rev = M/2 M / yTop where M = 1 << word_bit_size
            if (yTop != word_t(-1)) {
                word_t r;
                rev = div_word1(&r, word_t(1) << (word_bit_size - 1), 0, yTop + 1);
            }

            auto sub = get_sub(yn);
            auto mulUnit = get_mul_word(yn);
            while (xn >= yn) {
                if (x[xn - 1] == 0) {
                    xn--;
                    continue;
                }

                size_t d = xn - yn;
                if (cmp_ge_n(x + d, y, yn)) {
                    sub_n(x + d, x + d, y, yn);
                    if (q) {
                        add_word(q + d, qn - d, 1);
                    }
                    if (d == 0) break;
                }
                else {
                    if (d == 0) break;

                    word_t v;
                    if (yTop == word_t(-1)) {
                        v = x[xn - 1];
                    }
                    else {
                        word_t L = mul_word1(&v, x[xn - 1], rev);
                        v = (v << 1) | (L >> (word_bit_size - 1));
                        if (v == 0) {
                            v = 1;
                        }
                    }

                    word_t ret = mulUnit(t, y, v);
                    ret += sub(x + d - 1, x + d - 1, t);
                    x[xn-1] -= ret;
                    if (q) {
                        add_word(q + d - 1, qn - d + 1, v);
                    }
                }
            }

            assert(xn < yn || (xn == yn && cmp_lt_n(x, y, yn)));
            xn = get_real_size(x, xn);
            return xn;
        }

        // yn == 1
        inline constexpr size_t div1(word_t* q, size_t qn, word_t* x, size_t xn, const word_t* y)
        {
            assert(xn > 0);
            assert(q == 0 || qn >= xn);
            xn = get_real_size(x, xn);

            word_t t = 0;
            if (q) {
                if (qn > xn) {
                    clear_n(q + xn, qn - xn);
                }
                t = div_word(q, x, xn, y[0]);
            }
            else {
                t = mod_word(x, xn, y[0]);
            }

            x[0] = t;
            clear_n(x + 1, xn - 1);
            return 1;
        }

        // TODO: Make constexpr when __builtin_alloca is replaced and div_small is constexpr
        static size_t div(word_t* q, size_t qn, word_t* x, size_t xn, const word_t* y, size_t yn)
        {
            if (yn == 1) {
                return div1(q, qn, x, xn, y);
            }

            assert(xn > 0 && yn > 1);
            assert(xn < yn || (q == 0 || qn >= xn - yn + 1));
            assert(y[yn - 1] != 0);

            xn = get_real_size(x, xn);
            size_t new_xn = div_small(q, qn, x, xn, y, yn);
            if (new_xn > 0) {
                return new_xn;
            }

            /*
                bitwise left shift x and y to adjust MSB of y[yn - 1] = 1
            */
            const size_t yTopBit = detail::bsr(y[yn - 1]);
            const size_t shift = word_bit_size - 1 - yTopBit;
            if (shift) {
                //word_t* yShift = (word_t* )__builtin_alloca(sizeof(word_t) * yn);
                word_t yShift[sizeof(word_t) * yn];
                //word_t* yShift = (word_t* )alloca(sizeof(word_t) * yn);
                shl_n(yShift, y, shift, yn);
                //word_t* xx = (word_t*)__builtin_alloca(sizeof(word_t) * (xn + 1));
                word_t xx[sizeof(word_t) * (xn + 1)];
                //word_t* xx = (word_t*)alloca(sizeof(word_t) * (xn + 1));
                word_t v = shl_n(xx, x, shift, xn);
                if (v) {
                    xx[xn] = v;
                    xn++;
                }

                xn = div_full_bit(q, qn, xx, xn, yShift, yn);
                shr_n(x, xx, shift, xn);
                return xn;
            }
            else {
                return div_full_bit(q, qn, x, xn, y, yn);
            }
        }

        // TODO: Make constexpr when __builtin_alloca is replaced
        inline bool mul_nm(word_t* z, const word_t* x, size_t xn, const word_t* y, size_t yn)
        {
            if (xn == 0 || yn == 0) return true;
            if (yn > xn) {
                std::swap(yn, xn);
                std::swap(x, y);
            }

            assert(xn >= yn);
            if (xn < yn) {
                return false;
            }

            if (z == x) {
                word_t* p = (word_t*)__builtin_alloca(sizeof(word_t) * xn);
                //word_t* p = (word_t*)alloca(sizeof(word_t) * xn);
                copy_n(p, x, xn);
                x = p;
            }

            if (z == y) {
                word_t* p = (word_t*)__builtin_alloca(sizeof(word_t) * yn);
                //word_t* p = (word_t*)alloca(sizeof(word_t) * yn);
                copy_n(p, y, yn);
                y = p;
            }

            z[xn] = mul_word_n(z, x, y[0], xn);
            auto mulUnitAdd = get_mul_word_add(xn);
            for (size_t i = 1; i < yn; i++) {
                z[xn + i] = mulUnitAdd(&z[i], x, y[i]);
            }

            return true;
        }

         /*
            treat src[] as a little endian and set dst[]
            fill remain of dst if sizeof(D) * dst_len > sizeof(S) * src_len
            return false if sizeof(D) * dst_len < sizeof(S) * src_len
        */
        /**
         * Converts src array to dst array.
         * @tparam D destination type
         * @tparam S source type
         *
         * @param dst       - destination array
         * @param dst_len   - destination array length
         * @param src       - source array
         * @param src_len   - source array length
         * @param bigendian - if true, src is big endian else src is treated as little endian.
         * @return true if sizeof(D) * dst_len >= sizeof(S) * src_len
        */
        template<class D, class S>
        constexpr bool convert_array_as(D* dst, const std::size_t dst_len, const S* src, const std::size_t src_len, bool bigendian)
        {
            static_assert( std::is_unsigned_v<D> && std::is_unsigned_v<S> );

            if (sizeof(D) * dst_len < sizeof(S) * src_len) {
                return false;
            }

            size_t pos = 0;
            const std::size_t src_offs = bigendian ? src_len - 1 : 0;
            const auto get_src_elem = [&](size_t i) {
                return src[src_offs + (bigendian ? -i : i)];
            };

            if (sizeof(D) < sizeof(S)) {
                for (size_t i = 0; i < src_len; i++) {
                    S s = get_src_elem(i); //src[i];
                    for (size_t j = 0; j < sizeof(S); j += sizeof(D)) {
                        dst[pos++] = D(s);
                        s >>= sizeof(D) * 8;
                    }
                }
                for (; pos < dst_len; pos++) {
                    dst[pos] = 0;
                }
            }
            else {
                for (size_t i = 0; i < dst_len; i++) {
                    D u = 0;
                    for (size_t j = 0; j < sizeof(D); j += sizeof(S)) {
                        S s = (pos < src_len) ? get_src_elem(pos++) /*src[pos++]*/ : 0;
                        u |= D(s) << (j * 8);
                    }
                    dst[i] = u;
                }
            }
            return true;
        }
    } // detail


    /**
     * Signed big integer with variable length.
     * Based on mcl::Vint.
     *
     * @tparam Buffer - buffer type
     *
     * NOTE: Due to stack frame size limitation the fixed_buffer is bound by this size.
     *       Also all  calls to __builtin_alloca / alloca calls & VLA are limited to stack frame size.
     *       In case of antelopeIO the stack frame size is 512B, with some testing it was found that
     *       max size of fixed_buffer can be 128 bytes (1024 bits) for all ECC or RSA operations.
     *
     * TODO: Replace std::enable_if_t with buffer concept when clang 10 is supported.
     * TODO: All __builtin_alloca / alloca calls and VLA are limited to stack frame size
     *       find a way to replace them with heap allocation or static buffer.
     **/
    template<typename Buffer,
        typename = std::enable_if_t<std::is_base_of_v<buffer_base<Buffer, word_t>, Buffer>>>
    class bigint {
        public:
            using buffer_type = Buffer;
            static constexpr int invalid_var = -2147483647 - 1; // abs(invalid_var) is not defined

        private:
            buffer_type buf_;
            size_t size_ = 0;
            bool is_neg_ = false;
            template<typename, typename> friend class bigint;

            constexpr void trim(size_t n)
            {
                if ( n > 0 ) {
                    int i = (int)n - 1;
                    for (; i > 0; i--) {
                        if (buf_[i]) {
                            size_ = i + 1;
                            return;
                        }
                    }

                    size_ = 1;

                    // zero
                    if (buf_[0] == 0) {
                        is_neg_ = false;
                    }
                }
            }

            static inline constexpr int ucompare(const buffer_type& x, size_t xn, const buffer_type& y, size_t yn)
            {
                if (xn == yn) return detail::cmp_n(&x[0], &y[0], xn);
                return xn > yn ? 1 : -1;
            }

            static inline constexpr void uadd(bigint& z, const buffer_type& x, size_t xn, const buffer_type& y, size_t yn)
            {
                const word_t* px = &x[0];
                const word_t* py = &y[0];
                if (yn > xn) {
                    std::swap(xn, yn);
                    std::swap(px, py);
                }

                assert(xn >= yn);

                // &x[0] and &y[0] will not change if z == x or z == y
                const bool success = z.buf_.alloc(xn + 1);
                assert(success);
                if (!success) {
                    z.clear();
                    return;
                }

                word_t* dst = &z.buf_[0];
                word_t c = detail::add_n(dst, px, py, yn);
                if (xn > yn) {
                    size_t n = xn - yn;
                    if (dst != px) detail::copy_n(dst + yn, px + yn, n);
                    c = detail::add_word(dst + yn, n, c);
                }

                dst[xn] = c;
                z.trim(xn + 1);
            }

            static constexpr void uadd1(bigint& z, const buffer_type& x, size_t xn, word_t y)
            {
                size_t zn = xn + 1;
                const bool success = z.buf_.alloc(zn);
                assert(success);
                if (!success) {
                    z.clear();
                    return;
                }

                if (&z.buf_[0] != &x[0]) {
                    detail::copy_n(&z.buf_[0], &x[0], xn);
                }
                z.buf_[zn - 1] = detail::add_word(&z.buf_[0], xn, y);
                z.trim(zn);
            }

            static constexpr void usub1(bigint& z, const buffer_type& x, size_t xn, word_t y)
            {
                size_t zn = xn;
                const bool success = z.buf_.alloc(zn);
                assert(success);
                if (!success    ) {
                    z.clear();
                    return;
                }

                word_t* dst = &z.buf_[0];
                const word_t* src = &x[0];
                if (dst != src) detail::copy_n(dst, src, xn);
                [[maybe_unused]] const word_t c = detail::sub_word(dst, xn, y);
                assert(!c);

                z.trim(zn);
            }

            static constexpr void usub(bigint& z, const buffer_type& x, size_t xn, const buffer_type& y, size_t yn)
            {
                assert(xn >= yn);

                const bool success = z.buf_.alloc(xn);
                assert(success);
                if (!success) {
                    z.clear();
                    return;
                }

                word_t c = detail::sub_n(&z.buf_[0], &x[0], &y[0], yn);
                if (xn > yn) {
                    size_t n = xn - yn;
                    word_t* dst = &z.buf_[yn];
                    const word_t* src = &x[yn];
                    if (dst != src) detail::copy_n(dst, src, n);
                    c = detail::sub_word(dst, n, c);
                }

                assert(!c);
                z.trim(xn);
            }

            static constexpr void _add(bigint& z, const bigint& x, bool xNeg, const bigint& y, bool yNeg)
            {
                if ((xNeg ^ yNeg) == 0) {
                    // same sign
                    uadd(z, x.buf_, x.size(), y.buf_, y.size());
                    z.is_neg_ = xNeg;
                    return;
                }

                int r = ucompare(x.buf_, x.size(), y.buf_, y.size());
                if (r >= 0) {
                    usub(z, x.buf_, x.size(), y.buf_, y.size());
                    z.is_neg_ = xNeg;
                } else {
                    usub(z, y.buf_, y.size(), x.buf_, x.size());
                    z.is_neg_ = yNeg;
                }
            }

            static constexpr void _adds1(bigint& z, const bigint& x, int y, bool yNeg)
            {
                assert(y >= 0);
                if ((x.is_neg_ ^ yNeg) == 0) {
                    // same sign
                    uadd1(z, x.buf_, x.size(), y);
                    z.is_neg_ = yNeg;
                    return;
                }

                if (x.size() > 1 || x.buf_[0] >= (word_t)y) {
                    usub1(z, x.buf_, x.size(), y);
                    z.is_neg_ = x.is_neg_;
                } else {
                    z = y - x.buf_[0];
                    z.is_neg_ = yNeg;
                }
            }

            static constexpr void _addu1(bigint& z, const bigint& x, word_t y, bool yNeg)
            {
                if ((x.is_neg_ ^ yNeg) == 0) {
                    // same sign
                    uadd1(z, x.buf_, x.size(), y);
                    z.is_neg_ = yNeg;
                    return;
                }

                if (x.size() > 1 || x.buf_[0] >= y) {
                    usub1(z, x.buf_, x.size(), y);
                    z.is_neg_ = x.is_neg_;
                } else {
                    z = y - x.buf_[0];
                    z.is_neg_ = yNeg;
                }
            }

            /**
                @param q [out] x / y if q != 0
                @param r [out] x % y
            */
           // TODO: make constexpr when VL array is replaced with constexpr solution
            static bool udiv(bigint* q, bigint& r, const buffer_type& x, size_t xn, const buffer_type& y, size_t yn)
            {
                assert(q != &r);
                //if (q == &r) return false;
                if (xn < yn) {
                    r.buf_ = x;
                    r.trim(xn);
                    if (q) q->clear();
                    return true;
                }

                size_t qn = xn - yn + 1;
                if (q) {
                    const bool success = q->buf_.alloc(qn);
                    assert(success);
                    if (!success) return false;
                }

                //word_t* xx = (word_t*)__builtin_alloca(sizeof(word_t) * xn);
                word_t xx[sizeof(word_t) * xn];
                detail::copy_n(xx, &x[0], xn);

                word_t* qq = q ? &q->buf_[0] : nullptr;
                size_t rn = detail::div(qq, qn, xx, xn, &y[0], yn);

                const bool success = r.buf_.alloc(rn);
                assert(success);
                if (!success) {
                    return false;
                }

                detail::copy_n(&r.buf_[0], xx, rn);
                if (q) {
                    q->trim(qn);
                }

                r.trim(rn);
                return true;
            }

            /*
                @param x [inout] x <- d
                @retval s for x = 2^s d where d is odd
            */
            static constexpr uint32_t count_trailing_zero(bigint& x)
            {
                uint32_t s = 0;
                while (x.is_even()) {
                    x >>= 1;
                    s++;
                }
                return s;
            }

            struct mod_mul_t {
                const bigint* pm;
                constexpr bool operator()(bigint& z, const bigint& x, const bigint& y) const
                {
                    bool success = mul(z, x, y);
                    return success && mod(z, z, *pm);
                }
            };

            struct mod_sqr_t {
                const bigint* pm;
                constexpr bool operator()(bigint& y, const bigint& x) const
                {
                    bool success = bigint::sqr(y, x);
                    success = success && bigint::mod(y, y, *pm);
                    return success;
                }
            };

            // z = x^y
            // TODO: make constexpr when __builtin_alloca is replaced
            template<class Mul, class Sqr>
            static bool _pow(bigint& z, const bigint& x, const word_t* y, size_t n, const Mul& mul, const Sqr& sqr)
            {
                while (n > 0) {
                    if (y[n - 1]) break;
                    n--;
                }

                if (n == 0) n = 1;
                if (n == 1) {
                    switch (y[0]) {
                        case 0:
                            z = 1;
                            return true;
                        case 1:
                            z = x;
                            return true;
                        case 2:
                            return sqr(z, x);
                        case 3: {
                            bigint t;
                            bool success = sqr(t, x);
                            success = success && mul(z, t, x);
                            return success;
                        }
                        case 4: {
                            bool success = sqr(z, x);
                            success = success && sqr(z, z);
                            return success;
                        }
                    }
                }

                const size_t w = 4; // don't change
                const size_t m = word_bit_size / w;
                const size_t tblSize = (1 << w) - 1;
                bigint tbl[tblSize];
                tbl[0] = x;
                for (size_t i = 1; i < tblSize; i++) {
                    if (!mul(tbl[i], tbl[i - 1], x)) {
                        return false;
                    }
                }

                word_t* yy = 0;
                if (y == &z.buf_[0]) { // keep original y(=z)
                    yy = (word_t*)__builtin_alloca(sizeof(word_t) * n);
                    //yy = (word_t*)alloca(sizeof(word_t) * n);
                    detail::copy_n(yy, y, n);
                    y = yy;
                }

                z = 1;
                for (size_t i = 0; i < n; i++) {
                    word_t v = y[n - 1 - i];
                    for (size_t j = 0; j < m; j++) {
                        for (size_t k = 0; k < w; k++) {
                            if (!sqr(z, z)) {
                                return false;
                            }
                        }

                        word_t idx = (v >> ((m - 1 - j) * w)) & tblSize;
                        if (idx) {
                            if (!mul(z, z, tbl[idx - 1])) {
                                return false;
                            }
                        }
                    }
                }

                return true;
            }

        public:

            /**
             * Constructs bigint from integer.
             * @param x integer
            */
            constexpr bigint(int x = 0)
            {
                *this = x;
            }

            /**
             * Constructs bigint from unsigned integer.
             * @param x unsigned integer of type word_t
            */
            constexpr bigint(word_t x)
            {
                *this = x;
            }

            /**
             * Constructs bigint from 64bit integer.
             * @param x 64bit integer
            */
            constexpr bigint(int64_t x)
            {
                *this = x;
            }

             /**
             * Constructs bigint from unsigned 64bit integer.
             * @param x 64bit integer
            */
            constexpr bigint(uint64_t x)
            {
                *this = x;
            }

            /**
             * Constructs bigint from bytes.
             * Bytes are expected to be in big endian byte order.
             *
             * @param data bytes in big endian byte order.
            */
            constexpr bigint(const bytes& data)
            {
                check( set_bytes(data), "Couldn't construct bigint from bytes" );
            }

            /**
             * Constructs bigint from bytes.
             * Bytes are expected to be in big endian byte order.
             *
             * @param data bytes in big endian byte order.
            */
            template<std::size_t U>
            constexpr bigint(const fixed_bytes<U>& data)
            {
                check( set_bytes(data), "Couldn't construct bigint from bytes" );
            }

            /**
             * Constructs bigint from bytes.
             * Bytes are expected to be in big endian byte order.
             *
             * @param data bytes in big endian byte order.
            */
            constexpr bigint(const bytes_view data)
            {
                check( set_bytes(data), "Couldn't construct bigint from bytes" );
            }

            /**
             * Constructs bigint from hex string.
             * Bytes are expected to be in big endian byte order.
             *
             * @param hex_str hex string.
            */
            constexpr bigint(const std::string_view hex_str)
            {
                check( set_bytes( from_hex( hex_str ) ), "Couldn't construct bigint from hex string" );
            }

            /**
             * Constructs bigint from hex string.
             * Bytes are expected to be in big endian byte order.
             *
             * @param hex_str hex string literal.
            */
            template<std::size_t N>
            constexpr bigint(const char (&hex_str)[N])
            {
                check( set_bytes( from_hex<N>( hex_str ) ), "Couldn't construct bigint from hex string" );
            }

            constexpr bigint(const bigint& rhs):
                buf_(rhs.buf_),
                size_(rhs.size_),
                is_neg_(rhs.is_neg_)
            {}

            constexpr bigint(bigint&& rhs) noexcept:
                buf_(std::move(rhs.buf_)),
                size_(rhs.size_),
                is_neg_(rhs.is_neg_)
            {}

            constexpr bigint& operator = (int x)
            {
                assert(x != invalid_var);
                operator = (static_cast<word_t>( detail::cabs(x) ));
                is_neg_ = x < 0;
                return *this;
            }

            constexpr bigint& operator = (word_t x)
            {
                static_assert( sizeof(word_t) == 4 );
                is_neg_ = false;
                [[maybe_unused]] const bool success = buf_.alloc(1);
                assert(success);

                buf_[0] = x;
                size_ = 1;
                return *this;
            }

            constexpr bigint& operator = (int64_t x)
            {
                static_assert( sizeof(word_t) == 4 );
                assert(x != invalid_var);
                uint64_t ua = detail::cabs(x);
                this->operator = (ua);
                is_neg_ = x < 0;
                return *this;
            }

            constexpr bigint& operator = (uint64_t x)
            {
                is_neg_ = false;
                [[maybe_unused]] const bool success = buf_.alloc(get_word_size<uint64_t>(1));
                assert(success);

                static_assert( sizeof(word_t) == 4 );
                buf_[0] = word_t(x);
                buf_[1] = word_t(x >> 32);
                trim( buf_[1] ? 2 : 1 );
                return *this;
            }

            constexpr bigint& operator = (const bigint& rhs)
            {
                if (&rhs != this)
                {
                    buf_    = rhs.buf_;
                    size_   = rhs.size_;
                    is_neg_ = rhs.is_neg_;
                }
                return *this;
            }

            constexpr bigint& operator = (bigint&& rhs) noexcept
            {
                if (&rhs != this)
                {
                    buf_    = std::move(rhs.buf_);
                    size_   = rhs.size_;
                    is_neg_ = rhs.is_neg_;
                }
                return *this;
            }

            void print() const
            {
                const auto data = to_bytes();
                if (is_negative()) {
                    eosio::print("-");
                }
                eosio::printhex(data.data(), data.size());
            }

            constexpr void swap(bigint& rhs) noexcept
            {
                std::swap(buf_, rhs.buf_);
                std::swap(size_, rhs.size_);
                std::swap(is_neg_, rhs.is_neg_);
            }

            constexpr word_t* data()
            {
                return buf_.data();
            }

            constexpr const word_t* data() const
            {
                return buf_.data();
            }

            /*
                Sets positive value
                @note x is treated as a little endian
            */

            /**
             * Sets positive value from array.
             * @tparam S type of array elements.
             *
             * @param x         - array of elements of type S.
             * @param size      - number of elements in array. If size is 0, this is set to 0.
             * @param bigendian - if true, array is treated as big endian, otherwise array is treated as little endian.
             *                    Default is false.
             * @return true if successful, false otherwise.
            */
            template<class S>
            constexpr bool set_array(const S *x, size_t size, bool bigendian = false)
            {
                is_neg_ = false;
                if (size == 0) {
                    clear();
                    return true;
                }

                size_t word_size = get_word_size<S>(size);
                const bool success = buf_.alloc(word_size);
                if (!success) {
                    return false;
                }

                if (!detail::convert_array_as(&buf_[0], word_size, x, size, bigendian)) {
                    return false;
                }

                trim(word_size);
                return true;
            }

            /**
             * Gets integer as word_t array in little endian byte order.
             *
             * @param x         - array of word_t elements.
             * @param max_size  - maximum number of elements in array.
             * @return true if successful, false otherwise.
            */
            constexpr bool get_array(word_t* x, size_t max_size) const
            {
                size_t n = size();
                if (n > max_size) {
                    return false;
                }

                detail::copy_n(x, &buf_[0], n);
                detail::clear_n(x + n, max_size - n);
                return true;
            }

            /**
             * Assigns byte data as positive value.
             * @note Data is expected to be in big-endian byte orientation.
             *
             * @param data - byte data in big-endian byte orientation. If data.size() is 0, this is set to 0.
             * @return true if successful i.e. can allocate data.size(), false otherwise.
            */
            constexpr bool set_bytes(bytes_view data)
            {
                is_neg_ = false;
                if (data.size() == 0) {
                    clear();
                    return true;
                }

                // In constant evaluation we can't use reinterpret_cast
                // fallback to set_array
                if (std::is_constant_evaluated()) { // TODO: When c++23 is available, replace with 'if consteval'
                    return set_array( data.data(), data.size(), /*bigendian=*/true );
                }

                // We're not in constant-evaluated context
                // this implementation should be a little bit faster than set_array

                size_t word_size   = get_word_size(data);
                const bool success = buf_.alloc(word_size);
                if (!success) {
                    return false;
                }

                const size_t n_words      = data.size() / sizeof(word_t);
                const size_t n_left_bytes = data.size() % sizeof(word_t);
                const word_t* p_wdata     = reinterpret_cast<const word_t*>(data.data() + n_left_bytes);

                for (size_t i = 0; i < n_words; i++) {
                    buf_[i] = detail::bswap_word(p_wdata[n_words - i - 1]);
                }

                if (n_left_bytes != 0) {
                    word_t w = 0;
                    const byte_t* p_bdata = reinterpret_cast<const byte_t*>(data.data());
                    for (size_t j = 0; j < n_left_bytes; j++) {
                        w |= word_t(p_bdata[j]) << (8 * ((n_left_bytes - 1 - j) % sizeof(word_t)));
                    }
                    buf_[n_words] = w;
                }

                trim(word_size);
                return true;
            }

            /**
             * Retrieves integer as big-endian byte data.
             * @param data - byte data span to receive integer.
             *               The size of the span must be at least byte_length().
             * @return true if data.size() >= byte_length(), false otherwise
            */
            constexpr bool get_bytes(std::span<byte_t> data) const
            {
                auto num_bytes = byte_length();
                if (data.size() < num_bytes) {
                    return false;
                }

                for (size_t i = 0; i < num_bytes; ++i) {
                    unsigned b = num_bytes - 1 - i;
                    data[i] = buf_[b / sizeof(word_t)] >> (8 * (b % sizeof(word_t)));
                }
                return true;
            }

            /**
             * Returns integer as big-endian byte data.
             * @return byte data
            */
            bytes to_bytes() const
            {
                bytes data(byte_length());
                get_bytes(data); // TODO: add check fro error. Should probably never return false
                return data;
            }

            constexpr void clear()
            {
                *this = 0;
            }

            /*
                return bit_size(abs(*this))
                @note return 1 if zero
            */
            constexpr std::size_t bit_length() const
            {
                if (is_zero()) {
                    return 1;
                }

                size_t n = size();
                word_t v = buf_[n - 1];
                assert(v);
                return (n - 1) * word_bit_size + 1 + detail::bsr<word_t>(v);
            }

            // ignore sign
            constexpr bool test_bit(size_t i) const
            {
                size_t q = i / word_bit_size;
                size_t r = i % word_bit_size;
                if (q >= size()) {
                    return false;
                }

                word_t mask = word_t(1) << r;
                return (buf_[q] & mask) != 0;
            }

            constexpr bigint& set_bit(size_t i, bool v = true)
            {
                size_t q = i / word_bit_size;
                size_t r = i % word_bit_size;
                //assert(q <= size()); // assert not needed, cause new logic allows to set bit in the next word

                std::size_t new_size = q + 1;
                if ( new_size > size() ) {
                    const bool success = buf_.alloc( new_size );
                    assert(success);
                    if (!success) {
                        clear();
                        return *this;
                    }
                }

                word_t mask = word_t(1) << r;
                size_t bit_len = bit_length();
                if (v) {
                    buf_[q] |= mask;
                }
                else {
                    buf_[q] &= ~mask;
                }

                if ( ( i + 1 )  >= bit_len ) {
                    trim( new_size );
                }

                return *this;
            }

            static constexpr int compare(const bigint& x, const bigint& y)
            {
                if (x.is_neg_ ^ y.is_neg_) {
                    if (x.is_zero() && y.is_zero()) {
                        return 0;
                    }
                    return x.is_neg_ ? -1 : 1;
                }
                else {
                    // same sign
                    if( x.is_one() && y.is_one() ) {
                        return 0;
                    }

                    int c = ucompare(x.buf_, x.size(), y.buf_, y.size());
                    if (x.is_neg_) {
                        return -c;
                    }
                    return c;
                }
            }

            static constexpr int compares1(const bigint& x, int y)
            {
                assert(y != invalid_var);
                if (x.is_neg_ ^ (y < 0)) {
                    if (x.is_zero() && y == 0) {
                        return 0;
                    }
                    return x.is_neg_ ? -1 : 1;
                }
                else {
                    // same sign
                    if (x.is_one() && y == 1) {
                        return 0;
                    }

                    static_assert( sizeof(word_t) == sizeof(uint32_t) );
                    word_t y0 = detail::cabs(y);
                    int c = (x.size() > 1) ? 1 : detail::cmp_t<1>(&x.buf_[0], &y0);
                    if (x.is_neg_) {
                        return -c;
                    }
                    return c;
                }
            }

            static constexpr int compareu1(const bigint& x, uint32_t y)
            {
                if (x.is_neg_) return -1;
                if (x.size() > 1) return 1;

                static_assert( sizeof(word_t) == sizeof(uint32_t) );
                word_t x0 = x.buf_[0];
                return x0 > y ? 1 : x0 == y ? 0 : -1;
            }

            constexpr std::size_t size() const
            {
                return word_length();
            }

            constexpr std::size_t max_size() const
            {
                return buf_.max_size();
            }

            constexpr std::size_t max_byte_size() const
            {
                return max_size() * sizeof(word_t);
            }

            constexpr bool is_zero() const
            {
                return size() == 1 && buf_[0] == 0;
            }

            constexpr bool is_one() const
            {
                return size() == 1 && !is_neg_ && buf_[0] == 1;
            }

            constexpr bool is_negative() const
            {
                return !is_zero() && is_neg_;
            }

            constexpr uint32_t get_low32bit() const
            {
                return (uint32_t)buf_[0];
            }

            constexpr bool is_odd() const
            {
                 return (buf_[0] & 1) == 1;
            }

            constexpr bool is_even() const
            {
                return !is_odd();
            }

            constexpr const word_t* get_word() const // get pointer to word data
            {
                return &buf_[0];
            }

            constexpr std::size_t word_length() const
            {
                return size_;
            }

            constexpr std::size_t byte_length() const
            {
                return (bit_length() + 7) / 8;
            }

            static constexpr void add(bigint& z, const bigint& x, const bigint& y)
            {
                _add(z, x, x.is_neg_, y, y.is_neg_);
            }

            static constexpr void sub(bigint& z, const bigint& x, const bigint& y)
            {
                _add(z, x, x.is_neg_, y, !y.is_neg_);
            }

            // TODO: Make constexpr when detail::mul_nm is constexpr
            static bool mul(bigint& z, const bigint& x, const bigint& y)
            {
                const size_t xn = x.size();
                const size_t yn = y.size();
                size_t zn = xn + yn;

                const bool success = z.buf_.alloc(zn);
                assert(success);
                if (!success) {
                    return false;
                }

                if (!detail::mul_nm(&z.buf_[0], &x.buf_[0], xn, &y.buf_[0], yn)) {
                    return false;
                }

                z.trim(zn);
                z.is_neg_ = x.is_neg_ ^ y.is_neg_;
                return true;
            }

            // TODO: Make constexpr when detail::mul_nm is constexpr
            bigint mul(const bigint& y)
            {
                bigint z;
                mul(z, *this, y); // TODO: add some check here if mul fails
                return z;
            }

            // TODO: Make constexpr when mul is constexpr
            static bool sqr(bigint& y, const bigint& x)
            {
                return mul(y, x, x);
            }

            // TODO: Make constexpr when mul is constexpr
            bigint sqr()
            {
                bigint y;
                sqr(y, *this); // TODO: add some check here if sqr fails
                return y;
            }

            static constexpr void addu1(bigint& z, const bigint& x, word_t y)
            {
                _addu1(z, x, y, false);
            }

            static constexpr void subu1(bigint& z, const bigint& x, word_t y)
            {
                _addu1(z, x, y, true);
            }

            static constexpr void mulu1(bigint& z, const bigint& x, word_t y)
            {
                size_t xn = x.size();
                size_t zn = xn + 1;

                const bool success = z.buf_.alloc(zn);
                assert(success);
                if (!success) {
                    z.clear();
                    return;
                }

                z.buf_[zn - 1] = detail::mul_word_n(&z.buf_[0], &x.buf_[0], y, xn);
                z.is_neg_ = x.is_neg_;
                z.trim(zn);
            }

            static constexpr void divu1(bigint& q, const bigint& x, word_t y)
            {
                udiv_modu1(&q, x, y);
            }

            static constexpr void modu1(bigint& r, const bigint& x, word_t y)
            {
                bool xNeg = x.is_neg_;
                r = udiv_modu1(0, x, y);
                r.is_neg_ = xNeg;
            }

            static constexpr void adds1(bigint& z, const bigint& x, int y)
            {
                assert(y != invalid_var);
                _adds1(z, x, detail::cabs(y), y < 0);
            }

            static constexpr void subs1(bigint& z, const bigint& x, int y)
            {
                assert(y != invalid_var);
                _adds1(z, x, detail::cabs(y), !(y < 0));
            }

            static constexpr void muls1(bigint& z, const bigint& x, int y)
            {
                assert(y != invalid_var);
                mulu1(z, x, detail::cabs(y));
                z.is_neg_ ^= (y < 0);
            }

            /*
                @param q [out] q = x / y if q is not zero
                @param x [in]
                @param y [in] must be not zero
                return x % y
            */
            static constexpr int div_mods1(bigint* q, const bigint& x, int y)
            {
                assert(y != invalid_var);
                bool xNeg = x.is_neg_;
                bool yNeg = y < 0;
                word_t absY = detail::cabs(y);
                size_t xn   = x.size();
                int r       = 0;

                if (q) {
                    q->is_neg_ = xNeg ^ yNeg;
                    const bool success = q->buf_.alloc(xn);
                    assert(success);
                    if (!success) {
                        q->clear();
                        return 0;
                    }

                    r = (int)detail::div_word(&q->buf_[0], &x.buf_[0], xn, absY);
                    q->trim(xn);
                } else {
                    r = (int)detail::mod_word(&x.buf_[0], xn, absY);
                }

                return xNeg ? -r : r;
            }

            /*
                like C
                  13 /  5 =  2 ...  3
                  13 / -5 = -2 ...  3
                 -13 /  5 = -2 ... -3
                 -13 / -5 =  2 ... -3
            */
            // TODO: make constexpr when udiv is constexpr
            static bool div_mod(bigint* q, bigint& r, const bigint& x, const bigint& y)
            {
                bool xNeg = x.is_neg_;
                bool qsign = xNeg ^ y.is_neg_;
                if (!udiv(q, r, x.buf_, x.size(), y.buf_, y.size())){
                    return false;
                }

                r.is_neg_ = xNeg;
                if (q) q->is_neg_ = qsign;
                return true;
            }

            // TODO: make constexpr when div_mod is constexpr
            static bool div(bigint& q, const bigint& x, const bigint& y)
            {
                bigint r;
                return div_mod(&q, r, x, y);
            }

            // TODO: make constexpr when div_mod is constexpr
            static bool mod(bigint& r, const bigint& x, const bigint& y)
            {
                return div_mod(0, r, x, y);
            }

            static constexpr void divs1(bigint& q, const bigint& x, int y)
            {
                div_mods1(&q, x, y);
            }

            static constexpr void mods1(bigint& r, const bigint& x, int y)
            {
                bool xNeg = x.is_neg_;
                r = div_mods1(0, x, y);
                r.is_neg_ = xNeg;
            }

            static constexpr word_t udiv_modu1(bigint* q, const bigint& x, word_t y)
            {
                assert(!x.is_neg_);
                size_t xn = x.size();
                if (q) {
                    const bool success = q->buf_.alloc(xn);
                    assert(success);
                    if (!success) {
                        q->clear();
                        return 0;
                    }
                }

                word_t r = detail::div_word(q ? &q->buf_[0] : 0, &x.buf_[0], xn, y);
                if (q) {
                    q->trim(xn);
                    q->is_neg_ = false;
                }
                return r;
            }

            /*
                like Python
                 13 //  5 =  2 ...  3
                 13 // -5 = -3 ... -2
                -13 //  5 = -3 ...  2
                -13 // -5 =  2 ... -3
            */
            // TODO: make constexpr when udiv is constexpr
            static void quot_rem(bigint* q, bigint& r, const bigint& x, const bigint& y)
            {
                assert(q != &r);
                bigint yy = y;
                bool yNeg = y.is_neg_;
                bool qsign = x.is_neg_ ^ yNeg;

                udiv(q, r, x.buf_, x.size(), yy.buf_, yy.size());

                r.is_neg_ = yNeg;
                if (q) q->is_neg_ = qsign;
                if (!r.is_zero() && qsign) {
                    if (q) {
                        uadd1(*q, q->buf_, q->size(), 1);
                    }
                    usub(r, yy.buf_, yy.size(), r.buf_, r.size());
                }
            }

            // logical left shift (copy sign)
            static constexpr void shl(bigint& y, const bigint& x, std::size_t shift_bit)
            {
                size_t xn = x.size();
                size_t yn = xn + get_word_size_from_bitsize(shift_bit); /*(shift_bit + word_bit_size - 1) / word_bit_size;*/

                [[maybe_unused]] const bool success = y.buf_.alloc(yn);
                assert(success);

                detail::shift_left(&y.buf_[0], &x.buf_[0], shift_bit, xn);
                y.is_neg_ = x.is_neg_;
                y.trim(yn);
            }

            // logical right shift (copy sign)
            static constexpr void shr(bigint& y, const bigint& x, std::size_t shift_bit)
            {
                size_t xn = x.size();
                if (xn * word_bit_size <= shift_bit) {
                    y.clear();
                    return;
                }

                size_t yn = xn - shift_bit / word_bit_size;
                [[maybe_unused]] const bool success = y.buf_.alloc(yn);
                assert(success);

                detail::shift_right(&y.buf_[0], &x.buf_[0], shift_bit, xn);
                y.is_neg_ = x.is_neg_;
                y.trim(yn);
            }

            static constexpr void neg(bigint& y, const bigint& x)
            {
                if (&y != &x) { y = x; }
                y.is_neg_ = !x.is_neg_;
            }

            /** Negate of this number */
            constexpr bigint neg() const
            {
                bigint r;
                neg(r, *this);
                return r;
            }

            static constexpr void abs(bigint& y, const bigint& x)
            {
                if (&y != &x) { y = x; }
                y.is_neg_ = false;
            }

            static constexpr bigint abs(const bigint& x)
            {
                bigint y = x;
                abs(y, x);
                return y;
            }

            constexpr bigint abs() const
            {
                return abs(*this);
            }

            // accept only non-negative value
            static constexpr void or_bit(bigint& z, const bigint& x, const bigint& y)
            {
                assert(!x.is_neg_ && !y.is_neg_);
                const bigint* px = &x, *py = &y;
                if (x.size() < y.size()) {
                    std::swap(px, py);
                }

                size_t xn = px->size();
                size_t yn = py->size();
                assert(xn >= yn);

                const bool success = z.buf_.alloc(xn);
                assert(success);
                if (!success) {
                    z.clear();
                }

                for (size_t i = 0; i < yn; i++) {
                    z.buf_[i] = x.buf_[i] | y.buf_[i];
                }

                detail::copy_n(&z.buf_[0] + yn, &px->buf_[0] + yn, xn - yn);
                z.trim(xn);
            }

            static constexpr void and_bit(bigint& z, const bigint& x, const bigint& y)
            {
                assert(!x.is_neg_ && !y.is_neg_);
                const bigint* px = &x, *py = &y;
                if (x.size() < y.size()) {
                    std::swap(px, py);
                }

                size_t yn = py->size();
                assert(px->size() >= yn);

                const bool success = z.buf_.alloc(yn);
                assert(success);
                if (!success) {
                    z.clear();
                    return;
                }

                for (size_t i = 0; i < yn; i++) {
                    z.buf_[i] = x.buf_[i] & y.buf_[i];
                }
                z.trim(yn);
            }

            static constexpr void or_bitu1(bigint& z, const bigint& x, word_t y)
            {
                assert(!x.is_neg_);
                z = x;
                z.buf_[0] |= y;
            }

            static constexpr void and_bitu1(bigint& z, const bigint& x, word_t y)
            {
                assert(!x.is_neg_);

                [[maybe_unused]] const bool success = z.buf_.alloc(1);
                assert(success);

                z.buf_[0] = x.buf_[0] & y;
                z.size_   = 1;
                z.is_neg_  = false;
            }

            /*
                REMARK y >= 0;
            */
            // TODO: make constexpr when _pow is constexpr
            static bool pow(bigint& z, const bigint& x, const bigint& y)
            {
                assert(!y.is_neg_);
                if (y.is_neg_) {
                    return false;
                }

                constexpr bool (*Mul)(bigint&, const bigint&, const bigint&) = &bigint::mul;
                constexpr bool (*Sqr)(bigint&, const bigint&) = &bigint::sqr;
                return _pow(z, x, &y.buf_[0], y.size(), Mul, Sqr);
            }

            /*
                REMARK y >= 0;
            */
            // TODO: make constexpr when _pow is constexpr
            static bool pow(bigint& z, const bigint& x, int64_t y)
            {
                assert(y >= 0);
                if (y < 0) {
                    return false;
                }

                uint64_t ua = detail::cabs(y);
                word_t u[2] = { word_t(ua), word_t(ua >> 32) };
                size_t un = u[1] ? 2 : 1;

                constexpr bool (*Mul)(bigint&, const bigint&, const bigint&) = &bigint::mul;
                constexpr bool (*Sqr)(bigint&, const bigint&) = &bigint::sqr;
                return _pow(z, x, u, un, Mul, Sqr);
            }

            /*
                z = x ^ y mod m
                REMARK y >= 0;
                Note: Very slow function
            */
            // TODO: make constexpr when _pow is constexpr
            template<typename UBuffer>
            static bool modexp(bigint& z, const bigint& x, const bigint<UBuffer>& y, const bigint& m)
            {
                assert(!y.is_neg_);
                if (y.is_neg_) {
                    return false;
                }

                mod_mul_t mm;
                mod_sqr_t sm;
                mm.pm = &m;
                sm.pm = &m;
                return _pow(z, x, &y.buf_[0], y.size(), mm, sm);
            }

            /*
                z = x ^ y mod m
                REMARK y >= 0;
                Note: Very slow function
            */
            // TODO: make constexpr when _pow is constexpr
            static bool modexp(bigint& z, const bigint& x, const word_t y, const bigint& m)
            {
                mod_mul_t mm;
                mod_sqr_t sm;
                mm.pm = &m;
                sm.pm = &m;
                return _pow(z, x, &y, 1, mm, sm);
            }

            /*
                inverse mod
                y = 1/x mod m
                REMARK x != 0 and m != 0;
            */
            // TODO: make constexpr when div_mod is constexpr
            static bool modinv(bigint& y, const bigint& x, const bigint& m)
            {
                //assert(!x.is_zero() && !m.is_zero());
                check( !m.is_zero(), "division by zero" );
                if ( x.is_zero() ) {
                    y = 0;
                    return m.is_one();
                }

                if ( x.is_one() ) {
                    if ( m.is_one() ) {
                        y = 0;
                    }
                    else {
                        y = 1;
                    }
                    return true;
                }
            #if 0 // can be slower
                bigint u = x;
                bigint v = m;
                bigint x1 = 1, x2 = 0;
                while (u != 1 && v != 1) {
                    while (u.is_even()) {
                        u >>= 1;
                        if (x1.is_odd()) {
                            x1 += m;
                        }
                        x1 >>= 1;
                    }
                    while (v.is_even()) {
                        v >>= 1;
                        if (x2.is_odd()) {
                            x2 += m;
                        }
                        x2 >>= 1;
                    }
                    if (u >= v) {
                        u -= v;
                        x1 -= x2;
                        if (x1 < 0) {
                            x1 += m;
                        }
                    } else {
                        v -= u;
                        x2 -= x1;
                        if (x2 < 0) {
                            x2 += m;
                        }
                    }
                }
                if (u == 1) {
                    y = x1;
                } else {
                    y = x2;
                }
                return true;
            #else
                bigint a = 1;
                bigint t;
                bigint q;
                if (!div_mod(&q, t, m, x)) {
                    return false;
                }

                if (t.is_zero()) {
                    return false; // inverse doesn't exist
                }

                bigint s = x;
                bigint b = -q;

                for (;;) {
                    if (!div_mod(&q, s, s, t)) {
                        return false;
                    }

                    if (s.is_zero()) {
                        if (!t.is_one()) { // gcd != 1
                            return false;
                        }
                        if (b.is_neg_) {
                            b += m;
                        }
                        y = b;
                        return true;
                    }

                    a -= b * q;

                    if (!div_mod(&q, t, t, s)) {
                        return false;
                    }

                    if (t.is_zero()) {
                        if (!s.is_one()) { // gcd != 1
                            return false;
                        }
                        if (a.is_neg_) {
                            a += m;
                        }
                        y = a;
                        return true;
                    }

                    b -= a * q;
                }

                return true;
            #endif
            }

            [[maybe_unused]] inline bigint modinv(const bigint& m) const
            {
                bigint r;
                const bool ret = modinv(r, *this, m);
                check( ret, "modular inverse failed" ); // Either because inverse doesn't exist for the given modulus & base or buffer allocation failed
                return r;
            }

            // TODO: make constexpr when mod is constexpr
            static void gcd(bigint& z, bigint x, bigint y)
            {
                bigint t;
                for (;;) {
                    if (y.is_zero()) {
                        z = x;
                        return;
                    }
                    t = x;
                    x = y;
                    mod(y, t, y);
                }
            }

            // TODO: make constexpr when gcd is constexpr
            static bigint gcd(const bigint& x, const bigint& y)
            {
                bigint z;
                gcd(z, x, y);
                return z;
            }

            // TODO: make constexpr when gcd is constexpr
            bigint gcd(const bigint& y)
            {
                bigint z;
                gcd(z, *this, y);
                return z;
            }

            // TODO: make constexpr when gcd & mul are constexpr
            static void lcm(bigint& z, const bigint& x, const bigint& y)
            {
                bigint c;
                gcd(c, x, y);
                div(c, x, c);
                mul(z, c, y); // return mul(z, c, y);
            }

            // TODO: make constexpr when lcm is constexpr
            bigint lcm(const bigint& y)
            {
                bigint z;
                lcm(z, *this, y);
                return z;
            }

            /*
                 1 if m is quadratic residue modulo n (i.e., there exists an x s.t. x^2 = m mod n)
                 0 if m = 0 mod n
                -1 otherwise
                @note return legendre_symbol(m, p) for m and odd prime p
            */
            // TODO: make constexpr when quot_rem is constexpr
            static int jacobi(bigint m, bigint n)
            {
                assert(n.is_odd());
                if ( n.is_one() ) return 1;
                if (m < 0 || m > n) {
                    quot_rem(0, m, m, n); // m = m mod n
                }
                if ( m.is_zero() ) return 0;
                if ( m.is_one() )  return 1;
                if ( gcd(m, n) != 1 ) return 0;

                int j = 1;
                bigint t;
                goto START;
                while (m != 1) {
                    if ((m.get_low32bit() % 4) == 3 && (n.get_low32bit() % 4) == 3) {
                        j = -j;
                    }
                    mod(t, n, m);
                    n = m;
                    m = t;
                START:
                    int s = count_trailing_zero(m);
                    uint32_t nmod8 = n.get_low32bit() % 8;
                    if ((s % 2) && (nmod8 == 3 || nmod8 == 5)) {
                        j = -j;
                    }
                }
                // TODO: transform loop to this code
                // bool start = true;
                // do {
                //     if (!start) {
                //         if ((m.get_low32bit() % 4) == 3 && (n.get_low32bit() % 4) == 3) {
                //             j = -j;
                //         }
                //         mod(t, n, m);
                //         n = m;
                //         m = t;
                //     }

                //     int s = count_trailing_zero(m);
                //     uint32_t nmod8 = n.get_low32bit() % 8;
                //     if ((s % 2) && (nmod8 == 3 || nmod8 == 5)) {
                //         j = -j;
                //     }
                //     start = false;
                // } while (m != 1)

                return j;
            }

            constexpr bigint& operator++() { adds1(*this, *this, 1); return *this; }
            constexpr bigint& operator--() { subs1(*this, *this, 1); return *this; }
            constexpr bigint operator++(int) { bigint c = *this; adds1(*this, *this, 1); return c; }
            constexpr bigint operator--(int) { bigint c = *this; subs1(*this, *this, 1); return c; }

            constexpr friend bool operator == (const bigint& x, int y) { return compares1(x, y) == 0; }
            constexpr friend bool operator == (const bigint& x, uint32_t y) { return compareu1(x, y) == 0; }
            constexpr friend bool operator == (const bigint& x, int64_t y) { return compare(x, bigint(y)) == 0; }
            constexpr friend bool operator == (const bigint& x, uint64_t y) { return compare(x, bigint(y)) == 0; }
            constexpr friend bool operator == (const bigint& x, const bigint& y) { return compare(x, y) == 0; }
            constexpr friend bool operator == (int x, const bigint& y) { return compares1(y, x) == 0; }
            constexpr friend bool operator == (uint32_t x, const bigint& y) { return compareu1(y, x) == 0; }
            constexpr friend bool operator == (int64_t x, const bigint& y) { return compare(y, bigint(x)) == 0; }
            constexpr friend bool operator == (uint64_t x, const bigint& y) { return compare(y, bigint(x)) == 0; }

            constexpr friend bool operator != (const bigint& x, int y) { return !operator==(x, y); }
            constexpr friend bool operator != (const bigint& x, uint32_t y) { return !operator==(x, y); }
            constexpr friend bool operator != (const bigint& x, int64_t y) { return !operator==(x, y); }
            constexpr friend bool operator != (const bigint& x, uint64_t y) { return !operator==(x, y); }
            constexpr friend bool operator != (const bigint& x, const bigint& y) { return !operator==(x, y); }
            constexpr friend bool operator != (int x, const bigint& y) { return !operator==(x, y); }
            constexpr friend bool operator != (uint32_t x, const bigint& y) { return !operator==(x, y); }
            constexpr friend bool operator != (int64_t x, const bigint& y) { return !operator==(x, y); }
            constexpr friend bool operator != (uint64_t x, const bigint& y) { return !operator==(x, y); }

            constexpr friend bool operator < (const bigint& x, int y) { return compares1(x, y) < 0; }
            constexpr friend bool operator < (const bigint& x, uint32_t y) { return compareu1(x, y) < 0; }
            constexpr friend bool operator < (const bigint& x, int64_t y) { return compare(x, bigint(y)) < 0; }
            constexpr friend bool operator < (const bigint& x, uint64_t y) { return compare(x, bigint(y)) < 0; }
            constexpr friend bool operator < (const bigint& x, const bigint& y) { return compare(x, y) < 0; }
            constexpr friend bool operator < (int x, const bigint& y) { return compares1(y, x) > 0; }
            constexpr friend bool operator < (uint32_t x, const bigint& y) { return compareu1(y, x) > 0; }
            constexpr friend bool operator < (int64_t x, const bigint& y) { return compare(y, bigint(x)) > 0; }
            constexpr friend bool operator < (uint64_t x, const bigint& y) { return compare(y, bigint(x)) > 0; }

            constexpr friend bool operator <= (const bigint& x, int y) { return !operator>(x, y); }
            constexpr friend bool operator <= (const bigint& x, uint32_t y) { return !operator>(x, y); }
            constexpr friend bool operator <= (const bigint& x, int64_t y) { return !operator>(x, y); }
            constexpr friend bool operator <= (const bigint& x, uint64_t y) { return !operator>(x, y); }
            constexpr friend bool operator <= (const bigint& x, const bigint& y) { return !operator>(x, y); }
            constexpr friend bool operator <= (int x, const bigint& y) { return !operator>(x, y); }
            constexpr friend bool operator <= (uint32_t x, const bigint& y) { return !operator>(x, y); }
            constexpr friend bool operator <= (int64_t x, const bigint& y) { return !operator>(x, y); }
            constexpr friend bool operator <= (uint64_t x, const bigint& y) { return !operator>(x, y); }

            constexpr friend bool operator > (const bigint& x, int y) { return compares1(x, y) > 0; }
            constexpr friend bool operator > (const bigint& x, uint32_t y) { return compareu1(x, y) > 0; }
            constexpr friend bool operator > (const bigint& x, int64_t y) { return compare(x, bigint(y)) > 0; }
            constexpr friend bool operator > (const bigint& x, uint64_t y) { return compare(x, bigint(y)) > 0; }
            constexpr friend bool operator > (const bigint& x, const bigint& y) { return compare(x, y) > 0; }
            constexpr friend bool operator > (int x, const bigint& y) { return compares1(y, x) < 0; }
            constexpr friend bool operator > (uint32_t x, const bigint& y) { return compareu1(y, x) < 0; }
            constexpr friend bool operator > (int64_t x, const bigint& y) { return compare(y, bigint(x)) < 0; }
            constexpr friend bool operator > (uint64_t x, const bigint& y) { return compare(y, bigint(x)) < 0; }

            constexpr friend bool operator >= (const bigint& x, int y) { return !operator<(x, y); }
            constexpr friend bool operator >= (const bigint& x, uint32_t y) { return !operator<(x, y); }
            constexpr friend bool operator >= (const bigint& x, int64_t y) { return !operator<(x, y); }
            constexpr friend bool operator >= (const bigint& x, uint64_t y) { return !operator<(x, y); }
            constexpr friend bool operator >= (const bigint& x, const bigint& y) { return !operator<(x, y); }
            constexpr friend bool operator >= (int x, const bigint& y) { return !operator<(x, y); }
            constexpr friend bool operator >= (uint32_t x, const bigint& y) { return !operator<(x, y); }
            constexpr friend bool operator >= (int64_t x, const bigint& y) { return !operator<(x, y); }
            constexpr friend bool operator >= (uint64_t x, const bigint& y) { return !operator<(x, y); }

            constexpr friend bigint operator + (const bigint& a, int b) { bigint c; adds1(c, a, b); return c; }
            constexpr friend bigint operator + (const bigint& a, word_t b) { bigint c; addu1(c, a, b); return c; }
            constexpr friend bigint operator + (const bigint& a, int64_t b) { bigint c; add(c, a, bigint(b)); return c; }
            constexpr friend bigint operator + (const bigint& a, uint64_t b) { bigint c; add(c, a, bigint(b)); return c; }
            constexpr friend bigint operator + (const bigint& a, const bigint& b) { bigint c; add(c, a, b); return c; }

            constexpr bigint& operator += (int rhs) { adds1(*this, *this, rhs); return *this; }
            constexpr bigint& operator += (word_t rhs) { addu1(*this, *this, rhs); return *this; }
            constexpr bigint& operator += (int64_t rhs) { add(*this, *this, bigint(rhs)); return *this; }
            constexpr bigint& operator += (uint64_t rhs) { add(*this, *this, bigint(rhs)); return *this; }
            constexpr bigint& operator += (const bigint& rhs) { add(*this, *this, rhs); return *this; }

            constexpr friend bigint operator - (const bigint& a, int b) { bigint c; subs1(c, a, b); return c; }
            constexpr friend bigint operator - (const bigint& a, word_t b) { bigint c; subu1(c, a, b); return c; }
            constexpr friend bigint operator - (const bigint& a, int64_t b) { bigint c; sub(c, a, bigint(b)); return c; }
            constexpr friend bigint operator - (const bigint& a, uint64_t b) { bigint c; sub(c, a, bigint(b)); return c; }
            constexpr friend bigint operator - (const bigint& a, const bigint& b) { bigint c; sub(c, a, b); return c; }

            constexpr bigint& operator -= (int rhs) { subs1(*this, *this, rhs); return *this; }
            constexpr bigint& operator -= (word_t rhs) { subu1(*this, *this, rhs); return *this; }
            constexpr bigint& operator -= (int64_t rhs) { sub(*this, *this, bigint(rhs)); return *this; }
            constexpr bigint& operator -= (uint64_t rhs) { sub(*this, *this, bigint(rhs)); return *this; }
            constexpr bigint& operator -= (const bigint& rhs) { sub(*this, *this, rhs); return *this; }

            //TODO: Make constexpr when mul, div, mod are constexpr

            constexpr friend bigint operator * (const bigint& a, int b) { bigint c; muls1(c, a, b); return c; }
            constexpr friend bigint operator * (const bigint& a, word_t b) { bigint c; mulu1(c, a, b); return c; }
            friend bigint operator * (const bigint& a, int64_t b) { bigint c; mul(c, a, bigint(b)); return c; }
            friend bigint operator * (const bigint& a, uint64_t b) { bigint c; mul(c, a, bigint(b)); return c; }
            friend bigint operator * (const bigint& a, const bigint& b) { bigint c; mul(c, a, b); return c; }

            constexpr bigint& operator *= (int rhs) { muls1(*this, *this, rhs); return *this; }
            constexpr bigint& operator *= (word_t rhs) { mulu1(*this, *this, rhs); return *this; }
            bigint& operator *= (int64_t rhs) { mul(*this, *this, bigint(rhs)); return *this; }
            bigint& operator *= (uint64_t rhs) { mul(*this, *this, bigint(rhs)); return *this; }
            bigint& operator *= (const bigint& rhs) { mul(*this, *this, rhs); return *this; }

            constexpr friend bigint operator / (const bigint& a, int b) { bigint c; divs1(c, a, b); return c; }
            constexpr friend bigint operator / (const bigint& a, word_t b) { bigint c; divu1(c, a, b); return c; }
            friend bigint operator / (const bigint& a, int64_t b) { bigint c; div(c, a, bigint(b)); return c; }
            friend bigint operator / (const bigint& a, uint64_t b) { bigint c; div(c, a, bigint(b)); return c; }
            friend bigint operator / (const bigint& a, const bigint& b) { bigint c; div(c, a, b); return c; }

            constexpr bigint& operator /= (int rhs) { divs1(*this, *this, rhs); return *this; }
            constexpr bigint& operator /= (word_t rhs) { divu1(*this, *this, rhs); return *this; }
            bigint& operator /= (int64_t rhs) { div(*this, *this, bigint(rhs)); return *this; }
            bigint& operator /= (uint64_t rhs) { div(*this, *this, bigint(rhs)); return *this; }
            bigint& operator /= (const bigint& rhs) { div(*this, *this, rhs); return *this; }

            constexpr friend bigint operator % (const bigint& a, int b) { bigint c; mods1(c, a, b); return c; }
            constexpr friend bigint operator % (const bigint& a, word_t b) { bigint c; modu1(c, a, b); return c; }
            friend bigint operator % (const bigint& a, int64_t b) { bigint c; mod(c, a, bigint(b)); return c; }
            friend bigint operator % (const bigint& a, uint64_t b) { bigint c; mod(c, a, bigint(b)); return c; }
            friend bigint operator % (const bigint& a, const bigint& b) { bigint c; mod(c, a, b); return c; }

            constexpr bigint& operator %= (int rhs) { mods1(*this, *this, rhs); return *this; }
            constexpr bigint& operator %= (word_t rhs) { modu1(*this, *this, rhs); return *this; }
            bigint& operator %= (int64_t rhs) { div(*this, *this, bigint(rhs)); return *this; }
            bigint& operator %= (uint64_t rhs) { div(*this, *this, bigint(rhs)); return *this; }
            bigint& operator %= (const bigint& rhs) { mod(*this, *this, rhs); return *this; }

            constexpr friend bigint operator & (const bigint& a, word_t b) { bigint c; and_bitu1(c, a, b); return c; }
            constexpr friend bigint operator & (const bigint& a, uint64_t b) { bigint c; and_bit(c, a, bigint(b)); return c; }
            constexpr friend bigint operator & (const bigint& a, const bigint& b) { bigint c; and_bit(c, a, b); return c; }

            constexpr bigint& operator &= (word_t rhs) { and_bitu1(*this, *this, rhs); return *this; }
            constexpr bigint& operator &= (uint64_t rhs) { and_bit(*this, *this, bigint(rhs)); return *this; }
            constexpr bigint& operator &= (const bigint& rhs) { and_bit(*this, *this, rhs); return *this; }

            constexpr friend bigint operator | (const bigint& a, word_t b) { bigint c; or_bitu1(c, a, b); return c; }
            constexpr friend bigint operator | (const bigint& a, uint64_t b) { bigint c; or_bit(c, a, bigint(b)); return c; }
            constexpr friend bigint operator | (const bigint& a, const bigint& b) { bigint c; or_bit(c, a, b); return c; }

            constexpr bigint& operator |= (word_t rhs) { or_bitu1(*this, *this, rhs); return *this; }
            constexpr bigint& operator |= (uint64_t rhs) { or_bit(*this, *this, bigint(rhs)); return *this; }
            constexpr bigint& operator |= (const bigint& rhs) { or_bit(*this, *this, rhs); return *this; }

            constexpr bigint& operator <<= (size_t n) { shl(*this, *this, n); return *this; }
            constexpr bigint& operator >>= (size_t n) { shr(*this, *this, n); return *this; }
            constexpr bigint operator << (size_t n) const { bigint c = *this; c <<= n; return c; }
            constexpr bigint operator >> (size_t n) const { bigint c = *this; c >>= n; return c; }

            constexpr bigint operator - () const { bigint c; neg(c, *this); return c; }
    };

    /**
     *  Alias for a bigint with a fixed size buffer
     * @tparam MaxBitSize - the maximum number of bits that can be stored in the bigint
     *         Internal the actual size will be rounded up to the nearest word size
     *         (e.g. 1 bit will be 32 bits, since 1 word is 32 bits)
     *
     * NOTE: Due to antelopeIO wasm stack frame size limitations (512B), through some testing
     *       The maximum size of a fixed_bigint can be 512 bits for all ECC & RSA operations.
     */
    template<std::size_t MaxBitSize>
    using fixed_bigint = bigint<fixed_word_buffer<get_word_size_from_bitsize(MaxBitSize)>>;
    
    template <typename>
    struct is_bigint : std::false_type {};

    template <typename T>
    struct is_bigint<bigint<T>> : std::true_type {};
    
    template<typename T>
    constexpr bool is_bigint_v = is_bigint<T>::value;
}
