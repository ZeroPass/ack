// Implementation taken from UBOOT https://github.com/u-boot/u-boot/blob/096912b5fe9bb2fd90599d86a714001df6924198/lib/rsa/rsa-mod-exp.c#L258

// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2013, Google Inc.
 */
#pragma once
#ifndef USE_HOSTCC
// #include <common.h>
// #include <fdtdec.h>
// #include <log.h>
// #include <asm/types.h>
// #include <asm/byteorder.h>
// #include <linux/errno.h>
// #include <asm/types.h>
// #include <asm/unaligned.h>
#else
#include "fdt_host.h"
#include "mkimage.h"
#include <fdt_support.h>
#endif
// #include <u-boot/rsa.h>
// #include <u-boot/rsa-mod-exp.h>

#include <stdint.h>
#include <string.h>

#include <stdlib.h> // calloc

extern "C"
{
    #define EINVAL 22
    #define ENOMEM 12 /* Out of memory */

    // #define EXTRACT_BYTE(x, n) ((unsigned long long)((uint8_t *)&x)[n])
    // #define CPU_TO_FDT64(x) ((EXTRACT_BYTE(x, 0) << 56) | (EXTRACT_BYTE(x, 1) << 48) | \
    //                         (EXTRACT_BYTE(x, 2) << 40) | (EXTRACT_BYTE(x, 3) << 32) | \
    //                         (EXTRACT_BYTE(x, 4) << 24) | (EXTRACT_BYTE(x, 5) << 16) | \
    //                         (EXTRACT_BYTE(x, 6) << 8) | EXTRACT_BYTE(x, 7))

    #define ___constant_swab16(x) ((__u16)(    \
        (((__u16)(x) & (__u16)0x00ffU) << 8) | \
        (((__u16)(x) & (__u16)0xff00U) >> 8)))

    #define ___constant_swab32(x) ((__u32)(          \
        (((__u32)(x) & (__u32)0x000000ffUL) << 24) | \
        (((__u32)(x) & (__u32)0x0000ff00UL) << 8) |  \
        (((__u32)(x) & (__u32)0x00ff0000UL) >> 8) |  \
        (((__u32)(x) & (__u32)0xff000000UL) >> 24)))

    #define ___constant_swab64(x) ((__u64)(                   \
        (((__u64)(x) & (__u64)0x00000000000000ffULL) << 56) | \
        (((__u64)(x) & (__u64)0x000000000000ff00ULL) << 40) | \
        (((__u64)(x) & (__u64)0x0000000000ff0000ULL) << 24) | \
        (((__u64)(x) & (__u64)0x00000000ff000000ULL) << 8) |  \
        (((__u64)(x) & (__u64)0x000000ff00000000ULL) >> 8) |  \
        (((__u64)(x) & (__u64)0x0000ff0000000000ULL) >> 24) | \
        (((__u64)(x) & (__u64)0x00ff000000000000ULL) >> 40) | \
        (((__u64)(x) & (__u64)0xff00000000000000ULL) >> 56)))

    typedef uint16_t __u16;
    typedef unsigned int u32;
    typedef uint32_t __u32;
    typedef __u32 /*__bitwise*/ __be32;
    typedef unsigned int uint;
    typedef uint64_t __u64;
    typedef uint64_t /*__bitwise*/ fdt64_t;


    struct key_prop
    {
        const uint8_t *rr;              /* R^2 can be treated as byte array */
        const uint8_t *modulus;         /* modulus as byte array */
        const uint8_t *public_exponent; /* public exponent as byte array */
        uint32_t n0inv;              /* -1 / modulus[0] mod 2^32 */
        int num_bits;                /* Key length in bits */
        uint32_t exp_len;            /* Exponent length in number of uint8_t */
    };

    struct rsa_public_key
    {
        uint len;          /* len of modulus[] in number of uint32_t */
        uint32_t n0inv;    /* -1 / modulus[0] mod 2^32 */
        uint32_t *modulus; /* modulus as little endian array */
        uint32_t *rr;      /* R^2 as little endian array */
        uint64_t exponent; /* public exponent */
    };

    #define UINT64_MULT32(v, multby) (((uint64_t)(v)) * ((uint32_t)(multby)))
    #define get_unaligned_be16(a) ___constant_swab16(*(uint16_t *)a)
    #define get_unaligned_be32(a) fdt32_to_cpu(*(uint32_t *)a)
    #define put_unaligned_be32(a, b) (*(uint32_t *)(b) = cpu_to_fdt32(a))
    #define be32_to_cpu ___constant_swab32
    #define be64_to_cpu ___constant_swab64
    #define cpu_to_be32 ___constant_swab32
    #define fdt32_to_cpu(x) be32_to_cpu(x)
    #define cpu_to_fdt32(x) cpu_to_be32(x)
    #define fdt64_to_cpu(x) be64_to_cpu(x)
    #define GE(x, y)   NOT(GT(y, x))
    #define LT(x, y)   GT(y, x)
    #define MUL(x, y)   ((uint64_t)(x) * (uint64_t)(y))


    // static inline uint32_t get_unaligned_be32(const uint8_t *p)
    // {
    //     return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
    // }



    static inline uint64_t fdt64_to_cpup(const void *p)
    {
        fdt64_t w;
        memcpy(&w, p, sizeof(w));
        return fdt64_to_cpu(w);
    }

    /* Default public exponent for backward compatibility */
    #define RSA_DEFAULT_PUBEXP 65537


    /**
     * br_dec16be() - Convert 16-bit big-endian integer to native
     * @src:	Pointer to data
     * Return:	Native-endian integer
     */
    static unsigned br_dec16be(const void *src)
    {
        return get_unaligned_be16(src);
    }

    /**
     * br_dec32be() - Convert 32-bit big-endian integer to native
     * @src:	Pointer to data
     * Return:	Native-endian integer
     */
    static uint32_t br_dec32be(const void *src)
    {
        return get_unaligned_be32(src);
    }

    /* from BearSSL's src/inner.h */
    /*
    * Negate a boolean.
    */
    static uint32_t NOT(uint32_t ctl)
    {
        return ctl ^ 1;
    }

    /*
    * Multiplexer: returns x if ctl == 1, y if ctl == 0.
    */
    static uint32_t MUX(uint32_t ctl, uint32_t x, uint32_t y)
    {
        return y ^ (-ctl & (x ^ y));
    }

    /*
    * Equality check: returns 1 if x == y, 0 otherwise.
    */
    static uint32_t EQ(uint32_t x, uint32_t y)
    {
        uint32_t q;

        q = x ^ y;
        return NOT((q | -q) >> 31);
    }

    /*
    * Inequality check: returns 1 if x != y, 0 otherwise.
    */
    static uint32_t NEQ(uint32_t x, uint32_t y)
    {
        uint32_t q;

        q = x ^ y;
        return (q | -q) >> 31;
    }

    /*
    * Comparison: returns 1 if x > y, 0 otherwise.
    */
    static uint32_t GT(uint32_t x, uint32_t y)
    {
        /*
        * If both x < 2^31 and y < 2^31, then y-x will have its high
        * bit set if x > y, cleared otherwise.
        *
        * If either x >= 2^31 or y >= 2^31 (but not both), then the
        * result is the high bit of x.
        *
        * If both x >= 2^31 and y >= 2^31, then we can virtually
        * subtract 2^31 from both, and we are back to the first case.
        * Since (y-2^31)-(x-2^31) = y-x, the subtraction is already
        * fine.
        */
        uint32_t z;

        z = y - x;
        return (z ^ ((x ^ y) & (x ^ z))) >> 31;
    }


    /**
     * br_enc32be() - Convert native 32-bit integer to big-endian
     * @dst:	Pointer to buffer to store big-endian integer in
     * @x:		Native 32-bit integer
     */
    static void br_enc32be(void *dst, uint32_t x)
    {
        __be32 tmp;

        tmp = cpu_to_be32(x);
        memcpy(dst, &tmp, sizeof(tmp));
    }

    /* from BearSSL's src/int/i32_ninv32.c */
    /*
    * Compute -(1/x) mod 2^32. If x is even, then this function returns 0.
    */
    static uint32_t br_i32_ninv32(uint32_t x)
    {
        uint32_t y;

        y = 2 - x;
        y *= 2 - y * x;
        y *= 2 - y * x;
        y *= 2 - y * x;
        y *= 2 - y * x;
        return MUX(x & 1, -y, 0);
    }

    /*
    * Integers 'i32'
    * --------------
    *
    * The 'i32' functions implement computations on big integers using
    * an internal representation as an array of 32-bit integers. For
    * an array x[]:
    *  -- x[0] contains the "announced bit length" of the integer
    *  -- x[1], x[2]... contain the value in little-endian order (x[1]
    *     contains the least significant 32 bits)
    *
    * Multiplications rely on the elementary 32x32->64 multiplication.
    *
    * The announced bit length specifies the number of bits that are
    * significant in the subsequent 32-bit words. Unused bits in the
    * last (most significant) word are set to 0; subsequent words are
    * uninitialized and need not exist at all.
    *
    * The execution time and memory access patterns of all computations
    * depend on the announced bit length, but not on the actual word
    * values. For modular integers, the announced bit length of any integer
    * modulo n is equal to the actual bit length of n; thus, computations
    * on modular integers are "constant-time" (only the modulus length may
    * leak).
    */

    /*
    * Extract one word from an integer. The offset is counted in bits.
    * The word MUST entirely fit within the word elements corresponding
    * to the announced bit length of a[].
    */
    static uint32_t br_i32_word(const uint32_t *a, uint32_t off)
    {
        size_t u;
        unsigned j;

        u = (size_t)(off >> 5) + 1;
        j = (unsigned)off & 31;
        if (j == 0) {
            return a[u];
        } else {
            return (a[u] >> j) | (a[u + 1] << (32 - j));
        }
    }

    /*
    * Compute the bit length of a 32-bit integer. Returned value is between 0
    * and 32 (inclusive).
    */
    static uint32_t BIT_LENGTH(uint32_t x)
    {
        uint32_t k, c;

        k = NEQ(x, 0);
        c = GT(x, 0xFFFF); x = MUX(c, x >> 16, x); k += c << 4;
        c = GT(x, 0x00FF); x = MUX(c, x >>  8, x); k += c << 3;
        c = GT(x, 0x000F); x = MUX(c, x >>  4, x); k += c << 2;
        c = GT(x, 0x0003); x = MUX(c, x >>  2, x); k += c << 1;
        k += GT(x, 0x0001);
        return k;
    }

    /* from BearSSL's src/int/i32_bitlen.c */
    /*
    * Compute the actual bit length of an integer. The argument x should
    * point to the first (least significant) value word of the integer.
    * The len 'xlen' contains the number of 32-bit words to access.
    *
    * CT: value or length of x does not leak.
    */
    static uint32_t br_i32_bit_length(uint32_t *x, size_t xlen)
    {
        uint32_t tw, twk;

        tw = 0;
        twk = 0;
        while (xlen -- > 0) {
            uint32_t w, c;

            c = EQ(tw, 0);
            w = x[xlen];
            tw = MUX(c, w, tw);
            twk = MUX(c, (uint32_t)xlen, twk);
        }
        return (twk << 5) + BIT_LENGTH(tw);
    }

    /* from BearSSL's src/int/i32_decode.c */
    /*
    * Decode an integer from its big-endian unsigned representation. The
    * "true" bit length of the integer is computed, but all words of x[]
    * corresponding to the full 'len' bytes of the source are set.
    *
    * CT: value or length of x does not leak.
    */
    static void br_i32_decode(uint32_t *x, const uint8_t *src, size_t len)
    {
        const unsigned char *buf;
        size_t u, v;

        buf = src;
        u = len;
        v = 1;
        for (;;)
        {
            if (u < 4)
            {
                uint32_t w;

                if (u < 2)
                {
                    if (u == 0)
                    {
                        break;
                    }
                    else
                    {
                        w = buf[0];
                    }
                }
                else
                {
                    if (u == 2)
                    {
                        w = br_dec16be(buf);
                    }
                    else
                    {
                        w = ((uint32_t)buf[0] << 16) | br_dec16be(buf + 1);
                    }
                }
                x[v++] = w;
                break;
            }
            else
            {
                u -= 4;
                x[v++] = br_dec32be(buf + u);
            }
        }
        x[0] = br_i32_bit_length(x + 1, v - 1);
    }

    /* from BearSSL's src/int/i32_encode.c */
    /*
    * Encode an integer into its big-endian unsigned representation. The
    * output length in bytes is provided (parameter 'len'); if the length
    * is too short then the integer is appropriately truncated; if it is
    * too long then the extra bytes are set to 0.
    */
    static void br_i32_encode(uint8_t *dst, size_t len, const uint32_t *x)
    {
        unsigned char *buf;
        size_t k;

        buf = dst;

        /*
        * Compute the announced size of x in bytes; extra bytes are
        * filled with zeros.
        */
        k = (x[0] + 7) >> 3;
        while (len > k) {
            *buf ++ = 0;
            len --;
        }

        /*
        * Now we use k as index within x[]. That index starts at 1;
        * we initialize it to the topmost complete word, and process
        * any remaining incomplete word.
        */
        k = (len + 3) >> 2;
        switch (len & 3) {
        case 3:
            *buf ++ = x[k] >> 16;
            /* fall through */
        case 2:
            *buf ++ = x[k] >> 8;
            /* fall through */
        case 1:
            *buf ++ = x[k];
            k --;
        }

        /*
        * Encode all complete words.
        */
        while (k > 0) {
            br_enc32be(buf, x[k]);
            k --;
            buf += 4;
        }
    }

    /* from BearSSL's src/int/i32_add.c */
    /*
    * Add b[] to a[] and return the carry (0 or 1). If ctl is 0, then a[]
    * is unmodified, but the carry is still computed and returned. The
    * arrays a[] and b[] MUST have the same announced bit length.
    *
    * a[] and b[] MAY be the same array, but partial overlap is not allowed.
    */
    static uint32_t br_i32_add(uint32_t *a, const uint32_t *b, uint32_t ctl)
    {
        uint32_t cc;
        size_t u, m;

        cc = 0;
        m = (a[0] + 63) >> 5;
        for (u = 1; u < m; u ++) {
            uint32_t aw, bw, naw;

            aw = a[u];
            bw = b[u];
            naw = aw + bw + cc;

            /*
            * Carry is 1 if naw < aw. Carry is also 1 if naw == aw
            * AND the carry was already 1.
            */
            cc = (cc & EQ(naw, aw)) | LT(naw, aw);
            a[u] = MUX(ctl, naw, aw);
        }
        return cc;
    }

    /* from BearSSL's src/int/i32_sub.c */
    /*
    * Subtract b[] from a[] and return the carry (0 or 1). If ctl is 0,
    * then a[] is unmodified, but the carry is still computed and returned.
    * The arrays a[] and b[] MUST have the same announced bit length.
    *
    * a[] and b[] MAY be the same array, but partial overlap is not allowed.
    */
    static uint32_t br_i32_sub(uint32_t *a, const uint32_t *b, uint32_t ctl)
    {
        uint32_t cc;
        size_t u, m;

        cc = 0;
        m = (a[0] + 63) >> 5;
        for (u = 1; u < m; u ++) {
            uint32_t aw, bw, naw;

            aw = a[u];
            bw = b[u];
            naw = aw - bw - cc;

            /*
            * Carry is 1 if naw > aw. Carry is 1 also if naw == aw
            * AND the carry was already 1.
            */
            cc = (cc & EQ(naw, aw)) | GT(naw, aw);
            a[u] = MUX(ctl, naw, aw);
        }
        return cc;
    }

    /* from BearSSL's src/int/i32_div32.c */
    /*
    * Constant-time division. The dividend hi:lo is divided by the
    * divisor d; the quotient is returned and the remainder is written
    * in *r. If hi == d, then the quotient does not fit on 32 bits;
    * returned value is thus truncated. If hi > d, returned values are
    * indeterminate.
    */
    static uint32_t br_divrem(uint32_t hi, uint32_t lo, uint32_t d, uint32_t *r)
    {
        /* TODO: optimize this */
        uint32_t q;
        uint32_t ch, cf;
        int k;

        q = 0;
        ch = EQ(hi, d);
        hi = MUX(ch, 0, hi);
        for (k = 31; k > 0; k --) {
            int j;
            uint32_t w, ctl, hi2, lo2;

            j = 32 - k;
            w = (hi << j) | (lo >> k);
            ctl = GE(w, d) | (hi >> k);
            hi2 = (w - d) >> j;
            lo2 = lo - (d << k);
            hi = MUX(ctl, hi2, hi);
            lo = MUX(ctl, lo2, lo);
            q |= ctl << k;
        }
        cf = GE(lo, d) | hi;
        q |= cf;
        *r = MUX(cf, lo - d, lo);
        return q;
    }

    /*
    * Wrapper for br_divrem(); the remainder is returned, and the quotient
    * is discarded.
    */
    static uint32_t br_rem(uint32_t hi, uint32_t lo, uint32_t d)
    {
        uint32_t r;

        br_divrem(hi, lo, d, &r);
        return r;
    }

    /*
    * Wrapper for br_divrem(); the quotient is returned, and the remainder
    * is discarded.
    */
    static uint32_t br_div(uint32_t hi, uint32_t lo, uint32_t d)
    {
        uint32_t r;

        return br_divrem(hi, lo, d, &r);
    }

    /* from BearSSL's src/int/i32_muladd.c */
    /*
    * Multiply x[] by 2^32 and then add integer z, modulo m[]. This
    * function assumes that x[] and m[] have the same announced bit
    * length, and the announced bit length of m[] matches its true
    * bit length.
    *
    * x[] and m[] MUST be distinct arrays.
    *
    * CT: only the common announced bit length of x and m leaks, not
    * the values of x, z or m.
    */
    static void br_i32_muladd_small(uint32_t *x, uint32_t z, const uint32_t *m)
    {
        uint32_t m_bitlen;
        size_t u, mlen;
        uint32_t a0, a1, b0, hi, g, q, tb;
        uint32_t chf, clow, under, over;
        uint64_t cc;

        /*
        * We can test on the modulus bit length since we accept to
        * leak that length.
        */
        m_bitlen = m[0];
        if (m_bitlen == 0) {
            return;
        }
        if (m_bitlen <= 32) {
            x[1] = br_rem(x[1], z, m[1]);
            return;
        }
        mlen = (m_bitlen + 31) >> 5;

        /*
        * Principle: we estimate the quotient (x*2^32+z)/m by
        * doing a 64/32 division with the high words.
        *
        * Let:
        *   w = 2^32
        *   a = (w*a0 + a1) * w^N + a2
        *   b = b0 * w^N + b2
        * such that:
        *   0 <= a0 < w
        *   0 <= a1 < w
        *   0 <= a2 < w^N
        *   w/2 <= b0 < w
        *   0 <= b2 < w^N
        *   a < w*b
        * I.e. the two top words of a are a0:a1, the top word of b is
        * b0, we ensured that b0 is "full" (high bit set), and a is
        * such that the quotient q = a/b fits on one word (0 <= q < w).
        *
        * If a = b*q + r (with 0 <= r < q), we can estimate q by
        * doing an Euclidean division on the top words:
        *   a0*w+a1 = b0*u + v  (with 0 <= v < w)
        * Then the following holds:
        *   0 <= u <= w
        *   u-2 <= q <= u
        */
        a0 = br_i32_word(x, m_bitlen - 32);
        hi = x[mlen];
        memmove(x + 2, x + 1, (mlen - 1) * sizeof *x);
        x[1] = z;
        a1 = br_i32_word(x, m_bitlen - 32);
        b0 = br_i32_word(m, m_bitlen - 32);

        /*
        * We estimate a divisor q. If the quotient returned by br_div()
        * is g:
        * -- If a0 == b0 then g == 0; we want q = 0xFFFFFFFF.
        * -- Otherwise:
        *    -- if g == 0 then we set q = 0;
        *    -- otherwise, we set q = g - 1.
        * The properties described above then ensure that the true
        * quotient is q-1, q or q+1.
        */
        g = br_div(a0, a1, b0);
        q = MUX(EQ(a0, b0), 0xFFFFFFFF, MUX(EQ(g, 0), 0, g - 1));

        /*
        * We subtract q*m from x (with the extra high word of value 'hi').
        * Since q may be off by 1 (in either direction), we may have to
        * add or subtract m afterwards.
        *
        * The 'tb' flag will be true (1) at the end of the loop if the
        * result is greater than or equal to the modulus (not counting
        * 'hi' or the carry).
        */
        cc = 0;
        tb = 1;
        for (u = 1; u <= mlen; u ++) {
            uint32_t mw, zw, xw, nxw;
            uint64_t zl;

            mw = m[u];
            zl = MUL(mw, q) + cc;
            cc = (uint32_t)(zl >> 32);
            zw = (uint32_t)zl;
            xw = x[u];
            nxw = xw - zw;
            cc += (uint64_t)GT(nxw, xw);
            x[u] = nxw;
            tb = MUX(EQ(nxw, mw), tb, GT(nxw, mw));
        }

        /*
        * If we underestimated q, then either cc < hi (one extra bit
        * beyond the top array word), or cc == hi and tb is true (no
        * extra bit, but the result is not lower than the modulus). In
        * these cases we must subtract m once.
        *
        * Otherwise, we may have overestimated, which will show as
        * cc > hi (thus a negative result). Correction is adding m once.
        */
        chf = (uint32_t)(cc >> 32);
        clow = (uint32_t)cc;
        over = chf | GT(clow, hi);
        under = ~over & (tb | (~chf & LT(clow, hi)));
        br_i32_add(x, m, over);
        br_i32_sub(x, m, under);
    }

    /* from BearSSL's src/int/i32_reduce.c */
    /*
    * Reduce an integer (a[]) modulo another (m[]). The result is written
    * in x[] and its announced bit length is set to be equal to that of m[].
    *
    * x[] MUST be distinct from a[] and m[].
    *
    * CT: only announced bit lengths leak, not values of x, a or m.
    */
    static void br_i32_reduce(uint32_t *x, const uint32_t *a, const uint32_t *m)
    {
        uint32_t m_bitlen, a_bitlen;
        size_t mlen, alen, u;

        m_bitlen = m[0];
        mlen = (m_bitlen + 31) >> 5;

        x[0] = m_bitlen;
        if (m_bitlen == 0) {
            return;
        }

        /*
        * If the source is shorter, then simply copy all words from a[]
        * and zero out the upper words.
        */
        a_bitlen = a[0];
        alen = (a_bitlen + 31) >> 5;
        if (a_bitlen < m_bitlen) {
            memcpy(x + 1, a + 1, alen * sizeof *a);
            for (u = alen; u < mlen; u ++) {
                x[u + 1] = 0;
            }
            return;
        }

        /*
        * The source length is at least equal to that of the modulus.
        * We must thus copy N-1 words, and input the remaining words
        * one by one.
        */
        memcpy(x + 1, a + 2 + (alen - mlen), (mlen - 1) * sizeof *a);
        x[mlen] = 0;
        for (u = 1 + alen - mlen; u > 0; u --) {
            br_i32_muladd_small(x, a[u], m);
        }
    }

    /**
     * rsa_free_key_prop() - Free key properties
     * @prop:	Pointer to struct key_prop
     *
     * This function frees all the memories allocated by rsa_gen_key_prop().
     */
    inline void rsa_free_key_prop(struct key_prop *prop)
    {
        if (!prop)
            return;

        free((void *)prop->modulus);
        free((void *)prop->public_exponent);
        free((void *)prop->rr);

        free(prop);
    }

    /**
     * rsa_gen_key_prop() - Generate key properties of RSA public key
     * @key:	Specifies key data in DER format
     * @keylen:	Length of @key
     * @prop:	Generated key property
     *
     * This function takes a blob of encoded RSA public key data in DER
     * format, parse it and generate all the relevant properties
     * in key_prop structure.
     * Return a pointer to struct key_prop in @prop on success.
     *
     * Return:	0 on success, negative on error
     */
    static int rsa_gen_key_prop(const uint8_t *mod, uint32_t mod_len, const uint8_t *exp, uint32_t exp_len, struct key_prop **prop)
    {
        //struct rsa_key rsa_key;
        uint32_t *n = NULL, *rr = NULL, *rrtmp = NULL;
        int rlen, i, ret = 0;

        *prop = (key_prop*)calloc(sizeof(**prop), 1);
        if (!(*prop))
        {
            ret = -ENOMEM;
            goto out;
        }

        // ret = rsa_parse_pub_key(&rsa_key, key, keylen);
        // if (ret)
        //     goto out;

        /* modulus */
        /* removing leading 0's */
        for (i = 0; i < mod_len && !mod[i]; i++)
            ;
        // for (i = 0; i < rsa_key.n_sz && !rsa_key.n[i]; i++)
        //     ;
        // (*prop)->num_bits = (rsa_key.n_sz - i) * 8;
        // (*prop)->modulus = malloc(rsa_key.n_sz - i);
        (*prop)->num_bits = (mod_len - i) * 8;
        (*prop)->modulus = (uint8_t*)malloc(mod_len - i);
        if (!(*prop)->modulus)
        {
            ret = -ENOMEM;
            goto out;
        }
        memcpy((void *)(*prop)->modulus, &mod[i], mod_len - i);

        n = (uint32_t*)calloc(sizeof(uint32_t), 1 + ((*prop)->num_bits >> 5));
        rr = (uint32_t*)calloc(sizeof(uint32_t), 1 + (((*prop)->num_bits * 2) >> 5));
        rrtmp = (uint32_t*)calloc(sizeof(uint32_t), 2 + (((*prop)->num_bits * 2) >> 5));
        if (!n || !rr || !rrtmp)
        {
            ret = -ENOMEM;
            goto out;
        }

        /* exponent */
        (*prop)->public_exponent = (uint8_t*)calloc(1, sizeof(uint64_t));
        if (!(*prop)->public_exponent)
        {
            ret = -ENOMEM;
            goto out;
        }
        // memcpy((void *)(*prop)->public_exponent + sizeof(uint64_t) - rsa_key.e_sz,
        //        rsa_key.e, rsa_key.e_sz);
        memcpy((void *)((*prop)->public_exponent + sizeof(uint64_t) - exp_len),
               exp, exp_len);
        (*prop)->exp_len = sizeof(uint64_t);

        /* n0 inverse */
        br_i32_decode(n, &mod[i], mod_len - i);
        (*prop)->n0inv = br_i32_ninv32(n[1]);

        /* R^2 mod n; R = 2^(num_bits) */
        rlen = (*prop)->num_bits * 2; /* #bits of R^2 = (2^num_bits)^2 */
        rr[0] = 0;
        *(uint8_t *)&rr[0] = (1 << (rlen % 8));
        for (i = 1; i < (((rlen + 31) >> 5) + 1); i++)
            rr[i] = 0;
        br_i32_decode(rrtmp, (uint8_t*)rr, ((rlen + 7) >> 3) + 1);
        br_i32_reduce(rr, rrtmp, n);

        rlen = ((*prop)->num_bits + 7) >> 3; /* #bytes of R^2 mod n */
        (*prop)->rr = (uint8_t*)malloc(rlen);
        if (!(*prop)->rr)
        {
            ret = -ENOMEM;
            goto out;
        }
        br_i32_encode((uint8_t *)(*prop)->rr, rlen, rr);

    out:
        free(n);
        free(rr);
        free(rrtmp);
        if (ret < 0)
            rsa_free_key_prop(*prop);
        return ret;
    }

    /**
     * subtract_modulus() - subtract modulus from the given value
     *
     * @key:	Key containing modulus to subtract
     * @num:	Number to subtract modulus from, as little endian word array
     */
    static void subtract_modulus(const struct rsa_public_key *key, uint32_t num[])
    {
        int64_t acc = 0;
        uint i;

        for (i = 0; i < key->len; i++)
        {
            acc += (uint64_t)num[i] - key->modulus[i];
            num[i] = (uint32_t)acc;
            acc >>= 32;
        }
    }

    /**
     * greater_equal_modulus() - check if a value is >= modulus
     *
     * @key:	Key containing modulus to check
     * @num:	Number to check against modulus, as little endian word array
     * @return 0 if num < modulus, 1 if num >= modulus
     */
    static int greater_equal_modulus(const struct rsa_public_key *key,
                                     uint32_t num[])
    {
        int i;

        for (i = (int)key->len - 1; i >= 0; i--)
        {
            if (num[i] < key->modulus[i])
                return 0;
            if (num[i] > key->modulus[i])
                return 1;
        }

        return 1; /* equal */
    }

    /**
     * montgomery_mul_add_step() - Perform montgomery multiply-add step
     *
     * Operation: montgomery result[] += a * b[] / n0inv % modulus
     *
     * @key:	RSA key
     * @result:	Place to put result, as little endian word array
     * @a:		Multiplier
     * @b:		Multiplicand, as little endian word array
     */
    static void montgomery_mul_add_step(const struct rsa_public_key *key,
                                        uint32_t result[], const uint32_t a, const uint32_t b[])
    {
        uint64_t acc_a, acc_b;
        uint32_t d0;
        uint i;

        acc_a = (uint64_t)a * b[0] + result[0];
        d0 = (uint32_t)acc_a * key->n0inv;
        acc_b = (uint64_t)d0 * key->modulus[0] + (uint32_t)acc_a;
        for (i = 1; i < key->len; i++)
        {
            acc_a = (acc_a >> 32) + (uint64_t)a * b[i] + result[i];
            acc_b = (acc_b >> 32) + (uint64_t)d0 * key->modulus[i] +
                    (uint32_t)acc_a;
            result[i - 1] = (uint32_t)acc_b;
        }

        acc_a = (acc_a >> 32) + (acc_b >> 32);

        result[i - 1] = (uint32_t)acc_a;

        if (acc_a >> 32)
            subtract_modulus(key, result);
    }

    /**
 * montgomery_mul() - Perform montgomery mutitply
 *
 * Operation: montgomery result[] = a[] * b[] / n0inv % modulus
 *
 * @key:	RSA key
 * @result:	Place to put result, as little endian word array
 * @a:		Multiplier, as little endian word array
 * @b:		Multiplicand, as little endian word array
 */
    static void montgomery_mul(const struct rsa_public_key *key,
                               uint32_t result[], uint32_t a[], const uint32_t b[])
    {
        uint i;

        for (i = 0; i < key->len; ++i)
            result[i] = 0;
        for (i = 0; i < key->len; ++i)
            montgomery_mul_add_step(key, result, a[i], b);
    }

    /**
 * num_pub_exponent_bits() - Number of bits in the public exponent
 *
 * @key:	RSA key
 * @num_bits:	Storage for the number of public exponent bits
 */
    static int num_public_exponent_bits(const struct rsa_public_key *key,
                                        int *num_bits)
    {
        uint64_t exponent;
        int exponent_bits;
        const uint max_bits = (sizeof(exponent) * 8);

        exponent = key->exponent;
        exponent_bits = 0;

        if (!exponent)
        {
            *num_bits = exponent_bits;
            return 0;
        }

        for (exponent_bits = 1; exponent_bits < max_bits + 1; ++exponent_bits)
            if (!(exponent >>= 1))
            {
                *num_bits = exponent_bits;
                return 0;
            }

        return -EINVAL;
    }

    /**
 * is_public_exponent_bit_set() - Check if a bit in the public exponent is set
 *
 * @key:	RSA key
 * @pos:	The bit position to check
 */
    static int is_public_exponent_bit_set(const struct rsa_public_key *key,
                                          int pos)
    {
        return key->exponent & (1ULL << pos);
    }

    /**
 * pow_mod() - in-place public exponentiation
 *
 * @key:	RSA key
 * @inout:	Big-endian word array containing value and result
 */
    static int pow_mod(const struct rsa_public_key *key, uint32_t *inout)
    {
        uint32_t *result, *ptr;
        uint i;
        int j, k;

        /* Sanity check for stack size - key->len is in 32-bit words */
        // if (key->len > RSA_MAX_KEY_BITS / 32)
        // {
        //     debug("RSA key words %u exceeds maximum %d\n", key->len,
        //           RSA_MAX_KEY_BITS / 32);
        //     return -EINVAL;
        // }

        uint32_t val[key->len], acc[key->len], tmp[key->len];
        uint32_t a_scaled[key->len];
        result = tmp; /* Re-use location. */

        /* Convert from big endian byte array to little endian word array. */
        for (i = 0, ptr = inout + key->len - 1; i < key->len; i++, ptr--)
            val[i] = get_unaligned_be32(ptr);

        if (0 != num_public_exponent_bits(key, &k))
            return -EINVAL;

        if (k < 2)
        {
            // debug("Public exponent is too short (%d bits, minimum 2)\n",
            //       k);
            return -EINVAL;
        }

        if (!is_public_exponent_bit_set(key, 0))
        {
            //debug("LSB of RSA public exponent must be set.\n");
            return -EINVAL;
        }

        /* the bit at e[k-1] is 1 by definition, so start with: C := M */
        montgomery_mul(key, acc, val, key->rr); /* acc = a * RR / R mod n */
        /* retain scaled version for intermediate use */
        memcpy(a_scaled, acc, key->len * sizeof(a_scaled[0]));

        for (j = k - 2; j > 0; --j)
        {
            montgomery_mul(key, tmp, acc, acc); /* tmp = acc^2 / R mod n */

            if (is_public_exponent_bit_set(key, j))
            {
                /* acc = tmp * val / R mod n */
                montgomery_mul(key, acc, tmp, a_scaled);
            }
            else
            {
                /* e[j] == 0, copy tmp back to acc for next operation */
                memcpy(acc, tmp, key->len * sizeof(acc[0]));
            }
        }

        /* the bit at e[0] is always 1 */
        montgomery_mul(key, tmp, acc, acc); /* tmp = acc^2 / R mod n */
        montgomery_mul(key, acc, tmp, val); /* acc = tmp * a / R mod M */
        memcpy(result, acc, key->len * sizeof(result[0]));

        /* Make sure result < mod; result is at most 1x mod too large. */
        if (greater_equal_modulus(key, result))
            subtract_modulus(key, result);

        /* Convert to bigendian byte array */
        for (i = key->len - 1, ptr = inout; (int)i >= 0; i--, ptr++)
            put_unaligned_be32(result[i], ptr);
        return 0;
    }

    static void rsa_convert_big_endian(uint32_t *dst, const uint32_t *src, int len)
    {
        int i;

        for (i = 0; i < len; i++)
            dst[i] = fdt32_to_cpu(src[len - 1 - i]);
    }

    static int rsa_mod_exp_sw(const uint8_t *sig, uint32_t sig_len,
                       struct key_prop *prop, uint8_t *out)
    {
        struct rsa_public_key key;
        int ret;

        if (!prop)
        {
            //debug("%s: Skipping invalid prop", __func__);
            return -EBADF;
        }
        key.n0inv = prop->n0inv;
        key.len = prop->num_bits;

        if (!prop->public_exponent)
            key.exponent = RSA_DEFAULT_PUBEXP;
        else
            key.exponent = fdt64_to_cpup(prop->public_exponent);

        if (!key.len || !prop->modulus || !prop->rr)
        {
            //debug("%s: Missing RSA key info", __func__);
            return -EFAULT;
        }

        /* Sanity check for stack size */
        // if (key.len > RSA_MAX_KEY_BITS || key.len < RSA_MIN_KEY_BITS)
        // {
        //     debug("RSA key bits %u outside allowed range %d..%d\n",
        //           key.len, RSA_MIN_KEY_BITS, RSA_MAX_KEY_BITS);
        //     return -EFAULT;
        // }
        key.len /= sizeof(uint32_t) * 8;
        uint32_t key1[key.len], key2[key.len];

        key.modulus = key1;
        key.rr = key2;
        rsa_convert_big_endian(key.modulus, (uint32_t *)prop->modulus, key.len);
        rsa_convert_big_endian(key.rr, (uint32_t *)prop->rr, key.len);
        if (!key.modulus || !key.rr)
        {
            //debug("%s: Out of memory", __func__);
            return -ENOMEM;
        }

        uint32_t buf[sig_len / sizeof(uint32_t)];

        memcpy(buf, sig, sig_len);

        ret = pow_mod(&key, buf);
        if (ret)
            return ret;

        memcpy(out, buf, sig_len);

        return 0;
    }

    /**
     * rsa_gen_key_prop() - Generate key properties of RSA public key
     * @key:	Specifies key data in DER format
     * @keylen:	Length of @key
     * @prop:	Generated key property
     *
     * This function takes a blob of encoded RSA public key data in DER
     * format, parse it and generate all the relevant properties
     * in key_prop structure.
     * Return a pointer to struct key_prop in @prop on success.
     *
     * Return:	0 on success, negative on error
     */
    static int pow_mod(const uint8_t* base, uint32_t base_len, const uint8_t* mod, uint32_t mod_len, const uint8_t* exp, uint32_t exp_len, uint8_t* out, uint32_t out_len)
    {
        struct key_prop prop;
        memset(&prop, 0, sizeof(key_prop));

        //struct rsa_key rsa_key;
        int rlen, i, ret = 0;

        uint32_t n_len = sizeof(uint32_t) * (1 + (prop.num_bits >> 5));
        uint32_t lll =  (1 + (prop.num_bits >> 5));

        /* modulus */
        /* removing leading 0's */
        for (i = 0; i < mod_len && !mod[i]; i++)
            ;

        prop.num_bits = (mod_len - i) * 8;
        prop.modulus = mod + i;

        uint32_t n[sizeof(uint32_t) * (1 + (prop.num_bits >> 5))];
        uint32_t rr[sizeof(uint32_t) * (1 + ((prop.num_bits * 2) >> 5))];
        uint32_t rrtmp[sizeof(uint32_t) * (2 + ((prop.num_bits * 2) >> 5))];

        /* exponent */
        uint64_t ui64_exp = 0;
        prop.public_exponent = (uint8_t*)&ui64_exp;

        // TODO: verify exp_len not greater than sizeof(uint64_t)
        memcpy((void *)(prop.public_exponent + sizeof(uint64_t) - exp_len), exp, exp_len);
        prop.exp_len = sizeof(uint64_t);

        /* n0 inverse */
        br_i32_decode(n, &mod[i], mod_len - i);
        prop.n0inv = br_i32_ninv32(n[1]);

        /* R^2 mod n; R = 2^(num_bits) */
        rlen = prop.num_bits * 2; /* #bits of R^2 = (2^num_bits)^2 */
        rr[0] = 0;
        *(uint8_t *)&rr[0] = (1 << (rlen % 8));
        for (i = 1; i < (((rlen + 31) >> 5) + 1); i++)
            rr[i] = 0;
        br_i32_decode(rrtmp, (uint8_t*)rr, ((rlen + 7) >> 3) + 1);
        br_i32_reduce(rr, rrtmp, n);

        rlen = (prop.num_bits + 7) >> 3; /* #bytes of R^2 mod n */
        uint8_t byte_rr[rlen];
        prop.rr = byte_rr;
        br_i32_encode((uint8_t *)prop.rr, rlen, rr);

        return rsa_mod_exp_sw(base, base_len, &prop, out);
    }
}