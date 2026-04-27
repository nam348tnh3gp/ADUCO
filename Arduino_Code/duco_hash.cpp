#include "duco_hash.h"

#pragma GCC optimize("-Ofast")

#define sha1_rotl(bits, word) \
    (((word) << (bits)) | ((word) >> (32 - (bits))))

#if defined(__AVR__)
extern "C" uint32_t sha1_rotl5(uint32_t value);
extern "C" uint32_t sha1_rotl30(uint32_t value);
#define SHA1_ROTL5(word) sha1_rotl5(word)
#define SHA1_ROTL30(word) sha1_rotl30(word)
#else
#define SHA1_ROTL5(word) sha1_rotl(5, word)
#define SHA1_ROTL30(word) sha1_rotl(30, word)
#endif

// Hằng số length word theo nonceLen (giữ nguyên)
static uint32_t const kLengthWordByNonceLen[6] = {
    0x00000000UL,
    0x00000148UL,
    0x00000150UL,
    0x00000158UL,
    0x00000160UL,
    0x00000168UL
};

// Hàm init không đổi, chỉ copy sang cho đủ bộ
void duco_hash_init(duco_hash_state_t *hasher, char const *prevHash)
{
    uint32_t a = 0x67452301UL;
    uint32_t b = 0xEFCDAB89UL;
    uint32_t c = 0x98BADCFEUL;
    uint32_t d = 0x10325476UL;
    uint32_t e = 0xC3D2E1F0UL;

    for (uint8_t i = 0, i4 = 0; i < 10; i++, i4 += 4) {
        hasher->initialWords[i] =
            ((uint32_t)(uint8_t)prevHash[i4    ] << 24) |
            ((uint32_t)(uint8_t)prevHash[i4 + 1] << 16) |
            ((uint32_t)(uint8_t)prevHash[i4 + 2] <<  8) |
            ((uint32_t)(uint8_t)prevHash[i4 + 3]);
    }

    for (uint8_t i = 0; i < 10; i++) {
        uint32_t temp = SHA1_ROTL5(a) + e
                      + ((b & c) | ((~b) & d))      // f1: Ch(b,c,d)
                      + hasher->initialWords[i]
                      + 0x5A827999UL;
        e = d;
        d = c;
        c = SHA1_ROTL30(b);
        b = a;
        a = temp;
    }

    hasher->tempState[0] = a;
    hasher->tempState[1] = b;
    hasher->tempState[2] = c;
    hasher->tempState[3] = d;
    hasher->tempState[4] = e;
}

// Phiên bản try_nonce đã unroll triệt để
__attribute__((noinline)) 
bool duco_hash_try_nonce(duco_hash_state_t *hasher,
                         char const *nonce,
                         uint8_t nonceLen,
                         uint32_t const *targetWords)
{
    // 1. Nạp 16 word w0..w15 trực tiếp (tránh gọi load_block_words)
    uint32_t w0  = hasher->initialWords[0];
    uint32_t w1  = hasher->initialWords[1];
    uint32_t w2  = hasher->initialWords[2];
    uint32_t w3  = hasher->initialWords[3];
    uint32_t w4  = hasher->initialWords[4];
    uint32_t w5  = hasher->initialWords[5];
    uint32_t w6  = hasher->initialWords[6];
    uint32_t w7  = hasher->initialWords[7];
    uint32_t w8  = hasher->initialWords[8];
    uint32_t w9  = hasher->initialWords[9];
    uint32_t w10, w11, w12, w13, w14, w15;

    // Xử lý nonce (fast path cho len ≤ 5, fallback chung)
    uint8_t d0 = (uint8_t)nonce[0];
    uint8_t d1 = (uint8_t)nonce[1];
    uint8_t d2 = (uint8_t)nonce[2];
    uint8_t d3 = (uint8_t)nonce[3];
    uint8_t d4 = (uint8_t)nonce[4];

    if (nonceLen <= 5) {
        switch (nonceLen) {
            case 1:
                w10 = (d0 << 24) | 0x00800000UL;
                w11 = 0;
                w12 = 0;
                break;
            case 2:
                w10 = (d0 << 24) | (d1 << 16) | 0x00008000UL;
                w11 = 0;
                w12 = 0;
                break;
            case 3:
                w10 = (d0 << 24) | (d1 << 16) | (d2 << 8) | 0x00000080UL;
                w11 = 0;
                w12 = 0;
                break;
            case 4:
                w10 = (d0 << 24) | (d1 << 16) | (d2 << 8) | d3;
                w11 = 0x80000000UL;
                w12 = 0;
                break;
            default: // 5
                w10 = (d0 << 24) | (d1 << 16) | (d2 << 8) | d3;
                w11 = (d4 << 24) | 0x00800000UL;
                w12 = 0;
                break;
        }
        w13 = 0;
        w14 = 0;
        w15 = kLengthWordByNonceLen[nonceLen];
    } else {
        w10 = 0; w11 = 0; w12 = 0; w13 = 0; w14 = 0; w15 = 0;
        for (uint8_t i = 0; i < nonceLen; i++) {
            uint8_t wordIndex = 10 + (i >> 2);
            uint8_t shift = 24 - ((i & 3) << 3);
            uint32_t val = (uint32_t)(uint8_t)nonce[i] << shift;
            if (wordIndex == 10) w10 |= val;
            else if (wordIndex == 11) w11 |= val;
            else if (wordIndex == 12) w12 |= val;
            else if (wordIndex == 13) w13 |= val;
            else if (wordIndex == 14) w14 |= val;
        }
        uint8_t padIndex = 10 + (nonceLen >> 2);
        uint8_t padShift = 24 - ((nonceLen & 3) << 3);
        uint32_t pad = 0x80UL << padShift;
        if (padIndex == 10) w10 |= pad;
        else if (padIndex == 11) w11 |= pad;
        else if (padIndex == 12) w12 |= pad;
        else if (padIndex == 13) w13 |= pad;
        else if (padIndex == 14) w14 |= pad;
        w15 = (uint32_t)(40 + nonceLen) << 3;
    }

    // 2. Trạng thái bắt đầu từ sau vòng 9 (lấy từ tempState)
    uint32_t a = hasher->tempState[0];
    uint32_t b = hasher->tempState[1];
    uint32_t c = hasher->tempState[2];
    uint32_t d = hasher->tempState[3];
    uint32_t e = hasher->tempState[4];
    uint32_t t;

    // 3. 70 vòng SHA-1 (i=10..79) được unroll hoàn toàn

    // ---------- vòng 10..15 (dùng w10..w15, f = Ch, K = 0x5A827999) ----------
    // vòng 10
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + w10 + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // vòng 11
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + w11 + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // vòng 12
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + w12 + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // vòng 13
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + w13 + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // vòng 14
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + w14 + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // vòng 15
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + w15 + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;

    // ---------- vòng 16..19 (có expand, f = Ch, K = 0x5A827999) ----------
    // vòng 16: index 0 mới = w13 ^ w8 ^ w2 ^ w0
    w0 = sha1_rotl(1, w13 ^ w8 ^ w2 ^ w0);
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + w0 + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // vòng 17: index 1 mới = w14 ^ w9 ^ w3 ^ w1
    w1 = sha1_rotl(1, w14 ^ w9 ^ w3 ^ w1);
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + w1 + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // vòng 18: index 2 mới = w15 ^ w10 ^ w4 ^ w2
    w2 = sha1_rotl(1, w15 ^ w10 ^ w4 ^ w2);
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + w2 + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // vòng 19: index 3 mới = w0 ^ w11 ^ w5 ^ w3
    w3 = sha1_rotl(1, w0 ^ w11 ^ w5 ^ w3);
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + w3 + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;

    // ---------- vòng 20..39 (Parity, K = 0x6ED9EBA1, expand) ----------
    // 20: w4 = w1 ^ w12 ^ w6 ^ w4
    w4 = sha1_rotl(1, w1 ^ w12 ^ w6 ^ w4);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w4 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 21
    w5 = sha1_rotl(1, w2 ^ w13 ^ w7 ^ w5);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w5 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 22
    w6 = sha1_rotl(1, w3 ^ w14 ^ w8 ^ w6);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w6 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 23
    w7 = sha1_rotl(1, w4 ^ w15 ^ w9 ^ w7);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w7 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 24
    w8 = sha1_rotl(1, w5 ^ w0 ^ w10 ^ w8);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w8 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 25
    w9 = sha1_rotl(1, w6 ^ w1 ^ w11 ^ w9);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w9 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 26
    w10 = sha1_rotl(1, w7 ^ w2 ^ w12 ^ w10);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w10 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 27
    w11 = sha1_rotl(1, w8 ^ w3 ^ w13 ^ w11);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w11 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 28
    w12 = sha1_rotl(1, w9 ^ w4 ^ w14 ^ w12);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w12 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 29
    w13 = sha1_rotl(1, w10 ^ w5 ^ w15 ^ w13);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w13 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 30
    w14 = sha1_rotl(1, w11 ^ w6 ^ w0 ^ w14);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w14 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 31
    w15 = sha1_rotl(1, w12 ^ w7 ^ w1 ^ w15);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w15 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 32
    w0 = sha1_rotl(1, w13 ^ w8 ^ w2 ^ w0);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w0 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 33
    w1 = sha1_rotl(1, w14 ^ w9 ^ w3 ^ w1);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w1 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 34
    w2 = sha1_rotl(1, w15 ^ w10 ^ w4 ^ w2);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w2 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 35
    w3 = sha1_rotl(1, w0 ^ w11 ^ w5 ^ w3);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w3 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 36
    w4 = sha1_rotl(1, w1 ^ w12 ^ w6 ^ w4);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w4 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 37
    w5 = sha1_rotl(1, w2 ^ w13 ^ w7 ^ w5);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w5 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 38
    w6 = sha1_rotl(1, w3 ^ w14 ^ w8 ^ w6);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w6 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 39
    w7 = sha1_rotl(1, w4 ^ w15 ^ w9 ^ w7);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w7 + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;

    // ---------- vòng 40..59 (Majority, K = 0x8F1BBCDC) ----------
    // 40
    w8 = sha1_rotl(1, w5 ^ w0 ^ w10 ^ w8);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w8 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 41
    w9 = sha1_rotl(1, w6 ^ w1 ^ w11 ^ w9);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w9 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 42
    w10 = sha1_rotl(1, w7 ^ w2 ^ w12 ^ w10);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w10 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 43
    w11 = sha1_rotl(1, w8 ^ w3 ^ w13 ^ w11);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w11 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 44
    w12 = sha1_rotl(1, w9 ^ w4 ^ w14 ^ w12);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w12 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 45
    w13 = sha1_rotl(1, w10 ^ w5 ^ w15 ^ w13);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w13 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 46
    w14 = sha1_rotl(1, w11 ^ w6 ^ w0 ^ w14);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w14 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 47
    w15 = sha1_rotl(1, w12 ^ w7 ^ w1 ^ w15);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w15 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 48
    w0 = sha1_rotl(1, w13 ^ w8 ^ w2 ^ w0);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w0 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 49
    w1 = sha1_rotl(1, w14 ^ w9 ^ w3 ^ w1);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w1 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 50
    w2 = sha1_rotl(1, w15 ^ w10 ^ w4 ^ w2);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w2 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 51
    w3 = sha1_rotl(1, w0 ^ w11 ^ w5 ^ w3);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w3 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 52
    w4 = sha1_rotl(1, w1 ^ w12 ^ w6 ^ w4);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w4 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 53
    w5 = sha1_rotl(1, w2 ^ w13 ^ w7 ^ w5);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w5 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 54
    w6 = sha1_rotl(1, w3 ^ w14 ^ w8 ^ w6);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w6 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 55
    w7 = sha1_rotl(1, w4 ^ w15 ^ w9 ^ w7);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w7 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 56
    w8 = sha1_rotl(1, w5 ^ w0 ^ w10 ^ w8);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w8 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 57
    w9 = sha1_rotl(1, w6 ^ w1 ^ w11 ^ w9);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w9 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 58
    w10 = sha1_rotl(1, w7 ^ w2 ^ w12 ^ w10);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w10 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 59
    w11 = sha1_rotl(1, w8 ^ w3 ^ w13 ^ w11);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + w11 + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;

    // ---------- vòng 60..79 (Parity, K = 0xCA62C1D6) ----------
    // 60
    w12 = sha1_rotl(1, w9 ^ w4 ^ w14 ^ w12);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w12 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 61
    w13 = sha1_rotl(1, w10 ^ w5 ^ w15 ^ w13);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w13 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 62
    w14 = sha1_rotl(1, w11 ^ w6 ^ w0 ^ w14);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w14 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 63
    w15 = sha1_rotl(1, w12 ^ w7 ^ w1 ^ w15);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w15 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 64
    w0 = sha1_rotl(1, w13 ^ w8 ^ w2 ^ w0);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w0 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 65
    w1 = sha1_rotl(1, w14 ^ w9 ^ w3 ^ w1);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w1 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 66
    w2 = sha1_rotl(1, w15 ^ w10 ^ w4 ^ w2);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w2 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 67
    w3 = sha1_rotl(1, w0 ^ w11 ^ w5 ^ w3);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w3 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 68
    w4 = sha1_rotl(1, w1 ^ w12 ^ w6 ^ w4);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w4 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 69
    w5 = sha1_rotl(1, w2 ^ w13 ^ w7 ^ w5);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w5 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 70
    w6 = sha1_rotl(1, w3 ^ w14 ^ w8 ^ w6);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w6 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 71
    w7 = sha1_rotl(1, w4 ^ w15 ^ w9 ^ w7);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w7 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 72
    w8 = sha1_rotl(1, w5 ^ w0 ^ w10 ^ w8);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w8 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 73
    w9 = sha1_rotl(1, w6 ^ w1 ^ w11 ^ w9);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w9 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 74
    w10 = sha1_rotl(1, w7 ^ w2 ^ w12 ^ w10);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w10 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 75
    w11 = sha1_rotl(1, w8 ^ w3 ^ w13 ^ w11);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w11 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 76
    w12 = sha1_rotl(1, w9 ^ w4 ^ w14 ^ w12);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w12 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 77
    w13 = sha1_rotl(1, w10 ^ w5 ^ w15 ^ w13);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w13 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 78
    w14 = sha1_rotl(1, w11 ^ w6 ^ w0 ^ w14);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w14 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 79
    w15 = sha1_rotl(1, w12 ^ w7 ^ w1 ^ w15);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + w15 + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;

    // 4. Final addition (giá trị ban đầu của SHA-1)
    a += 0x67452301UL;
    b += 0xEFCDAB89UL;
    c += 0x98BADCFEUL;
    d += 0x10325476UL;
    e += 0xC3D2E1F0UL;

    // 5. So sánh với target
    return a == targetWords[0]
        && b == targetWords[1]
        && c == targetWords[2]
        && d == targetWords[3]
        && e == targetWords[4];
}
