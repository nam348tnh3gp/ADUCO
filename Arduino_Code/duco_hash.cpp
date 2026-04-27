#include "duco_hash.h"

#pragma GCC optimize("-Ofast")

// Rotate macros (giữ nguyên)
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

#define SHA1_EXPAND(i) \
    W[(i) & 15] = sha1_rotl(1,  W[((i)-3)  & 15] \
                              ^ W[((i)-8)  & 15] \
                              ^ W[((i)-14) & 15] \
                              ^ W[(i)      & 15])

#define SHA1_ROUND(f_expr, K) do {          \
    uint32_t _t = SHA1_ROTL5(a) + (f_expr) + e + W[i & 15] + (K); \
    e = d;                                  \
    d = c;                                  \
    c = SHA1_ROTL30(b);                     \
    b = a;                                  \
    a = _t;                                 \
} while (0)

static uint32_t const kLengthWordByNonceLen[6] = {
    0x00000000UL,
    0x00000148UL,
    0x00000150UL,
    0x00000158UL,
    0x00000160UL,
    0x00000168UL
};

// Hàm load block words – giữ nguyên hoàn toàn (bạn đã tối ưu rất tốt)
static inline __attribute__((always_inline)) void duco_hash_load_block_words(
    uint32_t *W,
    uint32_t const *baseWords,
    char const *nonce,
    uint8_t nonceLen)
{
    W[0] = baseWords[0];
    W[1] = baseWords[1];
    W[2] = baseWords[2];
    W[3] = baseWords[3];
    W[4] = baseWords[4];
    W[5] = baseWords[5];
    W[6] = baseWords[6];
    W[7] = baseWords[7];
    W[8] = baseWords[8];
    W[9] = baseWords[9];

    uint32_t d0 = (uint8_t)nonce[0];
    uint32_t d1 = (uint8_t)nonce[1];
    uint32_t d2 = (uint8_t)nonce[2];
    uint32_t d3 = (uint8_t)nonce[3];
    uint32_t d4 = (uint8_t)nonce[4];

    if (nonceLen <= 5) {
        switch (nonceLen) {
            case 1:
                W[10] = (d0 << 24) | 0x00800000UL;
                W[11] = 0;
                W[12] = 0;
                break;
            case 2:
                W[10] = (d0 << 24) | (d1 << 16) | 0x00008000UL;
                W[11] = 0;
                W[12] = 0;
                break;
            case 3:
                W[10] = (d0 << 24) | (d1 << 16) | (d2 << 8) | 0x00000080UL;
                W[11] = 0;
                W[12] = 0;
                break;
            case 4:
                W[10] = (d0 << 24) | (d1 << 16) | (d2 << 8) | d3;
                W[11] = 0x80000000UL;
                W[12] = 0;
                break;
            default: // 5
                W[10] = (d0 << 24) | (d1 << 16) | (d2 << 8) | d3;
                W[11] = (d4 << 24) | 0x00800000UL;
                W[12] = 0;
                break;
        }
        W[13] = 0;
        W[14] = 0;
        W[15] = kLengthWordByNonceLen[nonceLen];
        return;
    }

    W[10] = 0; W[11] = 0; W[12] = 0; W[13] = 0; W[14] = 0;
    for (uint8_t i = 0; i < nonceLen; i++) {
        uint8_t wordIndex = 10 + (i >> 2);
        uint8_t shift = 24 - ((i & 3) << 3);
        W[wordIndex] |= (uint32_t)(uint8_t)nonce[i] << shift;
    }
    {
        uint8_t wordIndex = 10 + (nonceLen >> 2);
        uint8_t shift = 24 - ((nonceLen & 3) << 3);
        W[wordIndex] |= 0x80UL << shift;
    }
    W[15] = (uint32_t)(40 + nonceLen) << 3;
}

/*
   duco_hash_try_nonce – phiên bản UNROLL HOÀN TOÀN 70 VÒNG SHA-1
   - Dùng mảng tĩnh W[16] (static) → không chiếm stack
   - Chỉ có 5 biến trạng thái a,b,c,d,e → ít áp lực thanh ghi
   - Mỗi vòng được viết tường minh, không còn for()
   - Tránh tràn stack → board phản hồi ổn định
*/
__attribute__((noinline)) bool duco_hash_try_nonce(duco_hash_state_t *hasher,
                                                   char const *nonce,
                                                   uint8_t nonceLen,
                                                   uint32_t const *targetWords)
{
    static uint32_t W[16];
    duco_hash_load_block_words(W, hasher->initialWords, nonce, nonceLen);

    uint32_t a = hasher->tempState[0];
    uint32_t b = hasher->tempState[1];
    uint32_t c = hasher->tempState[2];
    uint32_t d = hasher->tempState[3];
    uint32_t e = hasher->tempState[4];
    uint32_t t;   // biến tạm, compiler sẽ tối ưu vào thanh ghi

    // ======= Vòng 10 -> 79 (70 vòng) =======

    // --- Vòng 10..15 (f = Ch, K = 0x5A827999, không cần expand) ---
    // Vòng 10
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + W[10] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // Vòng 11
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + W[11] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // Vòng 12
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + W[12] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // Vòng 13
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + W[13] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // Vòng 14
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + W[14] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // Vòng 15
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + W[15] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;

    // --- Vòng 16..19 (f = Ch, K = 0x5A827999, có expand) ---
    // 16: W[0] = rotl(W[13]^W[8]^W[2]^W[0],1)
    W[0] = sha1_rotl(1, W[13] ^ W[8] ^ W[2] ^ W[0]);
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + W[0] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 17
    W[1] = sha1_rotl(1, W[14] ^ W[9] ^ W[3] ^ W[1]);
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + W[1] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 18
    W[2] = sha1_rotl(1, W[15] ^ W[10] ^ W[4] ^ W[2]);
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + W[2] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 19
    W[3] = sha1_rotl(1, W[0] ^ W[11] ^ W[5] ^ W[3]);
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + W[3] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;

    // --- Vòng 20..39 (Parity, K = 0x6ED9EBA1) ---
    // 20
    W[4] = sha1_rotl(1, W[1] ^ W[12] ^ W[6] ^ W[4]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[4] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 21
    W[5] = sha1_rotl(1, W[2] ^ W[13] ^ W[7] ^ W[5]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[5] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 22
    W[6] = sha1_rotl(1, W[3] ^ W[14] ^ W[8] ^ W[6]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[6] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 23
    W[7] = sha1_rotl(1, W[4] ^ W[15] ^ W[9] ^ W[7]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[7] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 24
    W[8] = sha1_rotl(1, W[5] ^ W[0] ^ W[10] ^ W[8]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[8] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 25
    W[9] = sha1_rotl(1, W[6] ^ W[1] ^ W[11] ^ W[9]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[9] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 26
    W[10] = sha1_rotl(1, W[7] ^ W[2] ^ W[12] ^ W[10]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[10] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 27
    W[11] = sha1_rotl(1, W[8] ^ W[3] ^ W[13] ^ W[11]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[11] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 28
    W[12] = sha1_rotl(1, W[9] ^ W[4] ^ W[14] ^ W[12]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[12] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 29
    W[13] = sha1_rotl(1, W[10] ^ W[5] ^ W[15] ^ W[13]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[13] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 30
    W[14] = sha1_rotl(1, W[11] ^ W[6] ^ W[0] ^ W[14]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[14] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 31
    W[15] = sha1_rotl(1, W[12] ^ W[7] ^ W[1] ^ W[15]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[15] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 32
    W[0] = sha1_rotl(1, W[13] ^ W[8] ^ W[2] ^ W[0]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[0] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 33
    W[1] = sha1_rotl(1, W[14] ^ W[9] ^ W[3] ^ W[1]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[1] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 34
    W[2] = sha1_rotl(1, W[15] ^ W[10] ^ W[4] ^ W[2]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[2] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 35
    W[3] = sha1_rotl(1, W[0] ^ W[11] ^ W[5] ^ W[3]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[3] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 36
    W[4] = sha1_rotl(1, W[1] ^ W[12] ^ W[6] ^ W[4]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[4] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 37
    W[5] = sha1_rotl(1, W[2] ^ W[13] ^ W[7] ^ W[5]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[5] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 38
    W[6] = sha1_rotl(1, W[3] ^ W[14] ^ W[8] ^ W[6]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[6] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 39
    W[7] = sha1_rotl(1, W[4] ^ W[15] ^ W[9] ^ W[7]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[7] + 0x6ED9EBA1UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;

    // --- Vòng 40..59 (Majority, K = 0x8F1BBCDC) ---
    // 40
    W[8] = sha1_rotl(1, W[5] ^ W[0] ^ W[10] ^ W[8]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[8] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 41
    W[9] = sha1_rotl(1, W[6] ^ W[1] ^ W[11] ^ W[9]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[9] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 42
    W[10] = sha1_rotl(1, W[7] ^ W[2] ^ W[12] ^ W[10]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[10] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 43
    W[11] = sha1_rotl(1, W[8] ^ W[3] ^ W[13] ^ W[11]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[11] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 44
    W[12] = sha1_rotl(1, W[9] ^ W[4] ^ W[14] ^ W[12]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[12] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 45
    W[13] = sha1_rotl(1, W[10] ^ W[5] ^ W[15] ^ W[13]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[13] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 46
    W[14] = sha1_rotl(1, W[11] ^ W[6] ^ W[0] ^ W[14]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[14] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 47
    W[15] = sha1_rotl(1, W[12] ^ W[7] ^ W[1] ^ W[15]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[15] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 48
    W[0] = sha1_rotl(1, W[13] ^ W[8] ^ W[2] ^ W[0]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[0] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 49
    W[1] = sha1_rotl(1, W[14] ^ W[9] ^ W[3] ^ W[1]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[1] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 50
    W[2] = sha1_rotl(1, W[15] ^ W[10] ^ W[4] ^ W[2]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[2] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 51
    W[3] = sha1_rotl(1, W[0] ^ W[11] ^ W[5] ^ W[3]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[3] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 52
    W[4] = sha1_rotl(1, W[1] ^ W[12] ^ W[6] ^ W[4]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[4] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 53
    W[5] = sha1_rotl(1, W[2] ^ W[13] ^ W[7] ^ W[5]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[5] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 54
    W[6] = sha1_rotl(1, W[3] ^ W[14] ^ W[8] ^ W[6]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[6] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 55
    W[7] = sha1_rotl(1, W[4] ^ W[15] ^ W[9] ^ W[7]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[7] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 56
    W[8] = sha1_rotl(1, W[5] ^ W[0] ^ W[10] ^ W[8]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[8] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 57
    W[9] = sha1_rotl(1, W[6] ^ W[1] ^ W[11] ^ W[9]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[9] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 58
    W[10] = sha1_rotl(1, W[7] ^ W[2] ^ W[12] ^ W[10]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[10] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 59
    W[11] = sha1_rotl(1, W[8] ^ W[3] ^ W[13] ^ W[11]);
    t = SHA1_ROTL5(a) + ((b & c) | (b & d) | (c & d)) + e + W[11] + 0x8F1BBCDCUL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;

    // --- Vòng 60..79 (Parity, K = 0xCA62C1D6) ---
    // 60
    W[12] = sha1_rotl(1, W[9] ^ W[4] ^ W[14] ^ W[12]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[12] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 61
    W[13] = sha1_rotl(1, W[10] ^ W[5] ^ W[15] ^ W[13]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[13] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 62
    W[14] = sha1_rotl(1, W[11] ^ W[6] ^ W[0] ^ W[14]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[14] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 63
    W[15] = sha1_rotl(1, W[12] ^ W[7] ^ W[1] ^ W[15]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[15] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 64
    W[0] = sha1_rotl(1, W[13] ^ W[8] ^ W[2] ^ W[0]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[0] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 65
    W[1] = sha1_rotl(1, W[14] ^ W[9] ^ W[3] ^ W[1]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[1] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 66
    W[2] = sha1_rotl(1, W[15] ^ W[10] ^ W[4] ^ W[2]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[2] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 67
    W[3] = sha1_rotl(1, W[0] ^ W[11] ^ W[5] ^ W[3]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[3] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 68
    W[4] = sha1_rotl(1, W[1] ^ W[12] ^ W[6] ^ W[4]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[4] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 69
    W[5] = sha1_rotl(1, W[2] ^ W[13] ^ W[7] ^ W[5]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[5] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 70
    W[6] = sha1_rotl(1, W[3] ^ W[14] ^ W[8] ^ W[6]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[6] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 71
    W[7] = sha1_rotl(1, W[4] ^ W[15] ^ W[9] ^ W[7]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[7] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 72
    W[8] = sha1_rotl(1, W[5] ^ W[0] ^ W[10] ^ W[8]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[8] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 73
    W[9] = sha1_rotl(1, W[6] ^ W[1] ^ W[11] ^ W[9]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[9] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 74
    W[10] = sha1_rotl(1, W[7] ^ W[2] ^ W[12] ^ W[10]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[10] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 75
    W[11] = sha1_rotl(1, W[8] ^ W[3] ^ W[13] ^ W[11]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[11] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 76
    W[12] = sha1_rotl(1, W[9] ^ W[4] ^ W[14] ^ W[12]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[12] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 77
    W[13] = sha1_rotl(1, W[10] ^ W[5] ^ W[15] ^ W[13]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[13] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 78
    W[14] = sha1_rotl(1, W[11] ^ W[6] ^ W[0] ^ W[14]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[14] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // 79
    W[15] = sha1_rotl(1, W[12] ^ W[7] ^ W[1] ^ W[15]);
    t = SHA1_ROTL5(a) + (b ^ c ^ d) + e + W[15] + 0xCA62C1D6UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;

    // Cộng giá trị khởi tạo SHA1
    a += 0x67452301UL;
    b += 0xEFCDAB89UL;
    c += 0x98BADCFEUL;
    d += 0x10325476UL;
    e += 0xC3D2E1F0UL;

    return a == targetWords[0]
        && b == targetWords[1]
        && c == targetWords[2]
        && d == targetWords[3]
        && e == targetWords[4];
}

// duco_hash_init giữ nguyên hoàn toàn
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
                      + ((b & c) | ((~b) & d))
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
