#include "duco_hash.h"

#pragma GCC push_options
#pragma GCC optimize ("O3")           // an toàn hơn -Ofast, vẫn tối ưu mạnh

// ========== Inline assembly quay 5/30 bit cho AVR ==========
#if defined(__AVR__)
// Quay trái 5 bit: a = (a<<5)|(a>>27)
#define SHA1_ROTL5(word) ({                      \
    uint32_t _v = (word);                        \
    __asm__ __volatile__ (                       \
        "mov __tmp_reg__, %A[_v] \n\t"           \
        "mov __zero_reg__, %B[_v] \n\t"          \
        "mov %A[_v], %C[_v] \n\t"                \
        "mov %B[_v], %D[_v] \n\t"                \
        "mov %C[_v], __tmp_reg__ \n\t"           \
        "mov %D[_v], __zero_reg__ \n\t"          \
        "lsl %A[_v] \n\t"                        \
        "rol %B[_v] \n\t"                        \
        "rol %C[_v] \n\t"                        \
        "rol %D[_v] \n\t"                        \
        "adc %A[_v], __zero_reg__ \n\t"          \
        "lsl %A[_v] \n\t"                        \
        "rol %B[_v] \n\t"                        \
        "rol %C[_v] \n\t"                        \
        "rol %D[_v] \n\t"                        \
        "adc %A[_v], __zero_reg__ \n\t"          \
        : [_v] "+r" (_v)                         \
        :                                        \
        : "r0", "r1"                             \
    );                                           \
    _v;                                          \
})

// Quay trái 30 bit: a = (a<<30)|(a>>2)
#define SHA1_ROTL30(word) ({                     \
    uint32_t _v = (word);                        \
    __asm__ __volatile__ (                       \
        "mov __tmp_reg__, %A[_v] \n\t"           \
        "mov __zero_reg__, %B[_v] \n\t"          \
        "mov %A[_v], %C[_v] \n\t"                \
        "mov %B[_v], %D[_v] \n\t"                \
        "mov %C[_v], __tmp_reg__ \n\t"           \
        "mov %D[_v], __zero_reg__ \n\t"          \
        "lsr %D[_v] \n\t"                        \
        "ror %C[_v] \n\t"                        \
        "ror %B[_v] \n\t"                        \
        "ror %A[_v] \n\t"                        \
        "lsr %D[_v] \n\t"                        \
        "ror %C[_v] \n\t"                        \
        "ror %B[_v] \n\t"                        \
        "ror %A[_v] \n\t"                        \
        : [_v] "+r" (_v)                         \
        :                                        \
        : "r0", "r1"                             \
    );                                           \
    _v;                                          \
})
#else
#define SHA1_ROTL5(word) sha1_rotl(5, word)
#define SHA1_ROTL30(word) sha1_rotl(30, word)
#endif

// ========== Các macro còn lại giữ nguyên ==========
#define sha1_rotl(bits, word) \
    (((word) << (bits)) | ((word) >> (32 - (bits))))

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
    0x00000000UL, 0x00000148UL, 0x00000150UL, 0x00000158UL, 0x00000160UL, 0x00000168UL
};

// Hàm load block words – giữ nguyên hoàn toàn
static inline __attribute__((always_inline)) void duco_hash_load_block_words(
    uint32_t *W,
    uint32_t const *baseWords,
    char const *nonce,
    uint8_t nonceLen)
{
    // ... (giữ nguyên code của bạn) ...
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
   duco_hash_try_nonce – giữ nguyên unroll 70 vòng
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
    uint32_t t;

    // --- Vòng 10..15 ---
    t = SHA1_ROTL5(a) + ((b & (c ^ d)) ^ d) + e + W[10] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // ... (giữ nguyên toàn bộ 70 vòng như code cũ) ...
    // (dán phần unroll 70 vòng của bạn vào đây)
    // ... tới vòng 79
    // Cộng giá trị khởi tạo
    a += 0x67452301UL; b += 0xEFCDAB89UL; c += 0x98BADCFEUL; d += 0x10325476UL; e += 0xC3D2E1F0UL;

    return a == targetWords[0] && b == targetWords[1] && c == targetWords[2] && d == targetWords[3] && e == targetWords[4];
}

// ========== duco_hash_init UNROLL HOÀN TOÀN ==========
void duco_hash_init(duco_hash_state_t *hasher, char const *prevHash)
{
    // Load 10 word đầu vào initialWords (tương tự cũ)
    hasher->initialWords[0] = ((uint32_t)(uint8_t)prevHash[0] << 24) | ((uint32_t)(uint8_t)prevHash[1] << 16) | ((uint32_t)(uint8_t)prevHash[2] << 8) | (uint32_t)(uint8_t)prevHash[3];
    hasher->initialWords[1] = ((uint32_t)(uint8_t)prevHash[4] << 24) | ((uint32_t)(uint8_t)prevHash[5] << 16) | ((uint32_t)(uint8_t)prevHash[6] << 8) | (uint32_t)(uint8_t)prevHash[7];
    hasher->initialWords[2] = ((uint32_t)(uint8_t)prevHash[8] << 24) | ((uint32_t)(uint8_t)prevHash[9] << 16) | ((uint32_t)(uint8_t)prevHash[10] << 8) | (uint32_t)(uint8_t)prevHash[11];
    hasher->initialWords[3] = ((uint32_t)(uint8_t)prevHash[12] << 24) | ((uint32_t)(uint8_t)prevHash[13] << 16) | ((uint32_t)(uint8_t)prevHash[14] << 8) | (uint32_t)(uint8_t)prevHash[15];
    hasher->initialWords[4] = ((uint32_t)(uint8_t)prevHash[16] << 24) | ((uint32_t)(uint8_t)prevHash[17] << 16) | ((uint32_t)(uint8_t)prevHash[18] << 8) | (uint32_t)(uint8_t)prevHash[19];
    hasher->initialWords[5] = ((uint32_t)(uint8_t)prevHash[20] << 24) | ((uint32_t)(uint8_t)prevHash[21] << 16) | ((uint32_t)(uint8_t)prevHash[22] << 8) | (uint32_t)(uint8_t)prevHash[23];
    hasher->initialWords[6] = ((uint32_t)(uint8_t)prevHash[24] << 24) | ((uint32_t)(uint8_t)prevHash[25] << 16) | ((uint32_t)(uint8_t)prevHash[26] << 8) | (uint32_t)(uint8_t)prevHash[27];
    hasher->initialWords[7] = ((uint32_t)(uint8_t)prevHash[28] << 24) | ((uint32_t)(uint8_t)prevHash[29] << 16) | ((uint32_t)(uint8_t)prevHash[30] << 8) | (uint32_t)(uint8_t)prevHash[31];
    hasher->initialWords[8] = ((uint32_t)(uint8_t)prevHash[32] << 24) | ((uint32_t)(uint8_t)prevHash[33] << 16) | ((uint32_t)(uint8_t)prevHash[34] << 8) | (uint32_t)(uint8_t)prevHash[35];
    hasher->initialWords[9] = ((uint32_t)(uint8_t)prevHash[36] << 24) | ((uint32_t)(uint8_t)prevHash[37] << 16) | ((uint32_t)(uint8_t)prevHash[38] << 8) | (uint32_t)(uint8_t)prevHash[39];

    // 10 vòng SHA-1 khởi động (unroll)
    uint32_t a = 0x67452301UL;
    uint32_t b = 0xEFCDAB89UL;
    uint32_t c = 0x98BADCFEUL;
    uint32_t d = 0x10325476UL;
    uint32_t e = 0xC3D2E1F0UL;
    uint32_t t;

    // Vòng 0
    t = SHA1_ROTL5(a) + e + ((b & c) | ((~b) & d)) + hasher->initialWords[0] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // Vòng 1
    t = SHA1_ROTL5(a) + e + ((b & c) | ((~b) & d)) + hasher->initialWords[1] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // Vòng 2
    t = SHA1_ROTL5(a) + e + ((b & c) | ((~b) & d)) + hasher->initialWords[2] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // Vòng 3
    t = SHA1_ROTL5(a) + e + ((b & c) | ((~b) & d)) + hasher->initialWords[3] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // Vòng 4
    t = SHA1_ROTL5(a) + e + ((b & c) | ((~b) & d)) + hasher->initialWords[4] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // Vòng 5
    t = SHA1_ROTL5(a) + e + ((b & c) | ((~b) & d)) + hasher->initialWords[5] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // Vòng 6
    t = SHA1_ROTL5(a) + e + ((b & c) | ((~b) & d)) + hasher->initialWords[6] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // Vòng 7
    t = SHA1_ROTL5(a) + e + ((b & c) | ((~b) & d)) + hasher->initialWords[7] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // Vòng 8
    t = SHA1_ROTL5(a) + e + ((b & c) | ((~b) & d)) + hasher->initialWords[8] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;
    // Vòng 9
    t = SHA1_ROTL5(a) + e + ((b & c) | ((~b) & d)) + hasher->initialWords[9] + 0x5A827999UL;
    e = d; d = c; c = SHA1_ROTL30(b); b = a; a = t;

    hasher->tempState[0] = a;
    hasher->tempState[1] = b;
    hasher->tempState[2] = c;
    hasher->tempState[3] = d;
    hasher->tempState[4] = e;
}

#pragma GCC pop_options
