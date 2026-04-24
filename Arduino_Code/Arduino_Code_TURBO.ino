/*
   ____  __  __  ____  _  _  _____       ___  _____  ____  _  _
  (  _ \(  )(  )(_  _)( \( )(  _  )___  / __)(  _  )(_  _)( \( )
   )(_) ))(__)(  _)(_  )  (  )(_)((___)( (__  )(_)(  _)(_  )  (
  (____/(______)(____)(_)\_)(_____)     \___)(_____)(____)(_)\_)
  Unofficial code for Arduino boards (and relatives)   version 5.0 EXTREME

  Duino-Coin Team & Community 2019-2024 © MIT Licensed
  https://duinocoin.com
  https://github.com/revoxhere/duino-coin

  HASHRATE UPGRADE – fully inlined SHA1 + zero-string nonce handling
  Fixed: No String usage, proper includes, AVR-safe PROGMEM access.
  Fixed: removed const from W. sha1_rotl now macro for AVR too.
*/

#pragma GCC optimize ("-Ofast")

#include <Arduino.h>
#include <string.h>
#include <stdlib.h>
#if defined(__AVR__)
  #include <avr/pgmspace.h>
#endif

/* ---------- LED & serial config ---------- */
#ifndef LED_BUILTIN
#define LED_BUILTIN 13
#endif
#define SEP_TOKEN ","
#define END_TOKEN "\n"

/* ---------- Difficulty typedef ---------- */
#if defined(ARDUINO_ARCH_AVR) || defined(ARDUINO_ARCH_MEGAAVR)
typedef uint32_t uintDiff;
#else
typedef uint32_t uintDiff;
#endif

/* ---------- UniqueID ---------- */
#include "uniqueID.h"

char DUCOID[23];
void make_DUCOID() {
  char* p = DUCOID;
  memcpy(p, "DUCOID", 6);
  p += 6;
  for (size_t i = 0; i < 8; i++) {
    uint8_t b = UniqueID8[i];
    uint8_t hi = b >> 4;
    uint8_t lo = b & 0x0F;
    *p++ = (hi < 10) ? ('0' + hi) : ('A' + hi - 10);
    *p++ = (lo < 10) ? ('0' + lo) : ('A' + lo - 10);
  }
  *p = '\0';
}

/* ---------- SHA1 helpers ---------- */
#define SHA1_HASH_LEN 20

/* Rotate macros: assembly for 5/30 on AVR, plain C for expand (1 bit) */
#if defined(__AVR__)
extern "C" uint32_t sha1_rotl5(uint32_t value);
extern "C" uint32_t sha1_rotl30(uint32_t value);
#define SHA1_ROTL5(word) sha1_rotl5(word)
#define SHA1_ROTL30(word) sha1_rotl30(word)
// Generic rotate macro for SHA1_EXPAND (1-bit rotate)
#define sha1_rotl(bits, word) (((word) << (bits)) | ((word) >> (32 - (bits))))
#else
#define sha1_rotl(bits, word) (((word) << (bits)) | ((word) >> (32 - (bits))))
#define SHA1_ROTL5(word) sha1_rotl(5, word)
#define SHA1_ROTL30(word) sha1_rotl(30, word)
#endif

/* SHA1_EXPAND & SHA1_ROUND macros */
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

/* Length padding words (PROGMEM on AVR to save RAM) */
static const uint32_t kLengthWordByNonceLen[6] PROGMEM = {
    0x00000000UL,
    0x00000148UL,
    0x00000150UL,
    0x00000158UL,
    0x00000160UL,
    0x00000168UL
};

/* Fast hex conversion */
static inline uint8_t lowercase_hex_nibble(uint8_t x) {
  uint8_t b = x >> 6;
  return ((x & 0xf) | (b << 3)) + b;
}
void lowercase_hex_to_words(char const * hexDigest, uint32_t * digestWords) {
  for (uint8_t i = 0, word = 0; word < (SHA1_HASH_LEN / 4); word++, i += 8) {
    uint8_t b0 = (lowercase_hex_nibble(hexDigest[i]) << 4)
               | lowercase_hex_nibble(hexDigest[i + 1]);
    uint8_t b1 = (lowercase_hex_nibble(hexDigest[i + 2]) << 4)
               | lowercase_hex_nibble(hexDigest[i + 3]);
    uint8_t b2 = (lowercase_hex_nibble(hexDigest[i + 4]) << 4)
               | lowercase_hex_nibble(hexDigest[i + 5]);
    uint8_t b3 = (lowercase_hex_nibble(hexDigest[i + 6]) << 4)
               | lowercase_hex_nibble(hexDigest[i + 7]);
    digestWords[word] = ((uint32_t)b0 << 24)
                      | ((uint32_t)b1 << 16)
                      | ((uint32_t)b2 << 8)
                      | (uint32_t)b3;
  }
}

/* AVR nonce ASCII increment */
#if defined(__AVR__)
static inline void increment_nonce_ascii(char *nonceStr, uint8_t *nonceLen) {
  for (int8_t i = *nonceLen - 1; i >= 0; --i) {
    if (nonceStr[i] != '9') {
      nonceStr[i]++;
      return;
    }
    nonceStr[i] = '0';
  }
  for (uint8_t i = *nonceLen; i > 0; --i) {
    nonceStr[i] = nonceStr[i - 1];
  }
  nonceStr[0] = '1';
  (*nonceLen)++;
  nonceStr[*nonceLen] = 0;
}
#endif

/* SHA1 state structure */
struct duco_hash_state_t {
    uint32_t initialWords[10];
    uint32_t tempState[5];
};

/* Initialize SHA1 state */
void duco_hash_init(duco_hash_state_t *hasher, char const *prevHash) {
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

/* Fully inlined hash check – W must be writable */
static inline __attribute__((always_inline)) bool hash_check(
    uint32_t *W,
    const duco_hash_state_t *hasher,
    const uint32_t *targetWords)
{
    uint32_t a = hasher->tempState[0];
    uint32_t b = hasher->tempState[1];
    uint32_t c = hasher->tempState[2];
    uint32_t d = hasher->tempState[3];
    uint32_t e = hasher->tempState[4];

    #pragma GCC unroll 4
    for (uint8_t i = 10; i < 16; i++) {
        SHA1_ROUND((b & (c ^ d)) ^ d, 0x5A827999UL);
    }
    #pragma GCC unroll 4
    for (uint8_t i = 16; i < 20; i++) {
        SHA1_EXPAND(i);
        SHA1_ROUND((b & (c ^ d)) ^ d, 0x5A827999UL);
    }
    #pragma GCC unroll 4
    for (uint8_t i = 20; i < 40; i++) {
        SHA1_EXPAND(i);
        SHA1_ROUND(b ^ c ^ d, 0x6ED9EBA1UL);
    }
    #pragma GCC unroll 4
    for (uint8_t i = 40; i < 60; i++) {
        SHA1_EXPAND(i);
        SHA1_ROUND((b & c) | (b & d) | (c & d), 0x8F1BBCDCUL);
    }
    #pragma GCC unroll 4
    for (uint8_t i = 60; i < 80; i++) {
        SHA1_EXPAND(i);
        SHA1_ROUND(b ^ c ^ d, 0xCA62C1D6UL);
    }

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

/* DUCO-S1A EXTREME hasher */
uintDiff ducos1a(char const * prevBlockHash,
                char const * targetBlockHash,
                uintDiff difficulty) {
#if defined(ARDUINO_ARCH_AVR) || defined(ARDUINO_ARCH_MEGAAVR)
    if (difficulty > 655) return 0;
#endif

    uint32_t targetWords[SHA1_HASH_LEN / 4];
    lowercase_hex_to_words(targetBlockHash, targetWords);

    duco_hash_state_t hasher;
    duco_hash_init(&hasher, prevBlockHash);

    uintDiff const maxNonce = difficulty * 100 + 1;

#if defined(__AVR__)
    char nonceStr[6] = "0";
    uint8_t nonceLen = 1;
    uint16_t maxNonceAvr = (uint16_t)maxNonce;
    uint32_t W[16];
    memcpy(W, hasher.initialWords, 40);

    for (uint16_t nonce = 0; nonce < maxNonceAvr; nonce++) {
        {
            uint8_t d0 = nonceStr[0];
            uint8_t d1 = nonceStr[1];
            uint8_t d2 = nonceStr[2];
            uint8_t d3 = nonceStr[3];
            uint8_t d4 = nonceStr[4];
            switch (nonceLen) {
                case 1:
                    W[10] = (d0 << 24) | 0x00800000UL;
                    W[11] = 0; W[12] = 0;
                    break;
                case 2:
                    W[10] = (d0 << 24) | (d1 << 16) | 0x00008000UL;
                    W[11] = 0; W[12] = 0;
                    break;
                case 3:
                    W[10] = (d0 << 24) | (d1 << 16) | (d2 << 8) | 0x00000080UL;
                    W[11] = 0; W[12] = 0;
                    break;
                case 4:
                    W[10] = (d0 << 24) | (d1 << 16) | (d2 << 8) | d3;
                    W[11] = 0x80000000UL;
                    W[12] = 0;
                    break;
                default:
                    W[10] = (d0 << 24) | (d1 << 16) | (d2 << 8) | d3;
                    W[11] = (d4 << 24) | 0x00800000UL;
                    W[12] = 0;
                    break;
            }
            W[13] = 0;
            W[14] = 0;
            #if defined(__AVR__)
                W[15] = pgm_read_dword(&kLengthWordByNonceLen[nonceLen]);
            #else
                W[15] = kLengthWordByNonceLen[nonceLen];
            #endif
        }
        if (hash_check(W, &hasher, targetWords)) return nonce;
        increment_nonce_ascii(nonceStr, &nonceLen);
    }
#else
    uint32_t W[16];
    memcpy(W, hasher.initialWords, 40);
    for (uintDiff nonce = 0; nonce < maxNonce; nonce++) {
        uint8_t digits[10], len = 0;
        uint32_t n = nonce;
        do { digits[len++] = (n % 10) + '0'; n /= 10; } while (n);
        W[10] = 0; W[11] = 0; W[12] = 0; W[13] = 0; W[14] = 0;
        uint8_t wordIdx = 10, shift = 24;
        for (int8_t i = len - 1; i >= 0; i--) {
            W[wordIdx] |= (uint32_t)digits[i] << shift;
            shift -= 8;
            if (shift > 24) { wordIdx++; shift = 24; }
        }
        uint8_t padBytePos = len;
        uint8_t wIdx = 10 + (padBytePos >> 2);
        uint8_t sh = 24 - ((padBytePos & 3) << 3);
        W[wIdx] |= 0x80UL << sh;
        W[15] = ((uint32_t)(40 + len)) << 3;
        if (hash_check(W, &hasher, targetWords)) return nonce;
    }
#endif
    return 0;
}

/* ========== Setup & Loop ========== */
void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  make_DUCOID();
  Serial.begin(115200);
  Serial.setTimeout(10000);
  while (!Serial);
  Serial.flush();
}

void loop() {
  if (Serial.available() <= 0) return;
  char lastBlockHash[41], newBlockHash[41];
  if (Serial.readBytesUntil(',', lastBlockHash, 41) != 40) return;
  lastBlockHash[40] = 0;
  if (Serial.readBytesUntil(',', newBlockHash, 41) != 40) return;
  newBlockHash[40] = 0;

  uintDiff difficulty = 0;
  while (true) {
    int c = Serial.read();
    if (c == ',' || c == -1) break;
    if (c >= '0' && c <= '9') difficulty = difficulty * 10 + (c - '0');
  }
  while (Serial.available()) Serial.read();

#if defined(ARDUINO_ARCH_AVR)
  PORTB |= B00100000;   // LED off
#else
  digitalWrite(LED_BUILTIN, LOW);
#endif

  uint32_t startTime = micros();
  uintDiff result = ducos1a(lastBlockHash, newBlockHash, difficulty);
  uint32_t elapsedTime = micros() - startTime;

#if defined(ARDUINO_ARCH_AVR)
  PORTB &= B11011111;   // LED on
#else
  digitalWrite(LED_BUILTIN, HIGH);
#endif

  while (Serial.available()) Serial.read();

  Serial.print(result);
  Serial.print(SEP_TOKEN);
  Serial.print(elapsedTime);
  Serial.print(SEP_TOKEN);
  Serial.print(DUCOID);
  Serial.print(END_TOKEN);
}
