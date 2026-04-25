/*
   ____  __  __  ____  _  _  _____       ___  _____  ____  _  _ 
  (  _ \(  )(  )(_  _)( \( )(  _  )___  / __)(  _  )(_  _)( \( )
   )(_) ))(__)(  _)(_  )  (  )(_)((___)( (__  )(_)(  _)(_  )  ( 
  (____/(______)(____)(_)\_)(_____)     \___)(_____)(____)(_)\_)
  Duino-Coin AVR Miner - Optimized & Stable
  Based on Official v4.3 + memory-safe improvements
  Duino-Coin Team & Community 2019-2026 © MIT Licensed
*/

#pragma GCC optimize ("-Ofast")

#include <Arduino.h>
#include <string.h>
#include <stdlib.h>
#if defined(__AVR__)
  #include <avr/pgmspace.h>
#endif

#ifndef LED_BUILTIN
  #define LED_BUILTIN 13
#endif
#define SEP_TOKEN ","
#define END_TOKEN "\n"

#if defined(ARDUINO_ARCH_AVR) || defined(ARDUINO_ARCH_MEGAAVR)
  typedef uint32_t uintDiff;
#else
  typedef uint32_t uintDiff;
#endif

#include "uniqueID.h"

// ======================== SHA1 LIBRARY (from official duco_hash) ========================
#define SHA1_BLOCK_LEN 64
#define SHA1_HASH_LEN 20

struct duco_hash_state_t {
	uint8_t buffer[SHA1_BLOCK_LEN];
	uint8_t result[SHA1_HASH_LEN];
	uint32_t tempState[5];
	uint8_t block_offset;
	uint8_t total_bytes;
};

static void duco_hash_block(duco_hash_state_t * hasher) {
	static uint32_t w[16];
	uint8_t *b = hasher->buffer;
	for (uint8_t i = 0, i4 = 0; i < 16; i++, i4 += 4) {
		w[i] = (uint32_t(b[i4]) << 24) | (uint32_t(b[i4 + 1]) << 16) |
		       (uint32_t(b[i4 + 2]) << 8) | uint32_t(b[i4 + 3]);
	}
	uint32_t a = hasher->tempState[0], b_val = hasher->tempState[1],
	         c = hasher->tempState[2], d = hasher->tempState[3],
	         e = hasher->tempState[4];
	#define SHA1_ROTL(bits, word) (((word) << (bits)) | ((word) >> (32 - (bits))))
	for (uint8_t i = 10; i < 80; i++) {
		if (i >= 16)
			w[i & 15] = SHA1_ROTL(1, w[(i-3) & 15] ^ w[(i-8) & 15] ^ w[(i-14) & 15] ^ w[(i-16) & 15]);
		uint32_t temp = SHA1_ROTL(5, a) + e + w[i & 15];
		if (i < 20) { temp += (b_val & c) | ((~b_val) & d); temp += 0x5a827999; }
		else if(i < 40) { temp += b_val ^ c ^ d; temp += 0x6ed9eba1; }
		else if(i < 60) { temp += (b_val & c) | (b_val & d) | (c & d); temp += 0x8f1bbcdc; }
		else { temp += b_val ^ c ^ d; temp += 0xca62c1d6; }
		e = d; d = c; c = SHA1_ROTL(30, b_val); b_val = a; a = temp;
	}
	a += 0x67452301; b_val += 0xefcdab89; c += 0x98badcfe; d += 0x10325476; e += 0xc3d2e1f0;
	hasher->result[0] = a >> 24; hasher->result[1] = a >> 16; hasher->result[2] = a >> 8; hasher->result[3] = a;
	hasher->result[4] = b_val >> 24; hasher->result[5] = b_val >> 16; hasher->result[6] = b_val >> 8; hasher->result[7] = b_val;
	hasher->result[8] = c >> 24; hasher->result[9] = c >> 16; hasher->result[10] = c >> 8; hasher->result[11] = c;
	hasher->result[12] = d >> 24; hasher->result[13] = d >> 16; hasher->result[14] = d >> 8; hasher->result[15] = d;
	hasher->result[16] = e >> 24; hasher->result[17] = e >> 16; hasher->result[18] = e >> 8; hasher->result[19] = e;
}

static void duco_hash_init(duco_hash_state_t * hasher, const char* prevHash) {
	memcpy(hasher->buffer, prevHash, 40);
	uint32_t a = 0x67452301, b_val = 0xefcdab89, c = 0x98badcfe, d = 0x10325476, e = 0xc3d2e1f0;
	static uint32_t w[10];
	for (uint8_t i = 0, i4 = 0; i < 10; i++, i4 += 4) {
		w[i] = (uint32_t(hasher->buffer[i4]) << 24) | (uint32_t(hasher->buffer[i4 + 1]) << 16) |
		       (uint32_t(hasher->buffer[i4 + 2]) << 8) | uint32_t(hasher->buffer[i4 + 3]);
	}
	#define SHA1_ROTL(bits, word) (((word) << (bits)) | ((word) >> (32 - (bits))))
	for (uint8_t i = 0; i < 10; i++) {
		uint32_t temp = SHA1_ROTL(5, a) + e + w[i];
		temp += (b_val & c) | ((~b_val) & d); temp += 0x5a827999;
		e = d; d = c; c = SHA1_ROTL(30, b_val); b_val = a; a = temp;
	}
	hasher->tempState[0] = a; hasher->tempState[1] = b_val; hasher->tempState[2] = c; hasher->tempState[3] = d; hasher->tempState[4] = e;
}

static void duco_hash_set_nonce(duco_hash_state_t * hasher, const char* nonce) {
	uint8_t * b = hasher->buffer;
	uint8_t off = SHA1_HASH_LEN * 2;
	for (uint8_t i = 0; i < 10 && nonce[i] != 0; i++) b[off++] = nonce[i];
	uint8_t total_bytes = off;
	b[off++] = 0x80;
	while (off < 62) b[off++] = 0;
	b[62] = total_bytes >> 5;
	b[63] = total_bytes << 3;
}

// SỬA LỖI: đổi uint8_t const * -> const uint8_t*
static const uint8_t* duco_hash_try_nonce(duco_hash_state_t * hasher, const char* nonce) {
	duco_hash_set_nonce(hasher, nonce);
	duco_hash_block(hasher);
	return hasher->result;
}
// ======================== END OF SHA1 LIBRARY ========================

// Static buffer for DUCOID (không dùng String để tránh phân mảnh heap)
char DUCOID[23];
void make_DUCOID() {
  char* p = DUCOID;
  memcpy(p, "DUCOID", 6);
  p += 6;
  for (size_t i = 0; i < 8; i++) {
    uint8_t b = UniqueID8[i];
    uint8_t hi = b >> 4, lo = b & 0x0F;
    *p++ = (hi < 10) ? ('0' + hi) : ('A' + hi - 10);
    *p++ = (lo < 10) ? ('0' + lo) : ('A' + lo - 10);
  }
  *p = '\0';
}

void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  make_DUCOID();
  Serial.begin(115200);
  Serial.setTimeout(10000);
  while (!Serial);
  Serial.flush();
}

void lowercase_hex_to_bytes(const char* hexDigest, uint8_t* rawDigest) {
  for (uint8_t i = 0, j = 0; j < SHA1_HASH_LEN; i += 2, j += 1) {
    uint8_t x = hexDigest[i];
    uint8_t b = x >> 6;
    uint8_t r = ((x & 0xf) | (b << 3)) + b;
    x = hexDigest[i + 1];
    b = x >> 6;
    rawDigest[j] = (r << 4) | (((x & 0xf) | (b << 3)) + b);
  }
}

uintDiff ducos1a(const char* prevBlockHash, const char* targetBlockHash, uintDiff difficulty) {
  #if defined(ARDUINO_ARCH_AVR) || defined(ARDUINO_ARCH_MEGAAVR)
    if (difficulty > 655) return 0;
  #endif
  uint8_t target[SHA1_HASH_LEN];
  lowercase_hex_to_bytes(targetBlockHash, target);
  uintDiff const maxNonce = difficulty * 100 + 1;
  static duco_hash_state_t hash;
  duco_hash_init(&hash, prevBlockHash);
  char nonceStr[10 + 1];
  for (uintDiff nonce = 0; nonce < maxNonce; nonce++) {
    ultoa(nonce, nonceStr, 10);
    const uint8_t* hash_bytes = duco_hash_try_nonce(&hash, nonceStr);
    if (memcmp(hash_bytes, target, SHA1_HASH_LEN) == 0) {
      return nonce;
    }
  }
  return 0;
}

void loop() {
  if (Serial.available() <= 0) return;

  char lastBlockHash[40 + 1], newBlockHash[40 + 1];

  if (Serial.readBytesUntil(',', lastBlockHash, 41) != 40) return;
  lastBlockHash[40] = 0;

  if (Serial.readBytesUntil(',', newBlockHash, 41) != 40) return;
  newBlockHash[40] = 0;

  // Đọc difficulty không dùng String
  uintDiff difficulty = 0;
  while (true) {
    int c = Serial.read();
    if (c == ',' || c == -1) break;
    if (c >= '0' && c <= '9') difficulty = difficulty * 10 + (c - '0');
  }
  while (Serial.available()) Serial.read();

  #if defined(ARDUINO_ARCH_AVR)
    PORTB = PORTB | B00100000; // LED off
  #else
    digitalWrite(LED_BUILTIN, LOW);
  #endif

  uint32_t startTime = micros();
  uintDiff result = ducos1a(lastBlockHash, newBlockHash, difficulty);
  uint32_t elapsedTime = micros() - startTime;

  #if defined(ARDUINO_ARCH_AVR)
    PORTB = PORTB & B11011111; // LED on
  #else
    digitalWrite(LED_BUILTIN, HIGH);
  #endif

  while (Serial.available()) Serial.read();

  // Gửi kết quả về Python (định dạng BIN)
  Serial.print(String(result, 2) + SEP_TOKEN + String(elapsedTime, 2) + SEP_TOKEN + DUCOID + END_TOKEN);
}
