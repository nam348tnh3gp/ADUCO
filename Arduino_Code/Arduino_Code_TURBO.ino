/*
   ____  __  __  ____  _  _  _____       ___  _____  ____  _  _
  (  _ \(  )(  )(_  _)( \( )(  _  )___  / __)(  _  )(_  _)( \( )
   )(_) ))(__)(  _)(_  )  (  )(_)((___)( (__  )(_)(  _)(_  )  (
  (____/(______)(____)(_)\_)(_____)     \___)(_____)(____)(_)\_)
  Unofficial code for Arduino boards (and relatives)   version 4.3
  Duino-Coin Team & Community 2019-2024 © MIT Licensed
  https://duinocoin.com
  https://github.com/revoxhere/duino-coin
*/

#pragma GCC optimize ("-Ofast")

#ifndef LED_BUILTIN
#define LED_BUILTIN 13
#endif

#define SEP_TOKEN ","
#define END_TOKEN "\n"

// Kiểu biến dùng cho độ khó (luôn 32-bit)
typedef uint32_t uintDiff;

#include "uniqueID.h"
#include <string.h>
#include "duco_hash.h"

// Mảng tĩnh lưu DUCOID (không dùng String)
static char ducoid_chars[17]; // "DUCOID" + 8 byte hex (16 ký tự) + null

// Khởi tạo DUCOID một lần, dùng bảng tra hex để tránh sprintf
static void generate_ducoid() {
  memcpy(ducoid_chars, "DUCOID", 6);
  char* ptr = ducoid_chars + 6;
  for (uint8_t i = 0; i < 8; i++) {
    uint8_t val = (uint8_t)UniqueID8[i];
    *ptr++ = "0123456789ABCDEF"[val >> 4];
    *ptr++ = "0123456789ABCDEF"[val & 0x0F];
  }
  *ptr = '\0';
}

void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  generate_ducoid();          // chỉ tạo một lần, không dùng String động

  Serial.begin(115200);
  Serial.setTimeout(10000);
  while (!Serial);            // chờ với Leonardo/Mega32U4
}

// Macro chuyển ký tự hex thường sang nibble (nội tuyến, nhanh hơn gọi hàm)
#define HEX_NIBBLE(c) (((c) - '0' < 10) ? ((c) - '0') : ((c) - 'a' + 10))

// Chuyển chuỗi hex 40 ký tự thành mảng 5 số uint32_t (little-endian)
static void hex_to_words(const char* hex, uint32_t* words) {
  for (uint8_t w = 0; w < SHA1_HASH_LEN / 4; w++) {
    const char* src = hex + w * 8;
    uint32_t b0 = (HEX_NIBBLE(src[0]) << 4) | HEX_NIBBLE(src[1]);
    uint32_t b1 = (HEX_NIBBLE(src[2]) << 4) | HEX_NIBBLE(src[3]);
    uint32_t b2 = (HEX_NIBBLE(src[4]) << 4) | HEX_NIBBLE(src[5]);
    uint32_t b3 = (HEX_NIBBLE(src[6]) << 4) | HEX_NIBBLE(src[7]);

    words[w] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
  }
}

// Tăng chuỗi nonce ASCII lên 1 (dùng chung cho mọi kiến trúc)
static void increment_nonce_ascii(char* nonceStr, uint8_t* nonceLen) {
  int8_t i = *nonceLen - 1;
  for (; i >= 0; --i) {
    if (nonceStr[i] != '9') {
      nonceStr[i]++;
      return;
    }
    nonceStr[i] = '0';
  }
  // Tràn số: thêm '1' vào đầu chuỗi
  for (uint8_t j = *nonceLen; j > 0; --j)
    nonceStr[j] = nonceStr[j - 1];
  nonceStr[0] = '1';
  (*nonceLen)++;
  nonceStr[*nonceLen] = '\0';
}

// Hàm đào DUCO-S1A chính
uintDiff ducos1a(const char* prevBlockHash, const char* targetBlockHash, uintDiff difficulty) {
  // Giới hạn độ khó cho AVR 8-bit (difficulty <= 655)
#if defined(ARDUINO_ARCH_AVR) || defined(ARDUINO_ARCH_MEGAAVR)
  if (difficulty > 655) return 0;
#endif

  uint32_t targetWords[SHA1_HASH_LEN / 4];
  hex_to_words(targetBlockHash, targetWords);

  uintDiff maxNonce = difficulty * 100 + 1;
  return ducos1a_mine(prevBlockHash, targetWords, maxNonce);
}

// Hàm đào lõi – tăng nonce bằng chuỗi ASCII (không dùng sprintf)
uintDiff ducos1a_mine(const char* prevBlockHash, const uint32_t* targetWords, uintDiff maxNonce) {
  static duco_hash_state_t hash;
  duco_hash_init(&hash, prevBlockHash);

  char nonceStr[10 + 1] = "0";   // tối đa 10 chữ số
  uint8_t nonceLen = 1;

  for (uintDiff nonce = 0; nonce < maxNonce; nonce++) {
    if (duco_hash_try_nonce(&hash, nonceStr, nonceLen, targetWords)) {
      return nonce;
    }
    increment_nonce_ascii(nonceStr, &nonceLen);
  }
  return 0;
}

void loop() {
  if (Serial.available() <= 0)
    return;

  char lastBlockHash[40 + 1];
  char newBlockHash[40 + 1];

  // Đọc hash khối cũ (đúng 40 ký tự)
  if (Serial.readBytesUntil(',', lastBlockHash, 41) != 40)
    return;
  lastBlockHash[40] = '\0';

  // Đọc hash đích
  if (Serial.readBytesUntil(',', newBlockHash, 41) != 40)
    return;
  newBlockHash[40] = '\0';

  // Đọc difficulty mà không tạo String tạm
  char diffBuffer[16];
  int diffLen = Serial.readBytesUntil(',', diffBuffer, sizeof(diffBuffer));
  if (diffLen == 0) return;
  diffBuffer[diffLen] = '\0';
  uintDiff difficulty = strtoul(diffBuffer, NULL, 10);

  // Dọn dữ liệu thừa sau mỗi job
  while (Serial.available()) Serial.read();

  // Tắt LED (dùng PORTB cho AVR để nhanh hơn digitalWrite)
#if defined(ARDUINO_ARCH_AVR)
  PORTB |= B00100000;   // LED_BUILTIN thường là PB5 (chân 13)
#else
  digitalWrite(LED_BUILTIN, LOW);
#endif

  uint32_t startTime = micros();
  uintDiff ducos1result = ducos1a(lastBlockHash, newBlockHash, difficulty);
  uint32_t elapsedTime = micros() - startTime;

  // Bật LED
#if defined(ARDUINO_ARCH_AVR)
  PORTB &= B11011111;
#else
  digitalWrite(LED_BUILTIN, HIGH);
#endif

  // Dọn buffer trước khi gửi kết quả
  while (Serial.available()) Serial.read();

  // Gửi kết quả (không dùng String nối – tránh phân mảnh bộ nhớ)
  Serial.print(ducos1result);
  Serial.print(SEP_TOKEN);
  Serial.print(elapsedTime);
  Serial.print(SEP_TOKEN);
  Serial.println(ducoid_chars);
}
