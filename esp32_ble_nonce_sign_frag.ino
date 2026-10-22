#include <NimBLEDevice.h>
#include <Preferences.h>
#include <sodium.h>
#include <string.h>

/*
  BLE 分片廣播，協議版本 2。

  簽進去的內容（大端序）：
    [1B flags] [4B counter] [1B challenge_len] [challenge] [32B nonce]
  其後接 64B Ed25519 簽章。以上整段再切成 26 字節的數據幀廣播。

  flags bit0 = 1：驗證方應拒絕不大於上次的計數器（防雙花）
  flags bit0 = 0：測試模式，驗證方可以不檢查計數器

  驗證方要事先登記公鑰和固定挑戰碼。本程式只負責發送。
  多台裝置共用同一把私鑰時，靠不同的挑戰碼區分；
  驗證方要按「挑戰碼」分開記住計數器。

  幀格式：[Length][AD_Type][Seq(2B)][Data][CRC8]
  0xDD 宣告幀，0xDE 中間幀，0xDF 結束幀。
  同一輪的序號是連續的 uint16，下一輪從上一輪結尾之後繼續，避免兩輪序號重疊。
*/

// ====== 可改設定（燒錄前改這裡）======
// 程式裡有寫就用程式裡的，不寫進晶片。留空 "" 才用晶片裡的；晶片裡也沒有，才在第一次開機產生並存入。
// 晶片裡那組要換掉時，把 CLEAR_FLASH_SECRETS 改 true 上傳一次，完成後改回 false 再上傳。

// 64 個十六進位字（32 字節）。留空 "" 表示用晶片裡的私鑰。下面是示例，正式環境請換掉或留空。
static const char FIXED_SEED_HEX[] = "1032547698BADCFE0123456789ABCDEF55AA11EE22DD33CC44BB6699778800FF";

// true 才在開機時從序列埠印出私鑰。預設關閉。
static const bool PRINT_PRIVATE_KEY = false;

// 有文字就用這組挑戰碼，不寫進晶片。留空 "" 表示用晶片裡的挑戰碼。最長 32 字節。
static const char MANUAL_CHALLENGE[] = "test";

// true：開機時清掉晶片裡的私鑰、挑戰碼和計數器，然後停住。看到清除完成後改回 false 再上傳。
static const bool CLEAR_FLASH_SECRETS = false;

// true：每次簽名計數器加一，並把「要檢查」寫進簽章。
// false：測試用。計數器固定為 0，不寫入 NVS，簽章標記為不檢查。
// 可與固定私鑰、固定挑戰碼同時使用。
static const bool CHECK_COUNTER = true;

// ====== 協議常數 ======
static const uint8_t AD_TYPE_START  = 0xDD;
static const uint8_t AD_TYPE_MIDDLE = 0xDE;
static const uint8_t AD_TYPE_END    = 0xDF;
static const uint8_t PROTO_VERSION  = 2;
static const uint8_t FLAG_CHECK_COUNTER = 0x01;

static const size_t NONCE_SIZE = 32;
static const size_t SIG_SIZE   = 64;
static const size_t MAX_CHALLENGE_LEN = 32;
static const size_t RANDOM_CHALLENGE_LEN = 16;
static const uint8_t DATA_FRAME_SIZE = 26;
static const uint8_t ANNOUNCE_DATA_SIZE = 24;

static const uint32_t FRAME_INTERVAL_MS = 120;
static const uint32_t STATUS_INTERVAL_MS = 10000;
// 每次開機（以及用完一段之後）預留這多個號碼再寫入快閃記憶體，避免每一張票都寫一次。
static const uint32_t COUNTER_RESERVE = 8192;

static const char* NVS_NAMESPACE = "ed25519";
static const char* NVS_KEY_SK    = "sk";
static const char* NVS_KEY_PK    = "pk";
static const char* NVS_KEY_CTR   = "ctr";
static const char* NVS_KEY_CHAL  = "chal";

Preferences prefs;

static bool keyFromCode = false;
static bool challengeFromCode = false;
static bool challengeReady = false;

static unsigned long lastFrameMillis = 0;
static unsigned long lastStatusMillis = 0;
static uint8_t currentFrameIndex = 0;
static uint16_t globalSeq = 0;
static uint16_t packetBase = 0;
static uint8_t totalFrames = 1;
static uint8_t dataChunks = 0;

static uint8_t nonceBuf[NONCE_SIZE];
static uint8_t sigBuf[SIG_SIZE];
static uint8_t challenge[MAX_CHALLENGE_LEN];
static uint8_t challengeLen = 0;
static uint8_t flagsByte = 0;

static uint8_t body[1 + 4 + 1 + MAX_CHALLENGE_LEN + NONCE_SIZE + SIG_SIZE];
static uint16_t bodyLen = 0;
static bool payloadReady = false;

static uint8_t sk[crypto_sign_SECRETKEYBYTES];
static uint8_t pk[crypto_sign_PUBLICKEYBYTES];
static bool keyLoaded = false;

static uint32_t counterNext = 1;
static uint32_t counterLimit = 1;
static uint32_t lastCounter = 0;
static bool counterReady = false;

uint8_t crc8(const uint8_t* data, size_t len) {
  uint8_t crc = 0x00;
  for (size_t i = 0; i < len; ++i) {
    crc ^= data[i];
    for (uint8_t b = 0; b < 8; ++b) {
      if (crc & 0x80) crc = (uint8_t)((crc << 1) ^ 0x31);
      else crc = (uint8_t)(crc << 1);
    }
  }
  return crc;
}

void printHex(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (data[i] < 16) Serial.print('0');
    Serial.print(data[i], HEX);
  }
}

bool isPrintableText(const uint8_t* data, size_t len) {
  if (len == 0) return false;
  for (size_t i = 0; i < len; ++i) {
    if (data[i] < 0x20 || data[i] > 0x7E) return false;
  }
  return true;
}

void printStatus() {
  Serial.print("[PUB] ");
  printHex(pk, crypto_sign_PUBLICKEYBYTES);
  Serial.println();

  Serial.print("[CHAL] ");
  if (challengeLen == 0) {
    Serial.print("(empty)");
  } else if (challengeFromCode || isPrintableText(challenge, challengeLen)) {
    Serial.write(challenge, challengeLen);
  } else {
    printHex(challenge, challengeLen);
  }
  Serial.println();

  Serial.print("[CTR] ");
  Serial.print(lastCounter);
  Serial.print(" check=");
  Serial.print(CHECK_COUNTER ? "on" : "off");
  Serial.print(" key=");
  Serial.print(keyFromCode ? "code" : "flash");
  Serial.print(" chal=");
  Serial.println(challengeFromCode ? "code" : "flash");
}

bool reserveCounter(uint32_t start) {
  if (start > (0xFFFFFFFFu - COUNTER_RESERVE)) {
    Serial.println("[ERROR] counter exhausted");
    return false;
  }
  uint32_t limit = start + COUNTER_RESERVE;
  prefs.begin(NVS_NAMESPACE, false);
  size_t wrote = prefs.putUInt(NVS_KEY_CTR, limit);
  prefs.end();
  if (wrote == 0) {
    Serial.println("[ERROR] counter NVS write failed");
    return false;
  }
  counterNext = start;
  counterLimit = limit;
  return true;
}

void initCounter() {
  if (!CHECK_COUNTER) {
    lastCounter = 0;
    counterReady = true;
    return;
  }
  prefs.begin(NVS_NAMESPACE, false);
  uint32_t start = prefs.isKey(NVS_KEY_CTR) ? prefs.getUInt(NVS_KEY_CTR, 1) : 1;
  prefs.end();
  if (start == 0) start = 1;
  counterReady = reserveCounter(start);
  if (!counterReady) Serial.println("[ERROR] counter init failed");
}

bool takeCounter(uint32_t* out) {
  if (!CHECK_COUNTER) {
    lastCounter = 0;
    *out = 0;
    return true;
  }
  if (!counterReady) return false;
  if (counterNext >= counterLimit) {
    if (!reserveCounter(counterLimit)) return false;
  }
  lastCounter = counterNext++;
  *out = lastCounter;
  return true;
}

int hexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool parseSeedHex(const char* hex, uint8_t out[crypto_sign_SEEDBYTES]) {
  if (strlen(hex) != crypto_sign_SEEDBYTES * 2) return false;
  for (size_t i = 0; i < crypto_sign_SEEDBYTES; ++i) {
    int hi = hexValue(hex[i * 2]);
    int lo = hexValue(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

void clearFlashSecrets() {
  prefs.begin(NVS_NAMESPACE, false);
  bool ok = prefs.clear();
  prefs.end();
  if (ok) {
    Serial.println("[CLEAR] Stored key, challenge and counter removed.");
    Serial.println("[CLEAR] Set CLEAR_FLASH_SECRETS back to false, then upload again.");
  } else {
    Serial.println("[ERROR] Failed to clear stored secrets.");
  }
  while (true) delay(1000);
}

void loadChallenge() {
  challengeReady = false;
  challengeFromCode = false;
  if (MANUAL_CHALLENGE[0] != '\0') {
    size_t n = strlen(MANUAL_CHALLENGE);
    if (n > MAX_CHALLENGE_LEN) {
      Serial.println("[WARN] MANUAL_CHALLENGE truncated to 32 bytes");
      n = MAX_CHALLENGE_LEN;
    }
    memcpy(challenge, MANUAL_CHALLENGE, n);
    challengeLen = (uint8_t)n;
    challengeFromCode = true;
    challengeReady = true;
    Serial.println("[CHAL] Using challenge from code");
    return;
  }

  prefs.begin(NVS_NAMESPACE, false);
  size_t have = prefs.getBytesLength(NVS_KEY_CHAL);
  if (have > 0 && have <= MAX_CHALLENGE_LEN) {
    prefs.getBytes(NVS_KEY_CHAL, challenge, have);
    prefs.end();
    challengeLen = (uint8_t)have;
    challengeReady = true;
    Serial.println("[CHAL] Loaded challenge from flash");
    return;
  }
  challengeLen = RANDOM_CHALLENGE_LEN;
  randombytes_buf(challenge, challengeLen);
  size_t wrote = prefs.putBytes(NVS_KEY_CHAL, challenge, challengeLen);
  prefs.end();
  if (wrote != challengeLen) {
    Serial.println("[ERROR] challenge flash write failed");
    challengeLen = 0;
    return;
  }
  challengeReady = true;
  Serial.println("[CHAL] Generated challenge and stored to flash");
}

void ensureKeys() {
  keyFromCode = false;
  if (sodium_init() == -1) {
    Serial.println("[ERROR] sodium_init failed");
    return;
  }

  if (FIXED_SEED_HEX[0] != '\0') {
    uint8_t seed[crypto_sign_SEEDBYTES];
    if (!parseSeedHex(FIXED_SEED_HEX, seed)) {
      Serial.println("[ERROR] FIXED_SEED_HEX must be empty or 64 hex characters");
      return;
    }
    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
      Serial.println("[ERROR] crypto_sign_seed_keypair failed");
      return;
    }
    keyLoaded = true;
    keyFromCode = true;
    Serial.println("[KEY] Using private key from code");
  } else {
    prefs.begin(NVS_NAMESPACE, false);
    size_t haveSk = prefs.getBytesLength(NVS_KEY_SK);
    size_t havePk = prefs.getBytesLength(NVS_KEY_PK);
    if (haveSk == crypto_sign_SECRETKEYBYTES && havePk == crypto_sign_PUBLICKEYBYTES) {
      prefs.getBytes(NVS_KEY_SK, sk, crypto_sign_SECRETKEYBYTES);
      prefs.getBytes(NVS_KEY_PK, pk, crypto_sign_PUBLICKEYBYTES);
      prefs.end();
      keyLoaded = true;
      Serial.println("[KEY] Loaded private key from flash");
    } else {
      if (crypto_sign_keypair(pk, sk) != 0) {
        prefs.end();
        Serial.println("[ERROR] keypair generation failed");
        return;
      }
      size_t wroteSk = prefs.putBytes(NVS_KEY_SK, sk, crypto_sign_SECRETKEYBYTES);
      size_t wrotePk = prefs.putBytes(NVS_KEY_PK, pk, crypto_sign_PUBLICKEYBYTES);
      prefs.end();
      if (wroteSk != crypto_sign_SECRETKEYBYTES || wrotePk != crypto_sign_PUBLICKEYBYTES) {
        Serial.println("[ERROR] key flash write failed");
        return;
      }
      keyLoaded = true;
      Serial.println("[KEY] Generated private key and stored to flash");
    }
  }

  if (PRINT_PRIVATE_KEY) {
    Serial.println("[WARN] private key follows; disable PRINT_PRIVATE_KEY after debugging");
    Serial.print("[PRIV] ");
    printHex(sk, crypto_sign_SECRETKEYBYTES);
    Serial.println();
  }
}

void assignPacketBase() {
  if ((uint32_t)globalSeq + totalFrames > 65535u) globalSeq = 0;
  packetBase = globalSeq;
  globalSeq = (uint16_t)(globalSeq + totalFrames);
}

void preparePayload() {
  payloadReady = false;
  if (!keyLoaded || !challengeReady || challengeLen > MAX_CHALLENGE_LEN) return;
  if (sodium_init() == -1) {
    Serial.println("[ERROR] sodium_init failed during payload prep");
    return;
  }

  flagsByte = CHECK_COUNTER ? FLAG_CHECK_COUNTER : 0;
  uint32_t ctr = 0;
  if (!takeCounter(&ctr)) {
    Serial.println("[ERROR] counter unavailable");
    return;
  }
  randombytes_buf(nonceBuf, NONCE_SIZE);

  uint8_t msg[1 + 4 + 1 + MAX_CHALLENGE_LEN + NONCE_SIZE];
  size_t n = 0;
  msg[n++] = flagsByte;
  msg[n++] = (uint8_t)((ctr >> 24) & 0xFF);
  msg[n++] = (uint8_t)((ctr >> 16) & 0xFF);
  msg[n++] = (uint8_t)((ctr >> 8) & 0xFF);
  msg[n++] = (uint8_t)(ctr & 0xFF);
  msg[n++] = challengeLen;
  memcpy(msg + n, challenge, challengeLen);
  n += challengeLen;
  memcpy(msg + n, nonceBuf, NONCE_SIZE);
  n += NONCE_SIZE;

  unsigned long long sigLen = 0;
  if (crypto_sign_detached(sigBuf, &sigLen, msg, n, sk) != 0 || sigLen != SIG_SIZE) {
    Serial.println("[ERROR] crypto_sign_detached failed");
    return;
  }

  memcpy(body, msg, n);
  memcpy(body + n, sigBuf, SIG_SIZE);
  bodyLen = (uint16_t)(n + SIG_SIZE);
  dataChunks = (uint8_t)((bodyLen + DATA_FRAME_SIZE - 1) / DATA_FRAME_SIZE);
  totalFrames = (uint8_t)(1 + dataChunks);
  assignPacketBase();
  payloadReady = true;

  Serial.print("[PAYLOAD] counter=");
  Serial.print(ctr);
  Serial.print(" check=");
  Serial.print(CHECK_COUNTER ? "on" : "off");
  Serial.print(" bytes=");
  Serial.println(bodyLen);
  Serial.print("  Nonce: ");
  printHex(nonceBuf, NONCE_SIZE);
  Serial.println();
  Serial.print("  Sig  : ");
  printHex(sigBuf, SIG_SIZE);
  Serial.println();
}

void sendAdv(uint8_t type, uint16_t seq, const uint8_t* data, uint8_t dataLen) {
  uint8_t raw[31];
  uint8_t crcInput[2 + DATA_FRAME_SIZE];
  memset(raw, 0, sizeof(raw));
  memset(crcInput, 0, sizeof(crcInput));

  crcInput[0] = (uint8_t)((seq >> 8) & 0xFF);
  crcInput[1] = (uint8_t)(seq & 0xFF);
  if (dataLen > 0 && data != nullptr) memcpy(crcInput + 2, data, dataLen);
  uint8_t crcLen = (uint8_t)(2 + dataLen);
  uint8_t crc = crc8(crcInput, crcLen);

  raw[0] = (uint8_t)(crcLen + 2); // type + seq/data + crc
  raw[1] = type;
  memcpy(raw + 2, crcInput, crcLen);
  raw[2 + crcLen] = crc;
  uint8_t total = (uint8_t)(crcLen + 3);

  NimBLEAdvertisementData advPacket;
  advPacket.addData(raw, total);
  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->stop();
  adv->setAdvertisementData(advPacket);
  adv->start();

  Serial.print("[ADV] Frame ");
  Serial.print(currentFrameIndex);
  Serial.print(" seq=");
  Serial.print(seq);
  Serial.print(" RAW=");
  printHex(raw, total);
  Serial.println();
}

void sendFrame(uint8_t frameIdx) {
  if (!payloadReady || frameIdx >= totalFrames) return;

  uint16_t seq = (uint16_t)(packetBase + frameIdx);
  if (frameIdx == 0) {
    uint8_t meta[ANNOUNCE_DATA_SIZE];
    memset(meta, 0, sizeof(meta));
    meta[0] = (uint8_t)((bodyLen >> 8) & 0xFF);
    meta[1] = (uint8_t)(bodyLen & 0xFF);
    meta[2] = dataChunks;
    meta[3] = PROTO_VERSION;
    meta[4] = flagsByte;
    meta[5] = challengeLen;
    sendAdv(AD_TYPE_START, seq, meta, ANNOUNCE_DATA_SIZE);
    return;
  }

  uint16_t offset = (uint16_t)((frameIdx - 1) * DATA_FRAME_SIZE);
  if (offset >= bodyLen) return;
  uint8_t n = DATA_FRAME_SIZE;
  if ((uint16_t)(offset + n) > bodyLen) n = (uint8_t)(bodyLen - offset);
  uint8_t type = (frameIdx == totalFrames - 1) ? AD_TYPE_END : AD_TYPE_MIDDLE;
  sendAdv(type, seq, body + offset, n);
}

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("=== Fragmented BLE broadcaster v2 ===");
  Serial.print("[MODE] counter=");
  Serial.println(CHECK_COUNTER ? "on" : "off");

  if (sodium_init() == -1) {
    Serial.println("[FATAL] libsodium init failed");
  }

  if (CLEAR_FLASH_SECRETS) clearFlashSecrets();

  ensureKeys();
  loadChallenge();
  initCounter();
  preparePayload();
  printStatus();

  NimBLEDevice::init("");
  {
    NimBLEAddress addr = NimBLEDevice::getAddress();
    Serial.print("[MAC] ");
    Serial.println(addr.toString().c_str());
  }
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->setMinInterval(0x00A0);
  adv->setMaxInterval(0x00A0);
  adv->start();

  lastFrameMillis = millis();
  lastStatusMillis = millis();
  currentFrameIndex = 0;
  sendFrame(currentFrameIndex);
}

void loop() {
  unsigned long now = millis();

  if ((unsigned long)(now - lastStatusMillis) >= STATUS_INTERVAL_MS) {
    lastStatusMillis = now;
    printStatus();
  }

  if ((unsigned long)(now - lastFrameMillis) >= FRAME_INTERVAL_MS) {
    lastFrameMillis = now;
    currentFrameIndex++;
    if (currentFrameIndex >= totalFrames) {
      preparePayload();
      currentFrameIndex = 0;
    }
    sendFrame(currentFrameIndex);
  }
}
