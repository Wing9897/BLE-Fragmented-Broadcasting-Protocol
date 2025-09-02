#include <NimBLEDevice.h>
// 若使用固定私鑰，可不需 Preferences；保留以便回退
#include <Preferences.h>
#include <sodium.h>

/*
  分片 BLE 廣播協議設計：
  總資料 = nonce (32B) + signature (64B) = 96B
  
  廣播序列（最大化31字節BLE帧利用率）：
  0) AD Type 0xDD: GlobalSeq+0 - 宣告(total_size=96, chunks=4, ver=1) + padding (29B)
  1) AD Type 0xDE: GlobalSeq+1 - Nonce[0:25] (31B)
  2) AD Type 0xDE: GlobalSeq+2 - Nonce[26:31] + Signature[0:19] (31B)
  3) AD Type 0xDE: GlobalSeq+3 - Signature[20:45] (31B)
  4) AD Type 0xDF: GlobalSeq+4 - Signature[46:63] + padding (31B)

  統一AD結構格式: [Length][AD_Type][GlobalSeq(2B)][Data][CRC]
  
  特點：
  - 所有帧統一格式，包含全局序列號避免混淆
  - 26字節數據帧，84%效率，480ms傳輸完成
  - GlobalSeq每轮递增，65536個唯一包標識
  - 純自定義AD Type 0xDD/0xDE/0xDF協議
*/

// ====== 常數設定 ======
static const uint8_t AD_TYPE_START  = 0xDD; // 宣告帧
static const uint8_t AD_TYPE_MIDDLE = 0xDE; // 中間帧
static const uint8_t AD_TYPE_END    = 0xDF; // 結束帧

static const size_t NONCE_SIZE = 32;
static const size_t SIG_SIZE   = 64; // Ed25519 signature
static const size_t TOTAL_PAYLOAD_SIZE = NONCE_SIZE + SIG_SIZE; // 96

// 廣播間隔和分片設定
static const uint32_t FRAME_INTERVAL_MS = 120; // 廣播間隔
static const uint8_t TOTAL_FRAMES = 5; // 總帧數(含宣告帧): 1宣告+4數據帧
static const uint8_t DATA_FRAME_SIZE = 26; // 數據帧固定26字節
static const uint8_t TOTAL_DATA_CHUNKS = 4; // 數據分片數

// ====== 金鑰設定 ======
// 設為 true 則使用下方固定 SEED 產生固定金鑰，不再讀寫 NVS
static const bool USE_FIXED_KEY = true;

// 固定 32-byte Ed25519 seed（示範用，請自行更換；勿在正式環境使用示例值）
// 可用隨機工具生成 64 個 hex 字元 (32 bytes)
static const uint8_t FIXED_SEED[crypto_sign_SEEDBYTES] = {
  0x10,0x32,0x54,0x76,0x98,0xBA,0xDC,0xFE,
  0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
  0x55,0xAA,0x11,0xEE,0x22,0xDD,0x33,0xCC,
  0x44,0xBB,0x66,0x99,0x77,0x88,0x00,0xFF
};

// 若使用 NVS 自動持久化的命名空間與 Key
static const char* NVS_NAMESPACE = "ed25519";
static const char* NVS_KEY_SK    = "sk";
static const char* NVS_KEY_PK    = "pk";

Preferences prefs;

static unsigned long lastFrameMillis = 0;
static uint8_t currentFrameIndex = 0; // 0..4
static uint16_t globalSeq = 0; // 全局序列号，每轮递增

// 暫存一輪資料
static uint8_t nonceBuf[NONCE_SIZE];
static uint8_t sigBuf[SIG_SIZE];
static uint8_t payload[TOTAL_PAYLOAD_SIZE]; // nonce||sig

static uint8_t sk[crypto_sign_SECRETKEYBYTES];
static uint8_t pk[crypto_sign_PUBLICKEYBYTES];
static bool keyLoaded = false;

// ====== CRC8 (多項式 0x31, 初始 0x00) ======
uint8_t crc8(const uint8_t* data, size_t len) {
  uint8_t crc = 0x00;
  for (size_t i = 0; i < len; ++i) {
    crc ^= data[i];
    for (uint8_t b = 0; b < 8; ++b) {
      if (crc & 0x80) crc = (crc << 1) ^ 0x31; else crc <<= 1;
    }
  }
  return crc;
}

void ensureKeys() {
  if (sodium_init() == -1) {
    Serial.println("[ERROR] sodium_init failed");
    return;
  }

  if (USE_FIXED_KEY) {
    // 由固定 seed 派生穩定 Ed25519 keypair
    if (crypto_sign_seed_keypair(pk, sk, FIXED_SEED) != 0) {
      Serial.println("[ERROR] crypto_sign_seed_keypair failed");
      return;
    }
    keyLoaded = true;
    Serial.println("[KEY] Using FIXED Ed25519 seed (警告：勿在正式環境使用測試種子)");
  } else {
    // 舊行為：嘗試從 NVS 讀取，不存在則生成並保存
    prefs.begin(NVS_NAMESPACE, false);
    size_t haveSk = prefs.getBytesLength(NVS_KEY_SK);
    size_t havePk = prefs.getBytesLength(NVS_KEY_PK);
    if (haveSk == crypto_sign_SECRETKEYBYTES && havePk == crypto_sign_PUBLICKEYBYTES) {
      prefs.getBytes(NVS_KEY_SK, sk, crypto_sign_SECRETKEYBYTES);
      prefs.getBytes(NVS_KEY_PK, pk, crypto_sign_PUBLICKEYBYTES);
      keyLoaded = true;
      Serial.println("[KEY] Loaded existing Ed25519 keypair from NVS");
    } else {
      if (crypto_sign_keypair(pk, sk) != 0) {
        Serial.println("[ERROR] keypair generation failed");
        prefs.end();
        return;
      }
      prefs.putBytes(NVS_KEY_SK, sk, crypto_sign_SECRETKEYBYTES);
      prefs.putBytes(NVS_KEY_PK, pk, crypto_sign_PUBLICKEYBYTES);
      keyLoaded = true;
      Serial.println("[KEY] Generated new Ed25519 keypair and stored to NVS");
    }
    prefs.end();
  }

  // Print public key (hex)
  Serial.print("[PUB] ");
  for (size_t i = 0; i < crypto_sign_PUBLICKEYBYTES; ++i) {
    if (pk[i] < 16) Serial.print('0');
    Serial.print(pk[i], HEX);
  }
  Serial.println();

  // WARNING: 下方列印私鑰 (包含 seed + public key 64B) 僅供測試除錯，正式環境請移除
  Serial.print("[PRIV] ");
  for (size_t i = 0; i < crypto_sign_SECRETKEYBYTES; ++i) {
    if (sk[i] < 16) Serial.print('0');
    Serial.print(sk[i], HEX);
  }
  Serial.println();
}

void preparePayload() {
  if (sodium_init() == -1) {
    Serial.println("[ERROR] sodium_init failed during payload prep");
    return;
  }
  globalSeq++; // 每轮递增全局序列号
  randombytes_buf(nonceBuf, NONCE_SIZE);

  // 簽名 (使用 detached 方便直接得到 64B)
  unsigned long long sigLen = 0;
  if (crypto_sign_detached(sigBuf, &sigLen, nonceBuf, NONCE_SIZE, sk) != 0 || sigLen != SIG_SIZE) {
    Serial.println("[ERROR] crypto_sign_detached failed");
    return;
  }

  memcpy(payload, nonceBuf, NONCE_SIZE);
  memcpy(payload + NONCE_SIZE, sigBuf, SIG_SIZE);

  Serial.println("[PAYLOAD] New nonce + signature prepared:");
  Serial.print("  Nonce: ");
  for (int i = 0; i < NONCE_SIZE; ++i) { if (nonceBuf[i] < 16) Serial.print('0'); Serial.print(nonceBuf[i], HEX); }
  Serial.println();
  Serial.print("  Sig  : ");
  for (int i = 0; i < SIG_SIZE; ++i) { if (sigBuf[i] < 16) Serial.print('0'); Serial.print(sigBuf[i], HEX); }
  Serial.println();
}

// 建立純自定義AD結構的廣播封包 (按照精確規格：22字節固定長度frame)
void sendFrame(uint8_t frameIdx) {
  uint8_t advData[31]; // BLE最大31字節
  uint8_t dataLen = 0;
  
  switch(frameIdx) {
    case 0: { // 宣告帧 0xDD: [1B Len][1B Type][2B Seq][24B Data][1B CRC] = 29B
      uint8_t frame_data[26]; // Seq(2) + Data(24) = 26
      frame_data[0] = (globalSeq >> 8) & 0xFF; frame_data[1] = globalSeq & 0xFF; // 全局序列号
      frame_data[2] = 96;                          // total_size
      frame_data[3] = 4;                           // total_chunks  
      frame_data[4] = 0x01;                        // version
      memset(frame_data + 5, 0x00, 19);           // padding至24字节
      uint8_t crc = crc8(frame_data, 26);
      
      advData[0] = 28;             // Length: 1(type) + 26(seq+data) + 1(crc) = 28
      advData[1] = AD_TYPE_START;  // 0xDD
      memcpy(advData + 2, frame_data, 26);
      advData[28] = crc;
      dataLen = 29;
      break;
    }
    
    case 1: { // Frame 1: [1B Len][1B Type][2B Seq][26B Data][1B CRC] = 31B
      uint8_t frame_data[28]; // Seq(2) + Data(26) = 28
      frame_data[0] = (globalSeq >> 8) & 0xFF; frame_data[1] = (globalSeq & 0xFF) + 1; // 全局序列号+1
      memcpy(frame_data + 2, payload, 26); // Nonce[0:25] (26 bytes)
      uint8_t crc = crc8(frame_data, 28);
      
      advData[0] = 30;             // Length: 1(type) + 28(seq+data) + 1(crc) = 30
      advData[1] = AD_TYPE_MIDDLE; // 0xDE
      memcpy(advData + 2, frame_data, 28);
      advData[30] = crc;
      dataLen = 31;
      break;
    }
    
    case 2: { // Frame 2: Nonce[26:31] + Sig[0:19] = 6+20 = 26 bytes
      uint8_t frame_data[28]; // Seq(2) + Data(26) = 28
      frame_data[0] = (globalSeq >> 8) & 0xFF; frame_data[1] = (globalSeq & 0xFF) + 2; // 全局序列号+2
      memcpy(frame_data + 2, payload + 26, 6);                    // Nonce[26:31] (6 bytes)
      memcpy(frame_data + 8, payload + NONCE_SIZE, 20);           // Sig[0:19] (20 bytes)
      uint8_t crc = crc8(frame_data, 28);
      
      advData[0] = 30;
      advData[1] = AD_TYPE_MIDDLE; // 0xDE
      memcpy(advData + 2, frame_data, 28);
      advData[30] = crc;
      dataLen = 31;
      break;
    }
    
    case 3: { // Frame 3: Sig[20:45] = 26 bytes
      uint8_t frame_data[28]; // Seq(2) + Data(26) = 28
      frame_data[0] = (globalSeq >> 8) & 0xFF; frame_data[1] = (globalSeq & 0xFF) + 3; // 全局序列号+3
      memcpy(frame_data + 2, payload + NONCE_SIZE + 20, 26); // Sig[20:45] (26 bytes)
      uint8_t crc = crc8(frame_data, 28);
      
      advData[0] = 30;
      advData[1] = AD_TYPE_MIDDLE; // 0xDE
      memcpy(advData + 2, frame_data, 28);
      advData[30] = crc;
      dataLen = 31;
      break;
    }
    
    case 4: { // Frame 4: Sig[46:63] + padding = 18+8 = 26 bytes
      uint8_t frame_data[28]; // Seq(2) + Data(26) = 28
      frame_data[0] = (globalSeq >> 8) & 0xFF; frame_data[1] = (globalSeq & 0xFF) + 4; // 全局序列号+4
      memcpy(frame_data + 2, payload + NONCE_SIZE + 46, 18); // Sig[46:63] (18 bytes)
      memset(frame_data + 20, 0x00, 8);                      // Padding (8 bytes)
      uint8_t crc = crc8(frame_data, 28);
      
      advData[0] = 30;
      advData[1] = AD_TYPE_END;    // 0xDF
      memcpy(advData + 2, frame_data, 28);
      advData[30] = crc;
      dataLen = 31;
      break;
    }
    
    default: return;
  }

  // 使用NimBLE設定廣播資料
  NimBLEAdvertisementData advPacket;
  advPacket.addData(advData, dataLen);
  
  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->stop();
  adv->setAdvertisementData(advPacket);
  adv->start();

  Serial.print("[ADV] Frame "); Serial.print(frameIdx); Serial.print(" sent, RAW=");
  for (uint8_t i = 0; i < dataLen; i++) {
    if (advData[i] < 16) Serial.print('0');
    Serial.print(advData[i], HEX);
  }
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("=== Fragmented BLE Nonce+Signature Broadcaster (Ed25519) ===");

  if (sodium_init() == -1) {
    Serial.println("[FATAL] libsodium init failed");
  }

  ensureKeys();
  preparePayload();

  NimBLEDevice::init(""); // 名稱由後續 advertisementData.setName 設置
  // 列印本機 BLE MAC 地址
  {
    NimBLEAddress addr = NimBLEDevice::getAddress();
    Serial.print("[MAC] ");
    Serial.println(addr.toString().c_str());
  }
  NimBLEDevice::setPower(ESP_PWR_LVL_P9); // 依需求調整功率

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->setMinInterval(0x00A0); // 約 100ms
  adv->setMaxInterval(0x00A0);
  adv->start();

  lastFrameMillis = millis();
  currentFrameIndex = 0;
  sendFrame(currentFrameIndex);
}

void loop() {
  unsigned long now = millis();
  if (now - lastFrameMillis >= FRAME_INTERVAL_MS) {
    lastFrameMillis = now;
    currentFrameIndex++;
    if (currentFrameIndex >= TOTAL_FRAMES) {
      // 一輪完成，產生新資料並從頭再播
      preparePayload();
      currentFrameIndex = 0;
    }
    sendFrame(currentFrameIndex);
  }
}
