# BLE分片廣播協議 - 私匙簽名示例

## 協議設計

### 分片結構
```
總資料: nonce (32B) + signature (64B) = 96B

廣播序列：
0) AD Type 0xDD: GlobalSeq+0 - 宣告(total_size=96, chunks=4, ver=1) + padding (29B)
1) AD Type 0xDE: GlobalSeq+1 - Nonce[0:25] (31B)
2) AD Type 0xDE: GlobalSeq+2 - Nonce[26:31] + Signature[0:19] (31B)
3) AD Type 0xDE: GlobalSeq+3 - Signature[20:45] (31B)
4) AD Type 0xDF: GlobalSeq+4 - Signature[46:63] + padding (31B)
```

### 統一幀格式
```
[Length][AD_Type][GlobalSeq(2B)][Data][CRC]
```

### 關鍵特性
- 全局序列號避免包混淆
- 26字節數據幀，84%效率
- 480ms傳輸完成(5幀×120ms)
- 純自定義AD Type協議

## Ed25519私匙簽名實現

### 密鑰管理
```cpp
// 固定種子（示例）
static const uint8_t FIXED_SEED[32] = {
  0x10,0x32,0x54,0x76,0x98,0xBA,0xDC,0xFE,
  0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
  0x55,0xAA,0x11,0xEE,0x22,0xDD,0x33,0xCC,
  0x44,0xBB,0x66,0x99,0x77,0x88,0x00,0xFF
};

// 從種子生成密鑰對
crypto_sign_seed_keypair(pk, sk, FIXED_SEED);
```

### 數據準備
```cpp
void preparePayload() {
  globalSeq++; // 序列號遞增
  randombytes_buf(nonceBuf, 32); // 生成隨機nonce
  
  // 對nonce進行簽名
  crypto_sign_detached(sigBuf, &sigLen, nonceBuf, 32, sk);
  
  // 組合payload: nonce||signature
  memcpy(payload, nonceBuf, 32);
  memcpy(payload + 32, sigBuf, 64);
}
```

### 幀發送邏輯
```cpp
void sendFrame(uint8_t frameIdx) {
  uint8_t advData[31];
  
  switch(frameIdx) {
    case 0: // 宣告幀
      frame_data[0] = (globalSeq >> 8) & 0xFF;
      frame_data[1] = globalSeq & 0xFF;
      frame_data[2] = 96;    // total_size
      frame_data[3] = 4;     // chunks
      frame_data[4] = 0x01;  // version
      // ... CRC計算和廣播
      
    case 1: // Nonce[0:25]
      memcpy(frame_data + 2, payload, 26);
      // ...
      
    // 其他幀類似處理
  }
}
```

### CRC8校驗
```cpp
uint8_t crc8(const uint8_t* data, size_t len) {
  uint8_t crc = 0x00;
  for (size_t i = 0; i < len; ++i) {
    crc ^= data[i];
    for (uint8_t b = 0; b < 8; ++b) {
      if (crc & 0x80) crc = (crc << 1) ^ 0x31;
      else crc <<= 1;
    }
  }
  return crc;
}
```

## 時序控制

```cpp
void loop() {
  if (millis() - lastFrameMillis >= 120) {
    lastFrameMillis = millis();
    currentFrameIndex++;
    
    if (currentFrameIndex >= 5) {
      // 一輪完成，準備新數據
      preparePayload();
      currentFrameIndex = 0;
    }
    sendFrame(currentFrameIndex);
  }
}
```

## 效能指標

- **傳輸時間**: 480ms
- **數據效率**: 84% (96B/115B)
- **包識別**: 65536個唯一序列號
- **錯誤檢測**: 每幀CRC8校驗

---

**作者**: Wing9897 & claude code