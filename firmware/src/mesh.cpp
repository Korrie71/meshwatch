#include "mesh.h"
#include <Preferences.h>

namespace mesh {

static void dbg(const char* fmt, ...);

static const char NUS_SVC[] = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
static const char NUS_RX[]  = "6e400002-b5a3-f393-e0a9-e50e24dcca9e";   // we write
static const char NUS_TX[]  = "6e400003-b5a3-f393-e0a9-e50e24dcca9e";   // radio notifies

// Companion protocol codes
enum : uint8_t {
  CMD_APP_START = 1, CMD_SEND_TXT = 2, CMD_SEND_CHAN_TXT = 3, CMD_GET_CONTACTS = 4,
  CMD_GET_TIME = 5, CMD_SEND_ADVERT = 7, CMD_SYNC_NEXT = 10, CMD_DEVICE_QUERY = 22, CMD_GET_CHANNEL = 31,
  RSP_OK = 0, RSP_ERR = 1, RSP_CONTACT = 3, RSP_END_CONTACTS = 4, RSP_SELF_INFO = 5,
  RSP_SENT = 6, RSP_CONTACT_MSG = 7, RSP_CHAN_MSG = 8, RSP_CURR_TIME = 9, RSP_NO_MORE = 10,
  RSP_DEVICE_INFO = 13, RSP_CONTACT_MSG_V3 = 16, RSP_CHAN_MSG_V3 = 17, RSP_CHANNEL_INFO = 18,
  PUSH_SEND_CONFIRMED = 0x82, PUSH_MSG_WAITING = 0x83,
};
#define PROTOCOL_VER   3
#define MAX_CHANNELS   8
#define MAX_CONTACTS   (MESH_MAX_CONVS - MAX_CHANNELS)
#define STEP_TIMEOUT   5000
#define RETRY_MS       15000

enum Step : uint8_t { ST_QUERY, ST_START, ST_TIME, ST_CONTACTS, ST_CHANNELS, ST_SYNC, ST_IDLE, ST_SENDING, ST_ADVERT, ST_POS };

struct Frame { uint8_t len; uint8_t d[200]; };

static Preferences prefs;
static State st = SEARCHING;
static Step step = ST_IDLE;
static bool waiting = false;
static uint32_t deadline = 0, nextAttempt = 0;
static uint8_t chanIdx = 0;
static bool needSync = false;
static int incoming = -1;
static Announce announceSt = AN_IDLE;
static uint32_t announceAt = 0;
static bool wantAnnounce = false;

static uint32_t pinCode = 123456;
static NimBLEAddress savedAddr;
static bool haveSaved = false;
static NimBLEAddress foundAddr;
static volatile bool found = false;
static volatile bool dropped = false;

#define MAX_CANDS 6
static Radio cands[MAX_CANDS];
static NimBLEAddress candAddr[MAX_CANDS];

static NimBLEClient* client = nullptr;
static NimBLERemoteCharacteristic* rxChr = nullptr;
static QueueHandle_t frameQ;

static char selfName[24] = "";
static char savedLabel[24] = "";
static bool haveTime = false;
static uint32_t epochBase = 0;        // radio epoch at millis() == 0
static int32_t selfLatRaw = 0, selfLonRaw = 0;   // degrees * 1e6
static bool havePos = false;
static uint32_t lastPosMs = 0;

static Conv convs[MESH_MAX_CONVS];
static Msg msgs[MESH_MAX_MSGS];
static int msgHead = 0, msgUsed = 0;  // ring buffer
static int sending = -1;              // msgs[] index being transmitted

// ------------------------------------------------------------------ storage
// Mesh text is untrusted and the display font is ASCII: keep it printable.
// Returns the output length; dst needs room for len + 1 bytes.
static size_t ascii(char* dst, const char* src, size_t len) {
  size_t o = 0;
  for (size_t i = 0; i < len && src[i]; i++) {
    uint8_t c = src[i];
    if ((c & 0xC0) == 0x80) continue;                 // UTF-8 continuation byte
    if (c >= 0xF0) continue;                          // emoji and other 4-byte glyphs
    dst[o++] = c < 0x20 ? ' ' : c > 0x7e ? '?' : (char)c;
  }
  dst[o] = '\0';
  return o;
}

static Msg& newMsg(int convIdx, uint8_t state, const char* text, size_t len) {
  Msg& m = msgs[msgHead];
  if (sending == msgHead) sending = -1;
  msgHead = (msgHead + 1) % MESH_MAX_MSGS;
  if (msgUsed < MESH_MAX_MSGS) msgUsed++;
  m.conv = convIdx;
  m.state = state;
  m.at = millis();
  m.ack = 0;
  if (len > MESH_TEXT_MAX) len = MESH_TEXT_MAX;
  ascii(m.text, text, len);
  convs[convIdx].lastMsg = m.at ? m.at : 1;
  return m;
}

static int findChannel(uint8_t idx) {
  for (int i = 0; i < MESH_MAX_CONVS; i++)
    if (convs[i].used && convs[i].channel && convs[i].chIdx == idx) return i;
  return -1;
}

static int findContact(const uint8_t* key) {
  for (int i = 0; i < MESH_MAX_CONVS; i++)
    if (convs[i].used && !convs[i].channel && memcmp(convs[i].key, key, 6) == 0) return i;
  return -1;
}

static int freeSlot() {
  for (int i = 0; i < MESH_MAX_CONVS; i++) if (!convs[i].used) return i;
  return -1;
}

static void setName(Conv& c, const char* name, size_t max) {
  char buf[40];
  ascii(buf, name, max < sizeof(buf) - 1 ? max : sizeof(buf) - 1);
  strlcpy(c.name, buf, sizeof(c.name));
}

static int upsertChannel(uint8_t idx, const char* name, size_t max) {
  int i = findChannel(idx);
  if (i < 0) {
    i = freeSlot();
    if (i < 0) return -1;
    memset(&convs[i], 0, sizeof(Conv));
    convs[i].used = convs[i].channel = true;
    convs[i].chIdx = idx;
  }
  if (name) setName(convs[i], name, max);
  return i;
}

static int upsertContact(const uint8_t* key, const char* name, size_t max, uint32_t recency) {
  int i = findContact(key);
  if (i < 0) {
    int contacts = 0, oldest = -1;
    for (int k = 0; k < MESH_MAX_CONVS; k++) {
      if (!convs[k].used || convs[k].channel) continue;
      contacts++;
      if (!convs[k].lastMsg && (oldest < 0 || convs[k].recency < convs[oldest].recency)) oldest = k;
    }
    if (contacts < MAX_CONTACTS) i = freeSlot();
    // Table full: replace the stalest contact that has no messages.
    if (i < 0 && oldest >= 0 && recency > convs[oldest].recency) i = oldest;
    if (i < 0) return -1;
    memset(&convs[i], 0, sizeof(Conv));
    convs[i].used = true;
    memcpy(convs[i].key, key, 6);
  }
  convs[i].recency = recency;
  if (name) setName(convs[i], name, max);
  return i;
}

// ---------------------------------------------------------------------- BLE
static void notifyCB(NimBLERemoteCharacteristic*, uint8_t* data, size_t len, bool) {
  Frame f;
  if (len == 0 || len > sizeof(f.d)) return;
  f.len = len;
  memcpy(f.d, data, len);
  xQueueSend(frameQ, &f, 0);
}

// Diagnostics go out as JSON lines on USB serial.
static void dbg(const char* fmt, ...) {
  char msg[120];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  Serial.printf("{\"t\":\"dbg\",\"ms\":%lu,\"msg\":\"%s\"}\n", (unsigned long)millis(), msg);
}

class ClientCB : public NimBLEClientCallbacks {
  void onConnect(NimBLEClient*) override { dbg("link up"); }
  void onDisconnect(NimBLEClient* c) override {
    dbg("link down, reason %d", c->getLastError());
    dropped = true;
  }
  uint32_t onPassKeyRequest() override {
    dbg("passkey requested");
    return pinCode;
  }
  bool onConfirmPIN(uint32_t pin) override {
    dbg("numeric comparison %06lu", (unsigned long)pin);
    return true;
  }
  void onAuthenticationComplete(ble_gap_conn_desc* desc) override {
    dbg("auth complete enc=%d auth=%d bond=%d keysize=%d", desc->sec_state.encrypted,
        desc->sec_state.authenticated, desc->sec_state.bonded, desc->sec_state.key_size);
  }
};

static bool write(const uint8_t* d, size_t len) {
  if (!rxChr) return false;
  return rxChr->writeValue(d, len, true);
}

static void request(const uint8_t* d, size_t len) {
  write(d, len);
  waiting = true;
  deadline = millis() + STEP_TIMEOUT;
}

static void resumeScan() {
  NimBLEScan* scan = NimBLEDevice::getScan();
  if (!scan->isScanning()) scan->start(0, nullptr, false);
}

static void connectRadio() {
  st = CONNECTING;
  NimBLEDevice::getScan()->stop();
  if (!client) {
    client = NimBLEDevice::createClient();
    client->setClientCallbacks(new ClientCB(), true);
    client->setConnectTimeout(8);
  }
  dropped = false;
  dbg("connecting to %s (%s)", savedLabel, foundAddr.toString().c_str());
  bool ok = client->connect(foundAddr);
  dbg("connect %s err %d rssi %d mtu %d", ok ? "ok" : "failed", client->getLastError(),
      ok ? client->getRssi() : 0, ok ? client->getMTU() : 0);
  bool paired = ok && client->secureConnection();
  if (ok) dbg("secure %s err %d", paired ? "ok" : "failed", client->getLastError());
  NimBLERemoteService* svc = paired ? client->getService(NUS_SVC) : nullptr;
  NimBLERemoteCharacteristic* tx = svc ? svc->getCharacteristic(NUS_TX) : nullptr;
  rxChr = svc ? svc->getCharacteristic(NUS_RX) : nullptr;
  if (paired) dbg("service %d tx %d rx %d", svc != nullptr, tx != nullptr, rxChr != nullptr);
  if (tx && rxChr && tx->subscribe(true, notifyCB)) {
    xQueueReset(frameQ);
    st = SYNCING;
    step = ST_QUERY;
    waiting = false;
  } else {
    // Connected but could not pair means the PIN is wrong.
    st = (ok && !paired) ? PAIR_FAILED : SEARCHING;
    if (client->isConnected()) client->disconnect();
    if (ok && !paired) NimBLEDevice::deleteBond(foundAddr);
    rxChr = nullptr;
    nextAttempt = millis() + (ok ? RETRY_MS : 3000);
  }
  found = false;
  resumeScan();
}

void onScanResult(NimBLEAdvertisedDevice* dev) {
  // Anything advertising the Nordic UART service could be a companion radio;
  // the user picks which one.
  if (!dev->isAdvertisingService(NimBLEUUID(NUS_SVC))) return;
  NimBLEAddress addr = dev->getAddress();
  uint32_t now = millis();
  int slot = -1;
  for (int i = 0; i < MAX_CANDS; i++) if (cands[i].seen && candAddr[i] == addr) slot = i;
  if (slot < 0) {
    for (int i = 0; i < MAX_CANDS; i++)
      if (slot < 0 || !cands[i].seen || (cands[slot].seen && cands[i].seen < cands[slot].seen)) slot = i;
    candAddr[slot] = addr;
    strlcpy(cands[slot].name, addr.toString().c_str(), sizeof(cands[slot].name));
  }
  if (dev->haveName()) {
    char buf[40];
    ascii(buf, dev->getName().c_str(), sizeof(buf) - 1);
    strlcpy(cands[slot].name, buf, sizeof(cands[slot].name));
  }
  cands[slot].rssi = dev->getRSSI();
  cands[slot].seen = now ? now : 1;

  if (found || st != SEARCHING || !haveSaved || !(addr == savedAddr)) return;
  foundAddr = addr;
  found = true;
}

// ----------------------------------------------------------------- protocol
static uint32_t rd32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }
static void wr32(uint8_t* p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static uint32_t nowEpoch() { return epochBase + millis() / 1000; }

static void advance(Step next) {
  step = next;
  waiting = false;
  if (next == ST_IDLE && st == SYNCING) {
    st = READY;
    int n = 0;
    for (auto& c : convs) n += c.used;
    dbg("ready: %d conversations, clock %s", n, haveTime ? "ok" : "unknown");
  }
}

static void storeIncoming(int convIdx, const uint8_t* text, int len) {
  if (convIdx < 0 || len <= 0) return;
  newMsg(convIdx, MS_IN, (const char*)text, len);
  if (convs[convIdx].unread < 99) convs[convIdx].unread++;
  incoming = convIdx;
}

static void handleFrame(const Frame& f) {
  const uint8_t* d = f.d;
  int len = f.len;
  switch (d[0]) {
    case RSP_DEVICE_INFO:
      if (step == ST_QUERY) advance(ST_START);
      break;
    case RSP_SELF_INFO:
      // type, txPower, maxTx, pubkey[32], lat, lon, reserved[3], manualAdd, freq, bw, sf, cr, name
      if (len > 58) {
        char buf[40];
        size_t n = len - 58;
        ascii(buf, (const char*)d + 58, n < sizeof(buf) - 1 ? n : sizeof(buf) - 1);
        strlcpy(selfName, buf, sizeof(selfName));
      }
      if (len > 44) {
        int32_t la = rd32(d + 36), lo = rd32(d + 40);
        if (la || lo) { selfLatRaw = la; selfLonRaw = lo; havePos = true; }
        lastPosMs = millis();
      }
      if (step == ST_START) advance(ST_TIME);
      else if (step == ST_POS) advance(ST_IDLE);
      break;
    case RSP_CURR_TIME:
      if (len >= 5) {
        epochBase = rd32(d + 1) - millis() / 1000;
        haveTime = true;
      }
      if (step == ST_TIME) advance(ST_CONTACTS);
      break;
    case RSP_CONTACT:
      // pubkey[32], type, flags, pathLen, path[64], name[32], lastAdvert, ...
      if (len >= 136 && (d[33] == 1 || d[33] == 3)) {
        upsertContact(d + 1, (const char*)d + 100, 32, rd32(d + 132));
      }
      deadline = millis() + STEP_TIMEOUT;
      break;
    case RSP_END_CONTACTS:
      if (step == ST_CONTACTS) { chanIdx = 0; advance(ST_CHANNELS); }
      break;
    case RSP_CHANNEL_INFO:
      if (len >= 34 && d[2]) upsertChannel(d[1], (const char*)d + 2, 32);
      if (step == ST_CHANNELS) {
        chanIdx++;
        advance(chanIdx < MAX_CHANNELS ? ST_CHANNELS : ST_SYNC);
      }
      break;
    case RSP_CONTACT_MSG:
    case RSP_CONTACT_MSG_V3: {
      int o = d[0] == RSP_CONTACT_MSG_V3 ? 4 : 1;     // V3 adds snr + 2 reserved
      if (len > o + 12) {
        int c = findContact(d + o);
        if (c < 0) {
          char hexName[13];
          snprintf(hexName, sizeof(hexName), "%02x%02x%02x%02x%02x%02x", d[o], d[o + 1], d[o + 2],
                   d[o + 3], d[o + 4], d[o + 5]);
          c = upsertContact(d + o, hexName, 12, UINT32_MAX);
        }
        storeIncoming(c, d + o + 12, len - o - 12);
      }
      if (step == ST_SYNC) advance(ST_SYNC);
      break;
    }
    case RSP_CHAN_MSG:
    case RSP_CHAN_MSG_V3: {
      int o = d[0] == RSP_CHAN_MSG_V3 ? 4 : 1;
      if (len > o + 7) {
        int c = findChannel(d[o]);
        if (c < 0) {
          char nm[12];
          snprintf(nm, sizeof(nm), "Channel %u", d[o]);
          c = upsertChannel(d[o], nm, sizeof(nm));
        }
        storeIncoming(c, d + o + 7, len - o - 7);
      }
      if (step == ST_SYNC) advance(ST_SYNC);
      break;
    }
    case RSP_NO_MORE:
      needSync = false;
      if (step == ST_SYNC) advance(ST_IDLE);
      break;
    case PUSH_MSG_WAITING:
      needSync = true;
      break;
    case PUSH_SEND_CONFIRMED:
      if (len >= 5) {
        uint32_t ack = rd32(d + 1);
        for (int i = 0; i < msgUsed; i++)
          if (msgs[i].state == MS_SENT && msgs[i].ack == ack && ack) msgs[i].state = MS_DELIVERED;
      }
      break;
    case RSP_SENT:
      if (step == ST_SENDING) {
        if (sending >= 0) {
          msgs[sending].state = MS_SENT;
          if (len >= 6) msgs[sending].ack = rd32(d + 2);
        }
        sending = -1;
        advance(ST_IDLE);
      }
      break;
    case RSP_OK:
      if (step == ST_ADVERT) {
        announceSt = AN_SENT;
        announceAt = millis();
        advance(ST_IDLE);
      }
      if (step == ST_SENDING) {
        if (sending >= 0) msgs[sending].state = MS_SENT;
        sending = -1;
        advance(ST_IDLE);
      }
      break;
    case RSP_ERR:
      if (step == ST_ADVERT) {
        announceSt = AN_FAILED;
        announceAt = millis();
        advance(ST_IDLE);
      } else if (step == ST_SENDING) {
        if (sending >= 0) msgs[sending].state = MS_FAILED;
        sending = -1;
        advance(ST_IDLE);
      } else if (step == ST_CHANNELS) {
        advance(ST_SYNC);                             // past the last channel slot
      } else if (step == ST_QUERY) {
        advance(ST_START);
      }
      break;
  }
}

static void onTimeout() {
  dbg("step %d timed out", (int)step);
  switch (step) {
    case ST_QUERY:    advance(ST_START); break;
    case ST_START:    advance(ST_TIME); break;
    case ST_TIME:     advance(ST_CONTACTS); break;
    case ST_CONTACTS: chanIdx = 0; advance(ST_CHANNELS); break;
    case ST_CHANNELS: advance(ST_SYNC); break;
    case ST_SENDING:
      if (sending >= 0) msgs[sending].state = MS_FAILED;
      sending = -1;
      advance(ST_IDLE);
      break;
    case ST_POS:
      advance(ST_IDLE);
      break;
    case ST_ADVERT:
      announceSt = AN_FAILED;
      announceAt = millis();
      advance(ST_IDLE);
      break;
    default:          advance(ST_IDLE);
  }
}

static int nextQueued() {
  int best = -1;
  for (int i = 0; i < msgUsed; i++)
    if (msgs[i].state == MS_QUEUED && (best < 0 || (int32_t)(msgs[i].at - msgs[best].at) < 0)) best = i;
  return best;
}

static void startStep() {
  uint8_t b[200];
  switch (step) {
    case ST_QUERY:
      b[0] = CMD_DEVICE_QUERY; b[1] = PROTOCOL_VER;
      request(b, 2);
      break;
    case ST_START:
      memset(b, 0, 8);
      b[0] = CMD_APP_START; b[1] = 1;
      memcpy(b + 8, "MeshWatch", 9);
      request(b, 17);
      break;
    case ST_TIME:
      b[0] = CMD_GET_TIME;
      request(b, 1);
      break;
    case ST_CONTACTS:
      b[0] = CMD_GET_CONTACTS;
      request(b, 1);
      break;
    case ST_CHANNELS:
      b[0] = CMD_GET_CHANNEL; b[1] = chanIdx;
      request(b, 2);
      break;
    case ST_SYNC:
      b[0] = CMD_SYNC_NEXT;
      request(b, 1);
      break;
    case ST_IDLE: {
      if (needSync) { step = ST_SYNC; break; }
      if (wantAnnounce) {
        wantAnnounce = false;
        b[0] = CMD_SEND_ADVERT; b[1] = 1;             // 1 = flood
        step = ST_ADVERT;
        request(b, 2);
        break;
      }
      if (havePos && millis() - lastPosMs > 30000) {  // refresh GPS position
        memset(b, 0, 8);
        b[0] = CMD_APP_START; b[1] = 1;
        memcpy(b + 8, "MeshWatch", 9);
        step = ST_POS;
        request(b, 17);
        break;
      }
      int q = nextQueued();
      if (q < 0) break;
      Msg& m = msgs[q];
      const Conv& c = convs[m.conv];
      size_t tl = strlen(m.text), n;
      if (c.channel) {
        b[0] = CMD_SEND_CHAN_TXT; b[1] = 0; b[2] = c.chIdx;
        wr32(b + 3, nowEpoch());
        n = 7;
      } else {
        b[0] = CMD_SEND_TXT; b[1] = 0; b[2] = 0;
        wr32(b + 3, nowEpoch());
        memcpy(b + 7, c.key, 6);
        n = 13;
      }
      memcpy(b + n, m.text, tl);
      sending = q;
      step = ST_SENDING;
      request(b, n + tl);
      break;
    }
    default:
      break;
  }
}

// ---------------------------------------------------------------------- API
void begin() {
  frameQ = xQueueCreate(16, sizeof(Frame));
  prefs.begin("meshwatch", false);
  pinCode = prefs.getUInt("pin", 123456);
  String a = prefs.getString("addr", "");
  if (a.length()) {
    savedAddr = NimBLEAddress(a.c_str(), prefs.getUChar("atype", BLE_ADDR_PUBLIC));
    haveSaved = true;
    strlcpy(savedLabel, prefs.getString("rname", "").c_str(), sizeof(savedLabel));
  }
  NimBLEDevice::setSecurityAuth(true, true, true);
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_KEYBOARD_ONLY);
}

void loop() {
  if (dropped) {
    dropped = false;
    rxChr = nullptr;
    if (st == SYNCING || st == READY) st = SEARCHING;
    for (int i = 0; i < msgUsed; i++) if (msgs[i].state == MS_QUEUED) msgs[i].state = MS_FAILED;
    sending = -1;
    wantAnnounce = false;
    if (announceSt == AN_SENDING) announceSt = AN_FAILED;
    nextAttempt = millis() + 3000;
    resumeScan();
  }
  // A wrong PIN is not retried until the PIN is changed or the radio forgotten.
  if (st == PAIR_FAILED) return;
  if (st == SEARCHING) {
    if (found && (int32_t)(millis() - nextAttempt) >= 0) connectRadio();
    return;
  }
  Frame f;
  while (xQueueReceive(frameQ, &f, 0) == pdTRUE) handleFrame(f);
  if (waiting && (int32_t)(millis() - deadline) >= 0) onTimeout();
  if (!waiting && rxChr) startStep();
}

State state() { return st; }
const char* radioName() { return selfName; }
Conv& conv(int i) { return convs[i]; }

int order(int* out) {
  int n = 0;
  for (int i = 0; i < MESH_MAX_CONVS; i++) if (convs[i].used) out[n++] = i;
  // insertion sort: channels first, then newest message, then name
  for (int i = 1; i < n; i++) {
    int v = out[i], j = i - 1;
    auto before = [](const Conv& a, const Conv& b) {
      if (a.channel != b.channel) return a.channel;
      if (a.channel) return a.chIdx < b.chIdx;
      if (a.lastMsg != b.lastMsg) return a.lastMsg > b.lastMsg;
      return strcasecmp(a.name, b.name) < 0;
    };
    while (j >= 0 && before(convs[v], convs[out[j]])) { out[j + 1] = out[j]; j--; }
    out[j + 1] = v;
  }
  return n;
}

const Msg* message(int convIdx, int nthNewest) {
  for (int k = 1; k <= msgUsed; k++) {
    const Msg& m = msgs[(msgHead - k + MESH_MAX_MSGS) % MESH_MAX_MSGS];
    if (m.conv == convIdx && nthNewest-- == 0) return &m;
  }
  return nullptr;
}

void markRead(int convIdx) { convs[convIdx].unread = 0; }

int unreadTotal() {
  int n = 0;
  for (auto& c : convs) if (c.used) n += c.unread;
  return n;
}

bool send(int convIdx, const char* text) {
  if (st != READY || convIdx < 0 || !convs[convIdx].used || !text[0]) return false;
  newMsg(convIdx, MS_QUEUED, text, strlen(text));
  return true;
}

int takeIncoming() {
  int c = incoming;
  incoming = -1;
  return c;
}

uint32_t pin() { return pinCode; }
uint32_t epoch() { return haveTime ? nowEpoch() : 0; }

bool pos(double* lat, double* lon) {
  if (!havePos) return false;
  *lat = selfLatRaw / 1e6;
  *lon = selfLonRaw / 1e6;
  return true;
}

bool announce() {
  if (st != READY || announceSt == AN_SENDING) return false;
  wantAnnounce = true;
  announceSt = AN_SENDING;
  announceAt = millis();
  return true;
}

Announce announceState() {
  if (announceSt != AN_IDLE && announceSt != AN_SENDING && millis() - announceAt > 5000) announceSt = AN_IDLE;
  return announceSt;
}

void setPin(uint32_t p) {
  pinCode = p;
  prefs.putUInt("pin", p);
  if (st == PAIR_FAILED) st = SEARCHING;
  nextAttempt = 0;
}

static void reset() {
  if (client && client->isConnected()) client->disconnect();
  st = SEARCHING;
  memset(convs, 0, sizeof(convs));
  msgUsed = msgHead = 0;
  sending = -1;
  selfName[0] = '\0';
  found = false;
  nextAttempt = 0;
}

void forget() {
  if (haveSaved) NimBLEDevice::deleteBond(savedAddr);
  haveSaved = false;
  prefs.remove("addr");
  prefs.remove("rname");
  reset();
}

bool hasRadio() { return haveSaved; }
const char* savedName() { return savedLabel; }

int radios(Radio* out, int max) {
  int n = 0;
  uint32_t now = millis();
  for (int i = 0; i < MAX_CANDS && n < max; i++) {
    if (!cands[i].seen || now - cands[i].seen > 30000) continue;
    out[n] = cands[i];
    out[n].slot = i;
    n++;
  }
  for (int i = 1; i < n; i++) {                       // strongest first
    Radio v = out[i];
    int j = i - 1;
    while (j >= 0 && out[j].rssi < v.rssi) { out[j + 1] = out[j]; j--; }
    out[j + 1] = v;
  }
  return n;
}

void choose(int slot) {
  if (slot < 0 || slot >= MAX_CANDS || !cands[slot].seen) return;
  if (haveSaved) NimBLEDevice::deleteBond(savedAddr);
  savedAddr = candAddr[slot];
  haveSaved = true;
  strlcpy(savedLabel, cands[slot].name, sizeof(savedLabel));
  prefs.putString("addr", savedAddr.toString().c_str());
  prefs.putUChar("atype", savedAddr.getType());
  prefs.putString("rname", savedLabel);
  reset();
}

}  // namespace mesh
