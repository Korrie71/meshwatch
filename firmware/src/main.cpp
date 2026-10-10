// MeshWatch detector - M5Stack StickS3
//
// Passive WiFi + BLE scanner for surveillance hardware. Detections are shown
// on the LCD, announced on the speaker, printed as JSON lines on USB serial
// and streamed over BLE to the MeshWatch app, which relays them to a MeshCore
// radio.
//
// It also connects to a MeshCore companion radio over BLE (see mesh.h) so
// messages can be read and sent from the stick itself, with no phone.
//
//   Button A (front)  select / act        hold: backspace while typing
//   Button B (side)   next                hold: next screen / back
//   On the DETECT screen B opens the menu: MeshCore messages and what to scan for.

#include <Arduino.h>
#include <M5Unified.h>
#include <WiFi.h>
#include <NimBLEDevice.h>
#include "esp_wifi.h"
#include <Preferences.h>
#include "signatures.h"
#include "mesh.h"

#define FW_VERSION "2.1.0"

// ------------------------------------------------------------------- config
#define CHANNEL_DWELL_MS   250
#define REDISCOVER_MS      60000   // silent this long = announced again
#define ACTIVE_MS          60000   // "in range" window for the counters
#define UPDATE_EMIT_MS     5000    // per-device update rate over BLE
#define STATUS_EMIT_MS     10000
#define RSSI_MIN           -95
#define MAX_DEVS           96
#define DEAUTH_WINDOW_MS   5000
#define DEAUTH_THRESHOLD   20
#define BANNER_MS          3500
#define SCAN_ALL           ((1 << CAT_COUNT) - 1)
#define FWD_COOLDOWN_MS     600000  // per device
#define FWD_GAP_MS          20000   // between forwarded alerts (airtime)

// 1/6/11 carry most traffic, so they get visited between every other channel.
static const uint8_t HOP[] = {1, 6, 11, 2, 7, 12, 1, 6, 11, 3, 8, 13,
                              1, 6, 11, 4, 9, 1, 6, 11, 5, 10};
static const size_t HOP_COUNT = sizeof(HOP);

// App link (custom service so the app can tell us apart from a MeshCore radio)
#define SVC_UUID "4d575400-7f3a-4c1e-9b2d-6a1f0c0de001"
#define TX_UUID  "4d575401-7f3a-4c1e-9b2d-6a1f0c0de001"   // notify: JSON lines
#define RX_UUID  "4d575402-7f3a-4c1e-9b2d-6a1f0c0de001"   // write: commands

// -------------------------------------------------------------------- types
struct Hit {
  uint8_t cat, method, conf, ch;
  int8_t  rssi;
  uint8_t mac[6];
  uint16_t fp;                 // identity fingerprint for MAC-rotation grouping
  char    detail[48];
};

struct Dev {
  bool     used;
  uint8_t  cat, method, conf, ch;
  uint8_t  mac[6];
  int8_t   rssi, peak;
  bool     persist, fwdPending, known, isNew, hasPos, ign, hadFirstPos, rotated;
  float    lat, lon, firstLat, firstLon, movedM;
  uint16_t id, minutes, fp;
  uint32_t first, last, lastEmit, lastMinute, lastFwd, count;
  char     detail[48];
};

static Dev devs[MAX_DEVS];
static uint16_t nextId = 1;
static QueueHandle_t hitQ;

static bool muted = false;
static uint16_t scanMask = SCAN_ALL;  // bit per Cat: what to scan for (needs >8 bits)
// Canary SSID: a bait network name. If anything nearby beacons it (an evil twin
// spoofing your network) or probes for it, raise a CAT_CANARY alert.
static char canarySsid[33] = "";
static bool canaryOn = false;
static uint8_t curChannel = 1;
static volatile uint32_t deauthCount = 0;
static uint8_t deauthBssid[6];
static volatile uint32_t bleSpamCount = 0;
static uint8_t bleSpamMac[6];
static volatile uint32_t beaconSpamCount = 0;   // random-MAC beacons per window
static uint8_t beaconSpamMac[6];
static volatile uint32_t lastDeauthMs = 0;      // for deauth-then-EAPOL correlation
static volatile uint32_t eapolCount = 0;        // EAPOL key frames per window
static uint8_t eapolBssid[6];

// Karma / SSID-flood: a legitimate AP advertises one SSID; a Pineapple-style
// rogue answers to many. Track distinct SSID hashes per BSSID in a small table.
struct KarmaEntry { uint8_t bssid[6]; uint16_t hashes[KARMA_SSID_THRESHOLD + 2]; uint8_t count; uint32_t first; bool raised; };
static KarmaEntry karma[16];

static NimBLECharacteristic* txChr = nullptr;
static volatile bool appConnected = false;
static volatile bool wantList = false;
static volatile bool wantClear = false;
static volatile bool wantFakeFollow = false;
static volatile bool wantFakeConvoy = false;
static volatile bool wantCanary = false;
static char canaryPending[33] = "";
static volatile uint16_t appMtu = 23;

static M5Canvas canvas(&M5.Display);
static uint32_t bannerUntil = 0;
static int bannerDev = -1;       // detection banner, or
static int bannerConv = -1;      // incoming-message banner, or
static int bannerConvoy = 0;     // convoy / team-tail banner (count of units)

// Signal finder: the device being hunted is exempt from throttling so its
// signal strength updates as fast as it transmits.
static volatile bool finding = false;
static uint8_t findMac[6];
static int findIdx = -1;
static uint16_t findId = 0;

static uint16_t screenOffSecs = 0;   // 0 = never
static bool asleep = false;
static uint32_t lastInput = 0;
static uint32_t sessionStart = 0;   // sweep window start: boot, or last clear

static Preferences uiPrefs;
static bool fwdOn = false;
static uint8_t fwdCh = 0;
static bool reportOn = false;   // periodic in-range summary to the mesh
static uint8_t brightness = 90;
static bool stealthOn = false;      // stop advertising, passive scan, mute
static bool bannerTeam = false;     // tint the message banner as a team alert
static uint32_t bleDebugUntil = 0;  // when >now, dump every BLE advert over USB

// Baseline watch: learn the devices present in a safe place, then alert on any
// device that was not part of that baseline. Useful for sweeping a room.
enum { BL_OFF, BL_LEARNING, BL_ACTIVE };
static uint8_t baselineState = BL_OFF;
static uint16_t blHashes[192];
static uint16_t blCount = 0;
static uint32_t blLearnUntil = 0;
#define BL_LEARN_MS 60000

static uint16_t macHash(const uint8_t* mac) {
  uint16_t h = 0x811c;
  for (int i = 0; i < 6; i++) h = (h ^ mac[i]) * 0x0193;
  return h ? h : 1;
}
static bool blKnown(uint16_t h) {
  for (uint16_t i = 0; i < blCount; i++) if (blHashes[i] == h) return true;
  return false;
}
static void blAdd(uint16_t h) {
  if (blKnown(h) || blCount >= (sizeof(blHashes) / sizeof(blHashes[0]))) return;
  blHashes[blCount++] = h;
}

// Ignore list: devices you have marked as yours, silenced permanently. Stored
// as MAC hashes in flash.
static uint16_t ignHashes[96];
static uint16_t ignCount = 0;
static bool ignored(uint16_t h) {
  for (uint16_t i = 0; i < ignCount; i++) if (ignHashes[i] == h) return true;
  return false;
}
static void ignToggle(uint16_t h) {
  for (uint16_t i = 0; i < ignCount; i++) {
    if (ignHashes[i] == h) {                       // remove
      ignHashes[i] = ignHashes[--ignCount];
      uiPrefs.putBytes("ign", ignHashes, ignCount * 2);
      return;
    }
  }
  if (ignCount < (sizeof(ignHashes) / sizeof(ignHashes[0]))) {
    ignHashes[ignCount++] = h;
    uiPrefs.putBytes("ign", ignHashes, ignCount * 2);
  }
}

// Close-range alarm: a threat stronger than this gets an urgent repeating tone.
static bool closeAlarm = false;
#define CLOSE_RSSI -52

// ------------------------------------------------------------------ helpers
static bool isThreat(uint8_t cat) { return cat != CAT_BEACON && cat != CAT_TRACKER && cat != CAT_MESH; }

// Great-circle distance in metres between two WGS84 points.
static float distM(float la1, float lo1, float la2, float lo2) {
  const float R = 6371000.0f, D = 0.017453293f;  // deg->rad
  float dla = (la2 - la1) * D, dlo = (lo2 - lo1) * D;
  float a = sinf(dla / 2) * sinf(dla / 2) +
            cosf(la1 * D) * cosf(la2 * D) * sinf(dlo / 2) * sinf(dlo / 2);
  return R * 2 * atan2f(sqrtf(a), sqrtf(1 - a));
}

// Categories whose continued co-presence (without GPS) suggests being followed:
// wearable / body-worn surveillance that would normally pass by, not linger.
static bool mobileCat(uint8_t c) { return c == CAT_TRACKER || c == CAT_AXON || c == CAT_GLASSES; }
// Fixed infrastructure / noise that should never be called "following".
static bool fixedCat(uint8_t c) {
  return c == CAT_BEACON || c == CAT_MESH || c == CAT_FLOCK || c == CAT_CAMERA ||
         c == CAT_RAVEN || c == CAT_CANARY;
}
// Decide whether a device has become a "following you" case.
static bool isFollowing(const Dev& d) {
  // Strongest signal: the radio has GPS and this device stayed in range while
  // you actually travelled a real distance. Works for any non-fixed category.
  if (!fixedCat(d.cat) && d.hadFirstPos && d.movedM >= FOLLOW_MOVE_M && d.minutes >= 2)
    return true;
  // Trackers keep their own (longer) time-only threshold.
  if (d.cat == CAT_TRACKER) return d.minutes >= TRACKER_PERSIST_MINUTES;
  // Other wearable surveillance: flagged on prolonged co-presence.
  if (mobileCat(d.cat)) return d.minutes >= FOLLOW_MINUTES;
  return false;
}

static uint16_t catColor(uint8_t cat) {
  switch (cat) {
    case CAT_FLOCK:   return 0xF9A6;  // red
    case CAT_RAVEN:   return 0xFC60;  // orange
    case CAT_AXON:    return 0xFE60;  // amber
    case CAT_TRACKER: return 0xC39F;  // violet
    case CAT_GLASSES: return 0x3E7F;  // cyan
    case CAT_DEAUTH:  return 0xFAB6;  // pink
    case CAT_MESH:    return 0x47E9;  // green
    case CAT_ROGUE:   return 0xFD0F;  // yellow
    case CAT_ATTACK:  return 0xF800;  // bright red
    case CAT_SKIMMER: return 0xFD24;  // orange-red
    case CAT_CAMERA:  return 0xFB2C;  // salmon
    case CAT_DRONE:   return 0x5D1F;  // blue
    case CAT_CANARY:  return 0xF81F;  // magenta
    default:          return 0x8C71;  // grey
  }
}

static const char* labelFor(uint8_t cat, uint8_t method) {
  switch (cat) {
    case CAT_FLOCK:
      return (method == M_BLE_NAME || method == M_BLE_MFG) ? "Flock battery pack" : "Flock camera";
    case CAT_RAVEN:   return "Raven gunshot sensor";
    case CAT_AXON:    return "Axon body cam/Taser";
    case CAT_GLASSES: return "Meta smart glasses";
    case CAT_DEAUTH:  return "WiFi deauth flood";
    case CAT_MESH:    return method == M_MESHTASTIC ? "Meshtastic radio" : "MeshCore radio";
    case CAT_ROGUE:   return "Rogue AP (karma)";
    case CAT_ATTACK:
      return method == M_FLIPPER ? "Flipper Zero"
           : method == M_BEACON_SPAM ? "WiFi beacon spam"
           : method == M_HANDSHAKE ? "Handshake capture"
           : method == M_PMKID ? "PMKID / EAPOL grab" : "BLE advert spam";
    case CAT_SKIMMER: return "Card-skimmer BT module";
    case CAT_CAMERA:  return "WiFi camera";
    case CAT_DRONE:
      return method == M_ODID_BLE ? "Drone (Remote ID, BLE)"
           : method == M_DRONE_SSID ? "Drone (WiFi)" : "Drone (Remote ID)";
    case CAT_CANARY:  return method == M_CANARY_AP ? "Canary: evil twin AP" : "Canary: someone probing";
    case CAT_TRACKER:
      switch (method) {
        case M_FINDMY:   return "Find My tracker";
        case M_TILE:     return "Tile tracker";
        case M_SMARTTAG: return "Samsung SmartTag";
        case M_CHIPOLO:  return "Chipolo tracker";
        case M_TRACKER_NAME: return "Item tracker";
        default:         return "Google FMD tracker";
      }
    default:
      return method == M_EDDYSTONE ? "Eddystone beacon" : "iBeacon";
  }
}

// Printable ASCII only, no JSON metacharacters.
static void sanitize(char* dst, size_t cap, const uint8_t* src, size_t len) {
  size_t o = 0;
  for (size_t i = 0; i < len && o + 1 < cap; i++) {
    uint8_t c = src[i];
    dst[o++] = (c < 0x20 || c > 0x7e || c == '"' || c == '\\') ? '?' : (char)c;
  }
  dst[o] = '\0';
}

static bool containsNoCase(const char* hay, const char* needle) {
  size_t n = strlen(needle);
  for (; *hay; hay++) if (strncasecmp(hay, needle, n) == 0) return true;
  return false;
}

static bool cameraOui(const uint8_t* mac) {
  for (size_t i = 0; i < CAMERA_OUI_COUNT; i++)
    if (memcmp(mac, CAMERA_OUIS[i], 3) == 0) return true;
  return false;
}

static bool cameraName(const char* name) {
  for (size_t i = 0; i < CAMERA_NAME_COUNT; i++)
    if (containsNoCase(name, CAMERA_NAMES[i])) return true;
  return false;
}

static bool droneName(const char* name) {
  for (size_t i = 0; i < DRONE_NAME_COUNT; i++)
    if (containsNoCase(name, DRONE_NAMES[i])) return true;
  return false;
}

// Returns the confidence of a tracker-name match, or 0 for none.
static uint8_t trackerName(const char* name) {
  for (size_t i = 0; i < TRACKER_NAME_COUNT; i++)
    if (containsNoCase(name, TRACKER_NAMES[i].s)) return TRACKER_NAMES[i].conf;
  return 0;
}

static int flockOui(const uint8_t* mac) {
  for (size_t i = 0; i < FLOCK_OUI_COUNT; i++) {
    const uint8_t* b = FLOCK_OUIS[i].b;
    if (mac[0] == b[0] && mac[1] == b[1] && mac[2] == b[2]) return FLOCK_OUIS[i].conf;
  }
  return -1;
}

// Small per-task cache so one chatty device cannot flood the queue.
struct Recent { uint8_t mac[6]; uint8_t method; uint32_t t; };

static bool throttled(Recent* cache, size_t n, uint8_t* cursor, const uint8_t* mac,
                      uint8_t method, uint32_t windowMs) {
  uint32_t now = millis();
  for (size_t i = 0; i < n; i++) {
    if (cache[i].method == method && memcmp(cache[i].mac, mac, 6) == 0) {
      if (now - cache[i].t < windowMs) return true;
      cache[i].t = now;
      return false;
    }
  }
  Recent& r = cache[(*cursor)++ % n];
  memcpy(r.mac, mac, 6);
  r.method = method;
  r.t = now;
  return false;
}

// A stable identity fingerprint from the device's own advertised name, so a
// device that rotates its MAC (randomised BLE address) but keeps its name is
// recognised as the same unit. Only for mobile categories that carry a specific
// per-device name; shared or generic names (cameras, mesh, beacons) are left at
// 0 so two of the same model are never merged.
static bool fingerprintCat(uint8_t c) {
  return c == CAT_TRACKER || c == CAT_AXON || c == CAT_GLASSES || c == CAT_ATTACK ||
         c == CAT_SKIMMER || c == CAT_FLOCK;
}
static uint16_t fingerprint(uint8_t cat, const char* detail) {
  if (!fingerprintCat(cat) || !detail) return 0;
  size_t n = strlen(detail);
  if (n < 5) return 0;                              // too short to be distinctive
  uint32_t h = 2166136261u ^ (cat * 131u);         // FNV-1a over cat + name
  for (size_t i = 0; i < n; i++) h = (h ^ (uint8_t)detail[i]) * 16777619u;
  uint16_t fp = (uint16_t)(h ^ (h >> 16));
  return fp ? fp : 1;
}

static void pushHit(uint8_t cat, uint8_t method, uint8_t conf, const uint8_t* mac,
                    int8_t rssi, uint8_t ch, const char* detail) {
  Hit h;
  h.cat = cat; h.method = method; h.conf = conf; h.ch = ch; h.rssi = rssi;
  memcpy(h.mac, mac, 6);
  h.fp = fingerprint(cat, detail);
  strlcpy(h.detail, detail ? detail : "", sizeof(h.detail));
  xQueueSend(hitQ, &h, 0);
}

// --------------------------------------------------------------------- WiFi
static Recent wifiRecent[12];
static uint8_t wifiCursor = 0;

static void wifiHit(uint8_t cat, uint8_t method, uint8_t conf, const uint8_t* mac,
                    int8_t rssi, const char* detail) {
  bool hunted = finding && memcmp(mac, findMac, 6) == 0;
  if (!hunted && throttled(wifiRecent, 12, &wifiCursor, mac, method, 1000)) return;
  pushHit(cat, method, conf, mac, rssi, curChannel, detail);
}

// Finds the SSID element. Returns its length, or -1 if absent.
static int findSsid(const uint8_t* ies, int len, const uint8_t** ssid) {
  while (len >= 2) {
    int elen = ies[1];
    if (elen + 2 > len) break;
    if (ies[0] == 0) { *ssid = ies + 2; return elen; }
    ies += elen + 2;
    len -= elen + 2;
  }
  return -1;
}

// Builds the IE-order fingerprint and compares it with the Flock signature.
static bool probeSigMatches(const uint8_t* ies, int len) {
  static const char hex[] = "0123456789abcdef";
  char sig[128];
  size_t pos = 0;
  int i = 0;
  while (i + 2 <= len) {
    uint8_t id = ies[i];
    int elen = ies[i + 1];
    if (i + 2 + elen > len) return false;
    const uint8_t* body = ies + i + 2;
    i += 2 + elen;
    if (id == 0) continue;
    char tok[24];
    if (id == 221 && elen >= 4) {
      int take = elen < 8 ? elen : 8;
      memcpy(tok, "221:", 4);
      for (int k = 0; k < take; k++) {
        tok[4 + k * 2] = hex[body[k] >> 4];
        tok[5 + k * 2] = hex[body[k] & 0x0f];
      }
      tok[4 + take * 2] = '\0';
    } else {
      snprintf(tok, sizeof(tok), "%u", id);
    }
    size_t tl = strlen(tok);
    if (pos + tl + 2 >= sizeof(sig)) return false;
    if (pos) sig[pos++] = ',';
    memcpy(sig + pos, tok, tl);
    pos += tl;
  }
  sig[pos] = '\0';
  return strcmp(sig, FLOCK_PROBE_IE_SIG) == 0;
}

// A rogue AP answering probes with many different SSIDs from one radio. Called
// for beacons and probe responses; raises CAT_ROGUE once the BSSID has been
// seen advertising KARMA_SSID_THRESHOLD distinct names within 30 s.
static void trackKarma(const uint8_t* bssid, const uint8_t* ssid, int slen, int8_t rssi) {
  if (slen <= 0 || slen > 32 || (bssid[0] & 0x01)) return;
  uint16_t h = 2166;
  for (int i = 0; i < slen; i++) h = (h * 31) ^ ssid[i];
  uint32_t now = millis();
  int slot = -1, dead = -1;
  for (int i = 0; i < 16; i++) {
    if (karma[i].count && memcmp(karma[i].bssid, bssid, 6) == 0) { slot = i; break; }
    if (karma[i].count == 0 || now - karma[i].first > 30000) dead = i;
  }
  if (slot < 0) {
    if (dead < 0) return;
    slot = dead;
    memset(&karma[slot], 0, sizeof(KarmaEntry));
    memcpy(karma[slot].bssid, bssid, 6);
    karma[slot].first = now;
  }
  KarmaEntry& e = karma[slot];
  if (now - e.first > 30000) { e.count = 0; e.raised = false; e.first = now; }
  for (int i = 0; i < e.count; i++) if (e.hashes[i] == h) return;   // SSID already counted
  if (e.count < KARMA_SSID_THRESHOLD + 2) e.hashes[e.count++] = h;
  if (e.count >= KARMA_SSID_THRESHOLD && !e.raised) {
    e.raised = true;
    char d[48];
    snprintf(d, sizeof(d), "%u SSIDs in %lus", e.count, (unsigned long)((now - e.first) / 1000 + 1));
    wifiHit(CAT_ROGUE, M_KARMA, 3, bssid, rssi, d);
  }
}

static void checkCameraSsid(const uint8_t* ssid, int slen, const uint8_t* mac, int8_t rssi) {
  if (slen <= 0 || slen > 32) return;
  char name[33];
  sanitize(name, sizeof(name), ssid, slen);
  if (cameraName(name)) wifiHit(CAT_CAMERA, M_CAM_SSID, 3, mac, rssi, name);
}

// Canary SSID: the user plants a bait network name. An AP beaconing it (subtype
// 8) or answering probes with it (5) is an evil twin impersonating that network;
// a client probing for it (4) is a device that has the bait saved. Exact match.
static void checkCanary(const uint8_t* ssid, int slen, const uint8_t* mac, int8_t rssi,
                        uint8_t subtype) {
  if (!canaryOn || !canarySsid[0]) return;
  if (slen <= 0 || slen > 32 || slen != (int)strlen(canarySsid)) return;
  if (memcmp(ssid, canarySsid, slen) != 0) return;
  if (subtype == 8 || subtype == 5)
    wifiHit(CAT_CANARY, M_CANARY_AP, 4, mac, rssi, canarySsid);
  else
    wifiHit(CAT_CANARY, M_CANARY_PROBE, 3, mac, rssi, canarySsid);
}

// Set (and persist) the bait SSID. Empty string clears and disarms it.
static void setCanary(const char* s) {
  char clean[33];
  sanitize(clean, sizeof(clean), (const uint8_t*)s, strlen(s));
  strlcpy(canarySsid, clean, sizeof(canarySsid));
  canaryOn = canarySsid[0] != '\0';
  uiPrefs.putString("canssid", canarySsid);
  uiPrefs.putBool("canon", canaryOn);
}

// Pwnagotchi beacons a JSON SSID (can exceed 32 bytes) carrying "pwnd_tot".
static void checkPwnagotchi(const uint8_t* ssid, int slen, const uint8_t* mac, int8_t rssi) {
  if (slen < 8 || slen > 230 || ssid[0] != '{') return;
  for (int i = 0; i + 8 <= slen; i++) {
    if (memcmp(ssid + i, "pwnd_tot", 8) == 0) {
      wifiHit(CAT_ATTACK, M_PWNAGOTCHI, 3, mac, rssi, "Pwnagotchi");
      return;
    }
  }
}

// Open Drone ID vendor IE (OUI 90:3a:e6 or fa:0b:bc) inside a beacon body.
static bool droneBeaconIE(const uint8_t* ies, int len) {
  while (len >= 2) {
    int elen = ies[1];
    if (elen + 2 > len) break;
    if (ies[0] == 0xdd && elen >= 4 &&
        ((ies[2] == 0x90 && ies[3] == 0x3a && ies[4] == 0xe6) ||
         (ies[2] == 0xfa && ies[3] == 0x0b && ies[4] == 0xbc)))
      return true;
    ies += elen + 2;
    len -= elen + 2;
  }
  return false;
}

static void checkSsid(const uint8_t* ssid, int slen, const uint8_t* mac, int8_t rssi) {
  if (slen <= 0 || slen > 32) return;
  char name[33];
  sanitize(name, sizeof(name), ssid, slen);
  if (strncasecmp(name, "Flock", 5) == 0) {
    wifiHit(CAT_FLOCK, M_WIFI_SSID, strncmp(name, "Flock-", 6) == 0 ? 4 : 3, mac, rssi, name);
  } else if (strncasecmp(name, "Penguin-", 8) == 0 || containsNoCase(name, "FS Ext Battery")) {
    wifiHit(CAT_FLOCK, M_WIFI_SSID, 3, mac, rssi, name);
  } else if (strncasecmp(name, "Axon", 4) == 0) {
    wifiHit(CAT_AXON, M_WIFI_SSID, 3, mac, rssi, name);
  } else if (droneName(name)) {
    wifiHit(CAT_DRONE, M_DRONE_SSID, 3, mac, rssi, name);
  }
}

static void wifiSniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
  int len = pkt->rx_ctrl.sig_len;
  int8_t rssi = pkt->rx_ctrl.rssi;
  if (len < 24 || rssi < RSSI_MIN) return;
  const uint8_t* p = pkt->payload;
  const uint8_t* addr1 = p + 4;
  const uint8_t* addr2 = p + 10;
  const uint8_t* addr3 = p + 16;
  uint8_t subtype = p[0] >> 4;
  bool mgmt = type == WIFI_PKT_MGMT;

  if (mgmt && (subtype == 12 || subtype == 10)) {   // deauth / disassoc
    memcpy(deauthBssid, addr3, 6);
    deauthCount++;
    lastDeauthMs = millis();
  }

  // EAPOL key frame (4-way handshake / PMKID): a data frame, not WEP/CCMP
  // protected, whose LLC/SNAP EtherType is 0x888E. Seeing one right after a
  // deauth is a forced handshake capture; a burst of them is also suspicious.
  if (!mgmt && type == WIFI_PKT_DATA && !(p[1] & 0x40)) {   // not a protected frame
    int hdr = 24;
    if (subtype & 0x08) hdr += 2;                           // QoS data: QoS control
    if (p[1] & 0x80) hdr += 4;                              // HT control present
    if (len >= hdr + 8 &&
        p[hdr] == 0xAA && p[hdr + 1] == 0xAA && p[hdr + 2] == 0x03 &&
        p[hdr + 6] == 0x88 && p[hdr + 7] == 0x8E) {
      memcpy(eapolBssid, addr3, 6);
      eapolCount++;
      uint32_t ld = lastDeauthMs;
      if (ld && millis() - ld < DEAUTH_RECENT_MS)
        wifiHit(CAT_ATTACK, M_HANDSHAKE, 4, addr3, rssi, "deauth + EAPOL capture");
    }
  }

  // Drone Remote ID over WiFi NAN (addr1 is the fixed NAN cluster address).
  if (mgmt && memcmp(addr1, ODID_NAN_DEST, 6) == 0)
    wifiHit(CAT_DRONE, M_ODID_WIFI, 4, addr2, rssi, "Remote ID (NAN)");

  // Transmitter side
  bool txHit = false;
  int conf = flockOui(addr2);
  if (conf >= 0) {
    txHit = true;
    uint8_t method = M_WIFI_OUI;
    if (mgmt && subtype == 4) {                     // probe request
      const uint8_t* ies = p + 24;
      int ilen = len - 24;
      const uint8_t* ssid;
      if (findSsid(ies, ilen, &ssid) == 0) {        // wildcard probe
        method = M_WIFI_PROBE;
        if (conf < 3) conf = 3;
        // sig_len may or may not include the 4-byte FCS
        if (probeSigMatches(ies, ilen) || (ilen > 4 && probeSigMatches(ies, ilen - 4))) {
          method = M_WIFI_PROBE_SIG;
          conf = 4;
        }
      }
    }
    wifiHit(CAT_FLOCK, method, conf, addr2, rssi, "");
  } else if (memcmp(addr2, AXON_OUI, 3) == 0) {
    txHit = true;
    wifiHit(CAT_AXON, M_WIFI_OUI, 3, addr2, rssi, "");
  } else if (cameraOui(addr2)) {
    txHit = true;
    wifiHit(CAT_CAMERA, M_CAM_OUI, 2, addr2, rssi, "");
  }

  // SSIDs in beacons, probe responses and directed probes
  if (mgmt && (subtype == 8 || subtype == 5 || subtype == 4)) {
    int off = subtype == 4 ? 24 : 36;
    if (len > off + 2) {
      const uint8_t* ssid;
      int slen = findSsid(p + off, len - off, &ssid);
      checkSsid(ssid, slen, addr2, rssi);
      checkCameraSsid(ssid, slen, addr2, rssi);
      checkCanary(ssid, slen, addr2, rssi, subtype);
      if (subtype == 8) {
        trackKarma(addr2, ssid, slen, rssi);
        checkPwnagotchi(ssid, slen, addr2, rssi);
        if (droneBeaconIE(p + off, len - off))
          wifiHit(CAT_DRONE, M_ODID_WIFI, 4, addr2, rssi, "Remote ID (beacon)");
        // Beacon-spam attack: a flood of beacons from random (locally-
        // administered) BSSIDs. Real APs beacon from their vendor OUI.
        if ((addr2[0] & 0x02) && !(addr2[0] & 0x01)) {
          memcpy(beaconSpamMac, addr2, 6);
          beaconSpamCount++;
        }
      } else if (subtype == 5) {
        trackKarma(addr2, ssid, slen, rssi);
      }
    }
  }

  // Receiver / BSSID side: a sleeping camera still shows up as the target of
  // frames from nearby APs. Second-hand, so the RSSI is the AP's, not the
  // camera's, and confidence is low.
  if (!txHit && !(addr1[0] & 0x01)) {
    if (flockOui(addr1) >= 2) wifiHit(CAT_FLOCK, M_WIFI_OUI_RX, 1, addr1, rssi, "");
    else if (flockOui(addr3) >= 2 && memcmp(addr3, addr2, 6) != 0)
      wifiHit(CAT_FLOCK, M_WIFI_OUI_RX, 1, addr3, rssi, "");
  }
}

static void wifiStart() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  wifi_promiscuous_filter_t filt = {};
  filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(wifiSniffer);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
}

// ---------------------------------------------------------------------- BLE
static Recent bleRecent[24];
static uint8_t bleCursor = 0;

static void bleHit(uint8_t cat, uint8_t method, uint8_t conf, const uint8_t* mac,
                   int8_t rssi, const char* detail) {
  bool hunted = finding && memcmp(mac, findMac, 6) == 0;
  if (!hunted && throttled(bleRecent, 24, &bleCursor, mac, method, 2000)) return;
  pushHit(cat, method, conf, mac, rssi, 0, detail);
}

static bool isTenDigits(const char* s) {
  if (strlen(s) != 10) return false;
  for (int i = 0; i < 10; i++) if (!isdigit((unsigned char)s[i])) return false;
  return true;
}

class ScanCB : public NimBLEAdvertisedDeviceCallbacks {
  NimBLEUUID flockGatt{FLOCK_GATT_UUID};
  NimBLEUUID meshtastic{MESHTASTIC_SVC_UUID};

  void onResult(NimBLEAdvertisedDevice* dev) override {
    mesh::onScanResult(dev);
    int8_t rssi = dev->getRSSI();
    if (bleDebugUntil && millis() < bleDebugUntil) {
      char nm[40] = "";
      if (dev->haveName()) sanitize(nm, sizeof(nm), (const uint8_t*)dev->getName().data(), dev->getName().size());
      char svcs[120] = "";
      for (int i = 0; i < dev->getServiceUUIDCount() && strlen(svcs) < 88; i++) {
        strlcat(svcs, dev->getServiceUUID(i).toString().c_str(), sizeof(svcs));
        strlcat(svcs, " ", sizeof(svcs));
      }
      char mfg[48] = "";
      if (dev->haveManufacturerData()) {
        std::string md = dev->getManufacturerData();
        for (size_t i = 0; i < md.size() && i < 18; i++) sprintf(mfg + i * 2, "%02x", (uint8_t)md[i]);
      }
      Serial.printf("{\"t\":\"ble\",\"addr\":\"%s\",\"at\":%d,\"rssi\":%d,\"name\":\"%s\",\"svc\":\"%s\",\"mfg\":\"%s\"}\n",
                    dev->getAddress().toString().c_str(), dev->getAddress().getType(), rssi, nm, svcs, mfg);
    }
    if (rssi < RSSI_MIN) return;
    NimBLEAddress addr = dev->getAddress();
    const uint8_t* n = addr.getNative();            // little-endian
    uint8_t mac[6] = {n[5], n[4], n[3], n[2], n[1], n[0]};
    bool flipperOui = memcmp(mac, FLIPPER_OUI, 3) == 0;   // STM radio: likely a Flipper
    char detail[48] = "";

    if (addr.getType() == BLE_ADDR_PUBLIC && memcmp(mac, AXON_OUI, 3) == 0) {
      if (dev->haveName()) {
        std::string nm = dev->getName();
        sanitize(detail, sizeof(detail), (const uint8_t*)nm.data(), nm.size());
      }
      bleHit(CAT_AXON, M_BLE_OUI, 4, mac, rssi, detail);
      return;
    }

    if (dev->haveName()) {
      std::string nm = dev->getName();
      char name[48];
      sanitize(name, sizeof(name), (const uint8_t*)nm.data(), nm.size());
      if (strncasecmp(name, "Penguin-", 8) == 0 || containsNoCase(name, "FS Ext Battery") ||
          strncasecmp(name, "Flock", 5) == 0) {
        bleHit(CAT_FLOCK, M_BLE_NAME, 4, mac, rssi, name);
        return;
      }
      if (isTenDigits(name)) {                       // alternate Penguin naming
        bleHit(CAT_FLOCK, M_BLE_NAME, 2, mac, rssi, name);
        return;
      }
      if (strncasecmp(name, "Axon", 4) == 0) {
        bleHit(CAT_AXON, M_BLE_NAME, 3, mac, rssi, name);
        return;
      }
      if (strncasecmp(name, "MeshCore", 8) == 0) {
        bleHit(CAT_MESH, M_BLE_NAME, 2, mac, rssi, name);
        return;
      }
      for (size_t k = 0; k < FLIPPER_NAME_COUNT; k++) {   // "Flipper ...", "BadKB ...", etc.
        if (containsNoCase(name, FLIPPER_NAMES[k])) {
          bleHit(CAT_ATTACK, M_FLIPPER, 4, mac, rssi, name);
          return;
        }
      }
      for (size_t k = 0; k < SKIMMER_NAME_COUNT; k++) {
        if (strncasecmp(name, SKIMMER_NAMES[k], strlen(SKIMMER_NAMES[k])) == 0) {
          bleHit(CAT_SKIMMER, M_SKIMMER, 3, mac, rssi, name);
          return;
        }
      }
      if (droneName(name)) {                           // DJI/Autel/etc. in BLE
        bleHit(CAT_DRONE, M_DRONE_SSID, 3, mac, rssi, name);
        return;
      }
      if (uint8_t tc = trackerName(name)) {            // named item trackers
        bleHit(CAT_TRACKER, M_TRACKER_NAME, tc, mac, rssi, name);
        return;
      }
    }

    for (int i = 0; i < dev->getServiceUUIDCount(); i++) {
      NimBLEUUID u = dev->getServiceUUID(i);
      if (u.bitSize() == 16) {
        uint16_t v = u.getNative()->u16.value;
        if ((v & 0xFFF0) == FLIPPER_SVC_BASE) {       // Flipper Zero, any name
          const char* color = v == 0x3081 ? "black" : v == 0x3082 ? "white" : v == 0x3083 ? "clear" : "";
          char fd[40];
          snprintf(fd, sizeof(fd), "Flipper Zero %s", color);
          bleHit(CAT_ATTACK, M_FLIPPER, 4, mac, rssi, fd);
          return;
        }
        if (v == HID_SVC_UUID && flipperOui) {        // Flipper running BadKB/BadBT keyboard injection
          bleHit(CAT_ATTACK, M_FLIPPER, 4, mac, rssi, "Flipper BadKB (fake keyboard)");
          return;
        }
        if (v >= RAVEN_SVC_MIN && v <= RAVEN_SVC_MAX) {
          snprintf(detail, sizeof(detail), "svc 0x%04X", v);
          bleHit(CAT_RAVEN, M_BLE_SVC, 3, mac, rssi, detail);
          return;
        }
        if (v == SVC_TILE || v == SVC_TILE_ALT) { bleHit(CAT_TRACKER, M_TILE, 2, mac, rssi, ""); return; }
        if (v == SVC_SMARTTAG) { bleHit(CAT_TRACKER, M_SMARTTAG, 2, mac, rssi, ""); return; }
        if (v == SVC_CHIPOLO)  { bleHit(CAT_TRACKER, M_CHIPOLO, 2, mac, rssi, ""); return; }
        if (v == SVC_META)     { bleHit(CAT_GLASSES, M_BLE_SVC, 2, mac, rssi, "Meta wearable"); return; }
      } else if (u.equals(flockGatt)) {
        bleHit(CAT_FLOCK, M_BLE_SVC, 4, mac, rssi, "Flock GATT service");
        return;
      } else if (u.equals(meshtastic)) {
        bleHit(CAT_MESH, M_MESHTASTIC, 3, mac, rssi, "Meshtastic");
        return;
      }
    }

    for (int i = 0; i < dev->getServiceDataCount(); i++) {
      NimBLEUUID u = dev->getServiceDataUUID(i);
      if (u.bitSize() != 16) continue;
      uint16_t v = u.getNative()->u16.value;
      std::string sd = dev->getServiceData(i);
      if (v == SVC_SMARTTAG) { bleHit(CAT_TRACKER, M_SMARTTAG, 2, mac, rssi, ""); return; }
      if (v == ODID_BLE_SVC && !sd.empty() && (uint8_t)sd[0] == 0x0D) {
        bleHit(CAT_DRONE, M_ODID_BLE, 4, mac, rssi, "Remote ID (BLE)");
        return;
      }
      if (v == SVC_FASTPAIR || v == SVC_NEARBY) { memcpy(bleSpamMac, mac, 6); bleSpamCount++; return; }
      if (v == SVC_EDDYSTONE && !sd.empty()) {
        uint8_t frame = (uint8_t)sd[0];
        if (frame == 0x40 || frame == 0x41) {
          bleHit(CAT_TRACKER, M_FMDN, 2, mac, rssi, "");
        } else {
          const char* kind = frame == 0x00 ? "UID" : frame == 0x10 ? "URL"
                           : frame == 0x20 ? "TLM" : frame == 0x30 ? "EID" : "?";
          bleHit(CAT_BEACON, M_EDDYSTONE, 1, mac, rssi, kind);
        }
        return;
      }
    }

    if (dev->haveManufacturerData()) {
      std::string md = dev->getManufacturerData();
      if (md.size() < 2) return;
      const uint8_t* d = (const uint8_t*)md.data();
      uint16_t cid = d[0] | (d[1] << 8);
      if (cid == BLE_CID_XUNTONG) {
        sanitize(detail, sizeof(detail), d + 2, md.size() - 2);
        bleHit(CAT_FLOCK, M_BLE_MFG, 3, mac, rssi, detail);
      } else if (cid == BLE_CID_APPLE && md.size() >= 25 && d[2] == 0x02 && d[3] == 0x15) {
        char* o = detail;
        for (int k = 0; k < 16; k++) o += sprintf(o, "%02X", d[4 + k]);
        snprintf(o, sizeof(detail) - 32, " %u/%u", (d[20] << 8) | d[21], (d[22] << 8) | d[23]);
        bleHit(CAT_BEACON, M_IBEACON, 1, mac, rssi, detail);
      } else if (cid == BLE_CID_APPLE && md.size() >= 4 && d[2] == 0x12 && d[3] == 0x19) {
        // Long Find My frame: the tag is away from its owner's phone.
        bleHit(CAT_TRACKER, M_FINDMY, 2, mac, rssi, "separated from owner");
      } else if (cid == BLE_CID_APPLE && md.size() >= 4 &&
                 (d[2] == APPLE_PROX_PAIR || d[2] == APPLE_NEARBY_ACT)) {
        // These Continuity sub-types are what BLE-spam tools flood; the rate
        // test in loop() decides, since one real device emits them too.
        memcpy(bleSpamMac, mac, 6);
        bleSpamCount++;
      } else if (cid == BLE_CID_META || cid == BLE_CID_META_TECH) {
        bleHit(CAT_GLASSES, M_BLE_MFG, 2, mac, rssi, "Meta wearable");
      }
    }

    // Nothing specific matched, but the radio is an ST part like the Flipper's.
    // Too broad to alarm on, so it is listed quietly at low confidence.
    if (flipperOui) bleHit(CAT_ATTACK, M_FLIPPER, 2, mac, rssi, "STM radio (maybe Flipper)");
  }
};

class ServerCB : public NimBLEServerCallbacks {
  void onConnect(NimBLEServer*, ble_gap_conn_desc*) override {
    appMtu = 23;
    appConnected = true;
  }
  void onDisconnect(NimBLEServer*) override {
    appConnected = false;
    if (!stealthOn) NimBLEDevice::startAdvertising();
  }
  void onMTUChange(uint16_t mtu, ble_gap_conn_desc*) override { appMtu = mtu; }
};

class RxCB : public NimBLECharacteristicCallbacks {
  void onWrite(NimBLECharacteristic* c) override {
    std::string v = c->getValue();
    if (v.rfind("list", 0) == 0) wantList = true;
    else if (v.rfind("clear", 0) == 0) wantClear = true;
    else if (v.rfind("mute 1", 0) == 0) muted = true;
    else if (v.rfind("mute 0", 0) == 0) muted = false;
    else if (v.rfind("canary ", 0) == 0) { strlcpy(canaryPending, v.c_str() + 7, sizeof(canaryPending)); wantCanary = true; }
    else if (v == "canary") { canaryPending[0] = '\0'; wantCanary = true; }
  }
};

static void bleStart() {
  NimBLEDevice::init("MeshWatch");
  NimBLEDevice::setMTU(247);

  NimBLEServer* server = NimBLEDevice::createServer();
  server->setCallbacks(new ServerCB());
  NimBLEService* svc = server->createService(SVC_UUID);
  txChr = svc->createCharacteristic(TX_UUID, NIMBLE_PROPERTY::NOTIFY);
  NimBLECharacteristic* rx =
      svc->createCharacteristic(RX_UUID, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR);
  rx->setCallbacks(new RxCB());
  svc->start();

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->addServiceUUID(SVC_UUID);
  adv->setScanResponse(true);
  adv->start();

  // Active scanning is needed to read device names, which several signatures
  // depend on. The 50% duty cycle leaves the shared radio free for WiFi.
  NimBLEScan* scan = NimBLEDevice::getScan();
  scan->setAdvertisedDeviceCallbacks(new ScanCB(), true);
  scan->setActiveScan(true);
  scan->setInterval(160);
  scan->setWindow(80);
  scan->setMaxResults(0);
  scan->start(0, nullptr, false);
}

// Stealth: stop emitting detectable RF. Active scanning sends scan requests and
// our GATT server advertises "MeshWatch", so both are turned off; WiFi stays
// receive-only and the radio link is a low-duty connection, not a beacon.
static void applyStealth() {
  NimBLEScan* scan = NimBLEDevice::getScan();
  scan->stop();
  scan->setActiveScan(!stealthOn);
  scan->start(0, nullptr, false);
  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  if (stealthOn) adv->stop();
  else if (!appConnected) adv->start();
  if (stealthOn) muted = true;
}

// ------------------------------------------------------------------- output
static void sendLine(const char* line) {
  Serial.println(line);
  if (!appConnected || !txChr) return;
  size_t len = strlen(line);
  size_t chunk = appMtu > 23 ? (size_t)appMtu - 3 : 20;
  for (size_t off = 0; off <= len; off += chunk) {
    size_t n = len - off;
    bool last = n < chunk;
    if (!last) n = chunk;
    uint8_t buf[250];
    memcpy(buf, line + off, n);
    if (last) buf[n++] = '\n';
    txChr->setValue(buf, n);
    txChr->notify();
    delay(4);
    if (last) break;
  }
}

static void emitDev(const Dev& d, const char* ev) {
  uint32_t now = millis();
  char line[320];
  snprintf(line, sizeof(line),
    "{\"t\":\"det\",\"ev\":\"%s\",\"id\":%u,\"cat\":\"%s\",\"m\":\"%s\",\"lbl\":\"%s\","
    "\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"rssi\":%d,\"pk\":%d,\"conf\":%u,"
    "\"n\":%lu,\"ch\":%u,\"age\":%lu,\"dur\":%lu,\"persist\":%d,\"rot\":%d,\"hp\":%d,\"lat\":%.6f,\"lon\":%.6f,\"d\":\"%s\"}",
    ev, d.id, CAT_KEY[d.cat], METHOD_KEY[d.method], labelFor(d.cat, d.method),
    d.mac[0], d.mac[1], d.mac[2], d.mac[3], d.mac[4], d.mac[5], d.rssi, d.peak, d.conf,
    (unsigned long)d.count, d.ch, (unsigned long)((now - d.last) / 1000),
    (unsigned long)((d.last - d.first) / 1000), d.persist ? 1 : 0, d.rotated ? 1 : 0,
    d.hasPos ? 1 : 0, d.hasPos ? d.lat : 0, d.hasPos ? d.lon : 0, d.detail);
  sendLine(line);
}

static int activeCount(uint8_t cat) {
  uint32_t now = millis();
  int n = 0;
  for (auto& d : devs) if (d.used && d.cat == cat && now - d.last < ACTIVE_MS) n++;
  return n;
}

static void emitStatus() {
  char line[200];
  snprintf(line, sizeof(line),
    "{\"t\":\"st\",\"fw\":\"%s\",\"up\":%lu,\"bat\":%d,\"mute\":%d,\"ch\":%u,"
    "\"flock\":%d,\"raven\":%d,\"axon\":%d,\"tracker\":%d,\"glasses\":%d,\"beacon\":%d}",
    FW_VERSION, (unsigned long)(millis() / 1000), (int)M5.Power.getBatteryLevel(), muted ? 1 : 0,
    curChannel, activeCount(CAT_FLOCK), activeCount(CAT_RAVEN), activeCount(CAT_AXON),
    activeCount(CAT_TRACKER), activeCount(CAT_GLASSES), activeCount(CAT_BEACON));
  sendLine(line);
}

static void alertSound(uint8_t cat, bool persist) {
  if (muted) return;
  if (persist) {
    M5.Speaker.tone(1800, 120);
    M5.Speaker.tone(1800, 120, -1, false);
    M5.Speaker.tone(1800, 120, -1, false);
    return;
  }
  // A distinct signature per threat class, so the category is recognisable by
  // ear without looking at the screen.
  switch (cat) {
    case CAT_FLOCK:                         // rising two-tone: fixed ALPR camera
    case CAT_RAVEN:
      M5.Speaker.tone(2000, 70);
      M5.Speaker.tone(2800, 110, -1, false);
      break;
    case CAT_AXON:                          // double chirp: body cam
      M5.Speaker.tone(2600, 70);
      M5.Speaker.tone(2600, 70, -1, false);
      break;
    case CAT_TRACKER:                       // soft low-high pair: item tracker
      M5.Speaker.tone(1200, 90);
      M5.Speaker.tone(1700, 90, -1, false);
      break;
    case CAT_GLASSES:                       // high single: wearable camera
      M5.Speaker.tone(3200, 120);
      break;
    case CAT_DEAUTH:                         // low buzz: active WiFi attack
      M5.Speaker.tone(900, 250);
      break;
    case CAT_ROGUE:                          // warble: rogue AP / Pineapple
      M5.Speaker.tone(1500, 70);
      M5.Speaker.tone(1050, 70, -1, false);
      M5.Speaker.tone(1500, 70, -1, false);
      break;
    case CAT_ATTACK:                         // fast triple high: Flipper / spam
      M5.Speaker.tone(3000, 55);
      M5.Speaker.tone(3000, 55, -1, false);
      M5.Speaker.tone(3000, 55, -1, false);
      break;
    case CAT_SKIMMER:                        // low double: card-skimmer module
      M5.Speaker.tone(1000, 90);
      M5.Speaker.tone(1000, 90, -1, false);
      break;
    case CAT_CAMERA:                         // mid falling: WiFi camera
      M5.Speaker.tone(2400, 80);
      M5.Speaker.tone(1800, 110, -1, false);
      break;
    case CAT_DRONE:                          // rising sweep feel: drone
      M5.Speaker.tone(1600, 60);
      M5.Speaker.tone(2200, 60, -1, false);
      M5.Speaker.tone(2800, 90, -1, false);
      break;
    case CAT_CANARY:                         // urgent high-low: evil twin / bait
      M5.Speaker.tone(3400, 90);
      M5.Speaker.tone(2000, 130, -1, false);
      break;
    default:
      M5.Speaker.tone(1400, 60);
  }
}

// -------------------------------------------------------------------- table
static int findDev(const Hit& h) {
  for (int i = 0; i < MAX_DEVS; i++)
    if (devs[i].used && devs[i].cat == h.cat && memcmp(devs[i].mac, h.mac, 6) == 0) return i;
  return -1;
}

// No exact MAC match: look for the same unit under a rotated address. Match on
// the identity fingerprint, but only when the candidate's current address has
// gone quiet (its advertising stopped), which is what a rotation looks like;
// two of the same device advertising at once both stay active and are not
// merged. Returns its index (caller adopts the new MAC), or -1.
#define ROTATE_QUIET_MS 4000
static int findDevRotated(const Hit& h) {
  if (!h.fp) return -1;
  uint32_t now = millis();
  int best = -1;
  for (int i = 0; i < MAX_DEVS; i++) {
    Dev& d = devs[i];
    if (!d.used || d.cat != h.cat || d.fp != h.fp) continue;
    if (memcmp(d.mac, h.mac, 6) == 0) continue;
    if (now - d.last < ROTATE_QUIET_MS) continue;          // still active = a twin
    if (best < 0 || (int32_t)(d.last - devs[best].last) > 0) best = i;
  }
  return best;
}

// Free slot, else the stalest entry, preferring to evict non-threats.
static int allocDev() {
  int victim = -1;
  bool victimThreat = true;
  for (int i = 0; i < MAX_DEVS; i++) {
    if (!devs[i].used) return i;
    bool t = isThreat(devs[i].cat);
    if (victim < 0 || (victimThreat && !t) ||
        (victimThreat == t && (int32_t)(devs[i].last - devs[victim].last) < 0)) {
      victim = i;
      victimThreat = t;
    }
  }
  return victim;
}

static void wake() {
  lastInput = millis();
  if (asleep) {
    asleep = false;
    M5.Display.setBrightness(brightness);
  }
}

static void raise(int idx, bool persist) {
  wake();
  bannerDev = idx;
  bannerConv = -1;
  bannerConvoy = 0;
  devs[idx].fwdPending = true;
  bannerUntil = millis() + BANNER_MS;
  const Dev& rd = devs[idx];
  if (closeAlarm && !muted && isThreat(rd.cat) && rd.rssi >= CLOSE_RSSI) {
    M5.Speaker.tone(3000, 90);                       // urgent: threat is very close
    M5.Speaker.tone(2200, 90, -1, false);
    M5.Speaker.tone(3000, 90, -1, false);
  } else {
    alertSound(rd.cat, persist);
  }
}

static void handleHit(const Hit& h) {
  if (!(scanMask & (1 << h.cat))) return;
  uint32_t now = millis();
  int i = findDev(h);
  bool fresh = false;
  bool upgraded = false;

  if (i < 0) {                                   // same unit under a rotated MAC?
    i = findDevRotated(h);
    if (i >= 0) { memcpy(devs[i].mac, h.mac, 6); devs[i].rotated = true; }
  }
  if (i < 0) {
    i = allocDev();
    Dev& d = devs[i];
    memset(&d, 0, sizeof(d));
    d.used = true;
    d.id = nextId++;
    d.cat = h.cat; d.method = h.method; d.conf = h.conf;
    memcpy(d.mac, h.mac, 6);
    d.fp = h.fp;
    d.first = now;
    d.peak = h.rssi;
    d.lastMinute = UINT32_MAX;
    strlcpy(d.detail, h.detail, sizeof(d.detail));
    fresh = true;
  }

  Dev& d = devs[i];
  if (!fresh && now - d.last > REDISCOVER_MS) fresh = true;
  if (h.conf > d.conf) {
    upgraded = d.conf < CONF_ALERT && h.conf >= CONF_ALERT;
    d.conf = h.conf;
    d.method = h.method;
    if (h.detail[0]) strlcpy(d.detail, h.detail, sizeof(d.detail));
  } else if (!d.detail[0] && h.detail[0]) {
    strlcpy(d.detail, h.detail, sizeof(d.detail));
  }
  d.rssi = h.rssi;
  if (h.rssi > d.peak) d.peak = h.rssi;
  d.ch = h.ch;
  d.last = now;
  d.count++;

  uint16_t mh = macHash(h.mac);
  if (baselineState == BL_LEARNING) blAdd(mh);
  d.known = baselineState == BL_ACTIVE && blKnown(mh);
  d.ign = ignored(mh);
  double gla, glo;
  if (mesh::pos(&gla, &glo)) {
    d.lat = gla; d.lon = glo; d.hasPos = true;
    if (!d.hadFirstPos) { d.firstLat = gla; d.firstLon = glo; d.hadFirstPos = true; }
    else {
      float m = distM(d.firstLat, d.firstLon, (float)gla, (float)glo);
      if (m > d.movedM) d.movedM = m;
    }
  }

  uint32_t minute = now / 60000;
  bool nowPersistent = false;
  if (minute != d.lastMinute) {
    d.lastMinute = minute;
    d.minutes++;
    if (!d.persist && isFollowing(d)) {
      d.persist = true;
      nowPersistent = true;
    }
  }

  bool suppress = (baselineState == BL_ACTIVE && d.known) || d.ign;
  if (nowPersistent && !suppress) {
    raise(i, true);
    d.lastEmit = now;
    emitDev(d, "persist");
  } else if (fresh || upgraded) {
    bool doAlert;
    if (d.ign) doAlert = false;
    else if (baselineState == BL_ACTIVE) doAlert = fresh && !d.known;   // anything new to the area
    else doAlert = isThreat(d.cat) && d.conf >= CONF_ALERT;
    if (doAlert) {
      d.isNew = baselineState == BL_ACTIVE && !d.known;
      raise(i, false);
    }
    d.lastEmit = now;
    emitDev(d, "new");
  } else if (now - d.lastEmit > UPDATE_EMIT_MS) {
    d.lastEmit = now;
    emitDev(d, "upd");
  }
}

// ----------------------------------------------------------------------- UI
enum Screen : uint8_t { SCR_DETECT, SCR_MESH, SCR_THREAD, SCR_COMPOSE, SCR_TYPE, SCR_SETTINGS, SCR_PICK, SCR_SCAN, SCR_FIND, SCR_TRACK, SCR_BASELINE, SCR_RADAR, SCR_SUMMARY };
static Screen screen = SCR_DETECT;
static int sel = 0;                 // cursor in the current list
static int curConv = -1;
static int scroll = 0;              // thread scroll, in lines
static bool threadTop = false;

// Preset messages are Dutch on purpose; the interface itself stays English.
static const char* const CANNED[] = {
  "[ type a message ]", "OK", "Ja", "Nee", "Ik kom eraan", "Waar ben je?", "Bel me",
  "Hulp nodig", "Alles veilig", "Camera gezien hier", "Aangekomen in Oud-Turnhout",
};
static const int CANNED_COUNT = sizeof(CANNED) / sizeof(CANNED[0]);

// Text entry. \x01 = accept, \x02 = cancel.
static const char CHARS_TEXT[] = "\x01\x02 abcdefghijklmnopqrstuvwxyz0123456789.,?!'-:/@";
static const char CHARS_PIN[]  = "0123456789\x01\x02";
static char typed[MESH_TEXT_MAX + 1];
static int typedLen = 0, charIdx = 0;
enum { TYPE_MSG, TYPE_RADIO_PIN, TYPE_LOCK_PIN, TYPE_DURESS_PIN, TYPE_UNLOCK };
static uint8_t typePurpose = TYPE_MSG;
static bool typingPin = false;

// Device lock: an optional unlock code. A separate duress code unlocks too but
// first wipes the radio pairing and baseline. Off by default; a USB "lockoff"
// command clears it, so the device can never be locked for good.
static bool lockOn = false;
static uint32_t lockPin = 0, duressPin = 0;
static bool locked = false;

#define COL_DIM   0x7BEF
#define COL_FAINT 0x4208
#define COL_OK    0x07E0
#define COL_MINE  0x9FF3
#define COL_BAD   0xF9A6
#define COL_BRAND 0x3EF2   // MeshWatch green (#3ddc97)
#define COL_AMBER 0xFE60

static const char* meshStateText() {
  switch (mesh::state()) {
    case mesh::SEARCHING:
      return mesh::hasRadio() ? "Searching for your radio" : "No radio chosen: see settings";
    case mesh::CONNECTING:  return "Connecting to radio";
    case mesh::PAIR_FAILED: return "Pairing failed: check the PIN";
    case mesh::SYNCING:     return "Syncing with radio";
    default:                return "";
  }
}

static void drawHeader(const char* title) {
  canvas.setFont(&fonts::Font0);
  canvas.setTextDatum(top_left);
  canvas.fillRect(0, 0, 240, 14, 0x18E3);
  canvas.setTextColor(TFT_WHITE);
  char t[22];
  strlcpy(t, title, sizeof(t));
  canvas.drawString(t, 4, 3);

  mesh::State ms = mesh::state();
  canvas.setTextColor(ms == mesh::READY ? COL_OK : ms == mesh::PAIR_FAILED ? COL_BAD : COL_DIM);
  canvas.drawString(ms == mesh::READY ? "MESH" : ms == mesh::PAIR_FAILED ? "PIN?" : "mesh", 136, 3);
  int unread = mesh::unreadTotal();
  char buf[24];
  if (unread) {
    snprintf(buf, sizeof(buf), "%d", unread);
    canvas.fillRoundRect(163, 2, 6 * strlen(buf) + 6, 10, 3, COL_BAD);
    canvas.setTextColor(TFT_BLACK);
    canvas.drawString(buf, 166, 3);
  }
  uint32_t e = mesh::epoch();
  if (muted) {
    canvas.setTextColor(COL_BAD);
    canvas.drawString("MUTE", 186, 3);
  } else if (e) {
    time_t t = e;
    struct tm tm;
    localtime_r(&t, &tm);
    snprintf(buf, sizeof(buf), "%02d:%02d", tm.tm_hour, tm.tm_min);
    canvas.setTextColor(COL_DIM);
    canvas.drawString(buf, 177, 3);
  }
  // battery icon, coloured by level (green / amber / red), filled proportionally
  int bl = constrain((int)M5.Power.getBatteryLevel(), 0, 100);
  bool charging = M5.Power.isCharging();
  uint16_t bc = charging ? COL_OK : bl > 50 ? COL_OK : bl > 20 ? COL_AMBER : COL_BAD;
  const int bx = 219, by = 3, bw = 17, bh = 9;
  canvas.drawRect(bx, by, bw, bh, COL_DIM);
  canvas.fillRect(bx + bw, by + 2, 2, bh - 4, COL_DIM);       // positive nub
  int fw = (bw - 2) * bl / 100;
  if (fw > 0) canvas.fillRect(bx + 1, by + 1, fw, bh - 2, bc);
  if (charging) {                                             // small charge tick
    canvas.setTextColor(TFT_BLACK);
    canvas.drawString("+", bx + 6, by + 1);
  }
}

static void drawHint(const char* hint) {
  canvas.setFont(&fonts::Font0);
  canvas.setTextColor(COL_FAINT);
  canvas.drawFastHLine(0, 123, 240, 0x2104);
  canvas.drawString(hint, 4, 126);
}

static void drawBanner() {
  canvas.setTextDatum(middle_center);
  char line[48];
  if (bannerConvoy > 0) {
    canvas.fillScreen(0xC800);                        // deep red
    canvas.setTextColor(TFT_WHITE);
    canvas.setFont(&fonts::FreeSansBold12pt7b);
    canvas.drawString("CONVOY", 120, 28);
    canvas.setFont(&fonts::FreeSansBold9pt7b);
    canvas.drawString("possible team tail", 120, 52);
    canvas.setFont(&fonts::FreeSans9pt7b);
    snprintf(line, sizeof(line), "%d units shadowing you", bannerConvoy);
    canvas.drawString(line, 120, 78);
    canvas.setFont(&fonts::Font0);
    canvas.drawString("open Radar to see them", 120, 104);
    canvas.setTextDatum(top_left);
    return;
  }
  if (bannerConv >= 0) {
    const mesh::Conv& c = mesh::conv(bannerConv);
    const mesh::Msg* m = mesh::message(bannerConv, 0);
    canvas.fillScreen(bannerTeam ? 0x9800 : 0x0397);
    canvas.setTextColor(TFT_WHITE);
    canvas.setFont(&fonts::FreeSansBold9pt7b);
    if (bannerTeam) canvas.drawString("TEAM ALERT", 120, 12);
    snprintf(line, sizeof(line), "%s%s", c.channel ? "# " : "", c.name);
    canvas.drawString(line, 120, 26);
    canvas.setFont(&fonts::Font0);
    if (m) {
      for (int l = 0; l < 4 && (int)strlen(m->text) > l * 36; l++) {
        strlcpy(line, m->text + l * 36, 37);
        canvas.drawString(line, 120, 58 + l * 13);
      }
    }
  } else {
    const Dev& d = devs[bannerDev];
    canvas.fillScreen(catColor(d.cat));
    canvas.setTextColor(TFT_BLACK);
    canvas.setFont(&fonts::FreeSansBold12pt7b);
    canvas.drawString(d.persist ? "FOLLOWING YOU" : labelFor(d.cat, d.method), 120, 36);
    canvas.setFont(&fonts::FreeSansBold9pt7b);
    if (d.persist) canvas.drawString(labelFor(d.cat, d.method), 120, 58);
    else if (d.isNew) canvas.drawString("NEW IN AREA", 120, 58);
    canvas.setFont(&fonts::FreeSans9pt7b);
    snprintf(line, sizeof(line), "%d dBm   conf %u/4", d.rssi, d.conf);
    canvas.drawString(line, 120, 78);
    canvas.setFont(&fonts::Font0);
    char fb[48];
    const char* det = d.detail;
    if (d.persist) {
      if (d.hadFirstPos && d.movedM >= FOLLOW_MOVE_M)
        snprintf(fb, sizeof(fb), "stayed ~%dm as you moved, %um", (int)d.movedM, d.minutes);
      else
        snprintf(fb, sizeof(fb), "in range %u separate minutes", d.minutes);
      det = fb;
    }
    if (det[0]) canvas.drawString(det, 120, 104);
    snprintf(line, sizeof(line), "%02x:%02x:%02x:%02x:%02x:%02x  %s", d.mac[0], d.mac[1], d.mac[2],
             d.mac[3], d.mac[4], d.mac[5], METHOD_KEY[d.method]);
    canvas.drawString(line, 120, 120);
  }
  canvas.setTextDatum(top_left);
}

static void drawDetect() {
  uint32_t now = millis();
  char buf[40];
  int on = 0;
  for (int c = 0; c < CAT_COUNT; c++) on += (scanMask >> c) & 1;
  if (scanMask == SCAN_ALL) snprintf(buf, sizeof(buf), "DETECT all ch%u", curChannel);
  else snprintf(buf, sizeof(buf), "DETECT %d of %d ch%u", on, (int)CAT_COUNT, curChannel);
  drawHeader(buf);

  // counters: devices in range per category
  static const uint8_t cats[] = {CAT_FLOCK, CAT_AXON, CAT_RAVEN, CAT_TRACKER, CAT_GLASSES, CAT_BEACON};
  for (int c = 0; c < 6; c++) {
    int n = activeCount(cats[c]);
    int x = c * 40;
    bool scanned = scanMask & (1 << cats[c]);
    canvas.setTextColor(n ? catColor(cats[c]) : COL_FAINT);
    canvas.setFont(&fonts::FreeSansBold9pt7b);
    if (scanned) snprintf(buf, sizeof(buf), "%d", n);
    else strcpy(buf, "-");
    canvas.drawCentreString(buf, x + 20, 18);
    canvas.setFont(&fonts::Font0);
    canvas.drawCentreString(CAT_SHORT[cats[c]], x + 20, 36);
  }
  canvas.drawFastHLine(0, 47, 240, 0x2104);

  // most recent detections
  bool shown[MAX_DEVS] = {};
  int y = 51;
  for (int row = 0; row < 7; row++) {
    int best = -1;
    for (int i = 0; i < MAX_DEVS; i++) {
      const Dev& d = devs[i];
      if (!d.used || shown[i]) continue;
      if (best < 0 || (int32_t)(d.last - devs[best].last) > 0) best = i;
    }
    if (best < 0) break;
    shown[best] = true;
    const Dev& d = devs[best];
    bool live = now - d.last < ACTIVE_MS;
    uint16_t col = live ? catColor(d.cat) : COL_FAINT;
    canvas.fillRect(0, y, 3, 10, col);
    canvas.setTextColor(col);
    canvas.drawString(CAT_SHORT[d.cat], 6, y + 1);
    canvas.setTextColor(live ? TFT_WHITE : COL_DIM);
    char text[24];
    if (d.detail[0]) strlcpy(text, d.detail, sizeof(text));
    else snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x", d.mac[0], d.mac[1],
                  d.mac[2], d.mac[3], d.mac[4], d.mac[5]);
    canvas.drawString(text, 46, y + 1);
    uint32_t age = (now - d.last) / 1000;
    if (age < 100) snprintf(buf, sizeof(buf), "%d %c%u %2lus", d.rssi, d.persist ? '!' : 'c',
                            d.conf, (unsigned long)age);
    else snprintf(buf, sizeof(buf), "%d %c%u %2lum", d.rssi, d.persist ? '!' : 'c', d.conf,
                  (unsigned long)(age / 60));
    canvas.drawRightString(buf, 238, y + 1);
    y += 12;
  }
  if (y == 51) {
    canvas.setTextColor(COL_FAINT);
    canvas.drawCentreString(scanMask ? "nothing detected" : "scanning is off: press B", 120, 78);
    canvas.drawCentreString("A mute   B menu   hold B: messages", 120, 118);
  }
}

// Draws a scrolling list of n rows; row(i, buf, &right, &color) fills the text.
template <typename F>
static void drawRows(int n, int top, int rows, F row) {
  int first = sel - rows / 2;
  if (first > n - rows) first = n - rows;
  if (first < 0) first = 0;
  for (int r = 0; r < rows && first + r < n; r++) {
    int i = first + r, y = top + r * 13;
    char left[44] = "", right[24] = "";
    uint16_t col = TFT_WHITE;
    row(i, left, right, &col);
    if (i == sel) canvas.fillRect(0, y - 2, 240, 13, 0x2145);
    canvas.setTextColor(col);
    canvas.drawString(left, 6, y);
    canvas.drawRightString(right, 236, y);
  }
}

static void drawMesh() {
  drawHeader("MESSAGES");
  int ord[MESH_MAX_CONVS];
  int n = mesh::order(ord);
  if (sel >= n) sel = n ? n - 1 : 0;
  int top = 19, rows = 8;
  if (mesh::state() != mesh::READY) {
    canvas.setTextColor(mesh::state() == mesh::PAIR_FAILED ? COL_BAD : COL_DIM);
    canvas.drawString(meshStateText(), 6, 19);
    top = 33;
    rows = 7;
  }
  drawRows(n, top, rows, [&](int i, char* left, char* right, uint16_t* col) {
    const mesh::Conv& c = mesh::conv(ord[i]);
    snprintf(left, 36, "%c %s", c.channel ? '#' : '@', c.name);
    if (c.unread) { snprintf(right, 16, "%u new", c.unread); *col = COL_MINE; }
  });
  if (!n && mesh::state() == mesh::READY) {
    canvas.setTextColor(COL_FAINT);
    canvas.drawCentreString("no channels or contacts on the radio", 120, 60);
  }
  drawHint("A open   B next   hold B: settings");
}

static void drawThread() {
  const mesh::Conv& c = mesh::conv(curConv);
  char title[28];
  snprintf(title, sizeof(title), "%c %s", c.channel ? '#' : '@', c.name);
  drawHeader(title);
  mesh::markRead(curConv);

  const int per = 38;
  int skip = scroll, y = 111;
  threadTop = false;
  for (int n = 0; y >= 17; n++) {
    const mesh::Msg* m = mesh::message(curConv, n);
    if (!m) { threadTop = true; break; }
    int len = strlen(m->text);
    int lines = len ? (len + per - 1) / per : 1;
    bool mine = m->state != mesh::MS_IN;
    for (int l = lines - 1; l >= 0 && y >= 17; l--) {
      if (skip > 0) { skip--; continue; }
      char buf[per + 1];
      strlcpy(buf, m->text + l * per, sizeof(buf));
      canvas.setTextColor(m->state == mesh::MS_FAILED ? COL_BAD : mine ? COL_MINE : TFT_WHITE);
      canvas.drawString(buf, 10, y);
      if (l == 0 && mine) {
        const char* mark = m->state == mesh::MS_QUEUED ? "." : m->state == mesh::MS_SENT ? ">"
                         : m->state == mesh::MS_DELIVERED ? "*" : "!";
        canvas.drawString(mark, 2, y);
      }
      y -= 11;
    }
  }
  if (y == 111 && !scroll) {
    canvas.setTextColor(COL_FAINT);
    canvas.drawCentreString("no messages yet", 120, 60);
  }
  drawHint(mesh::state() == mesh::READY ? "A write   B older   hold B: back"
                                        : "radio offline   B older   hold B: back");
}

static void drawCompose() {
  char title[28];
  snprintf(title, sizeof(title), "TO %s", mesh::conv(curConv).name);
  drawHeader(title);
  drawRows(CANNED_COUNT, 19, 8, [&](int i, char* left, char*, uint16_t* col) {
    strlcpy(left, CANNED[i], 40);
    if (i == 0) *col = COL_MINE;
  });
  drawHint("A send   B next   hold B: back");
}

static void drawType() {
  const char* set = typingPin ? CHARS_PIN : CHARS_TEXT;
  int n = strlen(set);
  const char* title = typePurpose == TYPE_MSG ? "WRITE"
                    : typePurpose == TYPE_RADIO_PIN ? "RADIO PIN"
                    : typePurpose == TYPE_LOCK_PIN ? "SET UNLOCK CODE"
                    : typePurpose == TYPE_DURESS_PIN ? "SET DURESS CODE"
                    : "ENTER CODE TO UNLOCK";
  drawHeader(title);

  // text so far, last three lines
  const int per = 38;
  int lines = typedLen / per + 1;
  int first = lines > 3 ? lines - 3 : 0;
  canvas.setTextColor(TFT_WHITE);
  for (int l = first; l < lines; l++) {
    char buf[per + 2];
    strlcpy(buf, typed + l * per, per + 1);
    if (l == lines - 1) strlcat(buf, "_", sizeof(buf));
    canvas.drawString(buf, 6, 20 + (l - first) * 11);
  }

  // character strip
  for (int off = -3; off <= 3; off++) {
    char ch = set[((charIdx + off) % n + n) % n];
    const char* label;
    char one[2] = {ch, 0};
    if (ch == '\x01') label = typingPin ? "SAVE" : "SEND";
    else if (ch == '\x02') label = "ESC";
    else if (ch == ' ') label = "SPC";
    else label = one;
    int x = 120 + off * 26;
    if (off == 0) {
      canvas.fillRoundRect(96, 62, 48, 44, 5, 0x2145);
      canvas.drawRoundRect(96, 62, 48, 44, 5, COL_OK);
      canvas.setTextColor(TFT_WHITE);
      canvas.setFont(strlen(label) > 1 ? &fonts::FreeSansBold9pt7b : &fonts::FreeSansBold18pt7b);
      canvas.setTextDatum(middle_center);
      canvas.drawString(label, 120, 84);
      canvas.setTextDatum(top_left);
      canvas.setFont(&fonts::Font0);
    } else {
      x += off < 0 ? -12 : 12;
      canvas.setTextColor(COL_DIM);
      canvas.drawCentreString(label, x, 80);
    }
  }
  drawHint("A pick, hold: del   B next, hold: fast");
}

#define SETTING_COUNT 15
static void drawSettings() {
  drawHeader("SETTINGS");
  drawRows(SETTING_COUNT, 19, 8, [&](int i, char* left, char* right, uint16_t* col) {
    switch (i) {
      case 0:
        strlcpy(left, "Radio", 40);
        if (mesh::state() == mesh::READY || mesh::state() == mesh::SYNCING)
          strlcpy(right, mesh::radioName()[0] ? mesh::radioName() : "connected", 16);
        else if (!mesh::hasRadio()) strlcpy(right, "choose", 16);
        else snprintf(right, 24, "%s %.12s", mesh::state() == mesh::PAIR_FAILED ? "bad PIN" : "search",
                      mesh::savedName());
        break;
      case 1:
        strlcpy(left, "Radio PIN", 40);
        snprintf(right, 16, "%06lu", (unsigned long)mesh::pin());
        break;
      case 2:
        strlcpy(left, "Forward alerts to mesh", 40);
        strlcpy(right, fwdOn ? "on" : "off", 16);
        if (fwdOn) *col = COL_MINE;
        break;
      case 3: {
        strlcpy(left, "Forward to channel", 40);
        snprintf(right, 16, "#%u", fwdCh);
        for (int k = 0; k < MESH_MAX_CONVS; k++) {
          const mesh::Conv& c = mesh::conv(k);
          if (c.used && c.channel && c.chIdx == fwdCh) snprintf(right, 16, "#%s", c.name);
        }
        break;
      }
      case 4: {
        strlcpy(left, "Announce me on the mesh", 40);
        mesh::Announce an = mesh::announceState();
        strlcpy(right, an == mesh::AN_SENDING ? "sending" : an == mesh::AN_SENT ? "sent"
                     : an == mesh::AN_FAILED ? "failed" : "press A", 16);
        if (an == mesh::AN_SENT) *col = COL_MINE;
        if (an == mesh::AN_FAILED) *col = COL_BAD;
        break;
      }
      case 5:
        strlcpy(left, "Sound", 40);
        strlcpy(right, muted ? "muted" : "on", 16);
        break;
      case 6:
        strlcpy(left, "Brightness", 40);
        snprintf(right, 16, "%u", brightness);
        break;
      case 7:
        strlcpy(left, "Screen off after", 40);
        if (screenOffSecs) snprintf(right, 16, "%u s", screenOffSecs);
        else strlcpy(right, "never", 16);
        break;
      case 8:
        strlcpy(left, "Stealth (no RF beacon)", 40);
        strlcpy(right, stealthOn ? "on" : "off", 16);
        if (stealthOn) *col = COL_OK;
        break;
      case 9:
        strlcpy(left, "Device lock", 40);
        strlcpy(right, lockOn ? "on" : "set code", 16);
        if (lockOn) *col = COL_OK;
        break;
      case 10:
        strlcpy(left, "Duress wipe code", 40);
        strlcpy(right, duressPin ? "set" : "off", 16);
        if (duressPin) *col = COL_MINE;
        break;
      case 11:
        strlcpy(left, "Auto-report to mesh (5m)", 40);
        strlcpy(right, reportOn ? "on" : "off", 16);
        if (reportOn) *col = COL_MINE;
        break;
      case 12:
        strlcpy(left, "Close-range alarm", 40);
        strlcpy(right, closeAlarm ? "on" : "off", 16);
        if (closeAlarm) *col = COL_MINE;
        break;
      case 13:
        strlcpy(left, "Silenced devices", 40);
        snprintf(right, 16, ignCount ? "%u - clear" : "none", ignCount);
        break;
      case 14:
        strlcpy(left, "Canary SSID", 40);
        if (!canarySsid[0]) strlcpy(right, "set in app", 16);
        else { strlcpy(right, canaryOn ? canarySsid : "off", 16); }
        if (canaryOn && canarySsid[0]) *col = COL_MINE;
        break;
    }
  });
  drawHint(sel == 0 ? "A choose radio   hold A: forget" : "A change   B next   hold B: detect");
}

static const char* const SCAN_NAME[CAT_COUNT] = {
  "Flock cameras", "Raven gunshot sensors", "Axon body cams / Tasers", "Trackers (AirTag, Tile...)",
  "Smart glasses", "WiFi deauth attacks", "Beacons (iBeacon...)", "MeshCore radios nearby",
  "Rogue access points", "Attack tools (Flipper...)", "Card skimmers (HC-05...)",
  "WiFi cameras (Ring/Wyze...)", "Drones (Remote ID)", "Canary SSID (your bait name)",
};

// Rows 0-1 are apps, row 2 is "Scan all", rows 3.. are the categories.
#define MENU_APPS 5
#define MENU_ROWS (CAT_COUNT + 1 + MENU_APPS)
static void drawScan() {
  drawHeader("MENU");
  drawRows(MENU_ROWS, 19, 8, [&](int i, char* left, char* right, uint16_t* col) {
    if (i == 0) {
      strlcpy(left, " >  MeshCore messages", 40);
      int unread = mesh::unreadTotal();
      if (unread) snprintf(right, 16, "%d new", unread);
      else strlcpy(right, mesh::state() == mesh::READY ? "online" : "offline", 16);
      *col = COL_OK;
      return;
    }
    if (i == 1) {
      strlcpy(left, " >  Signal finder", 40);
      int n = 0;
      for (auto& d : devs) n += d.used;
      snprintf(right, 16, "%d found", n);
      *col = COL_OK;
      return;
    }
    if (i == 2) {
      strlcpy(left, " >  Baseline watch", 40);
      strlcpy(right, baselineState == BL_ACTIVE ? "active" : baselineState == BL_LEARNING ? "learning" : "off", 16);
      if (baselineState != BL_OFF) *col = COL_MINE;
      return;
    }
    if (i == 3) {
      strlcpy(left, " >  Radar", 40);
      int n = 0;
      for (auto& d : devs) if (d.used && millis() - d.last < ACTIVE_MS) n++;
      snprintf(right, 16, "%d live", n);
      *col = COL_OK;
      return;
    }
    if (i == 4) {
      strlcpy(left, " >  Sweep summary", 40);
      int t = 0;
      for (auto& d : devs) if (d.used && isThreat(d.cat) && d.conf >= CONF_ALERT) t++;
      if (t) { snprintf(right, 16, "%d threats", t); *col = COL_BAD; }
      else   { strlcpy(right, "clean", 16); *col = COL_OK; }
      return;
    }
    int cat = i - MENU_APPS - 1;
    bool on = cat < 0 ? scanMask == SCAN_ALL : scanMask & (1 << cat);
    snprintf(left, 40, "[%c] %s", on ? 'x' : ' ', cat < 0 ? "Scan all" : SCAN_NAME[cat]);
    if (!on) *col = COL_DIM;
    else if (cat >= 0) *col = catColor(cat);
  });
  drawHint(sel < MENU_APPS ? "A open   B next   hold B: back" : "A on/off   B next   hold B: back");
}

// Signal finder: pick a detected device, then walk around watching its signal.
static int findList(int* out) {
  int n = 0;
  bool taken[MAX_DEVS] = {};
  for (;;) {
    int best = -1;
    for (int i = 0; i < MAX_DEVS; i++) {
      if (!devs[i].used || taken[i]) continue;
      if (best < 0 || (int32_t)(devs[i].last - devs[best].last) > 0) best = i;
    }
    if (best < 0) break;
    taken[best] = true;
    out[n++] = best;
  }
  return n;
}

static void drawFind() {
  drawHeader("SIGNAL FINDER");
  int list[MAX_DEVS];
  int n = findList(list);
  if (sel >= n) sel = n ? n - 1 : 0;
  drawRows(n, 19, 8, [&](int i, char* left, char* right, uint16_t* col) {
    const Dev& d = devs[list[i]];
    if (d.detail[0]) snprintf(left, 36, "%-6s %s", CAT_SHORT[d.cat], d.detail);
    else snprintf(left, 36, "%-6s %02x:%02x:%02x:%02x:%02x:%02x", CAT_SHORT[d.cat], d.mac[0], d.mac[1],
                  d.mac[2], d.mac[3], d.mac[4], d.mac[5]);
    left[30] = '\0';
    snprintf(right, 16, d.ign ? "mute %d" : "%d", d.rssi);
    *col = d.ign ? COL_FAINT : (millis() - d.last < ACTIVE_MS ? catColor(d.cat) : COL_DIM);
  });
  if (!n) {
    canvas.setTextColor(COL_FAINT);
    canvas.drawCentreString("nothing detected yet", 120, 60);
  }
  drawHint("A track  B next  hold A: silence  hold B: back");
}

static bool findValid() {
  return findIdx >= 0 && devs[findIdx].used && devs[findIdx].id == findId;
}

static void drawTrack() {
  drawHeader("TRACKING");
  if (!findValid()) {
    canvas.setTextColor(COL_BAD);
    canvas.drawCentreString("device no longer in the list", 120, 60);
    drawHint("hold B: back");
    return;
  }
  const Dev& d = devs[findIdx];
  uint32_t age = millis() - d.last;
  bool live = age < 4000;
  uint16_t col = live ? catColor(d.cat) : COL_FAINT;
  char buf[48];

  canvas.setTextColor(col);
  canvas.drawString(labelFor(d.cat, d.method), 6, 19);
  canvas.setTextColor(COL_DIM);
  snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", d.mac[0], d.mac[1], d.mac[2], d.mac[3],
           d.mac[4], d.mac[5]);
  canvas.drawRightString(buf, 236, 19);
  if (d.detail[0]) {
    strlcpy(buf, d.detail, 39);
    canvas.drawString(buf, 6, 31);
  }

  // Smoothed signal and short history for a direction cue. Reset on new target.
  static uint16_t histId = 0;
  static float smooth = -100, prevSmooth = -100;
  static int8_t hist[60];
  static uint8_t histN = 0, histHead = 0;
  static uint32_t lastSample = 0;
  if (histId != d.id) {
    histId = d.id; smooth = prevSmooth = d.rssi; histN = histHead = 0;
  }
  uint32_t now = millis();
  if (live && now - lastSample > 150) {
    lastSample = now;
    prevSmooth = smooth;
    smooth += (d.rssi - smooth) * 0.35f;              // exponential smoothing
    hist[histHead] = (int8_t)smooth;
    histHead = (histHead + 1) % 60;
    if (histN < 60) histN++;
  }
  float trend = smooth - prevSmooth;                  // >0 getting closer

  canvas.setFont(&fonts::FreeSansBold24pt7b);
  canvas.setTextColor(live ? TFT_WHITE : COL_FAINT);
  snprintf(buf, sizeof(buf), "%d", d.rssi);
  canvas.drawRightString(buf, 132, 44);
  canvas.setFont(&fonts::Font0);
  canvas.setTextColor(COL_DIM);
  canvas.drawString("dBm", 136, 58);
  if (live) snprintf(buf, sizeof(buf), "peak %d", d.peak);
  else snprintf(buf, sizeof(buf), "lost %lus", (unsigned long)(age / 1000));
  canvas.drawString(buf, 136, 44);

  // direction cue
  if (live) {
    const char* word = trend > 0.6f ? "CLOSER" : trend < -0.6f ? "FARTHER" : "steady";
    uint16_t tc = trend > 0.6f ? COL_OK : trend < -0.6f ? COL_BAD : COL_DIM;
    int ax = 180, ay = 44;                            // direction triangle
    if (trend > 0.6f) canvas.fillTriangle(ax, ay - 7, ax - 6, ay + 5, ax + 6, ay + 5, tc);
    else if (trend < -0.6f) canvas.fillTriangle(ax, ay + 7, ax - 6, ay - 5, ax + 6, ay - 5, tc);
    else canvas.fillRect(ax - 6, ay - 2, 12, 4, tc);
    canvas.setFont(&fonts::Font0);
    canvas.setTextColor(tc);
    canvas.drawCentreString(word, ax, ay + 10);
  }

  // sparkline of smoothed history
  canvas.setFont(&fonts::Font0);
  for (uint8_t i = 1; i < histN; i++) {
    int a = hist[(histHead - histN + i - 1 + 120) % 60];
    int b = hist[(histHead - histN + i + 120) % 60];
    int x0 = 6 + (i - 1) * 228 / 59, x1 = 6 + i * 228 / 59;
    int y0 = 90 - constrain((a + 95) * 20 / 60, 0, 20);
    int y1 = 90 - constrain((b + 95) * 20 / 60, 0, 20);
    canvas.drawLine(x0, y0, x1, y1, col);
  }

  // strength bar, -95 dBm (empty) to -35 dBm (full)
  int w = constrain((d.rssi + 95) * 228 / 60, 0, 228);
  canvas.drawRect(5, 96, 230, 16, 0x2104);
  canvas.fillRect(6, 97, w, 14, col);
  int pk = constrain((d.peak + 95) * 228 / 60, 0, 227);
  canvas.drawFastVLine(6 + pk, 94, 20, TFT_WHITE);
  drawHint(d.ch ? "locked to WiFi ch   hold B: back" : "A mute   hold B: back");
}

// row 0 = scan all, rows 1.. = categories
static void toggleScan(int row) {
  if (row == 0) scanMask = scanMask == SCAN_ALL ? 0 : SCAN_ALL;
  else scanMask ^= 1 << (row - 1);
  uiPrefs.putUShort("scan3", scanMask);
  uiPrefs.putUChar("scancnt", CAT_COUNT);
  // drop what is no longer being scanned for
  for (int i = 0; i < MAX_DEVS; i++) {
    if (!devs[i].used || (scanMask & (1 << devs[i].cat))) continue;
    devs[i].used = false;
    if (bannerDev == i) bannerDev = -1;
  }
}

static void drawBaseline() {
  drawHeader("BASELINE WATCH");
  canvas.setFont(&fonts::Font0);
  char buf[48];
  if (baselineState == BL_LEARNING) {
    uint32_t left = blLearnUntil > millis() ? (blLearnUntil - millis()) / 1000 : 0;
    canvas.setTextColor(COL_MINE);
    canvas.drawString("Learning this area...", 6, 24);
    snprintf(buf, sizeof(buf), "%u devices logged, %lus left", blCount, (unsigned long)left);
    canvas.setTextColor(COL_DIM);
    canvas.drawString(buf, 6, 40);
    canvas.drawString("Hold still and let nearby devices be", 6, 62);
    canvas.drawString("seen. They become the 'known' set.", 6, 74);
    drawHint("A finish now   hold B: back");
  } else if (baselineState == BL_ACTIVE) {
    canvas.setTextColor(COL_OK);
    canvas.drawString("Watching for new devices", 6, 24);
    snprintf(buf, sizeof(buf), "%u known devices in the baseline", blCount);
    canvas.setTextColor(COL_DIM);
    canvas.drawString(buf, 6, 40);
    canvas.drawString("Anything not in the baseline raises", 6, 62);
    canvas.drawString("an alert, whatever its type.", 6, 74);
    drawHint("A clear baseline   hold B: back");
  } else {
    canvas.setTextColor(TFT_WHITE);
    canvas.drawString("Learn the devices around you now,", 6, 24);
    canvas.drawString("then get alerted on anything new.", 6, 36);
    canvas.setTextColor(COL_DIM);
    canvas.drawString("Do this somewhere you trust, so the", 6, 58);
    canvas.drawString("baseline is clean.", 6, 70);
    drawHint("A learn this area (60s)   hold B: back");
  }
}

// Radar: active detections placed by signal strength (radius) and a stable
// per-MAC angle, coloured by category. A sweep line animates.
static void drawRadar() {
  drawHeader("RADAR");
  const int cx = 120, cy = 72, R = 52;
  uint32_t now = millis();
  for (int r = R; r > 0; r -= R / 3) canvas.drawCircle(cx, cy, r, 0x18E3);
  canvas.drawFastHLine(cx - R, cy, 2 * R, 0x18E3);
  canvas.drawFastVLine(cx, cy - R, 2 * R, 0x18E3);
  // sweep
  float sweep = (now % 3000) / 3000.0f * 6.2832f;
  canvas.drawLine(cx, cy, cx + cosf(sweep) * R, cy + sinf(sweep) * R, 0x3DEA);

  int live = 0, strongest = -1;
  for (int i = 0; i < MAX_DEVS; i++) {
    const Dev& d = devs[i];
    if (!d.used || now - d.last > ACTIVE_MS) continue;
    if (!(scanMask & (1 << d.cat))) continue;
    live++;
    if (strongest < 0 || d.rssi > devs[strongest].rssi) strongest = i;
    float ang = (macHash(d.mac) % 360) * 0.01745f;
    float rad = R * (1.0f - constrain((d.rssi + 95) / 60.0f, 0.0f, 1.0f));
    int x = cx + cosf(ang) * rad, y = cy + sinf(ang) * rad;
    uint16_t c = d.ign ? COL_FAINT : catColor(d.cat);
    canvas.fillCircle(x, y, isThreat(d.cat) ? 3 : 2, c);
    if (isThreat(d.cat) && !d.ign && (now / 400) % 2) canvas.drawCircle(x, y, 5, c);
  }
  canvas.fillCircle(cx, cy, 2, COL_OK);

  canvas.setFont(&fonts::Font0);
  canvas.setTextColor(COL_DIM);
  char buf[40];
  snprintf(buf, sizeof(buf), "%d in range   center = you", live);
  canvas.drawCentreString(buf, 120, 128 - 6);
  if (strongest >= 0) {
    const Dev& d = devs[strongest];
    canvas.setTextColor(catColor(d.cat));
    snprintf(buf, sizeof(buf), "closest: %s %ddBm", labelFor(d.cat, d.method), d.rssi);
    canvas.drawString(buf, 4, 18);
  }
  drawHint("B refresh   hold B: back");
}

static int convoyUnits();   // defined later, next to the convoy detector

// A one-screen verdict for the current sweep: is this place clean, what is the
// worst thing seen, and did anything follow you or arrive as a convoy. Computed
// live from the device table (what is here and recently seen).
static void drawSummary() {
  drawHeader("SWEEP SUMMARY");
  uint32_t now = millis();
  int total = 0, threats = 0, following = 0, strongest = -1;
  int perCat[CAT_COUNT] = {};
  for (int i = 0; i < MAX_DEVS; i++) {
    const Dev& d = devs[i];
    if (!d.used) continue;
    total++;
    if (d.persist) following++;
    if (isThreat(d.cat) && d.conf >= CONF_ALERT) {
      threats++;
      perCat[d.cat]++;
      if (strongest < 0 || d.peak > devs[strongest].peak) strongest = i;
    }
  }
  int convoy = convoyUnits();

  uint32_t secs = (now - sessionStart) / 1000;
  char buf[48];
  canvas.setFont(&fonts::Font0);
  canvas.setTextColor(COL_DIM);
  if (secs < 600) snprintf(buf, sizeof(buf), "scanned %lum %lus   %d devices seen",
                           (unsigned long)(secs / 60), (unsigned long)(secs % 60), total);
  else snprintf(buf, sizeof(buf), "scanned %lu min   %d devices seen",
                (unsigned long)(secs / 60), total);
  canvas.drawString(buf, 4, 17);

  // verdict
  canvas.setTextDatum(middle_center);
  canvas.setFont(&fonts::FreeSansBold12pt7b);
  if (threats == 0) {
    canvas.setTextColor(COL_OK);
    canvas.drawString("AREA CLEAN", 120, 42);
  } else {
    canvas.setTextColor(COL_BAD);
    snprintf(buf, sizeof(buf), "%d THREAT%s", threats, threats == 1 ? "" : "S");
    canvas.drawString(buf, 120, 42);
  }
  canvas.setTextDatum(top_left);

  int y = 60;
  if (strongest >= 0) {
    const Dev& d = devs[strongest];
    canvas.setFont(&fonts::Font0);
    canvas.setTextColor(catColor(d.cat));
    snprintf(buf, sizeof(buf), "worst: %s  %ddBm", labelFor(d.cat, d.method), d.peak);
    canvas.drawString(buf, 4, y);
    y += 12;
    // up to three category tallies
    canvas.setTextColor(COL_DIM);
    char line[48] = "";
    for (int c = 0; c < CAT_COUNT; c++) {
      if (!perCat[c]) continue;
      char seg[16];
      snprintf(seg, sizeof(seg), "%d %s  ", perCat[c], CAT_SHORT[c]);
      if (strlen(line) + strlen(seg) < sizeof(line)) strlcat(line, seg, sizeof(line));
    }
    canvas.drawString(line, 4, y);
    y += 12;
  }

  if (following) {
    canvas.setTextColor(COL_BAD);
    snprintf(buf, sizeof(buf), "** %d following you **", following);
    canvas.drawString(buf, 4, y);
    y += 11;
  }
  if (convoy >= CONVOY_MIN) {
    canvas.setTextColor(COL_BAD);
    snprintf(buf, sizeof(buf), "** convoy: %d units **", convoy);
    canvas.drawString(buf, 4, y);
    y += 11;
  }
  if (!following && convoy < CONVOY_MIN && threats == 0) {
    canvas.setTextColor(COL_FAINT);
    canvas.drawString("nothing is tailing you", 4, y);
  }
  drawHint("B refresh   hold A: new sweep   hold B: back");
}

static void drawPick() {
  drawHeader("CHOOSE RADIO");
  mesh::Radio list[6];
  int n = mesh::radios(list, 6);
  if (sel >= n) sel = n ? n - 1 : 0;
  drawRows(n, 19, 8, [&](int i, char* left, char* right, uint16_t*) {
    strlcpy(left, list[i].name, 30);
    snprintf(right, 16, "%d dBm", list[i].rssi);
  });
  if (!n) {
    canvas.setTextColor(COL_FAINT);
    canvas.drawCentreString("no radios heard yet", 120, 52);
    canvas.drawCentreString("turn on Bluetooth on the radio and", 120, 68);
    canvas.drawCentreString("disconnect any phone from it", 120, 80);
  }
  drawHint("A connect   B next   hold B: back");
}

static void draw() {
  canvas.fillScreen(TFT_BLACK);
  canvas.setFont(&fonts::Font0);
  canvas.setTextDatum(top_left);
  bool banner = millis() < bannerUntil &&
                (bannerConvoy > 0 || bannerConv >= 0 || (bannerDev >= 0 && devs[bannerDev].used));
  if (banner && screen != SCR_TYPE) drawBanner();
  else switch (screen) {
    case SCR_DETECT:   drawDetect(); break;
    case SCR_MESH:     drawMesh(); break;
    case SCR_THREAD:   drawThread(); break;
    case SCR_COMPOSE:  drawCompose(); break;
    case SCR_TYPE:     drawType(); break;
    case SCR_SETTINGS: drawSettings(); break;
    case SCR_PICK:     drawPick(); break;
    case SCR_SCAN:     drawScan(); break;
    case SCR_FIND:     drawFind(); break;
    case SCR_TRACK:    drawTrack(); break;
    case SCR_BASELINE: drawBaseline(); break;
    case SCR_RADAR:    drawRadar(); break;
    case SCR_SUMMARY:  drawSummary(); break;
  }
  canvas.pushSprite(0, 0);
}

static void go(Screen s) {
  screen = s;
  sel = 0;
  scroll = 0;
}

static void startTyping(uint8_t purpose) {
  typePurpose = purpose;
  typingPin = purpose != TYPE_MSG;
  typedLen = 0;
  typed[0] = '\0';
  charIdx = typingPin ? 0 : 3;     // '0' or 'a'
  screen = SCR_TYPE;
}

static void wipeForDuress() {
  mesh::forget();
  baselineState = BL_OFF;
  blCount = 0;
}

static void finishTyping(bool accept) {
  uint32_t v = strtoul(typed, nullptr, 10);
  switch (typePurpose) {
    case TYPE_MSG:
      if (accept && typedLen) mesh::send(curConv, typed);
      go(SCR_THREAD);
      break;
    case TYPE_RADIO_PIN:
      if (accept && typedLen == 6) mesh::setPin(v);
      go(SCR_SETTINGS);
      sel = 1;
      break;
    case TYPE_LOCK_PIN:
      if (accept && typedLen == 6) {
        lockPin = v;
        lockOn = true;
        uiPrefs.putBool("lockon", true);
        uiPrefs.putUInt("lockpin", v);
      }
      go(SCR_SETTINGS);
      break;
    case TYPE_DURESS_PIN:
      if (accept && typedLen == 6) {
        duressPin = v;
        uiPrefs.putUInt("duress", v);
      }
      go(SCR_SETTINGS);
      break;
    case TYPE_UNLOCK:
      if (typedLen == 6 && lockOn && v == lockPin) {
        locked = false;
        go(SCR_DETECT);
      } else if (typedLen == 6 && lockOn && duressPin && v == duressPin) {
        wipeForDuress();
        locked = false;
        go(SCR_DETECT);
      } else {
        M5.Speaker.tone(300, 200);   // wrong code, ask again
        startTyping(TYPE_UNLOCK);
      }
      break;
  }
}

static void changeSetting(int i) {
  switch (i) {
    case 0: go(SCR_PICK); break;
    case 1: startTyping(TYPE_RADIO_PIN); break;
    case 2:
      fwdOn = !fwdOn;
      uiPrefs.putBool("fwd", fwdOn);
      break;
    case 3: {
      // next channel index that exists on the radio
      for (int step = 1; step <= 8; step++) {
        uint8_t cand = (fwdCh + step) % 8;
        bool exists = false;
        for (int k = 0; k < MESH_MAX_CONVS; k++) {
          const mesh::Conv& c = mesh::conv(k);
          if (c.used && c.channel && c.chIdx == cand) exists = true;
        }
        if (exists) { fwdCh = cand; break; }
      }
      uiPrefs.putUChar("fwdch", fwdCh);
      break;
    }
    case 4: mesh::announce(); break;
    case 5: muted = !muted; break;
    case 7:
      screenOffSecs = screenOffSecs == 0 ? 15 : screenOffSecs == 15 ? 60 : screenOffSecs == 60 ? 300 : 0;
      uiPrefs.putUShort("soff", screenOffSecs);
      break;
    case 8:
      stealthOn = !stealthOn;
      uiPrefs.putBool("stealth", stealthOn);
      applyStealth();
      break;
    case 9:
      if (lockOn) {                       // turn the lock off
        lockOn = false;
        uiPrefs.putBool("lockon", false);
      } else {
        startTyping(TYPE_LOCK_PIN);
      }
      break;
    case 10: startTyping(TYPE_DURESS_PIN); break;
    case 11:
      reportOn = !reportOn;
      uiPrefs.putBool("report", reportOn);
      break;
    case 12:
      closeAlarm = !closeAlarm;
      uiPrefs.putBool("close", closeAlarm);
      break;
    case 13:
      ignCount = 0;
      uiPrefs.remove("ign");
      for (auto& d : devs) d.ign = false;
      break;
    case 14:
      if (canarySsid[0]) {                 // arm / disarm; set the name from the app
        canaryOn = !canaryOn;
        uiPrefs.putBool("canon", canaryOn);
      }
      break;
    case 6:
      brightness = brightness >= 250 ? 30 : brightness >= 160 ? 255 : brightness >= 90 ? 160 : 90;
      M5.Display.setBrightness(brightness);
      uiPrefs.putUChar("bri", brightness);
      break;
  }
}

// USB serial debug commands: "a" / "b" click, "A" / "B" hold, "pick NAME" chooses
// the radio whose name contains NAME, "pin 123456" sets the radio PIN,
// "fake" injects a test beacon, "clear" empties the detection list, "canary
// <ssid>" arms the canary bait name (bare "canary" clears it), "lockoff" clears
// the device lock, "shot" dumps the screen as RGB565 hex.
static bool simA, simB, simAHold, simBHold;

static void serialCommands() {
  static char cmd[64];
  static uint8_t n = 0;
  while (Serial.available()) {
    char c = Serial.read();
    if (c != '\n' && c != '\r') {
      if (n < sizeof(cmd) - 1) cmd[n++] = c;
      continue;
    }
    cmd[n] = '\0';
    n = 0;
    if (!strcmp(cmd, "a")) simA = true;
    else if (!strcmp(cmd, "b")) simB = true;
    else if (!strcmp(cmd, "A")) simAHold = true;
    else if (!strcmp(cmd, "B")) simBHold = true;
    else if (!strncmp(cmd, "pick ", 5)) {
      mesh::Radio list[6];
      int n = mesh::radios(list, 6);
      for (int i = 0; i < n; i++)
        if (strstr(list[i].name, cmd + 5)) { mesh::choose(list[i].slot); break; }
    }
    else if (!strcmp(cmd, "clear")) wantClear = true;
    else if (!strncmp(cmd, "canary ", 7)) setCanary(cmd + 7);
    else if (!strcmp(cmd, "canary")) setCanary("");
    else if (!strcmp(cmd, "home")) { screen = SCR_DETECT; sel = 0; }
    else if (!strcmp(cmd, "summary")) { screen = SCR_SUMMARY; sel = 4; }
    else if (!strcmp(cmd, "blescan")) bleDebugUntil = millis() + 25000;
    else if (!strcmp(cmd, "lockoff")) {
      lockOn = false; locked = false;
      uiPrefs.putBool("lockon", false);
    }
    else if (!strcmp(cmd, "fake")) {
      // synthetic beacon for testing the UI without real hardware nearby
      static const uint8_t mac[6] = {0x02, 0x00, 0x00, 0xfa, 0xce, 0x01};
      pushHit(CAT_BEACON, M_IBEACON, 1, mac, -45 - (int)(millis() / 400 % 40), 0, "TEST BEACON");
    }
    else if (!strcmp(cmd, "fakecam")) {
      static const uint8_t m[6] = {0xec, 0x71, 0xdb, 0x11, 0x22, 0x33};
      pushHit(CAT_CAMERA, M_CAM_SSID, 3, m, -55, 6, "Reolink-Cam");
    }
    else if (!strcmp(cmd, "fakedrone")) {
      static const uint8_t m[6] = {0x3c, 0x1a, 0x2b, 0x44, 0x55, 0x66};
      pushHit(CAT_DRONE, M_ODID_WIFI, 4, m, -60, 6, "Remote ID (beacon)");
    }
    else if (!strcmp(cmd, "fakebspam")) {
      static const uint8_t m[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
      pushHit(CAT_ATTACK, M_BEACON_SPAM, 3, m, -48, 6, "61 fake APs / 3 s");
    }
    else if (!strcmp(cmd, "fakehandshake")) {
      static const uint8_t m[6] = {0xa0, 0x63, 0x91, 0x12, 0x34, 0x56};
      pushHit(CAT_ATTACK, M_HANDSHAKE, 4, m, -53, 6, "deauth + EAPOL capture");
    }
    else if (!strcmp(cmd, "fakedronewifi")) {
      static const uint8_t m[6] = {0x60, 0x60, 0x1f, 0x11, 0x22, 0x33};
      pushHit(CAT_DRONE, M_DRONE_SSID, 3, m, -58, 6, "Mavic-Air-2S");
    }
    else if (!strcmp(cmd, "faketracker")) {
      static const uint8_t m[6] = {0x02, 0x7b, 0xee, 0x44, 0x55, 0x66};
      pushHit(CAT_TRACKER, M_TRACKER_NAME, 3, m, -62, 0, "PebbleBee Clip");
    }
    else if (!strcmp(cmd, "fakeconvoy")) wantFakeConvoy = true;
    else if (!strcmp(cmd, "fakerot")) {
      // same named unit, a new MAC each call: tests MAC-rotation grouping
      static uint8_t seq = 0;
      uint8_t m[6] = {0x02, 0x11, 0x22, 0x33, 0x44, (uint8_t)(0x50 + seq++)};
      pushHit(CAT_AXON, M_BLE_NAME, 3, m, -61, 0, "RotUnit-77");
    }
    else if (!strcmp(cmd, "fakecanary")) {
      static const uint8_t m[6] = {0x02, 0xca, 0x11, 0x7a, 0xb1, 0x70};
      pushHit(CAT_CANARY, M_CANARY_AP, 4, m, -57, 6, canarySsid[0] ? canarySsid : "my-canary");
    }
    else if (!strcmp(cmd, "fakefollow")) wantFakeFollow = true;
    else if (!strncmp(cmd, "pin ", 4)) mesh::setPin(strtoul(cmd + 4, nullptr, 10));
    else if (!strcmp(cmd, "shot")) {
      const uint8_t* px = (const uint8_t*)canvas.getBuffer();
      Serial.println("SHOT 240 135");
      for (int y = 0; y < 135; y++) {
        for (int x = 0; x < 480; x++) Serial.printf("%02x", px[y * 480 + x]);
        Serial.println();
      }
      Serial.println("END");
    }
  }
}

static void handleButtons() {
  static uint32_t lastRepeat = 0;
  bool a = M5.BtnA.wasClicked() || simA, aHold = M5.BtnA.wasHold() || simAHold;
  bool b = M5.BtnB.wasClicked() || simB, bHold = M5.BtnB.wasHold() || simBHold;
  simA = simB = simAHold = simBHold = false;
  if (M5.BtnA.wasClicked() || M5.BtnB.wasClicked() || M5.BtnA.wasHold() || M5.BtnB.wasHold()) {
    char line[64];
    snprintf(line, sizeof(line), "{\"t\":\"btn\",\"a\":%d,\"b\":%d,\"hold\":%d}", M5.BtnA.wasClicked() || M5.BtnA.wasHold(),
             M5.BtnB.wasClicked() || M5.BtnB.wasHold(), M5.BtnA.wasHold() || M5.BtnB.wasHold());
    Serial.println(line);
  }
  if (a || b || aHold || bHold) {
    bannerUntil = 0;
    bannerConvoy = 0;
    bool wasAsleep = asleep;
    wake();
    if (wasAsleep) return;                // the first press only wakes the screen
  }

  switch (screen) {
    case SCR_DETECT:
      if (a) { muted = !muted; if (!muted) M5.Speaker.tone(1500, 50); }
      if (b) go(SCR_SCAN);
      if (bHold) go(SCR_MESH);
      break;

    case SCR_MESH: {
      int ord[MESH_MAX_CONVS];
      int n = mesh::order(ord);
      if (b && n) sel = (sel + 1) % n;
      if (a && n) { curConv = ord[sel]; go(SCR_THREAD); }
      if (bHold) go(SCR_SETTINGS);
      break;
    }

    case SCR_THREAD:
      if (b) scroll = threadTop ? 0 : scroll + 4;
      if (a && mesh::state() == mesh::READY) go(SCR_COMPOSE);
      if (bHold) go(SCR_MESH);
      break;

    case SCR_COMPOSE:
      if (b) sel = (sel + 1) % CANNED_COUNT;
      if (a) {
        if (sel == 0) startTyping(TYPE_MSG);
        else { mesh::send(curConv, CANNED[sel]); go(SCR_THREAD); }
      }
      if (bHold) go(SCR_THREAD);
      break;

    case SCR_TYPE: {
      const char* set = typingPin ? CHARS_PIN : CHARS_TEXT;
      int n = strlen(set);
      if (b) charIdx = (charIdx + 1) % n;
      if (M5.BtnB.isHolding() && millis() - lastRepeat > 110) {
        lastRepeat = millis();
        charIdx = (charIdx + 1) % n;
      }
      if (aHold && typedLen) typed[--typedLen] = '\0';
      if (a) {
        char ch = set[charIdx];
        int max = typingPin ? 6 : MESH_TEXT_MAX;
        if (ch == '\x01') finishTyping(true);
        else if (ch == '\x02') finishTyping(false);
        else if (typedLen < max) { typed[typedLen++] = ch; typed[typedLen] = '\0'; }
      }
      break;
    }

    case SCR_SETTINGS:
      if (b) sel = (sel + 1) % SETTING_COUNT;
      if (a) changeSetting(sel);
      if (aHold && sel == 0) mesh::forget();
      if (bHold) go(SCR_DETECT);
      break;

    case SCR_SCAN:
      if (b) sel = (sel + 1) % MENU_ROWS;
      if (a) {
        if (sel == 0) go(SCR_MESH);
        else if (sel == 1) go(SCR_FIND);
        else if (sel == 2) go(SCR_BASELINE);
        else if (sel == 3) go(SCR_RADAR);
        else if (sel == 4) go(SCR_SUMMARY);
        else toggleScan(sel - MENU_APPS);
      }
      if (bHold) go(SCR_DETECT);
      break;

    case SCR_FIND: {
      int list[MAX_DEVS];
      int n = findList(list);
      if (b && n) sel = (sel + 1) % n;
      if (aHold && n) {                               // silence / unsilence this device
        ignToggle(macHash(devs[list[sel]].mac));
        devs[list[sel]].ign = ignored(macHash(devs[list[sel]].mac));
      } else if (a && n) {
        findIdx = list[sel];
        findId = devs[findIdx].id;
        memcpy(findMac, devs[findIdx].mac, 6);
        finding = true;
        screen = SCR_TRACK;
      }
      if (bHold) { go(SCR_SCAN); sel = 3; }
      break;
    }

    case SCR_RADAR:
      if (bHold) { go(SCR_SCAN); sel = 3; }
      break;

    case SCR_SUMMARY:
      if (aHold) { memset(devs, 0, sizeof(devs)); bannerDev = -1; sessionStart = millis(); }
      if (bHold) { go(SCR_SCAN); sel = 4; }
      break;

    case SCR_TRACK:
      if (a) muted = !muted;
      if (bHold) { finding = false; go(SCR_FIND); }
      break;

    case SCR_BASELINE:
      if (a) {
        if (baselineState == BL_OFF) {
          blCount = 0;
          baselineState = BL_LEARNING;
          blLearnUntil = millis() + BL_LEARN_MS;
        } else if (baselineState == BL_LEARNING) {
          baselineState = BL_ACTIVE;
        } else {
          baselineState = BL_OFF;
          blCount = 0;
        }
      }
      if (bHold) go(SCR_SCAN);
      break;

    case SCR_PICK: {
      mesh::Radio list[6];
      int n = mesh::radios(list, 6);
      if (b && n) sel = (sel + 1) % n;
      if (a && n) { mesh::choose(list[sel].slot); go(SCR_MESH); }
      if (bHold) go(SCR_SETTINGS);
      break;
    }
  }
}

// Sends pending alerts to the mesh, spaced out to respect LoRa airtime.
static void forwardAlerts() {
  static uint32_t lastSent = 0;
  uint32_t now = millis();
  if (lastSent && now - lastSent < FWD_GAP_MS) return;
  for (int i = 0; i < MAX_DEVS; i++) {
    Dev& d = devs[i];
    if (!d.used || !d.fwdPending) continue;
    if (!fwdOn || (d.lastFwd && now - d.lastFwd < FWD_COOLDOWN_MS)) { d.fwdPending = false; continue; }
    if (mesh::state() != mesh::READY) continue;
    int target = -1;
    for (int k = 0; k < MESH_MAX_CONVS; k++) {
      const mesh::Conv& c = mesh::conv(k);
      if (c.used && c.channel && c.chIdx == fwdCh) target = k;
    }
    if (target < 0) return;
    char text[MESH_TEXT_MAX + 1];
    snprintf(text, sizeof(text), "[MW] %s%s c%u %ddBm %02x:%02x:%02x:%02x:%02x:%02x %s",
             d.persist ? "Following? " : "", labelFor(d.cat, d.method), d.conf, d.rssi, d.mac[0],
             d.mac[1], d.mac[2], d.mac[3], d.mac[4], d.mac[5], d.cat == CAT_TRACKER ? "" : d.detail);
    mesh::send(target, text);
    d.fwdPending = false;
    d.lastFwd = now ? now : 1;
    lastSent = now;
    return;
  }
}

static int fwdConvIndex() {
  for (int k = 0; k < MESH_MAX_CONVS; k++) {
    const mesh::Conv& c = mesh::conv(k);
    if (c.used && c.channel && c.chIdx == fwdCh) return k;
  }
  return -1;
}

// Periodic compact summary of what is in range, sent to the mesh so a team or
// base station keeps a picture without anyone touching the stick.
#define REPORT_INTERVAL_MS 300000   // 5 minutes
static void autoReport() {
  static uint32_t lastReport = 0;
  uint32_t now = millis();
  if (!reportOn || mesh::state() != mesh::READY) return;
  if (lastReport && now - lastReport < REPORT_INTERVAL_MS) return;
  int target = fwdConvIndex();
  if (target < 0) return;
  lastReport = now;

  char text[MESH_TEXT_MAX + 1];
  int o = snprintf(text, sizeof(text), "[MW] in range:");
  bool any = false;
  for (uint8_t c = 0; c < CAT_COUNT && o < (int)sizeof(text) - 12; c++) {
    if (!isThreat(c)) continue;
    int n = activeCount(c);
    if (!n) continue;
    o += snprintf(text + o, sizeof(text) - o, " %d%s", n, CAT_SHORT[c]);
    any = true;
  }
  if (!any) o += snprintf(text + o, sizeof(text) - o, " clear");
  double la, lo;
  if (mesh::pos(&la, &lo) && o < (int)sizeof(text) - 26)
    snprintf(text + o, sizeof(text) - o, " @%.5f,%.5f", la, lo);
  mesh::send(target, text);
}

// A device counts toward a convoy if it is a person/vehicle-borne unit (not
// fixed infrastructure, not an environmental event), seen across 2+ separate
// minute-windows and still around. Already-"following" units are included.
static bool convoyCat(uint8_t c) {
  return !fixedCat(c) && c != CAT_DEAUTH && c != CAT_ROGUE && c != CAT_CANARY;
}
static int convoyUnits() {
  uint32_t now = millis();
  int n = 0;
  for (auto& d : devs) {
    if (!d.used || d.ign || d.known) continue;
    if (!convoyCat(d.cat)) continue;
    if (d.minutes < 2 || now - d.last > CONVOY_WINDOW_MS) continue;
    n++;
  }
  return n;
}

static void raiseConvoy(int n) {
  uint32_t now = millis();
  wake();
  bannerConvoy = n; bannerDev = -1; bannerConv = -1;
  bannerUntil = now + BANNER_MS + 2000;
  if (!muted) {                                       // urgent descending triple
    M5.Speaker.tone(2600, 110);
    M5.Speaker.tone(2000, 110, -1, false);
    M5.Speaker.tone(1500, 160, -1, false);
  }
  char line[64];
  snprintf(line, sizeof(line), "{\"t\":\"convoy\",\"n\":%d}", n);
  sendLine(line);

  if (fwdOn && mesh::state() == mesh::READY) {        // tell the team
    int target = fwdConvIndex();
    if (target >= 0) {
      char text[MESH_TEXT_MAX + 1];
      int o = snprintf(text, sizeof(text), "[MW] CONVOY: %d units tailing you", n);
      double la, lo;
      if (mesh::pos(&la, &lo) && o < (int)sizeof(text) - 26)
        snprintf(text + o, sizeof(text) - o, " @%.5f,%.5f", la, lo);
      mesh::send(target, text);
    }
  }
}

// Watch for a coordinated tail: several mobile units that keep recurring around
// you. No single one need trip "following"; together they do.
static void convoyCheck() {
  static uint32_t lastEval = 0, armAt = 0;
  uint32_t now = millis();
  if (now - lastEval < 3000) return;                 // cheap, every few seconds
  lastEval = now;
  int n = convoyUnits();
  if (n < CONVOY_MIN || now < armAt) return;
  armAt = now + CONVOY_COOLDOWN_MS;
  raiseConvoy(n);
}

// Animated boot splash: brand mark, wordmark, and a radar sweep with a filling
// progress bar. p runs 0..1 over the animation.
static void drawSplash(float p) {
  canvas.fillSprite(0x0841);                               // near-black ground
  // decorative radar arcs + sweep, tucked into the bottom-right so they stay
  // clear of the wordmark
  const int cx = 232, cy = 150;
  for (int r = 40; r <= 150; r += 28) canvas.drawCircle(cx, cy, r, 0x1084);
  float a = 3.1416f + p * 6.2832f;
  canvas.drawLine(cx, cy, cx + cosf(a) * 150, cy + sinf(a) * 150, 0x236B);

  // logo tile with "M"
  const int lx = 6, ly = 33, ls = 28;
  canvas.fillRoundRect(lx, ly, ls, ls, 7, COL_BRAND);
  canvas.setTextDatum(middle_center);
  canvas.setFont(&fonts::FreeSansBold18pt7b);
  canvas.setTextColor(TFT_BLACK);
  canvas.drawString("M", lx + ls / 2, ly + ls / 2 - 1);

  // wordmark: Mesh (white) + Watch (brand)
  canvas.setTextDatum(middle_left);
  const int tx = lx + ls + 6;
  canvas.setTextColor(TFT_WHITE);
  canvas.drawString("Mesh", tx, ly + ls / 2 - 1);
  int w = canvas.textWidth("Mesh");
  canvas.setTextColor(COL_BRAND);
  canvas.drawString("Watch", tx + w, ly + ls / 2 - 1);

  // tagline + version
  canvas.setTextDatum(top_left);
  canvas.setFont(&fonts::Font0);
  canvas.setTextColor(COL_DIM);
  canvas.drawString("passive counter-surveillance detector", 20, 84);
  char v[40];
  snprintf(v, sizeof(v), "v%s   M5Stack StickS3", FW_VERSION);
  canvas.setTextColor(COL_FAINT);
  canvas.drawString(v, 20, 98);

  // progress bar
  const int px = 20, pw = 200, py = 118;
  canvas.drawRoundRect(px, py, pw, 6, 2, 0x2965);
  int fill = (int)(pw * constrain(p, 0.0f, 1.0f));
  if (fill > 2) canvas.fillRoundRect(px, py, fill, 6, 2, COL_BRAND);
  canvas.pushSprite(0, 0);
}

// --------------------------------------------------------------------- main
void setup() {
  auto cfg = M5.config();
  M5.begin(cfg);
  Serial.begin(115200);
  sessionStart = millis();
  uiPrefs.begin("mwui", false);
  fwdOn = uiPrefs.getBool("fwd", false);
  fwdCh = uiPrefs.getUChar("fwdch", 0);
  brightness = uiPrefs.getUChar("bri", 90);
  scanMask = uiPrefs.getUShort("scan3", SCAN_ALL) & SCAN_ALL;
  // Categories added since this was last saved default to on, so a new
  // detector is never silently disabled by an old stored selection.
  uint8_t storedCats = uiPrefs.getUChar("scancnt", 0);
  if (storedCats < CAT_COUNT) scanMask |= SCAN_ALL & ~((1u << storedCats) - 1);
  uiPrefs.putUChar("scancnt", CAT_COUNT);
  screenOffSecs = uiPrefs.getUShort("soff", 0);
  stealthOn = uiPrefs.getBool("stealth", false);
  reportOn = uiPrefs.getBool("report", false);
  closeAlarm = uiPrefs.getBool("close", false);
  uiPrefs.getString("canssid", canarySsid, sizeof(canarySsid));
  canaryOn = uiPrefs.getBool("canon", false) && canarySsid[0];
  size_t ignBytes = uiPrefs.getBytesLength("ign");
  if (ignBytes && ignBytes <= sizeof(ignHashes) && ignBytes % 2 == 0) {
    uiPrefs.getBytes("ign", ignHashes, ignBytes);
    ignCount = ignBytes / 2;
  }
  lockOn = uiPrefs.getBool("lockon", false);
  lockPin = uiPrefs.getUInt("lockpin", 0);
  duressPin = uiPrefs.getUInt("duress", 0);
  uiPrefs.remove("evlog");   // drop any evidence log saved by older firmware
  setenv("TZ", "CET-1CEST,M3.5.0,M10.5.0/3", 1);   // Belgium; the radio's clock is UTC
  tzset();
  M5.Display.setRotation(1);
  M5.Display.setBrightness(brightness);
  canvas.setColorDepth(16);
  canvas.createSprite(240, 135);
  M5.Speaker.setVolume(160);

  // boot splash (plays over the radio/scanner init that follows)
  M5.Speaker.tone(1500, 70);
  M5.Speaker.tone(2200, 90, -1, false);
  uint32_t t0 = millis();
  while (millis() - t0 < 1500) {
    M5.update();
    if (M5.BtnA.wasClicked() || M5.BtnB.wasClicked()) break;   // tap to skip
    drawSplash((millis() - t0) / 1500.0f);
    delay(20);
  }
  drawSplash(1.0f);

  hitQ = xQueueCreate(48, sizeof(Hit));
  wifiStart();
  bleStart();
  mesh::begin();
  if (stealthOn) applyStealth();
  emitStatus();

  if (lockOn && lockPin) {
    locked = true;
    startTyping(TYPE_UNLOCK);
  }
}

void loop() {
  static uint32_t lastHop = 0, lastDraw = 0, lastStatus = 0, lastDeauth = 0, lastFwdCheck = 0;
  static size_t hopIdx = 0;
  static mesh::State lastMeshState = mesh::SEARCHING;
  uint32_t now = millis();

  M5.update();
  serialCommands();
  handleButtons();

  // While tracking a WiFi device, stay on its channel instead of hopping.
  bool tracking = screen == SCR_TRACK && findValid();
  uint8_t lockCh = tracking ? devs[findIdx].ch : 0;
  if (lockCh) {
    if (curChannel != lockCh) {
      curChannel = lockCh;
      esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
    }
  } else if (now - lastHop >= CHANNEL_DWELL_MS) {
    lastHop = now;
    hopIdx = (hopIdx + 1) % HOP_COUNT;
    curChannel = HOP[hopIdx];
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
  }

  // Geiger-style ticks: faster and higher as the signal gets stronger.
  static uint32_t lastTick = 0;
  if (tracking && !muted && now - devs[findIdx].last < 4000) {
    int r = constrain(devs[findIdx].rssi, -95, -35);
    uint32_t gap = map(r, -95, -35, 1200, 90);
    if (now - lastTick >= gap) {
      lastTick = now;
      M5.Speaker.tone(map(r, -95, -35, 900, 3200), 25);
    }
  }

  if (!asleep && screenOffSecs && !tracking && now >= bannerUntil &&
      now - lastInput > screenOffSecs * 1000UL) {
    asleep = true;
    M5.Display.setBrightness(0);
  }

  if (baselineState == BL_LEARNING && (int32_t)(now - blLearnUntil) >= 0) baselineState = BL_ACTIVE;

  Hit h;
  while (xQueueReceive(hitQ, &h, 0) == pdTRUE) handleHit(h);

  if (now - lastDeauth >= DEAUTH_WINDOW_MS) {
    lastDeauth = now;
    uint32_t n = deauthCount;
    deauthCount = 0;
    if (n >= DEAUTH_THRESHOLD) {
      Hit dh = {};
      dh.cat = CAT_DEAUTH; dh.method = M_DEAUTH; dh.conf = 3; dh.ch = curChannel;
      memcpy(dh.mac, deauthBssid, 6);
      snprintf(dh.detail, sizeof(dh.detail), "%lu frames / 5 s", (unsigned long)n);
      handleHit(dh);
    }
  }

  static uint32_t lastSpam = 0;
  if (now - lastSpam >= 3000) {
    lastSpam = now;
    uint32_t n = bleSpamCount;
    bleSpamCount = 0;
    if (n >= BLE_SPAM_THRESHOLD) {
      Hit sh = {};
      sh.cat = CAT_ATTACK; sh.method = M_BLE_SPAM; sh.conf = 3; sh.rssi = -50;
      memcpy(sh.mac, bleSpamMac, 6);
      snprintf(sh.detail, sizeof(sh.detail), "%lu adverts / 3 s", (unsigned long)n);
      handleHit(sh);
    }
    uint32_t bn = beaconSpamCount;
    beaconSpamCount = 0;
    if (bn >= WIFI_BEACON_SPAM_THRESHOLD) {
      Hit bh = {};
      bh.cat = CAT_ATTACK; bh.method = M_BEACON_SPAM; bh.conf = 3; bh.rssi = -50;
      bh.ch = curChannel;
      memcpy(bh.mac, beaconSpamMac, 6);
      snprintf(bh.detail, sizeof(bh.detail), "%lu fake APs / 3 s", (unsigned long)bn);
      handleHit(bh);
    }
    uint32_t en = eapolCount;
    eapolCount = 0;
    // A burst of handshakes with no recent deauth (e.g. a PMKID sweep). The
    // deauth-correlated case already alerted immediately in the sniffer.
    if (en >= EAPOL_BURST && (!lastDeauthMs || now - lastDeauthMs > DEAUTH_RECENT_MS)) {
      Hit eh = {};
      eh.cat = CAT_ATTACK; eh.method = M_PMKID; eh.conf = 3; eh.rssi = -50;
      eh.ch = curChannel;
      memcpy(eh.mac, eapolBssid, 6);
      snprintf(eh.detail, sizeof(eh.detail), "%lu EAPOL / 3 s", (unsigned long)en);
      handleHit(eh);
    }
  }

  mesh::loop();   // connecting to the radio blocks for a few seconds
  if (mesh::state() != lastMeshState) {
    lastMeshState = mesh::state();
    char line[96];
    snprintf(line, sizeof(line), "{\"t\":\"mesh\",\"state\":%d,\"radio\":\"%s\"}", (int)lastMeshState,
             mesh::radioName());
    sendLine(line);
  }

  int inc = mesh::takeIncoming();
  if (inc >= 0 && mesh::state() == mesh::READY && !(screen == SCR_THREAD && curConv == inc)) {
    wake();
    bannerConv = inc;
    bannerConvoy = 0;
    const mesh::Msg* nm = mesh::message(inc, 0);
    bannerTeam = nm && strncmp(nm->text, "[MW]", 4) == 0;   // alert from another MeshWatch
    bannerUntil = now + (bannerTeam ? BANNER_MS + 2500 : BANNER_MS);
    if (!muted) {
      if (bannerTeam) {                                     // same tone as a local threat
        M5.Speaker.tone(2000, 70);
        M5.Speaker.tone(2800, 110, -1, false);
      } else {
        M5.Speaker.tone(1600, 60);
        M5.Speaker.tone(2100, 60, -1, false);
      }
    }
  }
  if (now - lastFwdCheck >= 1000) {
    lastFwdCheck = now;
    forwardAlerts();
    autoReport();
  }
  convoyCheck();

  if (wantClear) {
    wantClear = false;
    memset(devs, 0, sizeof(devs));
    bannerDev = -1;
    sessionStart = millis();
  }
  if (wantList) {
    wantList = false;
    emitStatus();
    for (auto& d : devs) if (d.used) emitDev(d, "list");
    sendLine("{\"t\":\"end\"}");
  }
  if (wantFakeFollow) {
    wantFakeFollow = false;
    // synthesise a body cam that has shadowed you for several minutes
    int i = -1;
    for (int k = 0; k < MAX_DEVS; k++) if (!devs[k].used) { i = k; break; }
    if (i >= 0) {
      Dev& d = devs[i];
      memset(&d, 0, sizeof(d));
      d.used = true; d.id = nextId++;
      d.cat = CAT_AXON; d.method = M_BLE_OUI; d.conf = 4;
      static const uint8_t m[6] = {0x00, 0x25, 0xdf, 0xab, 0xcd, 0xef};
      memcpy(d.mac, m, 6);
      d.rssi = d.peak = -58; d.ch = 0;
      d.first = now - 300000; d.last = now;
      d.minutes = FOLLOW_MINUTES; d.lastMinute = now / 60000;
      d.count = 42;
      strlcpy(d.detail, "Axon body cam", sizeof(d.detail));
      d.persist = isFollowing(d);
      raise(i, true);
      d.lastEmit = now;
      emitDev(d, "persist");
    }
  }
  if (wantFakeConvoy) {
    wantFakeConvoy = false;
    // synthesise three distinct mobile units recurring around you
    static const uint8_t cats[3] = {CAT_TRACKER, CAT_AXON, CAT_GLASSES};
    int made = 0;
    for (int u = 0; u < 3; u++) {
      int i = -1;
      for (int k = 0; k < MAX_DEVS; k++) if (!devs[k].used) { i = k; break; }
      if (i < 0) break;
      Dev& d = devs[i];
      memset(&d, 0, sizeof(d));
      d.used = true; d.id = nextId++;
      d.cat = cats[u]; d.method = M_BLE_MFG; d.conf = 3;
      uint8_t m[6] = {0x02, 0xc0, 0x17, 0x00, 0x00, (uint8_t)(0xa0 + u)};
      memcpy(d.mac, m, 6);
      d.rssi = d.peak = -60 - u * 4; d.ch = 0;
      d.first = now - 240000; d.last = now;
      d.minutes = 3; d.lastMinute = now / 60000;
      d.count = 20;
      made++;
    }
    int n = convoyUnits();
    if (made && n >= CONVOY_MIN) raiseConvoy(n);
  }
  if (wantCanary) { wantCanary = false; setCanary(canaryPending); }
  if (now - lastStatus >= STATUS_EMIT_MS) {
    lastStatus = now;
    emitStatus();
  }
  if (!asleep && now - lastDraw >= (screen == SCR_TYPE || screen == SCR_TRACK ? 60 : 200)) {
    lastDraw = now;
    draw();
  }
  delay(5);
}
