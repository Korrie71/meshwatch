// Detection signatures. All matching is passive: nothing here transmits to,
// connects to, or interferes with the devices being detected.
#pragma once
#include <Arduino.h>

// ---------------------------------------------------------------- categories
enum Cat : uint8_t {
  CAT_FLOCK = 0,   // Flock Safety ALPR cameras + Penguin battery packs
  CAT_RAVEN,       // Flock Raven acoustic (gunshot) sensors
  CAT_AXON,        // Axon body cameras / Tasers / Signal
  CAT_TRACKER,     // AirTag-style item trackers
  CAT_GLASSES,     // camera-capable smart glasses
  CAT_DEAUTH,      // WiFi deauth / disassoc flood
  CAT_BEACON,      // iBeacon / Eddystone
  CAT_MESH,        // other MeshCore radios (informational)
  CAT_ROGUE,       // rogue AP: karma / SSID-flood (Pineapple-style)
  CAT_ATTACK,      // live attack tools: BLE advert spam, Flipper Zero
  CAT_SKIMMER,     // BLE serial modules used in card skimmers (HC-05...)
  CAT_CAMERA,      // consumer / CCTV WiFi cameras (Hikvision, Ring, Wyze...)
  CAT_DRONE,       // drones broadcasting Remote ID (WiFi or BLE)
  CAT_CANARY,      // canary SSID: someone probing for or spoofing your bait name
  CAT_COUNT
};

static const char* const CAT_KEY[CAT_COUNT] = {
  "flock", "raven", "axon", "tracker", "glasses", "deauth", "beacon", "meshcore",
  "rogueap", "attack", "skimmer", "camera", "drone", "canary"
};
static const char* const CAT_SHORT[CAT_COUNT] = {
  "FLOCK", "RAVEN", "AXON", "TRACK", "GLASS", "DEAUTH", "BEACON", "MESH", "ROGUE",
  "ATTACK", "SKIM", "CAM", "DRONE", "CANARY"
};

enum Method : uint8_t {
  M_WIFI_PROBE_SIG = 0, M_WIFI_PROBE, M_WIFI_OUI, M_WIFI_OUI_RX, M_WIFI_SSID,
  M_BLE_NAME, M_BLE_MFG, M_BLE_SVC, M_BLE_OUI,
  M_IBEACON, M_EDDYSTONE, M_FINDMY, M_TILE, M_SMARTTAG, M_CHIPOLO, M_FMDN,
  M_DEAUTH, M_KARMA, M_BLE_SPAM, M_FLIPPER, M_SKIMMER,
  M_PWNAGOTCHI, M_MESHTASTIC, M_CAM_OUI, M_CAM_SSID, M_ODID_WIFI, M_ODID_BLE,
  M_CANARY_AP, M_CANARY_PROBE, M_COUNT
};

static const char* const METHOD_KEY[M_COUNT] = {
  "wifi_probe_sig", "wifi_probe", "wifi_oui", "wifi_oui_rx", "wifi_ssid",
  "ble_name", "ble_mfg", "ble_svc", "ble_oui",
  "ibeacon", "eddystone", "findmy", "tile", "smarttag", "chipolo", "fmdn",
  "deauth", "karma_ssid_flood", "ble_advert_spam", "flipper_zero", "bt_serial_module",
  "pwnagotchi", "meshtastic", "camera_oui", "camera_ssid", "remoteid_wifi", "remoteid_ble",
  "canary_evil_twin", "canary_probe"
};

// Confidence 0-4. CONF_ALERT and up makes noise and raises the banner; lower
// hits are listed quietly. Trackers and beacons never alert on first sight.
#define CONF_ALERT 3

// ------------------------------------------------------------- Flock (WiFi)
// OUI set from the flock-you project: community drive-test prefixes
// (@NitekryDPaul / DeFlockJoplin) plus two prefixes extracted from a camera
// firmware dump. Several of the community prefixes are shared with ordinary
// consumer hardware, so a bare OUI match is low confidence on purpose.
struct OuiSig { uint8_t b[3]; uint8_t conf; };

static const OuiSig FLOCK_OUIS[] = {
  {{0x70,0xc9,0x4e},2}, {{0x3c,0x91,0x80},2}, {{0xd8,0xf3,0xbc},2}, {{0x80,0x30,0x49},2},
  {{0xb8,0x35,0x32},2}, {{0x14,0x5a,0xfc},2}, {{0x74,0x4c,0xa1},2}, {{0x08,0x3a,0x88},2},
  {{0x9c,0x2f,0x9d},2}, {{0xc0,0x35,0x32},2}, {{0x94,0x08,0x53},2}, {{0xe4,0xaa,0xea},2},
  {{0xf4,0x6a,0xdd},2}, {{0xe0,0x0a,0xf6},2}, {{0x24,0xb2,0xb9},2}, {{0x00,0xf4,0x8d},2},
  {{0xd0,0x39,0x57},2}, {{0xe8,0xd0,0xfc},2}, {{0xe0,0x4f,0x43},2}, {{0xb8,0x1e,0xa4},2},
  {{0x70,0x08,0x94},2}, {{0x58,0x8e,0x81},2}, {{0xec,0x1b,0xbd},2}, {{0x3c,0x71,0xbf},2},
  {{0x58,0x00,0xe3},2}, {{0x90,0x35,0xea},2}, {{0x5c,0x93,0xa2},2}, {{0x64,0x6e,0x69},2},
  {{0x48,0x27,0xea},2}, {{0xa4,0xcf,0x12},2}, {{0x14,0xb5,0xcd},2}, {{0x82,0x6b,0xf2},2},
  {{0xb4,0x1e,0x52},4},   // Flock Safety's own IEEE registration
  {{0x00,0x03,0x7f},1},   // Qualcomm Atheros default MAC, generic on its own
};
static const size_t FLOCK_OUI_COUNT = sizeof(FLOCK_OUIS) / sizeof(FLOCK_OUIS[0]);

// Probe-request IE fingerprint of the LiteON-built cameras: IE tag order with
// vendor IEs as 221:<first 8 payload bytes>, SSID tag skipped.
static const char FLOCK_PROBE_IE_SIG[] =
    "2,12,127,221:506f9a16030103,45,191,221:0050f208000000";

// ------------------------------------------------------------- Flock (BLE)
#define BLE_CID_XUNTONG   0x09C8   // Penguin battery pack manufacturer data
#define RAVEN_SVC_MIN     0x3100
#define RAVEN_SVC_MAX     0x3500
static const char FLOCK_GATT_UUID[] = "e8ccbb38-9532-46a8-9fe5-1814df172e6f";

// ------------------------------------------------------------------- Axon
// 00:25:DF is registered to Axon Enterprise (formerly TASER International).
static const uint8_t AXON_OUI[3] = {0x00, 0x25, 0xdf};

// ------------------------------------------------------- trackers / beacons
#define BLE_CID_APPLE     0x004C
#define BLE_CID_META      0x01AB   // Meta Platforms, Inc.
#define BLE_CID_META_TECH 0x058E   // Meta Platforms Technologies, LLC
#define SVC_META          0xFD5F
#define SVC_TILE          0xFEED
#define SVC_TILE_ALT      0xFEEC
#define SVC_SMARTTAG      0xFD5A
#define SVC_CHIPOLO       0xFE33
#define SVC_EDDYSTONE     0xFEAA   // also carries Google Find My Device frames

// ---------------------------------------------------- attack-tool signatures
// Fast Pair (0xFE2C) and Nearby (0xFCF1) service data, plus Apple Continuity
// proximity-pairing (0x07) and nearby-action (0x0F) sub-types, are the advert
// kinds abused by BLE spam tools. A high rate of these across rotating MACs is
// the spam itself, not any single device.
#define SVC_FASTPAIR      0xFE2C
#define SVC_NEARBY        0xFCF1
#define APPLE_PROX_PAIR   0x07
#define APPLE_NEARBY_ACT  0x0F
// Flipper Zero (STM32WB55 radio). What it advertises depends on the app it is
// running, so several signals are matched (base signature from nyanBOX):
//   - idle: a 16-bit service UUID 0x3080-0x308F (0x3081 black, 0x3082 white,
//     0x3083 clear) -> confirmed Flipper.
//   - BadKB / BadUSB / BadBT keyboard injection: advertises HID (0x1812) and a
//     name like "BadKB ..." -> Flipper running an attack.
//   - BLE spam apps: rotating MACs with flood payloads (caught by the spam rate).
// The one constant is the STMicroelectronics OUI 80:e1:26 on its BLE MAC, but
// that OUI is shared with other ST devices, so OUI alone is only a weak hint.
#define FLIPPER_SVC_BASE  0x3080
#define HID_SVC_UUID      0x1812
static const uint8_t FLIPPER_OUI[3] = {0x80, 0xe1, 0x26};
// BLE names of Flipper attack apps (and the default "Flipper <name>").
static const char* const FLIPPER_NAMES[] = {
  "Flipper", "BadKB", "BadUSB", "BadBT", "BadBLE", "BlueKB"
};
static const size_t FLIPPER_NAME_COUNT = sizeof(FLIPPER_NAMES) / sizeof(FLIPPER_NAMES[0]);
// Card-skimmer BLE serial modules (nyanBOX). These names also appear in
// hobby electronics, so treat a hit as "worth checking", not proof.
static const char* const SKIMMER_NAMES[] = {
  "HC-03", "HC-05", "HC-06", "HC-08", "JDY-", "AT-09", "BT05", "MLT-BT05", "SPP-CA"
};
static const size_t SKIMMER_NAME_COUNT = sizeof(SKIMMER_NAMES) / sizeof(SKIMMER_NAMES[0]);
// ------------------------------------------------- consumer / CCTV cameras
// Vendor OUIs that belong almost exclusively to surveillance cameras or DVRs
// (from the IEEE registry). Shared-use vendors like Amazon/Nest/Ubiquiti are
// left out of the OUI list and caught by SSID instead, to avoid false alarms.
static const uint8_t CAMERA_OUIS[][3] = {
  {0x0c,0x75,0xd2},{0x54,0x8c,0x81},{0x24,0x48,0x45},{0xec,0xc8,0x9c},{0x8c,0xe7,0x48},
  {0x24,0x28,0xfd},{0xac,0xb9,0x2f},{0xd4,0xe8,0x53},                                  // Hikvision
  {0x74,0xc9,0x29},{0x6c,0x1c,0x71},{0x08,0xed,0xed},{0xe0,0x2e,0xfe},{0x40,0x7a,0xa4},
  {0x5c,0xf5,0x1a},{0xfc,0x5f,0x49},{0x24,0x52,0x6a},                                  // Dahua
  {0xec,0x71,0xdb},                                                                    // Reolink
  {0xd0,0x3f,0x27},{0x80,0x48,0x2c},{0x7c,0x78,0xb2},{0x2c,0xaa,0x8e},                 // Wyze
  {0x64,0xf2,0xfb},{0x94,0xec,0x13},{0xec,0x97,0xe0},{0x78,0xa6,0xa0},{0x58,0x8f,0xcf},// Ezviz
  {0xfc,0x9c,0x98},{0x48,0x62,0x64},{0xa4,0x11,0x62},                                  // Arlo
  {0x54,0xe0,0x19},{0xac,0x9f,0xc3},{0xcc,0x3b,0xfb},{0x5c,0x47,0x5e},{0x9c,0x76,0x13},// Ring
  {0xb8,0xa4,0x4f},{0x00,0x40,0x8c},{0xe8,0x27,0x25},{0xac,0xcc,0x8e},                 // Axis
};
static const size_t CAMERA_OUI_COUNT = sizeof(CAMERA_OUIS) / sizeof(CAMERA_OUIS[0]);
// Case-insensitive SSID/BLE-name substrings common to consumer cameras.
static const char* const CAMERA_NAMES[] = {
  "wyzecam", "wyze", "reolink", "ipcam", "ipc-", "ezviz", "tapo_", "tapo-cam", "arlo",
  "ring-", "nestcam", "hikvision", "dahua", "foscam", "amcrest", "lorex", "annke",
  "eufycam", "blink-", "insta360", "yicamera", "sricam", "vstarcam",
};
static const size_t CAMERA_NAME_COUNT = sizeof(CAMERA_NAMES) / sizeof(CAMERA_NAMES[0]);

// ----------------------------------------------------------- drone Remote ID
// Open Drone ID. WiFi: NAN action frames to 51:6f:9a:01:00:00, or beacon
// vendor IE 0xdd with OUI 90:3a:e6 / fa:0b:bc. BLE: service data UUID 0xFFFA
// with app code 0x0D. We detect the envelope and alert; we do not decode the
// operator's GPS. Signature from the nyanBOX project.
static const uint8_t ODID_NAN_DEST[6] = {0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00};
#define ODID_BLE_SVC      0xFFFA

// -------------------------------------------------------------- Pwnagotchi
// Pwnagotchi beacons a JSON SSID carrying "name" and "pwnd_tot". We match the
// shape rather than parsing JSON on the sniffer path.

// ------------------------------------------------------------- Meshtastic
// 128-bit BLE service UUID 6ba1b218-15a8-461f-9fa8-5dcae273ea05.
#define MESHTASTIC_SVC_UUID "6ba1b218-15a8-461f-9fa8-5dcae273ea05"

// Karma / SSID-flood: one transmitter beaconing many distinct SSIDs.
#define KARMA_SSID_THRESHOLD 6     // distinct SSIDs from one BSSID -> rogue
#define BLE_SPAM_THRESHOLD   22    // spam-type adverts per 3 s window

// A tracker that stays in range across this many distinct minutes is flagged
// as persistent (possibly travelling with you).
#define TRACKER_PERSIST_MINUTES 10

// "Following you" detection for other mobile devices (body cams, smart glasses).
// Co-present across this many distinct minute-windows -> flagged as following.
#define FOLLOW_MINUTES 4
// If the radio reports position: a device that stays in range while you travel
// at least this far (metres) is flagged as following, whatever its type.
#define FOLLOW_MOVE_M 120.0f
