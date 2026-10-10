// MeshCore companion-radio client. The stick plays the role the phone app
// normally has: it connects to a MeshCore companion radio over BLE and speaks
// the companion protocol to read and send messages.
#pragma once
#include <Arduino.h>
#include <NimBLEDevice.h>

namespace mesh {

enum State : uint8_t { SEARCHING, CONNECTING, PAIR_FAILED, SYNCING, READY };
enum MsgState : uint8_t { MS_IN, MS_QUEUED, MS_SENT, MS_DELIVERED, MS_FAILED };

#define MESH_MAX_CONVS 32
#define MESH_MAX_MSGS  48
#define MESH_TEXT_MAX  140

struct Conv {
  bool     used, channel;
  uint8_t  chIdx;          // channels
  uint8_t  key[6];         // contacts: public key prefix
  uint8_t  unread;
  uint32_t recency;        // contacts: last advert, used when the table is full
  uint32_t lastMsg;        // millis of the newest message, 0 if none
  char     name[24];
};

struct Msg {
  int8_t   conv;
  uint8_t  state;
  uint32_t at;             // millis
  uint32_t ack;
  char     text[MESH_TEXT_MAX + 1];
};

void begin();
void loop();
void onScanResult(NimBLEAdvertisedDevice* dev);   // called from the scan callback

State state();
const char* radioName();

Conv& conv(int i);
// Conversations in display order (channels first, then most recent). Returns count.
int order(int* out);
// nth newest message of a conversation, or nullptr.
const Msg* message(int convIdx, int nthNewest);
void markRead(int convIdx);
int unreadTotal();

bool send(int convIdx, const char* text);
// Pops the index of a conversation that just received a message, or -1.
int takeIncoming();

uint32_t pin();
void setPin(uint32_t pin);

uint32_t epoch();           // radio's clock (unix seconds), 0 if unknown
bool pos(double* lat, double* lon);  // radio GPS/advert position, if it reports one
// Broadcasts this node's advert across the mesh so others can find it.
bool announce();
enum Announce : uint8_t { AN_IDLE, AN_SENDING, AN_SENT, AN_FAILED };
Announce announceState();

// Radio selection. Nothing is connected until the user picks a radio.
struct Radio {
  char     name[24];
  int8_t   rssi;
  uint8_t  slot;
  uint32_t seen;
};
int radios(Radio* out, int max);   // radios heard in the last 30 s, strongest first
void choose(int slot);
bool hasRadio();
const char* savedName();
void forget();

}  // namespace mesh
