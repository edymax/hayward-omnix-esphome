// Hayward OmniX (TriStar VS) BLE application protocol — framework-independent.
//
// Recovered from the OmniX Android app and checked against a live BLE capture
// of a personally owned pump. Host tests in tests/ use synthetic vectors only.
//
//   Handshake (per BLE connection, plaintext):
//     write  0x06
//     read   challenge[16]
//     write  0x06 || AES-128-ECB_encrypt(key, challenge)
//
//   App -> pump frame (write):
//     0x07 || GCM_ciphertext || BE32(counter) || GCM_tag[16]
//     IV  = BE32(counter) || challenge[0..7]          (12 bytes)
//     counter starts at 1 for the first frame on every connection.
//
//   Pump -> app frame (read):
//     GCM_ciphertext || BE32(counter) || GCM_tag[16]   (no type byte)
//     IV  = BE32(counter) || reverse(challenge[0..7])
//
//   Plaintext = 0x02 || MAC[6] || UBJSON(object)   (app -> pump)
//               0x01 || MAC[6] || UBJSON(object)   (pump -> app)
//   AES-128-GCM, no AAD, 16-byte tag, key = site securityKey UUID hex.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace hayward {

using Key = std::array<uint8_t, 16>;
using Mac = std::array<uint8_t, 6>;
using Challenge = std::array<uint8_t, 16>;
using Bytes = std::vector<uint8_t>;

// Message type bytes on the characteristic.
static constexpr uint8_t MSG_AUTH = 0x06;
static constexpr uint8_t MSG_SECURE = 0x07;
// Plaintext header direction bytes.
static constexpr uint8_t HDR_APP_TO_PUMP = 0x02;
static constexpr uint8_t HDR_PUMP_TO_APP = 0x01;

// OPIDs (IOT_PARAMS_OPID, UBJSON key "\x03").
static constexpr int OP_UI_SET_FILTER_SPEED = 9;
static constexpr int OP_UI_IOT_REQUEST_TELEMETRY = 600;
static constexpr int OP_TELEMETRY_RESPONSE = 1600;
static constexpr int OP_ACK = 1000;

// Parse a UUID with or without hyphens, or plain 32 hex digits, into a key. Returns false on bad input.
bool parse_key(const std::string &text, Key &out);

// 0x06 || AES-128-ECB(key, challenge)  (17 bytes)
Bytes build_auth_response(const Key &key, const Challenge &challenge);

// Encrypt an app->pump plaintext into a ready-to-write 0x07 frame.
bool encrypt_frame(const Key &key, const Challenge &challenge, uint32_t counter, const Bytes &plaintext,
                   Bytes &frame_out);

// Decrypt a pump->app read value. Returns false if the tag does not verify.
bool decrypt_response(const Key &key, const Challenge &challenge, const uint8_t *data, size_t len, Bytes &plain_out,
                      uint32_t *counter_out = nullptr);

// ---- Minimal UBJSON (only what the pump uses) ----
struct UValue {
  enum Type { NONE, INT, BOOL, STRING, BYTES, INT_ARRAY, OBJECT } type{NONE};
  int64_t i{0};
  bool b{false};
  std::string s;
  Bytes bytes;                 // typed uint8 array ([$U#n) — the pump nests objects in these
  std::vector<int64_t> ints;   // other typed/untyped numeric arrays
  std::map<std::string, UValue> obj;
};
using UObject = std::map<std::string, UValue>;

// Encode a flat object of integer fields in the same way the OmniX app does:
//   key  = 'i' <len> <bytes>
//   int  = 'i' int8 | 'I' int16-BE | 'l' int32-BE (smallest signed type that fits)
Bytes ubjson_encode_ints(const std::vector<std::pair<std::string, int32_t>> &fields);

// Decode one UBJSON object. Returns false on malformed input.
bool ubjson_decode_object(const uint8_t *data, size_t len, UObject &out);

// ---- Command builders (return plaintext: 0x02 || MAC || UBJSON) ----
// Set filter speed: {"\x03": 9, "v": percent, "\x04": seq}
Bytes build_set_speed(const Mac &mac, int percent, int seq);
// Telemetry request: {"\x03": 600, "G": page}   (app sends page 0, then page 1)
Bytes build_telemetry_request(const Mac &mac, int page);

// ---- Response helpers ----
// Split a decrypted pump->app plaintext into header MAC + body object.
bool parse_pump_plaintext(const Bytes &plain, Mac &mac_out, UObject &body_out);

// Every field of the OPID-1600 telemetry blob ("g"). Field names are the app's own
// IOT_PARAMS_* constants (OmniX bundle @639044). -1 / -1000 = not present.
struct Telemetry {
  bool valid{false};
  int tid{-1};                 // outer "\x04" IOT_PARAMS_TID: pump's transaction counter (+1 per reply)
  int water_temp{-1000};       // 'W' IOT_PARAMS_WATERTEMP (F; matched app's 57 F)
  int air_temp{-1000};         // 'a' IOT_PARAMS_AIRTEMP (F)
  int speed[4]{-1, -1, -1, -1};  // 'V' IOT_PARAMS_SPEED_ARRAY = [filterSpeed, lastSpeed, reportedSpeed, desiredSpeed]
  int power{-1};               // 'p' IOT_PARAMS_POWER (units not confirmed)
  bool fp_override{false};     // 'o' IOT_PARAMS_FPOVERRIDE (freeze-protect override)
  bool has_fp_override{false};
  int state{-1};               // 'f' IOT_PARAMS_STATE -> FilterOnState enum (1 = FILTER_ON)
  int why_on{-1};              // 'w' IOT_PARAMS_WHYISON -> FilterMsgType enum (140 MANUAL_ON, 170 START_TIMED_EVENT)
  int version{-1};             // 'e' IOT_PARAMS_VERSION (telemetry/protocol version, 2)
  int refresh_counter{-1};     // 'c' IOT_PARAMS_REFRESHCNTR
  int64_t crc[3]{-1, -1, -1};  // 'X' IOT_PARAMS_CRC_ARRAY (config CRCs; change => pump config changed)
  int64_t fw_version{-1};      // 's' IOT_PARAMS_FWVERSION (0x03010001)
  int device_type{-1};         // 'z' IOT_PARAMS_DEVICETYPE (16)
  int system_state{-1};        // 'u' IOT_PARAMS_SYSTEMSTATE (1)
};

// UI_GET_FILTER_DIAGNOSTIC (386) -> response 1386, per the app's decodePumpDiagnosticData.
// NOT present in the capture: layout comes from the app code only (unverified on this pump).
struct Diagnostics {
  bool valid{false};
  int filter_on_state{-1};     // 'n' IOT_PARAMS_STATUS
  int speed{-1};               // 'v' IOT_PARAMS_SPEED
  int64_t power{-1};           // 'p'[0]
  int64_t current{-1};         // 'p'[1]
  int64_t voltage{-1};         // 'p'[2]
  int drive_temp{-1000};       // 'k' IOT_PARAMS_TEMP
  int air_temp{-1000};         // 'a'
  int water_temp{-1000};       // 'W'
  int64_t pump_rev{-1};        // 's'[0]
  int64_t drive_rev{-1};       // 's'[1]
  int error{-1};               // 'Q' IOT_PARAMS_ERROR
};
static constexpr int OP_UI_GET_FILTER_DIAGNOSTIC = 386;
static constexpr int OP_FILTER_DIAGNOSTIC_RESPONSE = 1386;
Bytes build_diagnostic_request(const Mac &mac);
Diagnostics parse_diagnostics(const UObject &body);
int get_opid(const UObject &body);
const char *filter_on_state_name(int v);
const char *filter_msg_type_name(int v);
// App's calculatePumpStatus(): Paused / Stopped / Priming / FreezeProtect / Running.
const char *pump_status_name(const Telemetry &t);

// body is the outer telemetry response object (OPID 1600, contains blob 'g').
Telemetry parse_telemetry(const UObject &body);

struct Ack {
  bool valid{false};
  int echoed_opid{-1};  // 'x'
  int echoed_seq{-1};   // "\x05"
  int result{-1};       // 'n'  (0 == OK in every captured ack)
};
Ack parse_ack(const UObject &body);

std::string hex(const uint8_t *data, size_t len);

}  // namespace hayward
