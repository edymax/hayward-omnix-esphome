#include "hayward_protocol.h"

#include <cstring>

#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"

namespace hayward {

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool parse_key(const std::string &text, Key &out) {
  std::string h;
  for (char c : text) {
    if (c == '-' || c == ' ' || c == ':') continue;
    if (hexval(c) < 0) return false;
    h.push_back(c);
  }
  if (h.size() != 32) return false;
  for (size_t i = 0; i < 16; i++) out[i] = (uint8_t) ((hexval(h[2 * i]) << 4) | hexval(h[2 * i + 1]));
  return true;
}

std::string hex(const uint8_t *data, size_t len) {
  static const char *d = "0123456789abcdef";
  std::string s;
  s.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    s.push_back(d[data[i] >> 4]);
    s.push_back(d[data[i] & 0xF]);
  }
  return s;
}

Bytes build_auth_response(const Key &key, const Challenge &challenge) {
  Bytes out(17, 0);
  out[0] = MSG_AUTH;
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, key.data(), 128);
  mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, challenge.data(), out.data() + 1);
  mbedtls_aes_free(&ctx);
  return out;
}

static void put_be32(uint8_t *p, uint32_t v) {
  p[0] = v >> 24;
  p[1] = v >> 16;
  p[2] = v >> 8;
  p[3] = v;
}

bool encrypt_frame(const Key &key, const Challenge &challenge, uint32_t counter, const Bytes &plaintext,
                   Bytes &frame_out) {
  uint8_t iv[12];
  put_be32(iv, counter);
  memcpy(iv + 4, challenge.data(), 8);
  frame_out.assign(1 + plaintext.size() + 4 + 16, 0);
  frame_out[0] = MSG_SECURE;
  uint8_t *ct = frame_out.data() + 1;
  uint8_t *cnt = ct + plaintext.size();
  uint8_t *tag = cnt + 4;
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), 128);
  if (rc == 0)
    rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext.size(), iv, sizeof(iv), nullptr, 0,
                                   plaintext.data(), ct, 16, tag);
  mbedtls_gcm_free(&gcm);
  put_be32(cnt, counter);
  return rc == 0;
}

bool decrypt_response(const Key &key, const Challenge &challenge, const uint8_t *data, size_t len, Bytes &plain_out,
                      uint32_t *counter_out) {
  if (len < 20 + 1) return false;
  size_t ct_len = len - 20;
  const uint8_t *cnt = data + ct_len;
  const uint8_t *tag = cnt + 4;
  uint8_t iv[12];
  memcpy(iv, cnt, 4);
  for (int i = 0; i < 8; i++) iv[4 + i] = challenge[7 - i];  // reversed session id (pump direction)
  plain_out.assign(ct_len, 0);
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), 128);
  if (rc == 0) rc = mbedtls_gcm_auth_decrypt(&gcm, ct_len, iv, sizeof(iv), nullptr, 0, tag, 16, data, plain_out.data());
  mbedtls_gcm_free(&gcm);
  if (counter_out) *counter_out = ((uint32_t) cnt[0] << 24) | ((uint32_t) cnt[1] << 16) | ((uint32_t) cnt[2] << 8) | cnt[3];
  if (rc != 0) plain_out.clear();
  return rc == 0;
}

// ---------------- UBJSON ----------------
static void enc_int(Bytes &b, int32_t v) {
  if (v >= -128 && v <= 127) {
    b.push_back('i');
    b.push_back((uint8_t) (int8_t) v);
  } else if (v >= -32768 && v <= 32767) {
    b.push_back('I');
    b.push_back((uint8_t) ((v >> 8) & 0xFF));
    b.push_back((uint8_t) (v & 0xFF));
  } else {
    b.push_back('l');
    for (int s = 24; s >= 0; s -= 8) b.push_back((uint8_t) ((v >> s) & 0xFF));
  }
}

Bytes ubjson_encode_ints(const std::vector<std::pair<std::string, int32_t>> &fields) {
  Bytes b;
  b.push_back('{');
  for (auto &f : fields) {
    b.push_back('i');
    b.push_back((uint8_t) f.first.size());
    b.insert(b.end(), f.first.begin(), f.first.end());
    enc_int(b, f.second);
  }
  b.push_back('}');
  return b;
}

namespace {
struct Reader {
  const uint8_t *p;
  size_t n, i{0};
  bool ok{true};
  bool need(size_t k) {
    if (i + k > n) ok = false;
    return ok;
  }
  uint8_t u8() { return need(1) ? p[i++] : 0; }
  int64_t be(size_t k, bool sign) {
    if (!need(k)) return 0;
    uint64_t v = 0;
    for (size_t j = 0; j < k; j++) v = (v << 8) | p[i++];
    if (sign && k < 8 && (v >> (8 * k - 1)) & 1) v |= ~((uint64_t(1) << (8 * k)) - 1);
    return (int64_t) v;
  }
};

bool read_scalar_int(Reader &r, char t, int64_t &out) {
  switch (t) {
    case 'i': out = r.be(1, true); return r.ok;
    case 'U': out = r.be(1, false); return r.ok;
    case 'I': out = r.be(2, true); return r.ok;
    case 'l': out = r.be(4, true); return r.ok;
    case 'L': out = r.be(8, true); return r.ok;
    default: return false;
  }
}

bool read_value(Reader &r, char t, UValue &v, int depth);

bool read_object_body(Reader &r, UObject &obj, int depth) {
  if (depth > 6) return false;
  while (r.ok && r.need(1) && r.p[r.i] != '}') {
    int64_t klen;
    if (!read_scalar_int(r, (char) r.u8(), klen) || klen < 0 || !r.need((size_t) klen)) return false;
    std::string key((const char *) r.p + r.i, (size_t) klen);
    r.i += (size_t) klen;
    UValue v;
    if (!read_value(r, (char) r.u8(), v, depth + 1)) return false;
    obj[key] = std::move(v);
  }
  if (!r.need(1)) return false;
  r.i++;  // '}'
  return true;
}

bool read_value(Reader &r, char t, UValue &v, int depth) {
  if (!r.ok) return false;
  int64_t iv;
  switch (t) {
    case 'Z': v.type = UValue::NONE; return true;
    case 'T': v.type = UValue::BOOL; v.b = true; return true;
    case 'F': v.type = UValue::BOOL; v.b = false; return true;
    case 'i': case 'U': case 'I': case 'l': case 'L':
      if (!read_scalar_int(r, t, iv)) return false;
      v.type = UValue::INT; v.i = iv; return true;
    case 'S': {
      int64_t n;
      if (!read_scalar_int(r, (char) r.u8(), n) || n < 0 || !r.need((size_t) n)) return false;
      v.type = UValue::STRING; v.s.assign((const char *) r.p + r.i, (size_t) n); r.i += (size_t) n; return true;
    }
    case '{':
      v.type = UValue::OBJECT;
      return read_object_body(r, v.obj, depth);
    case '[': {
      char et = 0;
      int64_t count = -1;
      if (r.need(1) && r.p[r.i] == '$') { r.i++; et = (char) r.u8(); }
      if (r.need(1) && r.p[r.i] == '#') {
        r.i++;
        if (!read_scalar_int(r, (char) r.u8(), count) || count < 0 || count > 4096) return false;
      }
      if (et == 'U' && count >= 0) {  // binary blob
        if (!r.need((size_t) count)) return false;
        v.type = UValue::BYTES; v.bytes.assign(r.p + r.i, r.p + r.i + count); r.i += (size_t) count; return true;
      }
      v.type = UValue::INT_ARRAY;
      if (count >= 0) {
        for (int64_t k = 0; k < count; k++) {
          UValue e;
          if (!read_value(r, et ? et : (char) r.u8(), e, depth + 1)) return false;
          v.ints.push_back(e.type == UValue::INT ? e.i : 0);
        }
        return true;
      }
      while (r.ok && r.need(1) && r.p[r.i] != ']') {
        UValue e;
        if (!read_value(r, (char) r.u8(), e, depth + 1)) return false;
        v.ints.push_back(e.type == UValue::INT ? e.i : 0);
      }
      if (!r.need(1)) return false;
      r.i++;
      return true;
    }
    default: return false;
  }
}
}  // namespace

bool ubjson_decode_object(const uint8_t *data, size_t len, UObject &out) {
  Reader r{data, len};
  if (len < 2 || data[0] != '{') return false;
  r.i = 1;
  out.clear();
  return read_object_body(r, out, 0) && r.ok;
}

// ---------------- builders ----------------
static Bytes header(uint8_t dir, const Mac &mac) {
  Bytes b;
  b.push_back(dir);
  b.insert(b.end(), mac.begin(), mac.end());
  return b;
}

Bytes build_set_speed(const Mac &mac, int percent, int seq) {
  Bytes b = header(HDR_APP_TO_PUMP, mac);
  Bytes body = ubjson_encode_ints({{std::string("\x03", 1), OP_UI_SET_FILTER_SPEED},
                                   {"v", percent},
                                   {std::string("\x04", 1), seq}});
  b.insert(b.end(), body.begin(), body.end());
  return b;
}

Bytes build_telemetry_request(const Mac &mac, int page) {
  Bytes b = header(HDR_APP_TO_PUMP, mac);
  Bytes body = ubjson_encode_ints({{std::string("\x03", 1), OP_UI_IOT_REQUEST_TELEMETRY}, {"G", page}});
  b.insert(b.end(), body.begin(), body.end());
  return b;
}

bool parse_pump_plaintext(const Bytes &plain, Mac &mac_out, UObject &body_out) {
  if (plain.size() < 9 || plain[0] != HDR_PUMP_TO_APP) return false;
  memcpy(mac_out.data(), plain.data() + 1, 6);
  return ubjson_decode_object(plain.data() + 7, plain.size() - 7, body_out);
}

static int get_int(const UObject &o, const std::string &k, int def) {
  auto it = o.find(k);
  return (it != o.end() && it->second.type == UValue::INT) ? (int) it->second.i : def;
}
static int64_t get_i64(const UObject &o, const std::string &k, int64_t def) {
  auto it = o.find(k);
  return (it != o.end() && it->second.type == UValue::INT) ? it->second.i : def;
}

static bool get_array(const UObject &o, const std::string &k, std::vector<int64_t> &out) {
  auto it = o.find(k);
  if (it == o.end()) return false;
  if (it->second.type == UValue::INT_ARRAY) { out = it->second.ints; return true; }
  if (it->second.type == UValue::BYTES) { out.assign(it->second.bytes.begin(), it->second.bytes.end()); return true; }
  if (it->second.type == UValue::INT) { out.assign(1, it->second.i); return true; }
  return false;
}

int get_opid(const UObject &body) { return get_int(body, std::string("\x03", 1), -1); }

Telemetry parse_telemetry(const UObject &body) {
  Telemetry t;
  if (get_opid(body) != OP_TELEMETRY_RESPONSE) return t;
  t.tid = get_int(body, std::string("\x04", 1), -1);
  auto g = body.find("g");
  if (g == body.end()) return t;  // page-1 reply carries no blob
  UObject blob;
  if (g->second.type == UValue::BYTES) {
    if (!ubjson_decode_object(g->second.bytes.data(), g->second.bytes.size(), blob)) return t;
  } else if (g->second.type == UValue::OBJECT) {
    blob = g->second.obj;
  } else {
    return t;
  }
  t.water_temp = get_int(blob, "W", -1000);
  t.air_temp = get_int(blob, "a", -1000);
  std::vector<int64_t> arr;
  if (get_array(blob, "V", arr))
    for (size_t k = 0; k < 4 && k < arr.size(); k++) t.speed[k] = (int) arr[k];
  if (get_array(blob, "X", arr))
    for (size_t k = 0; k < 3 && k < arr.size(); k++) t.crc[k] = arr[k];
  t.power = get_int(blob, "p", -1);
  auto o = blob.find("o");
  if (o != blob.end() && o->second.type == UValue::BOOL) { t.has_fp_override = true; t.fp_override = o->second.b; }
  t.state = get_int(blob, "f", -1);
  t.why_on = get_int(blob, "w", -1);
  t.version = get_int(blob, "e", -1);
  t.refresh_counter = get_int(blob, "c", -1);
  t.fw_version = get_i64(blob, "s", -1);
  t.device_type = get_int(blob, "z", -1);
  t.system_state = get_int(blob, "u", -1);
  t.valid = true;
  return t;
}

Bytes build_diagnostic_request(const Mac &mac) {
  Bytes b = header(HDR_APP_TO_PUMP, mac);
  Bytes body = ubjson_encode_ints({{std::string("\x03", 1), OP_UI_GET_FILTER_DIAGNOSTIC}});
  b.insert(b.end(), body.begin(), body.end());
  return b;
}

Diagnostics parse_diagnostics(const UObject &body) {
  Diagnostics d;
  if (get_opid(body) != OP_FILTER_DIAGNOSTIC_RESPONSE) return d;
  d.filter_on_state = get_int(body, "n", -1);
  d.speed = get_int(body, "v", -1);
  std::vector<int64_t> arr;
  if (get_array(body, "p", arr)) {
    if (arr.size() > 0) d.power = arr[0];
    if (arr.size() > 1) d.current = arr[1];
    if (arr.size() > 2) d.voltage = arr[2];
  }
  if (get_array(body, "s", arr)) {
    if (arr.size() > 0) d.pump_rev = arr[0];
    if (arr.size() > 1) d.drive_rev = arr[1];
  }
  d.drive_temp = get_int(body, "k", -1000);
  d.air_temp = get_int(body, "a", -1000);
  d.water_temp = get_int(body, "W", -1000);
  d.error = get_int(body, "Q", -1);
  d.valid = true;
  return d;
}

const char *filter_on_state_name(int v) {
  switch (v) {
    case 0: return "off";
    case 1: return "on";
    case 2: return "priming";
    case 3: return "waiting to turn off";
    case 4: return "waiting to turn off (manual)";
    case 5: return "heater extend";
    case 6: return "cool-down";
    case 7: return "suspended";
    case 8: return "CSAD extend";
    case 9: return "superchlorinate";
    case 10: return "force priming";
    case 11: return "waiting for pump to turn off";
    case 12: return "waiting to change valves";
    case 13: return "under remote control";
    case 14: return "pause button";
    default: return "unknown";
  }
}

const char *filter_msg_type_name(int v) {
  switch (v) {
    case 0: return "no message";
    case 10: return "stop filter";
    case 11: return "end manual commands";
    case 12: return "end countdown";
    case 30: return "cool-down";
    case 40: return "CSAD extend";
    case 50: return "heater extend";
    case 60: return "pause";
    case 70: return "resume";
    case 75: return "no water flow";
    case 80: return "off - valve changing";
    case 90: return "run at high speed";
    case 100: return "external interlock";
    case 105: return "freeze protect";
    case 110: return "superchlorinate";
    case 114: return "group commands";
    case 115: return "exit group commands";
    case 120: return "countdown timer";
    case 130: return "spillover countdown timer";
    case 140: return "manual on";
    case 150: return "manual spillover";
    case 160: return "timed spillover";
    case 170: return "timed event (schedule)";
    case 180: return "priming done";
    case 190: return "request off timeout";
    case 220: return "pool/spa spillover";
    case 230: return "spillover off";
    case 240: return "manual off";
    case 241: return "schedule disabled";
    case 250: return "waiting for pump off";
    case 260: return "set speed";
    case 270: return "requesting valve change";
    case 280: return "cancel freeze protect";
    default: return "unknown";
  }
}

const char *pump_status_name(const Telemetry &t) {
  if (!t.valid) return "unknown";
  if (t.state == 0) return "paused";
  if (t.state == 14) return "stopped";
  if (t.state == 2) return "priming";
  if (t.why_on == 105) return "freeze protect";
  return t.speed[0] > 0 ? "running" : "paused";
}

Ack parse_ack(const UObject &body) {
  Ack a;
  if (get_int(body, std::string("\x03", 1), -1) != OP_ACK) return a;
  a.echoed_opid = get_int(body, "x", -1);
  a.echoed_seq = get_int(body, std::string("\x05", 1), -1);
  a.result = get_int(body, "n", -1);
  a.valid = true;
  return a;
}

}  // namespace hayward
