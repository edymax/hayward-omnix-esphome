// Host-side test of the OmniX protocol code using a published synthetic key
// and frames. No live capture data and no real site key are included.
// Build: ./run_host_test.sh
#include "../components/hayward_pump/hayward_protocol.h"
#include <cstdio>
#include <string>
using namespace hayward;
static int fails = 0;
static Bytes unhex(const std::string &s) {
  Bytes b;
  for (size_t i = 0; i + 1 < s.size(); i += 2)
    b.push_back((uint8_t) std::stoi(s.substr(i, 2), nullptr, 16));
  return b;
}
static Challenge ch(const std::string &s) {
  Challenge c;
  auto b = unhex(s);
  for (int i = 0; i < 16; i++) c[i] = b[i];
  return c;
}
static void check(bool ok, const char *what) {
  printf("%s  %s\n", ok ? "PASS" : "FAIL", what);
  if (!ok) fails++;
}
int main() {
  // Published test key only. Never a real site security key.
  const char *key_uuid = "00112233-4455-6677-8899-aabbccddeeff";
  const char *key_hex = "00112233445566778899aabbccddeeff";
  Key key{}, key2{};
  check(parse_key(key_uuid, key) && parse_key(key_hex, key2) && key == key2,
        "parse_key accepts hyphenated UUID and plain 32 hex");
  Key bad{};
  check(!parse_key("not-a-key", bad) && !parse_key("00112233", bad),
        "parse_key rejects short or non hex input");

  Challenge c = ch("000102030405060708090a0b0c0d0e0f");
  Bytes auth = build_auth_response(key, c);
  check(hex(auth.data(), auth.size()) == "06279fb74a7572135e8f9b8ef6d1eee003",
        "handshake response matches synthetic AES-128-ECB vector");

  Mac mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  Bytes hello = unhex("02aabbccddeeff") ; // plus "HELLO"
  hello.insert(hello.end(), {'H','E','L','L','O'});
  Bytes frame;
  check(encrypt_frame(key, c, 1, hello, frame) &&
            hex(frame.data(), frame.size()) ==
                "072477702ce9ff4c977a09f12d0000000139770ad1070eb7c29547ef11dc5a0b1f",
        "app to pump AES-128-GCM frame matches synthetic vector");

  Bytes pump = unhex("aa8843c20769f28d74483a6e000000014eadd5df091290578cc7606b4c94b34e");
  Bytes pt;
  uint32_t ctr = 0;
  bool ok = decrypt_response(key, c, pump.data(), pump.size(), pt, &ctr);
  check(ok && ctr == 1 && hex(pt.data(), pt.size()) == "01aabbccddeeff574f524c44",
        "pump to app decrypt uses reversed session id IV");

  Bytes bad_frame = pump;
  bad_frame[3] ^= 0x01;
  check(!decrypt_response(key, c, bad_frame.data(), bad_frame.size(), pt),
        "tampered frame is rejected by the GCM tag");

  Bytes set = build_set_speed(mac, 75, 1000);
  check(hex(set.data(), set.size()).rfind("02aabbccddeeff", 0) == 0,
        "set speed plaintext starts with 0x02 and the placeholder MAC");
  Bytes tel = build_telemetry_request(mac, 1);
  check(hex(tel.data(), tel.size()).rfind("02aabbccddeeff", 0) == 0,
        "telemetry request plaintext starts with 0x02 and the placeholder MAC");
  Bytes dreq = build_diagnostic_request(mac);
  check(hex(dreq.data(), dreq.size()).rfind("02aabbccddeeff", 0) == 0,
        "diagnostic request plaintext starts with 0x02 and the placeholder MAC");

  // Synthetic 1386 body shaped like decodePumpDiagnosticData expects
  Bytes syn = unhex("7b5501034905" "6a" "55016e6901" "55017669" "4b"
                    "5501705b2449235503" "0384" "000a" "00e6"
                    "55016b6948" "5501516900" "7d");
  UObject so;
  bool sok = ubjson_decode_object(syn.data(), syn.size(), so);
  Diagnostics dg = parse_diagnostics(so);
  check(sok && dg.valid && dg.speed == 75 && dg.power == 900 && dg.current == 10 &&
            dg.voltage == 230 && dg.drive_temp == 72 && dg.error == 0,
        "diag parser on synthetic 1386 reply");

  printf(fails ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", fails);
  return fails ? 1 : 0;
}
