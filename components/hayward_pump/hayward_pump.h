#pragma once

#ifdef USE_ESP32

#include <array>
#include <string>
#include <vector>

#include "esphome/components/ble_client/ble_client.h"
#include "esphome/components/esp32_ble_tracker/esp32_ble_tracker.h"
#include "esphome/core/component.h"
#include "esphome/core/optional.h"
#include "esphome/core/preferences.h"
#ifdef USE_SENSOR
#include "esphome/components/sensor/sensor.h"
#endif
#ifdef USE_TEXT_SENSOR
#include "esphome/components/text_sensor/text_sensor.h"
#endif
#ifdef USE_BINARY_SENSOR
#include "esphome/components/binary_sensor/binary_sensor.h"
#endif
#ifdef USE_NUMBER
#include "esphome/components/number/number.h"
#endif

#include "hayward_protocol.h"

namespace esphome::hayward_pump {

namespace espbt = esphome::esp32_ble_tracker;

// Indexes for numeric sensors (must match SENSOR_FIELDS in __init__.py).
enum SensorIdx : uint8_t {
  S_WATER_TEMP = 0,
  S_AIR_TEMP,
  S_FILTER_SPEED,
  S_LAST_SPEED,
  S_REPORTED_SPEED,
  S_DESIRED_SPEED,
  S_POWER,
  S_FILTER_STATE_CODE,
  S_WHY_ON_CODE,
  S_REFRESH_COUNTER,
  S_TELEMETRY_VERSION,
  S_CRC1,
  S_CRC2,
  S_CRC3,
  S_DEVICE_TYPE,
  S_SYSTEM_STATE,
  S_PUMP_TID,
  S_LAST_ACK_RESULT,
  S_SESSION_FAILURES,
  S_DIAG_POWER,
  S_DIAG_CURRENT,
  S_DIAG_VOLTAGE,
  S_DRIVE_TEMP,
  S_DIAG_SPEED,
  S_DIAG_STATE_CODE,
  S_ERROR_CODE,
  S_COUNT
};

enum TextIdx : uint8_t { T_STATUS = 0, T_FIRMWARE, T_FILTER_STATE, T_WHY_ON, T_PUMP_STATUS, T_PUMP_REV, T_DRIVE_REV, T_COUNT };
enum BinIdx : uint8_t { B_LINK_OK = 0, B_FP_OVERRIDE, B_RUNNING, B_COUNT };

class HaywardPump;

#ifdef USE_NUMBER
class HaywardSpeedNumber : public number::Number, public Parented<HaywardPump> {
 protected:
  void control(float value) override;
};
#endif

class HaywardPump : public ble_client::BLEClientNode, public PollingComponent {
 public:
  void setup() override;
  void update() override;  // telemetry poll
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_BLUETOOTH; }
  void gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                           esp_ble_gattc_cb_param_t *param) override;

  void set_key(const std::string &key_hex);
  void set_pump_mac(uint64_t mac);
  void set_speed_limits(int min_pct, int max_pct) {
    this->min_speed_ = min_pct;
    this->max_speed_ = max_pct;
  }
  void set_initial_command_seq(int seq) { this->initial_seq_ = seq; }
  void set_poll_after_command(bool v) { this->poll_after_command_ = v; }
  void set_diagnostics(bool v) { this->diagnostics_ = v; }
  void set_auth_read_delay(uint32_t ms) { this->auth_read_delay_ = ms; }
  void set_max_failed_sessions(uint32_t n) { this->max_failed_sessions_ = n; }
#ifdef USE_SENSOR
  void set_sensor(uint8_t idx, sensor::Sensor *s) { this->sensors_[idx] = s; }
#endif
#ifdef USE_TEXT_SENSOR
  void set_text_sensor(uint8_t idx, text_sensor::TextSensor *s) { this->texts_[idx] = s; }
#endif
#ifdef USE_BINARY_SENSOR
  void set_binary_sensor(uint8_t idx, binary_sensor::BinarySensor *s) { this->bins_[idx] = s; }
#endif
#ifdef USE_NUMBER
  void set_speed_number(HaywardSpeedNumber *n) { this->speed_number_ = n; }
#endif

  /// Queue a set-speed command. Out-of-range values are REJECTED (never clamped to 0/off).
  bool request_speed(int percent);
  /// Queue a telemetry poll.
  void request_poll();

 protected:
  enum class Step : uint8_t { IDLE, CONNECTING, AUTH_REQ, AUTH_READ, AUTH_RESP, FRAME_WRITE, FRAME_READ, CLOSING };
  enum class Job : uint8_t { NONE, SPEED, POLL };

  void kick_();
  void start_session_();
  void begin_auth_();
  void send_next_frame_();
  void handle_response_(const uint8_t *data, uint16_t len);
  void finish_(bool ok, const std::string &why);
  bool write_(const hayward::Bytes &data);
  bool read_();
  void publish_status_(const std::string &s);
  void publish_telemetry_(const hayward::Telemetry &t);
  void publish_diagnostics_(const hayward::Diagnostics &d);
  void pub_text_(uint8_t idx, const std::string &v);
  void pub_(uint8_t idx, float v);
  uint16_t next_seq_();

  hayward::Key key_{};
  bool key_ok_{false};
  hayward::Mac mac_{};
  int min_speed_{18};
  int max_speed_{100};
  int initial_seq_{28000};
  bool poll_after_command_{true};
  bool diagnostics_{false};
  uint8_t diag_failures_{0};
  bool diag_frame_{false};  // true while the current frame is the (unverified) op-386 request
  bool mtu_set_{false};

  Step step_{Step::IDLE};
  Job job_{Job::NONE};
  optional<int> pending_speed_{};
  bool poll_pending_{false};
  int job_speed_{0};
  uint16_t job_seq_{0};
  std::vector<hayward::Bytes> frames_;  // plaintexts to send in this session
  size_t frame_idx_{0};
  uint32_t tx_counter_{0};
  hayward::Challenge challenge_{};
  uint16_t char_handle_{0};
  uint16_t mtu_{23};
  uint32_t failures_{0};
  uint32_t auth_read_delay_{0};
  uint32_t max_failed_sessions_{0};
  bool paused_{false};
  bool mtu_done_{false};
  bool search_done_{false};
  void maybe_begin_auth_();
  hayward::Bytes tx_buf_;

  uint16_t seq_{0};
  ESPPreferenceObject seq_pref_;

#ifdef USE_SENSOR
  std::array<sensor::Sensor *, S_COUNT> sensors_{};
#endif
#ifdef USE_TEXT_SENSOR
  std::array<text_sensor::TextSensor *, T_COUNT> texts_{};
#endif
#ifdef USE_BINARY_SENSOR
  std::array<binary_sensor::BinarySensor *, B_COUNT> bins_{};
#endif
#ifdef USE_NUMBER
  HaywardSpeedNumber *speed_number_{nullptr};
#endif
};

}  // namespace esphome::hayward_pump

#endif  // USE_ESP32
