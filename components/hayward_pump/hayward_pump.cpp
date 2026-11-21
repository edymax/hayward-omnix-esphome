#include "hayward_pump.h"

#ifdef USE_ESP32

#include <esp_gatt_common_api.h>
#include <esp_gattc_api.h>

#include "esphome/core/application.h"
#include "esphome/core/hal.h"
#include "esphome/core/helpers.h"
#include "esphome/core/log.h"

#include <cstring>

namespace esphome::hayward_pump {

static const char *const TAG = "hayward_pump";

// Hayward Industries SIG member service + the single OmniX characteristic (handle 0x000F on this pump).
static const uint16_t HAYWARD_SERVICE_UUID16 = 0xFCA5;
// OmniX appMessageUUID (from the app). On the wire (little-endian) its 16 bytes read
// f126b0b9 047bdbb4 f89b5987 30014666; from_raw() wants the canonical big-endian string.
static const char *const HAYWARD_CHAR_UUID = "66460130-8759-9bf8-b4db-7b04b9b026f1";
static const uint16_t HAYWARD_CHAR_HANDLE_FALLBACK = 0x000F;
static const uint32_t SESSION_TIMEOUT_MS = 15000;
static const uint16_t SEQ_MIN = 1000;
static const uint16_t SEQ_MAX = 32000;  // stay inside int16 so the body length matches the app (25-byte frame)

#ifdef USE_NUMBER
void HaywardSpeedNumber::control(float value) {
  // Do NOT publish optimistically; state is published after the pump ACKs (or from telemetry).
  this->parent_->request_speed((int) lroundf(value));
}
#endif

void HaywardPump::set_key(const std::string &key_hex) {
  this->key_ok_ = hayward::parse_key(key_hex, this->key_);
}

void HaywardPump::set_pump_mac(uint64_t mac) {
  for (int i = 0; i < 6; i++) this->mac_[i] = (mac >> (8 * (5 - i))) & 0xFF;
}

void HaywardPump::setup() {
  if (!this->key_ok_) {
    ESP_LOGE(TAG, "aes_key is not 32 hex digits — refusing to run");
    this->mark_failed();
    return;
  }
  uint32_t hash = fnv1_hash("hayward_pump_seq");
  this->seq_pref_ = global_preferences->make_preference<uint16_t>(hash);
  uint16_t stored = 0;
  if (this->seq_pref_.load(&stored) && stored >= SEQ_MIN && stored <= SEQ_MAX && stored >= this->initial_seq_) {
    this->seq_ = stored;
  } else {
    this->seq_ = (uint16_t) this->initial_seq_;
  }
  this->publish_status_("idle");
#ifdef USE_BINARY_SENSOR
  if (this->bins_[B_LINK_OK]) this->bins_[B_LINK_OK]->publish_state(false);
#endif
  this->pub_(S_SESSION_FAILURES, 0);
  // First telemetry poll shortly after boot; nothing is ever WRITTEN to the pump at boot except
  // the read-only telemetry request.
  this->set_timeout("hp_first_poll", 20000, [this]() { this->request_poll(); });
}

void HaywardPump::dump_config() {
  ESP_LOGCONFIG(TAG, "Hayward OmniX pump (BLE)");
  ESP_LOGCONFIG(TAG, "  Pump MAC: %02X:%02X:%02X:%02X:%02X:%02X", this->mac_[0], this->mac_[1], this->mac_[2],
                this->mac_[3], this->mac_[4], this->mac_[5]);
  ESP_LOGCONFIG(TAG, "  AES key: %s", this->key_ok_ ? "set (hidden)" : "INVALID");
  ESP_LOGCONFIG(TAG, "  Speed limits: %d..%d %%", this->min_speed_, this->max_speed_);
  ESP_LOGCONFIG(TAG, "  Next command seq: %u", this->seq_);
  ESP_LOGCONFIG(TAG, "  Op-386 diagnostics: %s", YESNO(this->diagnostics_));
  LOG_UPDATE_INTERVAL(this);
}

void HaywardPump::update() { this->request_poll(); }

bool HaywardPump::request_speed(int percent) {
  if (percent < this->min_speed_ || percent > this->max_speed_) {
    ESP_LOGW(TAG, "Rejected speed %d%% (allowed %d..%d). This component never sends off/0%%.", percent,
             this->min_speed_, this->max_speed_);
    this->publish_status_("rejected out-of-range speed");
    return false;
  }
  ESP_LOGI(TAG, "Queued set-speed %d%%", percent);
  this->pending_speed_ = percent;
  this->kick_();
  return true;
}

void HaywardPump::request_poll() {
  this->poll_pending_ = true;
  this->kick_();
}

void HaywardPump::kick_() {
  if (this->paused_) return;
  if (this->step_ != Step::IDLE) return;  // picked up when the current session ends
  if (!this->pending_speed_.has_value() && !this->poll_pending_) return;
  if (this->parent()->state() != espbt::ClientState::IDLE) {
    // BLE client still tearing down the previous link — try again shortly.
    this->set_timeout("hp_kick", 1000, [this]() { this->kick_(); });
    return;
  }
  this->start_session_();
}

uint16_t HaywardPump::next_seq_() {
  uint16_t s = this->seq_;
  this->seq_ = (this->seq_ >= SEQ_MAX) ? SEQ_MIN : this->seq_ + 1;
  this->seq_pref_.save(&this->seq_);
  return s;
}

void HaywardPump::start_session_() {
  this->frames_.clear();
  this->frame_idx_ = 0;
  this->tx_counter_ = 0;
  if (this->pending_speed_.has_value()) {
    this->job_ = Job::SPEED;
    this->job_speed_ = *this->pending_speed_;
    this->pending_speed_.reset();
    this->job_seq_ = this->next_seq_();
    this->frames_.push_back(hayward::build_set_speed(this->mac_, this->job_speed_, this->job_seq_));
    ESP_LOGI(TAG, "Session: set speed %d%% (seq %u)", this->job_speed_, this->job_seq_);
  } else {
    this->job_ = Job::POLL;
    this->poll_pending_ = false;
    // Exactly what the OmniX app sends: page 0 (returns the telemetry blob) then page 1.
    this->frames_.push_back(hayward::build_telemetry_request(this->mac_, 0));
    this->frames_.push_back(hayward::build_telemetry_request(this->mac_, 1));
    // Optional: UI_GET_FILTER_DIAGNOSTIC (read-only GET; layout from app code, not yet seen live).
    if (this->diagnostics_) this->frames_.push_back(hayward::build_diagnostic_request(this->mac_));
    ESP_LOGD(TAG, "Session: telemetry poll");
  }
  if (!this->mtu_set_) {
    // Frames are up to ~60 bytes; ask for a big ATT MTU so writes are single Write Requests
    // (the app requests 527 and the pump grants 251; the pump refuses reads when MTU < 251). Must be set before connecting.
    esp_err_t err = esp_ble_gatt_set_local_mtu(517);
    if (err != ESP_OK) ESP_LOGW(TAG, "esp_ble_gatt_set_local_mtu failed: %d", err);
    this->mtu_set_ = true;
  }
  this->mtu_done_ = false;
  this->search_done_ = false;
  this->step_ = Step::CONNECTING;
  this->publish_status_(this->job_ == Job::SPEED ? "connecting (set speed)" : "connecting (poll)");
  this->diag_frame_ = false;
  this->set_timeout("hp_session", SESSION_TIMEOUT_MS, [this]() {
    if (this->diag_frame_) {  // telemetry already succeeded; only the unverified op-386 hung
      ESP_LOGW(TAG, "No reply to op-386 diagnostics");
      if (++this->diag_failures_ >= 3) this->diagnostics_ = false;
      this->finish_(true, "ok (diag timeout)");
      return;
    }
    this->finish_(false, "timeout");
  });
  this->parent()->connect();
}

bool HaywardPump::write_(const hayward::Bytes &data) {
  if (data.size() + 3 > this->mtu_) {
    ESP_LOGW(TAG, "Frame %u B exceeds MTU %u — the stack will use a long write", (unsigned) data.size(), this->mtu_);
  }
  this->tx_buf_ = data;
  ESP_LOGV(TAG, "TX write h=0x%04X mtu=%u len=%u: %s", this->char_handle_, this->mtu_, (unsigned) data.size(),
           hayward::hex(data.data(), data.size()).c_str());
  esp_err_t err = esp_ble_gattc_write_char(this->parent()->get_gattc_if(), this->parent()->get_conn_id(),
                                           this->char_handle_, this->tx_buf_.size(), this->tx_buf_.data(),
                                           ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
  if (err != ESP_OK) {
    this->finish_(false, "write call failed");
    return false;
  }
  return true;
}

bool HaywardPump::read_() {
  ESP_LOGV(TAG, "TX read h=0x%04X mtu=%u", this->char_handle_, this->mtu_);
  esp_err_t err = esp_ble_gattc_read_char(this->parent()->get_gattc_if(), this->parent()->get_conn_id(),
                                          this->char_handle_, ESP_GATT_AUTH_REQ_NONE);
  if (err != ESP_OK) {
    this->finish_(false, "read call failed");
    return false;
  }
  return true;
}

void HaywardPump::maybe_begin_auth_() {
  // Mirror the OmniX app: MTU exchange (app: 527 -> pump 251) completes before the first write.
  if (this->step_ != Step::CONNECTING || !this->search_done_) return;
  if (!this->mtu_done_) {
    ESP_LOGD(TAG, "Discovery done, waiting for MTU exchange before auth");
    this->set_timeout("hp_mtu_wait", 2000, [this]() {
      if (this->step_ == Step::CONNECTING && this->search_done_ && !this->mtu_done_) {
        ESP_LOGW(TAG, "No MTU event after 2 s; continuing with mtu=%u", this->mtu_);
        this->mtu_done_ = true;
        this->begin_auth_();
      }
    });
    return;
  }
  this->begin_auth_();
}

void HaywardPump::begin_auth_() {
  this->step_ = Step::AUTH_REQ;
  this->write_(hayward::Bytes{hayward::MSG_AUTH});
}

void HaywardPump::send_next_frame_() {
  if (this->frame_idx_ >= this->frames_.size()) {
    this->finish_(true, "ok");
    return;
  }
  this->tx_counter_++;
  this->diag_frame_ = this->diagnostics_ && this->job_ == Job::POLL && this->frame_idx_ == 2;
  hayward::Bytes frame;
  if (!hayward::encrypt_frame(this->key_, this->challenge_, this->tx_counter_, this->frames_[this->frame_idx_],
                              frame)) {
    this->finish_(false, "encrypt failed");
    return;
  }
  this->step_ = Step::FRAME_WRITE;
  this->write_(frame);
}

void HaywardPump::handle_response_(const uint8_t *data, uint16_t len) {
  hayward::Bytes plain;
  uint32_t rx_counter = 0;
  if (this->diag_frame_) {
    // The diagnostic GET is unverified on this pump: never let it break the poll.
    hayward::Mac dmac;
    hayward::UObject dbody;
    hayward::Diagnostics d;
    if (hayward::decrypt_response(this->key_, this->challenge_, data, len, plain, &rx_counter) &&
        hayward::parse_pump_plaintext(plain, dmac, dbody))
      d = hayward::parse_diagnostics(dbody);
    if (d.valid) {
      this->diag_failures_ = 0;
      this->publish_diagnostics_(d);
    } else {
      ESP_LOGW(TAG, "Diagnostic (op 386) reply not understood (%u B): %s", len,
               plain.empty() ? "undecryptable" : hayward::hex(plain.data(), plain.size()).c_str());
      if (++this->diag_failures_ >= 3) {
        ESP_LOGW(TAG, "Disabling op-386 diagnostics after 3 failures (re-enable by reboot)");
        this->diagnostics_ = false;
      }
    }
    this->frame_idx_++;
    this->send_next_frame_();
    return;
  }
  if (!hayward::decrypt_response(this->key_, this->challenge_, data, len, plain, &rx_counter)) {
    // Wrong key or rejected handshake both end up here.
    this->finish_(false, "response failed to decrypt (wrong key / auth rejected?)");
    return;
  }
  hayward::Mac mac;
  hayward::UObject body;
  if (!hayward::parse_pump_plaintext(plain, mac, body)) {
    ESP_LOGW(TAG, "Unparseable reply: %s", hayward::hex(plain.data(), plain.size()).c_str());
    this->finish_(false, "unparseable reply");
    return;
  }
  ESP_LOGV(TAG, "Reply ctr=%u: %s", (unsigned) rx_counter, hayward::hex(plain.data(), plain.size()).c_str());

  if (this->job_ == Job::SPEED) {
    hayward::Ack ack = hayward::parse_ack(body);
    if (!ack.valid) {
      this->finish_(false, "no ack in reply");
      return;
    }
    this->pub_(S_LAST_ACK_RESULT, ack.result);
    if (ack.echoed_opid != hayward::OP_UI_SET_FILTER_SPEED || ack.echoed_seq != this->job_seq_ || ack.result != 0) {
      ESP_LOGW(TAG, "Pump NAK/mismatch: opid=%d seq=%d result=%d", ack.echoed_opid, ack.echoed_seq, ack.result);
      this->finish_(false, "pump rejected set-speed");
      return;
    }
    ESP_LOGI(TAG, "Pump ACKed set-speed %d%%", this->job_speed_);
#ifdef USE_NUMBER
    if (this->speed_number_) this->speed_number_->publish_state(this->job_speed_);
#endif
  } else {
    hayward::Telemetry t = hayward::parse_telemetry(body);
    if (t.valid) this->publish_telemetry_(t);
    else if (t.tid >= 0) this->pub_(S_PUMP_TID, t.tid);
  }
  this->frame_idx_++;
  this->send_next_frame_();
}

void HaywardPump::finish_(bool ok, const std::string &why) {
  if (this->step_ == Step::IDLE || this->step_ == Step::CLOSING) return;
  this->cancel_timeout("hp_session");
  Job finished = this->job_;
  if (ok) {
    this->publish_status_(finished == Job::SPEED ? "speed set" : "ok");
  } else {
    this->failures_++;
    this->pub_(S_SESSION_FAILURES, this->failures_);
    ESP_LOGW(TAG, "Session failed: %s", why.c_str());
    this->publish_status_(std::string("error: ") + why);
    // Never auto-retry a set-speed: the user (or automation) decides. Polls just wait for the next interval.
    if (this->max_failed_sessions_ > 0 && this->failures_ >= this->max_failed_sessions_) {
      this->paused_ = true;
      this->pending_speed_.reset();
      this->poll_pending_ = false;
      ESP_LOGW(TAG, "Paused: %u failed sessions since boot (max_failed_sessions). Reboot to resume.", (unsigned) this->failures_);
    }
  }
#ifdef USE_BINARY_SENSOR
  if (this->bins_[B_LINK_OK]) this->bins_[B_LINK_OK]->publish_state(ok);
#endif
  this->step_ = Step::CLOSING;
  this->job_ = Job::NONE;
  // Disconnect after every session, exactly like the OmniX app (keeps the pump free for the phone).
  if (this->parent()->state() != espbt::ClientState::IDLE) {
    this->parent()->disconnect();
  }
  this->step_ = Step::IDLE;
  if (ok && finished == Job::SPEED && this->poll_after_command_) {
    this->set_timeout("hp_post_cmd_poll", 3000, [this]() { this->request_poll(); });
  }
  if (this->paused_) this->publish_status_("paused after repeated failures (reboot to resume)");
  this->set_timeout("hp_kick", 1500, [this]() { this->kick_(); });
}

void HaywardPump::gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                                      esp_ble_gattc_cb_param_t *param) {
  switch (event) {
    case ESP_GATTC_OPEN_EVT:
      if (param->open.status != ESP_GATT_OK && param->open.status != ESP_GATT_ALREADY_OPEN &&
          this->step_ == Step::CONNECTING) {
        this->finish_(false, "connect failed (out of range / pump busy with phone?)");
      }
      break;
    case ESP_GATTC_CFG_MTU_EVT:
      if (param->cfg_mtu.conn_id != this->parent()->get_conn_id()) break;
      ESP_LOGD(TAG, "MTU event status=%d mtu=%u", param->cfg_mtu.status, param->cfg_mtu.mtu);
      if (param->cfg_mtu.status == ESP_GATT_OK) this->mtu_ = param->cfg_mtu.mtu;
      this->mtu_done_ = true;
      this->maybe_begin_auth_();
      break;
    case ESP_GATTC_SEARCH_CMPL_EVT: {
      if (param->search_cmpl.conn_id != this->parent()->get_conn_id()) break;
      auto *chr = this->parent()->get_characteristic(espbt::ESPBTUUID::from_uint16(HAYWARD_SERVICE_UUID16),
                                                     espbt::ESPBTUUID::from_raw(HAYWARD_CHAR_UUID));
      if (chr == nullptr) {
        ESP_LOGW(TAG, "Hayward characteristic not found by UUID; using handle 0x%04X", HAYWARD_CHAR_HANDLE_FALLBACK);
        this->char_handle_ = HAYWARD_CHAR_HANDLE_FALLBACK;
      } else {
        this->char_handle_ = chr->handle;
      }
      this->node_state = espbt::ClientState::ESTABLISHED;  // we only need the handle; services may be released
      ESP_LOGD(TAG, "Discovery done, char handle 0x%04X (%s), mtu=%u", this->char_handle_, chr ? "by UUID" : "fallback", this->mtu_);
      this->search_done_ = true;
      if (this->step_ == Step::CONNECTING) {
        this->maybe_begin_auth_();
      } else {
        // Connected without a job (shouldn't happen with auto_connect: false) — drop the link.
        this->parent()->disconnect();
      }
      break;
    }
    case ESP_GATTC_WRITE_CHAR_EVT: {
      if (param->write.conn_id != this->parent()->get_conn_id() || param->write.handle != this->char_handle_) break;
      ESP_LOGV(TAG, "RX write-rsp h=0x%04X status=%d", param->write.handle, param->write.status);
      if (param->write.status != ESP_GATT_OK && this->diag_frame_) {
        ESP_LOGW(TAG, "Pump rejected op-386 diagnostic write; skipping it");
        this->diagnostics_ = false;
        this->finish_(true, "ok (diag unsupported)");
        break;
      }
      if (param->write.status != ESP_GATT_OK) {
        this->finish_(false, "write rejected by pump (status " + to_string(param->write.status) + ")");
        break;
      }
      if (this->step_ == Step::AUTH_REQ) {
        this->step_ = Step::AUTH_READ;
        if (this->auth_read_delay_ > 0) {
          this->set_timeout("hp_auth_read", this->auth_read_delay_, [this]() {
            if (this->step_ == Step::AUTH_READ) this->read_();
          });
        } else {
          this->read_();
        }
      } else if (this->step_ == Step::AUTH_RESP) {
        this->send_next_frame_();
      } else if (this->step_ == Step::FRAME_WRITE) {
        this->step_ = Step::FRAME_READ;
        this->read_();
      }
      break;
    }
    case ESP_GATTC_READ_CHAR_EVT: {
      if (param->read.conn_id != this->parent()->get_conn_id() || param->read.handle != this->char_handle_) break;
      ESP_LOGV(TAG, "RX read-rsp h=0x%04X status=%d len=%u: %s", param->read.handle, param->read.status, param->read.value_len,
               param->read.status == ESP_GATT_OK ? hayward::hex(param->read.value, param->read.value_len).c_str() : "-");
      if (param->read.status != ESP_GATT_OK && this->diag_frame_) {
        if (++this->diag_failures_ >= 3) this->diagnostics_ = false;
        this->finish_(true, "ok (diag read failed)");
        break;
      }
      if (param->read.status != ESP_GATT_OK) {
        this->finish_(false, "read failed (status " + to_string(param->read.status) + ")");
        break;
      }
      if (this->step_ == Step::AUTH_READ) {
        if (param->read.value_len != 16) {
          this->finish_(false, "unexpected challenge length " + to_string(param->read.value_len));
          break;
        }
        memcpy(this->challenge_.data(), param->read.value, 16);
        this->step_ = Step::AUTH_RESP;
        this->write_(hayward::build_auth_response(this->key_, this->challenge_));
      } else if (this->step_ == Step::FRAME_READ) {
        this->handle_response_(param->read.value, param->read.value_len);
      }
      break;
    }
    case ESP_GATTC_DISCONNECT_EVT:
    case ESP_GATTC_CLOSE_EVT:
      if (this->step_ != Step::IDLE && this->step_ != Step::CLOSING) {
        this->finish_(false, "disconnected mid-session");
      }
      break;
    default:
      break;
  }
}

void HaywardPump::publish_status_(const std::string &s) {
#ifdef USE_TEXT_SENSOR
  if (this->texts_[T_STATUS]) this->texts_[T_STATUS]->publish_state(s);
#endif
}

void HaywardPump::pub_(uint8_t idx, float v) {
#ifdef USE_SENSOR
  if (idx < S_COUNT && this->sensors_[idx] != nullptr) this->sensors_[idx]->publish_state(v);
#endif
}

void HaywardPump::pub_text_(uint8_t idx, const std::string &v) {
#ifdef USE_TEXT_SENSOR
  if (idx < T_COUNT && this->texts_[idx] != nullptr) this->texts_[idx]->publish_state(v);
#endif
}

void HaywardPump::publish_telemetry_(const hayward::Telemetry &t) {
  ESP_LOGD(TAG, "Telemetry: W=%d a=%d V=[%d,%d,%d,%d] p=%d f=%d w=%d c=%d status=%s", t.water_temp, t.air_temp,
           t.speed[0], t.speed[1], t.speed[2], t.speed[3], t.power, t.state, t.why_on, t.refresh_counter,
           hayward::pump_status_name(t));
  if (t.water_temp > -1000) this->pub_(S_WATER_TEMP, t.water_temp);
  if (t.air_temp > -1000) this->pub_(S_AIR_TEMP, t.air_temp);
  if (t.speed[0] >= 0) this->pub_(S_FILTER_SPEED, t.speed[0]);
  if (t.speed[1] >= 0) this->pub_(S_LAST_SPEED, t.speed[1]);
  if (t.speed[2] >= 0) this->pub_(S_REPORTED_SPEED, t.speed[2]);
  if (t.speed[3] >= 0) this->pub_(S_DESIRED_SPEED, t.speed[3]);
  if (t.power >= 0) this->pub_(S_POWER, t.power);
  if (t.state >= 0) {
    this->pub_(S_FILTER_STATE_CODE, t.state);
    this->pub_text_(T_FILTER_STATE, hayward::filter_on_state_name(t.state));
  }
  if (t.why_on >= 0) {
    this->pub_(S_WHY_ON_CODE, t.why_on);
    this->pub_text_(T_WHY_ON, hayward::filter_msg_type_name(t.why_on));
  }
  if (t.refresh_counter >= 0) this->pub_(S_REFRESH_COUNTER, t.refresh_counter);
  if (t.version >= 0) this->pub_(S_TELEMETRY_VERSION, t.version);
  if (t.crc[0] >= 0) this->pub_(S_CRC1, (float) t.crc[0]);
  if (t.crc[1] >= 0) this->pub_(S_CRC2, (float) t.crc[1]);
  if (t.crc[2] >= 0) this->pub_(S_CRC3, (float) t.crc[2]);
  if (t.device_type >= 0) this->pub_(S_DEVICE_TYPE, t.device_type);
  if (t.system_state >= 0) this->pub_(S_SYSTEM_STATE, t.system_state);
  if (t.tid >= 0) this->pub_(S_PUMP_TID, t.tid);
  const char *status = hayward::pump_status_name(t);
  this->pub_text_(T_PUMP_STATUS, status);
  if (t.fw_version >= 0) {
    char buf[40];
    uint32_t s = (uint32_t) t.fw_version;
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u (0x%08X)", (unsigned) (s >> 24) & 0xFF, (unsigned) (s >> 16) & 0xFF,
             (unsigned) (s >> 8) & 0xFF, (unsigned) s & 0xFF, (unsigned) s);
    this->pub_text_(T_FIRMWARE, buf);
  }
#ifdef USE_BINARY_SENSOR
  if (this->bins_[B_FP_OVERRIDE] && t.has_fp_override) this->bins_[B_FP_OVERRIDE]->publish_state(t.fp_override);
  if (this->bins_[B_RUNNING]) this->bins_[B_RUNNING]->publish_state(strcmp(status, "running") == 0);
#endif
#ifdef USE_NUMBER
  // Reflect the pump's current filter speed (also catches changes from the phone app, keypad or schedule).
  if (this->speed_number_ && t.speed[0] >= this->min_speed_ && t.speed[0] <= this->max_speed_)
    this->speed_number_->publish_state(t.speed[0]);
#endif
}

void HaywardPump::publish_diagnostics_(const hayward::Diagnostics &d) {
  ESP_LOGD(TAG, "Diagnostics: n=%d v=%d p=[%lld,%lld,%lld] k=%d Q=%d", d.filter_on_state, d.speed, (long long) d.power,
           (long long) d.current, (long long) d.voltage, d.drive_temp, d.error);
  if (d.power >= 0) this->pub_(S_DIAG_POWER, (float) d.power);
  if (d.current >= 0) this->pub_(S_DIAG_CURRENT, (float) d.current);
  if (d.voltage >= 0) this->pub_(S_DIAG_VOLTAGE, (float) d.voltage);
  if (d.drive_temp > -1000) this->pub_(S_DRIVE_TEMP, d.drive_temp);
  if (d.speed >= 0) this->pub_(S_DIAG_SPEED, d.speed);
  if (d.filter_on_state >= 0) this->pub_(S_DIAG_STATE_CODE, d.filter_on_state);
  if (d.error >= 0) this->pub_(S_ERROR_CODE, d.error);
  if (d.pump_rev >= 0) this->pub_text_(T_PUMP_REV, to_string((long long) d.pump_rev));
  if (d.drive_rev >= 0) this->pub_text_(T_DRIVE_REV, to_string((long long) d.drive_rev));
}

}  // namespace esphome::hayward_pump

#endif  // USE_ESP32
