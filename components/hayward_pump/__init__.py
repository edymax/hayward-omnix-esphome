"""Hayward OmniX (TriStar VS) BLE pump — local control + full telemetry.

Protocol reverse-engineered from the OmniX app and verified against a real
capture; see README.md in the project root.
"""

import esphome.codegen as cg
from esphome.components import binary_sensor, ble_client, number, sensor, text_sensor
import esphome.config_validation as cv
from esphome.const import (
    CONF_ID,
    CONF_MAC_ADDRESS,
    DEVICE_CLASS_TEMPERATURE,
    ENTITY_CATEGORY_CONFIG,
    ENTITY_CATEGORY_DIAGNOSTIC,
    STATE_CLASS_MEASUREMENT,
    STATE_CLASS_TOTAL_INCREASING,
    UNIT_PERCENT,
)

UNIT_FAHRENHEIT = "°F"

DEPENDENCIES = ["ble_client"]
AUTO_LOAD = ["sensor", "text_sensor", "binary_sensor", "number"]

CONF_AES_KEY = "aes_key"
CONF_MIN_SPEED = "min_speed"
CONF_MAX_SPEED = "max_speed"
CONF_INITIAL_COMMAND_SEQ = "initial_command_seq"
CONF_POLL_AFTER_COMMAND = "poll_after_command"
CONF_SPEED = "speed"
CONF_DIAGNOSTICS = "diagnostics"
CONF_AUTH_READ_DELAY = "auth_read_delay"
CONF_MAX_FAILED_SESSIONS = "max_failed_sessions"

hayward_ns = cg.esphome_ns.namespace("hayward_pump")
HaywardPump = hayward_ns.class_("HaywardPump", ble_client.BLEClientNode, cg.PollingComponent)
HaywardSpeedNumber = hayward_ns.class_("HaywardSpeedNumber", number.Number, cg.Parented.template(HaywardPump))

_RAW = dict(accuracy_decimals=0, entity_category=ENTITY_CATEGORY_DIAGNOSTIC)
_PCT = dict(unit_of_measurement=UNIT_PERCENT, accuracy_decimals=0, state_class=STATE_CLASS_MEASUREMENT,
            icon="mdi:speedometer")

_TEMP = dict(unit_of_measurement=UNIT_FAHRENHEIT, accuracy_decimals=0, device_class=DEVICE_CLASS_TEMPERATURE,
             state_class=STATE_CLASS_MEASUREMENT)

# key -> (C++ index, schema).  Index order MUST match enum SensorIdx in hayward_pump.h.
SENSOR_FIELDS = {
    # --- op-600 telemetry (seen in the capture) ---
    "water_temperature": (0, sensor.sensor_schema(**_TEMP)),
    "air_temperature": (1, sensor.sensor_schema(**_TEMP)),
    "filter_speed": (2, sensor.sensor_schema(**_PCT)),
    "last_speed": (3, sensor.sensor_schema(**_PCT, entity_category=ENTITY_CATEGORY_DIAGNOSTIC)),
    "reported_speed": (4, sensor.sensor_schema(**_PCT)),
    "desired_speed": (5, sensor.sensor_schema(**_PCT, entity_category=ENTITY_CATEGORY_DIAGNOSTIC)),
    "power": (6, sensor.sensor_schema(accuracy_decimals=0, state_class=STATE_CLASS_MEASUREMENT, icon="mdi:flash")),
    "filter_state_code": (7, sensor.sensor_schema(**_RAW)),
    "why_on_code": (8, sensor.sensor_schema(**_RAW)),
    "refresh_counter": (9, sensor.sensor_schema(**_RAW, icon="mdi:counter")),
    "telemetry_version": (10, sensor.sensor_schema(**_RAW)),
    "config_crc_1": (11, sensor.sensor_schema(**_RAW, icon="mdi:pound")),
    "config_crc_2": (12, sensor.sensor_schema(**_RAW, icon="mdi:pound")),
    "config_crc_3": (13, sensor.sensor_schema(**_RAW, icon="mdi:pound")),
    "device_type": (14, sensor.sensor_schema(**_RAW)),
    "system_state": (15, sensor.sensor_schema(**_RAW)),
    "pump_transaction_id": (16, sensor.sensor_schema(**_RAW, icon="mdi:counter")),
    # --- link health ---
    "last_ack_result": (17, sensor.sensor_schema(**_RAW, icon="mdi:check-network")),
    "session_failures": (18, sensor.sensor_schema(**_RAW, state_class=STATE_CLASS_TOTAL_INCREASING,
                                                   icon="mdi:alert-circle-outline")),
    # --- op-386 filter diagnostics (layout from app code; unverified on this pump) ---
    "diag_power": (19, sensor.sensor_schema(accuracy_decimals=0, state_class=STATE_CLASS_MEASUREMENT,
                                             icon="mdi:flash", entity_category=ENTITY_CATEGORY_DIAGNOSTIC)),
    "diag_current": (20, sensor.sensor_schema(accuracy_decimals=0, state_class=STATE_CLASS_MEASUREMENT,
                                               icon="mdi:current-ac", entity_category=ENTITY_CATEGORY_DIAGNOSTIC)),
    "diag_voltage": (21, sensor.sensor_schema(accuracy_decimals=0, state_class=STATE_CLASS_MEASUREMENT,
                                               icon="mdi:sine-wave", entity_category=ENTITY_CATEGORY_DIAGNOSTIC)),
    "drive_temperature": (22, sensor.sensor_schema(**_TEMP, entity_category=ENTITY_CATEGORY_DIAGNOSTIC)),
    "diag_speed": (23, sensor.sensor_schema(**_PCT, entity_category=ENTITY_CATEGORY_DIAGNOSTIC)),
    "diag_filter_state_code": (24, sensor.sensor_schema(**_RAW)),
    "error_code": (25, sensor.sensor_schema(accuracy_decimals=0, icon="mdi:alert",
                                             entity_category=ENTITY_CATEGORY_DIAGNOSTIC)),
}
_DIAG_TEXT = dict(entity_category=ENTITY_CATEGORY_DIAGNOSTIC)
TEXT_FIELDS = {
    "status": (0, text_sensor.text_sensor_schema(**_DIAG_TEXT, icon="mdi:bluetooth-connect")),
    "firmware_version": (1, text_sensor.text_sensor_schema(**_DIAG_TEXT, icon="mdi:chip")),
    "filter_state": (2, text_sensor.text_sensor_schema(icon="mdi:pump")),
    "why_on": (3, text_sensor.text_sensor_schema(icon="mdi:help-circle-outline")),
    "pump_status": (4, text_sensor.text_sensor_schema(icon="mdi:pump")),
    "pump_revision": (5, text_sensor.text_sensor_schema(**_DIAG_TEXT, icon="mdi:chip")),
    "drive_revision": (6, text_sensor.text_sensor_schema(**_DIAG_TEXT, icon="mdi:chip")),
}
BINARY_FIELDS = {
    "link_ok": (0, binary_sensor.binary_sensor_schema(device_class="connectivity",
                                                      entity_category=ENTITY_CATEGORY_DIAGNOSTIC)),
    "freeze_protect_override": (1, binary_sensor.binary_sensor_schema(icon="mdi:snowflake-alert")),
    "running": (2, binary_sensor.binary_sensor_schema(device_class="running")),
}


def _key(value):
    value = cv.string_strict(value)
    h = value.replace("-", "").replace(" ", "").lower()
    if len(h) != 32 or any(c not in "0123456789abcdef" for c in h):
        raise cv.Invalid("aes_key must be the securityKey UUID (32 hex digits, hyphens optional)")
    return h


def _validate(config):
    if config[CONF_MIN_SPEED] >= config[CONF_MAX_SPEED]:
        raise cv.Invalid("min_speed must be < max_speed")
    return config


CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(HaywardPump),
            cv.Required(CONF_AES_KEY): cv.sensitive(_key),
            cv.Required(CONF_MAC_ADDRESS): cv.mac_address,
            # 18% is the pump's own configured minimum; never allow 0 / "off" through this component.
            cv.Optional(CONF_MIN_SPEED, default=18): cv.int_range(min=10, max=100),
            cv.Optional(CONF_MAX_SPEED, default=100): cv.int_range(min=10, max=100),
            cv.Optional(CONF_INITIAL_COMMAND_SEQ, default=28000): cv.int_range(min=1000, max=32000),
            cv.Optional(CONF_POLL_AFTER_COMMAND, default=True): cv.boolean,
            # Also send the read-only UI_GET_FILTER_DIAGNOSTIC (op 386) each poll. Unverified on this
            # pump; auto-disables after 3 unintelligible replies.
            cv.Optional(CONF_DIAGNOSTICS, default=False): cv.boolean,
            # Debug/safety: wait this long after the 0x06 write ACK before reading the challenge.
            cv.Optional(CONF_AUTH_READ_DELAY, default="0ms"): cv.All(cv.positive_time_period_milliseconds, cv.Range(max=cv.TimePeriod(milliseconds=2000))),
            # Safety: stop polling after this many failed sessions since boot (0 = never stop).
            cv.Optional(CONF_MAX_FAILED_SESSIONS, default=0): cv.int_range(min=0, max=1000),
            cv.Optional(CONF_SPEED): number.number_schema(
                HaywardSpeedNumber, unit_of_measurement=UNIT_PERCENT, icon="mdi:pump",
            ),
            **{cv.Optional(k): s for k, (_, s) in SENSOR_FIELDS.items()},
            **{cv.Optional(k): s for k, (_, s) in TEXT_FIELDS.items()},
            **{cv.Optional(k): s for k, (_, s) in BINARY_FIELDS.items()},
        }
    )
    .extend(ble_client.BLE_CLIENT_SCHEMA)
    .extend(cv.polling_component_schema("30s")),
    _validate,
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await ble_client.register_ble_node(var, config)

    cg.add(var.set_key(config[CONF_AES_KEY]))
    cg.add(var.set_pump_mac(config[CONF_MAC_ADDRESS].as_hex))
    cg.add(var.set_speed_limits(config[CONF_MIN_SPEED], config[CONF_MAX_SPEED]))
    cg.add(var.set_initial_command_seq(config[CONF_INITIAL_COMMAND_SEQ]))
    cg.add(var.set_poll_after_command(config[CONF_POLL_AFTER_COMMAND]))
    cg.add(var.set_diagnostics(config[CONF_DIAGNOSTICS]))
    cg.add(var.set_auth_read_delay(config[CONF_AUTH_READ_DELAY].total_milliseconds))
    cg.add(var.set_max_failed_sessions(config[CONF_MAX_FAILED_SESSIONS]))

    if CONF_SPEED in config:
        n = await number.new_number(config[CONF_SPEED], min_value=config[CONF_MIN_SPEED],
                                    max_value=config[CONF_MAX_SPEED], step=1)
        await cg.register_parented(n, config[CONF_ID])
        cg.add(var.set_speed_number(n))

    for key, (idx, _) in SENSOR_FIELDS.items():
        if key in config:
            s = await sensor.new_sensor(config[key])
            cg.add(var.set_sensor(idx, s))
    for key, (idx, _) in TEXT_FIELDS.items():
        if key in config:
            s = await text_sensor.new_text_sensor(config[key])
            cg.add(var.set_text_sensor(idx, s))
    for key, (idx, _) in BINARY_FIELDS.items():
        if key in config:
            s = await binary_sensor.new_binary_sensor(config[key])
            cg.add(var.set_binary_sensor(idx, s))
