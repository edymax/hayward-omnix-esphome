# Local Home Assistant control for a Hayward OmniX pool pump

This project lets a Home Assistant user run a compatible Hayward OmniX pump locally over Bluetooth. An ESP32 running ESPHome acts as a BLE proxy on your LAN and exposes speed plus telemetry as ordinary Home Assistant entities. Runtime traffic never goes through the Hayward cloud, and the pump firmware is never changed.

This is interoperability research done on a personally owned pump. It is not affiliated with Hayward. Use it at your own risk. See DISCLAIMER.md and LICENSE.

## What it does

The proxy opens a short Bluetooth session for each poll or command, the same way the OmniX phone app does. After a challenge handshake it sends encrypted commands and reads encrypted telemetry, then disconnects. You can set filter speed from Home Assistant, use Low / Medium / High presets, and watch water temperature, filter speed, running state, drive measurements, and link health.

## What you need

The firmware was proven on an Olimex ESP32-POE-ISO with wired Ethernet and PoE. Any ESP32 with Bluetooth Low Energy should be able to run the same code if you adjust the board and network sections of the example config. The pump used for this work was a Hayward TriStar VS 815 (1.85 HP, also labeled 1.85HP TriStar SQ in the OmniX app) running firmware R1.0.1. Other models or firmware versions may differ.

You also need a Home Assistant install that can compile and flash ESPHome (2026.10 or newer was used here), plus the site security key for your own OmniX site.

## Honest caveats

Telemetry has been solid in live use. Speed writes are implemented and were live tested lightly, with one supervised session that moved the pump from 55 percent to 75 percent and back. Both commands were accepted with a normal ACK and the next telemetry poll showed the new speed.

A speed change made this way puts the pump in manual mode until its next scheduled change. That is the same behavior as the OmniX app. The proxy never sends a stop or a 0 percent command, never writes schedules or freeze protect settings, and never touches pump firmware. A failed speed command is not retried automatically. Nothing is sent at boot except a read only telemetry poll.

If the OmniX app is connected at the same time, a poll may fail. That is expected because the pump appears to allow one Bluetooth central at a time.

## How to get your own site security key

Hayward issues a per site UUID called `securityKey` when the pump is claimed. Remove the hyphens and you have the 16 byte AES key used for the Bluetooth login and for every later command. Treat that value like a password. It is unique to your site. It is not in the OmniX app binary and it is not in this repository. In the config it belongs in `secrets.yaml` as `pump_aes_key`, in place of a placeholder such as `YOUR_SITE_SECURITY_KEY_HERE`.

The usual way to obtain it is to log into Hayward's cloud with the same email and password you use in the OmniX app, then read the site object. A helper script is included at `tools/fetch_security_key.py`. Set the `OMNIX_EMAIL` and `OMNIX_PASSWORD` environment variables and run the script. It posts to Hayward's auth service with the public app id shipped in the OmniX Android app (`X-HAYWARD-APP-ID`), then fetches `/v2/poolpad/site` and `/v2/poolpad/site/{id}` from the iot manager. The `securityKey` field sits at the top level of the site body. Copy that UUID into `secrets.yaml`. Hyphens are optional.

You can also look for the same field in OmniX app storage on the phone that claimed the pump.

Never commit `secrets.yaml`. The included `.gitignore` already excludes it.

## Quick start

Copy `pool-pump-ble.example.yaml` into your ESPHome config folder as `pool-pump-ble.yaml`, and copy the `components` directory next to it so the `hayward_pump` external component can be found. Copy `secrets.yaml.example` to `secrets.yaml` in that same folder. Generate a fresh API encryption key with the command in the example file and paste it as `api_encryption_key`. Paste your site security key as `pump_aes_key`. Set the `pump_mac` substitution to the Bluetooth address of your pump. The OmniX app and many phone Bluetooth scanners will show that address.

Flash the board over USB the first time. The example config is written for an Olimex ESP32-POE-ISO on wired Ethernet. If you use a different board, change the `esp32` board name and replace the `ethernet` block with a `wifi` block as needed. On a non ISO Olimex ESP32-POE, do not leave USB and PoE connected at the same time. After the device joins your network, Home Assistant should discover `pool-pump-ble`. Paste the same API encryption key when Home Assistant asks for it. Later updates can go over the air.

A first live speed change should be done with someone standing at the pump. Wait for one good telemetry read so the reported speed and water temperature match the pump display. Then make one reversible change, confirm the pump ramps and the next poll shows the new filter speed, and set it back.

One Bluetooth detail matters a lot. The pump needs an ATT MTU of 251. The firmware requests 517 and waits for the MTU negotiation to finish before it starts the login. If that wait is skipped, the pump answers reads with ATT error 0x0D and login fails.

## Protocol

The BLE scheme is documented in PROTOCOL.md. In short, there is one Hayward service (`0xFCA5`) and one characteristic (`66460130-8759-9bf8-b4db-7b04b9b026f1`). Login is AES-128-ECB of a 16 byte challenge under the site key. Commands use AES-128-GCM with a 12 byte IV built from a frame counter and the session id. The same site key is used for both.

## Repository layout

| Path | What it is |
|------|------------|
| `pool-pump-ble.example.yaml` | Example ESPHome config (Ethernet, API, OTA, BLE client, entities) |
| `secrets.yaml.example` | Template for the API/OTA key and the site security key |
| `components/hayward_pump/` | ESPHome external component (schema, BLE session, protocol) |
| `tools/fetch_security_key.py` | Helper that reads *your* `securityKey` from Hayward's cloud |
| `tests/` | Host tests with synthetic keys and frames (no live capture data) |
| `PROTOCOL.md` | The OmniX BLE scheme |
| `DISCLAIMER.md` | Use at your own risk, not affiliated with Hayward |
| `LICENSE` | MIT |

## License

Released under the MIT license. See LICENSE and DISCLAIMER.md.
