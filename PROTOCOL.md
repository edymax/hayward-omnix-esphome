# OmniX BLE protocol

This is the application layer used by a Hayward OmniX pump on Bluetooth Low Energy. It was recovered from the OmniX Android app (`com.hayward.omniflex` 1.3.40) and then checked against a live capture of a personally owned pump. No site key material appears in this document.

## Radio and GATT

The link is a plain LE connection. There is no pairing, no SMP, and no link layer encryption. Confidentiality lives entirely in the application frames on a single characteristic.

The Hayward service UUID is the 16 bit SIG member service `0xFCA5`. The characteristic UUID is `66460130-8759-9bf8-b4db-7b04b9b026f1` (this is the app's `appMessageUUID`). On the pump used for this work the value handle was `0x000F` and the properties were `0x0E` (Read, Write Without Response, and Write). The firmware looks the characteristic up by UUID and falls back to handle `0x000F` only if that lookup fails.

There is no CCCD and there are no notifications or indications. Every exchange is a Write Request followed by a Read on the same characteristic.

The ATT MTU must reach 251 before the first auth read. The OmniX app asks for 527 and the pump grants 251. This firmware does the same (`esp_ble_gatt_set_local_mtu(517)`) and waits for the MTU event (with a short fallback timer) before it writes the first `0x06`. If the MTU is still the default 23, or even 247, the pump answers those reads with ATT error `0x0D` (Invalid Attribute Value Length) and login never completes.

Each poll or command uses a fresh, short connection (connect, discover, handshake, one to three encrypted frames, disconnect). That is the same pattern as the phone app, which is why the app can still work when the proxy is idle.

## Site key

There is no hardcoded root key in the app or on the pump. Ownership is a per site UUID called `securityKey`, written to the pump at claim time and reused for every later session.

```
SITE_KEY[16] = unhex(securityKey UUID with hyphens removed)
```

That 16 byte value is the AES key for both the login handshake and the command traffic. How to obtain *your* copy is described in the README. This file never includes a real key.

## Login (type `0x06`)

```
1. Write  0x06
2. Read   CHALLENGE[16]
3. SESSION_ID[8] = CHALLENGE[0:8]
   FRAME_COUNTER = 0
4. Write  0x06 || AES-128-ECB_Encrypt(CHALLENGE, SITE_KEY)
```

The AES-128-ECB step is a single block with no IV. The pump accepts the connection only if that 16 byte response is the correct encrypt of the challenge it just issued.

## Command frames (AES-128-GCM)

After a successful login, application messages use AES-128-GCM with the same 16 byte site key, a 16 byte tag, and no AAD.

For each message the sender increments the frame counter first (so the first frame on a connection uses counter 1). The 12 byte IV is the 4 byte counter, big endian, followed by an 8 byte session id derived from the challenge.

```
FRAME_COUNTER += 1
IV_APP[12]  = BE32(FRAME_COUNTER) || CHALLENGE[0:8]
IV_PUMP[12] = BE32(FRAME_COUNTER) || reverse(CHALLENGE[0:8])
```

The pump uses the reversed first eight challenge bytes when *it* encrypts a reply. Using the app IV on a pump reply will fail the tag. This was confirmed against live frames.

App to pump write (this is what the ESP32 sends)

```
plaintext = 0x02 || destMAC[6] || UBJSON(object)
wire      = 0x07 || ciphertext || BE32(FRAME_COUNTER) || tag[16]
```

Pump to app read (what the ESP32 decrypts)

```
plaintext = 0x01 || srcMAC[6] || UBJSON(object)
wire      = ciphertext || BE32(FRAME_COUNTER) || tag[16]
```

Note that the pump reply has no type byte. The UBJSON object does not include SOURCE or DEST keys. Those exist only in the 7 byte binary header.

The command transaction id lives in UBJSON key `"\x04"`. The app requires values in `0` to `32767`. This firmware starts at `initial_command_seq` (28000 in the example) and persists the counter in flash. If you also use the OmniX app, pick a starting value above whatever the app last used.

## Set speed

The path used by the app slider and by this firmware is op 9 (`UI_SET_FILTER_SPEED`) with param `v` equal to the speed in percent, plus the transaction id.

```
{"\x03": 9, "v": <percent>, "\x04": <TID>}
```

The pump replies with an ACK

```
{"\x03": 1000, "\x05": <TID echo>, "x": 9, "n": 0}
```

`n = 0` has been the success code on every captured and live ACK. Other `n` values have not been observed. A set speed write produces a 25 byte plaintext (46 byte write on the wire). Speed was confirmed as percent, not RPM, by decrypting captured slider frames and by a live 55 to 75 to 55 percent run.

Changing speed this way leaves the pump in manual mode until its next scheduled change, the same as the OmniX app. In telemetry that shows up as `w` (Why On) switching from 170 (timed / schedule) to 140 (manual).

Op 8 (`UI_SET_POOL_FILTER_CMD`) is an on/off style command in the app. This firmware does not send it, and it refuses requests below the configured minimum (18 percent in the example).

## Telemetry (op 600 and op 386)

A status poll is two requests, pages 0 and 1

```
{"\x03": 600, "G": 0}
{"\x03": 600, "G": 1}
```

The reply is op 1600. On the pump used here, page `G:1` carried the status blob in field `g`, and page `G:0` came back empty. Field names below are the app's own `IOT_PARAMS_*` keys.

| Entity | Field | Notes |
|--------|-------|-------|
| Water Temperature | `W` | °F. Matched the app display on a live capture. |
| Air Temperature | `a` | °F. Plausible, sensor location not independently confirmed. |
| Filter Speed | `V[0]` | Percent. Tracks commanded speed. |
| Last Speed | `V[1]` | Percent. Meaning still a bit unclear. |
| Reported Speed | `V[2]` | Percent. Lags while the drive is ramping, then catches up. |
| Desired Speed | `V[3]` | Percent. Equal to the commanded speed in every reply seen. |
| Pump Power (est. units) | `p` | Relative power, roughly cubic in speed. Not watts. A watts scale has not been verified with a meter. |
| Filter State | `f` | `1` means on. Other enum names come from the app and were not observed. |
| Why On | `w` | `170` timed / schedule, `140` manual. Confirmed against app behavior. |
| Freeze Protect Override | `o` | Only `false` was seen. |
| Firmware Version | `s` | Raw integer `0x03010001` on the pump used here, shown in the app as R1.0.1. Byte layout is a best guess. |
| Refresh Counter | `c` | 8 bit counter. |
| Telemetry Version | `e` | Constant `2` on this firmware. |
| Config CRC 1 / 2 / 3 | `X` | Stable until pump settings change. |
| Device Type | `z` | Constant `16` on this pump. |
| System State | `u` | Constant `1` here. Enum not mapped. |

Op 386 (`UI_GET_FILTER_DIAGNOSTIC`) is an optional read only GET. The reply is op 1386. The field map comes from the app's `decodePumpDiagnosticData`. This firmware sends it when `diagnostics: true` is set and turns it off if several replies cannot be parsed.

| Entity | Field | Notes |
|--------|-------|-------|
| Drive Speed | `v` | Percent. Matches filter speed. |
| Pump Power units | `p[0]` | Same relative power number as telemetry `p`. |
| Motor Current (est.) | `p[1]` | Best current fit is drive motor current in mA, a quadratic in speed. It first looked like RPM because at 55 percent it was close to `0.55 * 3450`, but a 75 percent run ruled RPM out (`p[1]` was about 3334, not 2590). This is not the 230 V line current a clamp meter would show. |
| DC Bus Voltage | `p[2]` | Volts. Around 336 V at light load, a little lower at full speed, consistent with a rectified ~230 VAC bus. |
| Drive Electronics Temperature | `k` | Best guess is °F. |
| Error Code | `Q` | `0` while running normally. |
| Pump / Drive Revision | `s[0]`, `s[1]` | Raw integers. On the pump used here `s[0]` matched the telemetry firmware field. |

## What this firmware will not do

It never sends firmware update ops, schedule writes, config writes, freeze protect setting changes, time writes, or a factory reset. It never sends op 8 (on/off) and it never commands a speed of 0. The Speed entity is not restored or resent at boot. It only mirrors the pump's reported `V[0]` until you issue a new command.

## Session algorithm (card)

```
SITE_KEY[16] = unhex(site.securityKey UUID with hyphens removed)

Per connection
  1. Connect, request MTU 517, wait until the negotiated MTU is 251 (or the event fires)
  2. Write  0x06
  3. Read   CHALLENGE[16]
  4. SESSION_ID[8] = CHALLENGE[0:8]
     FRAME_COUNTER = 0
  5. Write  0x06 || AES-128-ECB_Encrypt(CHALLENGE, SITE_KEY)

Each app message
  6. FRAME_COUNTER += 1
  7. IV[12] = BE32(FRAME_COUNTER) || SESSION_ID          (app to pump)
     IV[12] = BE32(FRAME_COUNTER) || reverse(SESSION_ID) (pump to app)
  8. PT = 0x02 || MAC[6] || UBJSON({'\x03': OPID, ...params})
  9. CT, TAG = AES-128-GCM_Encrypt(PT, key=SITE_KEY, iv=IV)   # no AAD
 10. Write 0x07 || CT || BE32(FRAME_COUNTER) || TAG[16]
 11. Read  CT' || SEQ || TAG'  and decrypt with the pump IV rule
```
