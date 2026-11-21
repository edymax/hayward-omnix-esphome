#!/usr/bin/env python3
"""
fetch_security_key.py

Retrieve the per-site OmniX BLE `securityKey` (a UUID) from Hayward's cloud,
given the user's OmniX account email + password.

The securityKey (hyphens stripped -> 16 bytes) is the AES-128 key used for the
pump's BLE challenge-response (AES-128-ECB) and session AEAD (AES-128-GCM).
See APK_DECODE.md for the BLE protocol.

CLOUD MECHANISM (reverse-engineered from com.hayward.omniflex v1.3.40):
  * NOT AWS AppSync / Cognito. It is a plain REST API with Bearer (JWT) auth.
  * Auth service  (login)  : POST {AUTH}/v2/login
        headers: content-type: application/json, X-HAYWARD-APP-ID: <appId>
        body   : {"email": ..., "password": ...}
        resp   : {"userID":..., "email":..., "token":<JWT access>, "refreshToken":...}
        -> accessToken = resp["token"]
  * IoT manager   (data)   : Authorization: Bearer <accessToken>
        GET {IOT}/v2/poolpad/site            -> [ {id, ...}, ... ]   (site summaries)
        GET {IOT}/v2/poolpad/site/{siteId}   -> full site object, contains:
              securityKey (UUID), channelSet, panId, bodiesOfWater/devices (MACs)
  * iot-manager requests do NOT send X-HAYWARD-APP-ID, only Authorization + content-type.

CONFIG VALUES (from APK react-native-config: res/values strings + BuildConfig):
  HAYWARD_APP_ID               = 5f2j2qu3p27uhlnaiesdbkahqh
  HAYWARD_AUTH_SERVICE_ENDPOINT= https://services-gamma.haywardcloud.net/auth-service  (SHIPPED)
  HAYWARD_IOT_MANAGER_ENDPOINT = https://services-prod.haywardcloud.net/iot-manager
  (The shipped build mixes gamma auth with prod iot. Because the prod iot-manager
   must accept the token, this script tries the PROD auth cluster first, then the
   shipped GAMMA one. Override with OMNIX_AUTH_ENDPOINT if needed.)

USAGE:
  export OMNIX_EMAIL='you@example.com'
  export OMNIX_PASSWORD='your-password'
  python3 fetch_security_key.py

OPTIONAL OVERRIDES (env):
  OMNIX_AUTH_ENDPOINT   full auth-service base URL (skip auto prod/gamma try)
  OMNIX_IOT_ENDPOINT    full iot-manager base URL
  OMNIX_APP_ID          X-HAYWARD-APP-ID value
  OMNIX_SITE_ID         only fetch this one site id
  OMNIX_DEBUG=1         dump raw JSON responses

This script makes NO network calls until you supply credentials; with none set
it prints an error and exits 2.
"""

import json
import os
import re
import sys

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

# ---- Config recovered from the APK --------------------------------------
APP_ID = os.environ.get("OMNIX_APP_ID", "5f2j2qu3p27uhlnaiesdbkahqh")

AUTH_SHIPPED = "https://services-gamma.haywardcloud.net/auth-service"
AUTH_PROD    = "https://services-prod.haywardcloud.net/auth-service"
IOT_DEFAULT  = "https://services-prod.haywardcloud.net/iot-manager"

IOT_ENDPOINT = os.environ.get("OMNIX_IOT_ENDPOINT", IOT_DEFAULT).rstrip("/")

# If the user forces an auth endpoint, use only that; else try prod then gamma.
_forced_auth = os.environ.get("OMNIX_AUTH_ENDPOINT")
AUTH_CANDIDATES = (
    [_forced_auth.rstrip("/")] if _forced_auth else [AUTH_PROD, AUTH_SHIPPED]
)

DEBUG = os.environ.get("OMNIX_DEBUG") == "1"

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]?){6}$")


def _dbg(label, obj):
    if DEBUG:
        print(f"[debug] {label}:\n{json.dumps(obj, indent=2)[:4000]}", file=sys.stderr)


def login(session, email, password):
    """Try each auth endpoint; return (accessToken, auth_base_used)."""
    last_err = None
    for base in AUTH_CANDIDATES:
        url = base + "/v2/login"
        headers = {
            "content-type": "application/json",
            "X-HAYWARD-APP-ID": APP_ID,
        }
        try:
            r = session.post(
                url, headers=headers,
                data=json.dumps({"email": email, "password": password}),
                timeout=30,
            )
        except requests.RequestException as e:
            last_err = f"{url}: network error: {e}"
            continue
        if r.status_code == 200:
            try:
                body = r.json()
            except ValueError:
                last_err = f"{url}: 200 but non-JSON body"
                continue
            _dbg("login response", body)
            token = body.get("token") or body.get("accessToken")
            if not token:
                last_err = f"{url}: 200 but no 'token' field (keys={list(body)})"
                continue
            print(f"[+] Authenticated via {base}", file=sys.stderr)
            return token, base
        elif r.status_code in (401, 403):
            last_err = f"{url}: {r.status_code} (bad credentials or wrong cluster)"
        elif r.status_code == 404:
            last_err = f"{url}: 404 (endpoint not found on this cluster)"
        else:
            last_err = f"{url}: HTTP {r.status_code}: {r.text[:200]}"
    raise SystemExit(f"[!] Login failed. Last error: {last_err}")


def iot_get(session, token, path):
    url = IOT_ENDPOINT + path
    headers = {
        "content-type": "Application/json",
        "Authorization": "Bearer " + token,
    }
    r = session.get(url, headers=headers, timeout=30)
    if r.status_code != 200:
        raise SystemExit(f"[!] GET {url} -> HTTP {r.status_code}: {r.text[:300]}")
    try:
        return r.json()
    except ValueError:
        raise SystemExit(f"[!] GET {url} -> 200 but non-JSON body")


def find_all(obj, key_predicate, value_predicate):
    """Recursively yield (path, value) where key matches and value matches."""
    def walk(o, path):
        if isinstance(o, dict):
            for k, v in o.items():
                p = f"{path}.{k}" if path else k
                if key_predicate(k) and isinstance(v, str) and value_predicate(v):
                    yield (p, v)
                yield from walk(v, p)
        elif isinstance(o, list):
            for i, v in enumerate(o):
                yield from walk(v, f"{path}[{i}]")
    yield from walk(obj, "")


def extract_security_keys(site):
    return list(find_all(
        site,
        key_predicate=lambda k: k.lower() == "securitykey",
        value_predicate=lambda v: bool(UUID_RE.match(v)),
    ))


def extract_macs(site):
    found = list(find_all(
        site,
        key_predicate=lambda k: "mac" in k.lower(),
        value_predicate=lambda v: bool(MAC_RE.match(v)),
    ))
    # de-dup by normalized mac, keep first path
    seen = {}
    for path, mac in found:
        norm = re.sub(r"[:-]", "", mac).lower()
        if norm not in seen:
            seen[norm] = (path, mac)
    return list(seen.values())


def uuid_to_hex16(u):
    return u.replace("-", "").lower()


def main():
    email = os.environ.get("OMNIX_EMAIL")
    password = os.environ.get("OMNIX_PASSWORD")
    if not email or not password:
        print("ERROR: set OMNIX_EMAIL and OMNIX_PASSWORD environment variables.",
              file=sys.stderr)
        print("  export OMNIX_EMAIL='you@example.com'", file=sys.stderr)
        print("  export OMNIX_PASSWORD='...'", file=sys.stderr)
        print("  python3 fetch_security_key.py", file=sys.stderr)
        sys.exit(2)

    session = requests.Session()
    session.headers.update({"User-Agent": "OmniX-setup/1.3.40"})

    token, auth_base = login(session, email, password)

    only_site = os.environ.get("OMNIX_SITE_ID")
    if only_site:
        site_ids = [only_site]
    else:
        summaries = iot_get(session, token, "/v2/poolpad/site")
        _dbg("site summaries", summaries)
        if isinstance(summaries, dict) and "data" in summaries:
            summaries = summaries["data"]
        if not isinstance(summaries, list):
            raise SystemExit(f"[!] Unexpected site-list shape: {type(summaries)}")
        site_ids = [s.get("id") for s in summaries if isinstance(s, dict) and s.get("id")]
        if not site_ids:
            raise SystemExit("[!] No sites found on this account.")
        print(f"[+] Found {len(site_ids)} site(s): {site_ids}", file=sys.stderr)

    any_key = False
    for sid in site_ids:
        site = iot_get(session, token, f"/v2/poolpad/site/{sid}")
        if isinstance(site, dict) and set(site.keys()) == {"data"}:
            site = site["data"]
        _dbg(f"site {sid}", site)

        keys = extract_security_keys(site)
        macs = extract_macs(site)

        print("=" * 68)
        print(f"Site id   : {sid}")
        site_name = site.get("name") or site.get("siteName") if isinstance(site, dict) else None
        if site_name:
            print(f"Site name : {site_name}")
        if macs:
            for path, mac in macs:
                print(f"MAC       : {mac}   (at {path})")
        else:
            print("MAC       : <none found>")
        if keys:
            any_key = True
            for path, uuid in keys:
                print(f"securityKey (UUID) : {uuid}")
                print(f"  -> AES-128 key hex : {uuid_to_hex16(uuid)}")
                print(f"  (found at site JSON path: {path})")
        else:
            print("securityKey : <NOT FOUND in this site's JSON> "
                  "(run with OMNIX_DEBUG=1 to inspect the raw response)")
    print("=" * 68)
    if not any_key:
        sys.exit("[!] No securityKey found. Re-run with OMNIX_DEBUG=1 and inspect JSON.")


if __name__ == "__main__":
    main()
