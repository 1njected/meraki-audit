# Meraki Security Audit

A read-only Python script that checks a Cisco Meraki Dashboard setup against common security
best practices. It uses the official [Meraki Python SDK](https://github.com/meraki/dashboard-api-python)
and makes **GET requests only**.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export MERAKI_DASHBOARD_API_KEY=...   # ideally a key from a read-only org admin
```

## Usage

```bash
python meraki_audit.py                                   # all orgs, coloured text report
python meraki_audit.py --org-id 123456 --format markdown -o report.md
python meraki_audit.py --format json -o findings.json --fail-on HIGH     # CI gate (exit 2)
python meraki_audit.py --network-tag prod --min-severity MEDIUM
python meraki_audit.py --trusted-domain example.com --inactive-days 60 -v
```

Output formats: `text`, `markdown`, `json`, `csv`. Run `--help` to see every option and threshold.

Checks that fail with 400/403/404 (feature not licensed, not applicable, or no permission) are
listed as *skipped* instead of crashing the run. Add `-v` to see them.

**Secrets:** Wi‑Fi PSKs, SNMP communities and VPN pre-shared keys are checked locally for strength
but never written to the report. Change-log entries are reported by page and setting name
only; their old and new values (which can contain PSKs) are never written. The report still
includes admin names/emails, source IPs of API callers and network
details, so treat it as sensitive.

## Corporate proxy / "certificate verify failed"

If your network uses a TLS-inspecting proxy, Python does not trust the proxy's internal root CA by
default. The script handles this in the following order:

1. `--ca-bundle corp-root.pem` (or `$MERAKI_CA_BUNDLE`, `$REQUESTS_CA_BUNDLE`, `$SSL_CERT_FILE`)
   trusts that PEM file.
2. Otherwise, if `truststore` is installed (it is in `requirements.txt`), the OS trust store is
   used (macOS Keychain, Windows cert store). Managed machines usually already have the corporate
   CA there.
3. Otherwise it falls back to the certifi CA list bundled with Python.

Set the proxy with `--proxy http://proxy.corp:8080` or `$HTTPS_PROXY`. To export a corporate CA on
macOS:

```bash
security find-certificate -a -p -c "<Corp Root CA name>" /Library/Keychains/System.keychain > corp-root.pem
```

The first line on stderr (`[tls] ...`) shows which trust source is in use.

## What is checked

| Area | Checks |
|---|---|
| **Org login security** | 2FA enforced, strong passwords, account lockout, idle timeout, password reuse, login IP ranges, API key IP restrictions |
| **Admins** | admins without 2FA, inactive accounts, too many / only one full admin, pending/locked accounts, full admins with API keys, admins outside `--trusted-domain` |
| **API usage** | API keys unused in the last `--log-days` (max 31), configuration changed through the API (by admin, with source IPs and user agents), deprecated API v0 still in use |
| **Change log** | security settings turned off, changes by accounts that are not current org admins, changes by admins outside `--trusted-domain`, summary of recent security-relevant changes by area (look-back `--log-days`, max 365) |
| **SSO** | SAML enabled, IdP configured, SAML roles with full access |
| **SNMP** | Dashboard SNMP v2c, MD5/DES on v3, no peer IP restriction; device SNMP community mode |
| **VPN** | 3rd-party peers: IKEv1, default (weak) IPsec preset, DES/3DES/MD5/SHA1/DH 1/2/5, short PSK, scoping; site-to-site VPN firewall rules, including rules hidden by an earlier rule |
| **MX firewall** | any/any allow rules, rules that never match because an earlier rule covers them (conflicting → MEDIUM, redundant → INFO), no deny rules, undocumented rules, no syslog on rules, inbound rules from any source, port forwards / 1:1 / 1:many NAT open to the internet (sensitive ports → HIGH), WAN web/SNMP services unrestricted, passthrough mode, IP spoofing protection not set to block |
| **MX threat protection** | IDS/IPS disabled or detection-only, weak ruleset, AMP disabled, no blocked URL categories |
| **Wireless** | WEP, open SSIDs, WPA1/TKIP, weak PSKs, shared PSK on bridged SSIDs, guest SSIDs bridged into LAN, no client isolation, guest LAN access allowed, 802.1X without RADIUS, Air Marshal default policy, AP Bluetooth scanning / BLE beacon advertising on, AP USB ports enabled in port profiles |
| **Switching** | uplink trunk missing VLANs used by the switch's access ports, RSTP disabled, rogue DHCP not blocked / no alert, no 802.1X policies, 802.1X Multi-Host mode, fewer than two RADIUS servers, RADIUS accounting off, fail-open critical-auth VLAN, trunks allowing all VLANs, native VLAN 1, access ports in VLAN 1, no BPDU guard |
| **Management plane** | local status page without auth, remote status page access |
| **Logging & monitoring** | no syslog server, security events not sent to syslog, no alert recipients, security alerts disabled |
| **Firmware** | beta firmware, newer stable available, firmware older than `--firmware-max-age-days` |

### Known limits of the inferred checks

- **Uplink VLANs (`SW-TRUNK-01`)**: the uplink is the trunk port tagged `uplink` or with
  "uplink" in its name. Failing that, it is the switch's only trunk. A switch with several
  untagged trunks is skipped (shown with `-v`). Tag your uplinks in Dashboard. "In use" means
  "assigned to an enabled access port (data or voice VLAN)", not "a device is connected". A
  switch that routes a VLAN itself (MS L3 interface) will be flagged incorrectly.
- **Shadowed firewall rules (`MX-FW-05`, `ORG-VPN-08`)**: the comparison is structural. `Any`
  covers everything, a CIDR covers its subnets, ports compare as sets, and anything else
  (`VLAN(30).*`, FQDNs) must match exactly. Shadowing written in different notations is
  missed, but it is not invented.
- **AP USB ports (`WL-USB-01`)**: read from the AP port profiles, which only exist for AP
  models with configurable ports. Networks without such APs are skipped (shown with `-v`), so
  no finding there does not prove a USB port is disabled. Bluetooth (`WL-BT-01/02`) is a
  network-wide setting and covers every AP in the network.

Severities are `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Each finding has a stable `check_id`
(e.g. `MX-NAT-01`) so you can track or suppress it in downstream tooling.

## Tests

```bash
pip install pytest
pytest -q tests
```

The tests use a fake Dashboard object with an "insecure" and a "hardened" fixture, so no API key
or network access is needed.

## Notes / limitations

- Rate limits: the Dashboard API allows about 10 requests/s per org. The SDK backs off on 429
  responses automatically. `--workers` (default 4) controls how many networks are audited in parallel.
- Networks bound to configuration templates report the effective (template) settings.
- Thresholds such as PSK length, idle timeout and admin inactivity are opinions. Adjust them
  through the CLI options to match your policy.

## License

MIT, see [LICENSE](LICENSE). Not affiliated with or endorsed by Cisco Meraki.
