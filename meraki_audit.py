#!/usr/bin/env python3
"""
Meraki Security Audit
=====================

Read-only audit of a Cisco Meraki Dashboard setup against common security
best practices (Meraki/Cisco hardening guidance, CIS-style controls, NIST
800-63B for authentication).

The script only performs GET requests through the official Meraki Python SDK
(https://github.com/meraki/dashboard-api-python). Using an API key that
belongs to a *read-only* organization admin is recommended.

Usage examples:
    export MERAKI_DASHBOARD_API_KEY=xxxxxxxx
    python meraki_audit.py                              # all orgs, text report
    python meraki_audit.py --org-id 123456 --format markdown -o report.md
    python meraki_audit.py --format json -o findings.json --fail-on HIGH
    python meraki_audit.py --trusted-domain example.com --inactive-days 60

Secrets (PSKs, SNMP communities, VPN pre-shared keys) are evaluated locally
for strength and are never written to the report.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

try:
    import meraki
except ImportError:  # pragma: no cover
    sys.exit("The Meraki SDK is required: pip install meraki")

__version__ = "1.0.0"

# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RISKY_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 69: "TFTP", 110: "POP3", 135: "MS-RPC", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    445: "SMB", 636: "LDAPS", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM", 5986: "WinRM", 6379: "Redis", 8080: "HTTP-alt",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

WEAK_IPSEC = {
    "cipher": {"des", "3des", "null"},
    "auth": {"md5", "sha1"},
    "dh": {"1", "2", "5", "group1", "group2", "group5"},
}


@dataclass
class Finding:
    severity: str
    check_id: str
    category: str
    title: str
    detail: str
    recommendation: str
    org_id: str = ""
    org_name: str = ""
    network_id: str = ""
    network_name: str = ""
    resource: str = ""


@dataclass
class Skipped:
    scope: str
    check: str
    reason: str


@dataclass
class AuditConfig:
    inactive_days: int = 90
    max_full_admins: int = 5
    min_psk_length: int = 12
    idle_timeout_max: int = 30
    lockout_attempts_max: int = 10
    firmware_max_age_days: int = 365
    trusted_domains: list[str] = field(default_factory=list)


class Collector:
    """Thread-safe sink for findings and skipped checks."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.skipped: list[Skipped] = []
        self._lock = threading.Lock()

    def add(self, f: Finding) -> None:
        with self._lock:
            self.findings.append(f)

    def skip(self, s: Skipped) -> None:
        with self._lock:
            self.skipped.append(s)


class Scope:
    """Where a check runs (org or network) and how it reports."""

    def __init__(self, dashboard, cfg: AuditConfig, out: Collector,
                 org: dict, network: dict | None = None) -> None:
        self.d = dashboard
        self.cfg = cfg
        self.out = out
        self.org = org
        self.net = network or {}

    @property
    def label(self) -> str:
        if self.net:
            return f"{self.org.get('name')}/{self.net.get('name')}"
        return str(self.org.get("name"))

    def add(self, severity: str, check_id: str, category: str, title: str,
            detail: str, recommendation: str, resource: str = "") -> None:
        self.out.add(Finding(
            severity=severity, check_id=check_id, category=category,
            title=title, detail=detail, recommendation=recommendation,
            org_id=str(self.org.get("id", "")), org_name=self.org.get("name", ""),
            network_id=self.net.get("id", ""), network_name=self.net.get("name", ""),
            resource=resource,
        ))

    def call(self, check: str, fn: Callable, *args, **kwargs) -> Any:
        """Call an SDK GET; returns None (and records why) if unavailable."""
        try:
            return fn(*args, **kwargs)
        except meraki.APIError as e:
            status = getattr(e, "status", None)
            msg = _api_error_message(e)
            if status == 404:
                reason = "not applicable / not found"
            elif status == 403:
                reason = "permission denied for this API key"
            elif status == 400:
                reason = f"not supported or not licensed ({msg})"
            else:
                reason = f"API error {status}: {msg}"
            self.out.skip(Skipped(self.label, check, reason))
        except Exception as e:  # network errors etc.
            self.out.skip(Skipped(self.label, check, f"{type(e).__name__}: {e}"))
        return None


def _api_error_message(e: Exception) -> str:
    msg = getattr(e, "message", None)
    if isinstance(msg, dict):
        errs = msg.get("errors")
        if errs:
            return "; ".join(map(str, errs))[:200]
    return str(msg or e)[:200]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def parse_time(value: Any) -> datetime | None:
    if value in (None, "", 0):
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    s = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def days_since(dt: datetime | None) -> int | None:
    if not dt:
        return None
    return (datetime.now(timezone.utc) - dt).days


def is_any(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, list):
        return not value or any(is_any(v) for v in value)
    v = str(value).strip().lower()
    if v in ("any", "", "0.0.0.0/0", "::/0", "all"):
        return True
    return any(part.strip().lower() in ("any", "0.0.0.0/0", "::/0")
               for part in v.split(","))


def parse_ports(spec: Any) -> set[int] | None:
    """Return the set of ports in a Meraki port spec, or None for 'any'."""
    if spec is None:
        return None
    s = str(spec).strip().lower()
    if s in ("", "any", "all"):
        return None
    ports: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            if a.strip().isdigit() and b.strip().isdigit():
                lo, hi = int(a), int(b)
                if hi - lo > 2000:
                    return None  # effectively "wide open"
                ports.update(range(lo, hi + 1))
        elif part.isdigit():
            ports.add(int(part))
    return ports


def risky_in(ports: set[int] | None) -> list[str]:
    if ports is None:
        return ["ANY"]
    return [f"{p}/{RISKY_PORTS[p]}" for p in sorted(ports) if p in RISKY_PORTS]


def psk_weakness(psk: str, ssid_name: str, min_len: int) -> list[str]:
    issues = []
    if len(psk) < min_len:
        issues.append(f"shorter than {min_len} characters")
    if psk.isdigit():
        issues.append("digits only")
    if psk.isalpha() and psk.lower() == psk:
        issues.append("lowercase letters only")
    if len(set(psk)) <= 3:
        issues.append("very low character variety")
    if ssid_name and ssid_name.lower().replace(" ", "") in psk.lower():
        issues.append("contains the SSID name")
    if re.search(r"(password|passw0rd|welcome|qwerty|12345678|letmein|wifi)", psk, re.I):
        issues.append("contains a common dictionary pattern")
    return issues


def lower(v: Any) -> str:
    return str(v or "").strip().lower()


# --------------------------------------------------------------------------- #
# Organization-level checks
# --------------------------------------------------------------------------- #

def check_login_security(s: Scope) -> dict | None:
    ls = s.call("login-security", s.d.organizations.getOrganizationLoginSecurity, s.org["id"])
    if not ls:
        return None
    cat = "Identity & Access"
    if not ls.get("enforceTwoFactorAuth"):
        s.add("HIGH", "ORG-LS-01", cat, "Two-factor authentication not enforced",
              "Dashboard admins can log in with only a password.",
              "Organization > Settings > Security: enable 'Force users to set up and use two-factor "
              "authentication' (or enforce MFA through SAML SSO).")
    if not ls.get("enforceStrongPasswords"):
        s.add("MEDIUM", "ORG-LS-02", cat, "Strong passwords not enforced",
              "Admins may set weak Dashboard passwords.",
              "Enable 'Force users to choose strong passwords'.")
    if not ls.get("enforceAccountLockout"):
        s.add("MEDIUM", "ORG-LS-03", cat, "Account lockout not enabled",
              "No lockout after repeated failed logins (brute-force exposure).",
              f"Enable account lockout after <= {s.cfg.lockout_attempts_max} failed attempts.")
    elif (ls.get("accountLockoutAttempts") or 0) > s.cfg.lockout_attempts_max:
        s.add("LOW", "ORG-LS-04", cat, "Account lockout threshold is high",
              f"Lockout after {ls.get('accountLockoutAttempts')} attempts.",
              f"Lower the threshold to <= {s.cfg.lockout_attempts_max}.")
    if not ls.get("enforceIdleTimeout"):
        s.add("MEDIUM", "ORG-LS-05", cat, "Idle session timeout not enforced",
              "Dashboard sessions are not logged out when idle.",
              f"Enable idle timeout of <= {s.cfg.idle_timeout_max} minutes.")
    elif (ls.get("idleTimeoutMinutes") or 0) > s.cfg.idle_timeout_max:
        s.add("LOW", "ORG-LS-06", cat, "Idle session timeout is long",
              f"Idle timeout is {ls.get('idleTimeoutMinutes')} minutes.",
              f"Reduce to <= {s.cfg.idle_timeout_max} minutes.")
    if not ls.get("enforceDifferentPasswords"):
        s.add("LOW", "ORG-LS-07", cat, "Password reuse not prevented",
              "Admins can reuse previous passwords.",
              "Enable 'Force users to choose a password different from the last N passwords'.")
    if not ls.get("enforceLoginIpRanges"):
        s.add("LOW", "ORG-LS-08", cat, "Dashboard login not restricted by source IP",
              "Admins can log in to this organization from any IP address.",
              "Consider restricting Dashboard access to corporate/VPN egress IP ranges.")
    api_ip = ((ls.get("apiAuthentication") or {}).get("ipRestrictionsForKeys") or {})
    if not api_ip.get("enabled"):
        s.add("MEDIUM", "ORG-LS-09", cat, "API keys usable from any IP address",
              "A leaked API key can be used from anywhere on the internet.",
              "Enable 'API key IP restrictions' and list the automation hosts' egress IPs.")
    return ls


def check_saml(s: Scope) -> bool:
    saml = s.call("saml", s.d.organizations.getOrganizationSaml, s.org["id"])
    if saml is None:
        return False
    enabled = bool(saml.get("enabled"))
    if not enabled:
        s.add("LOW", "ORG-SSO-01", "Identity & Access", "SAML SSO not enabled",
              "Admin identities are managed locally in Dashboard.",
              "Use SAML SSO with your IdP for centralized MFA, joiner/mover/leaver and auditing.")
        return False
    idps = s.call("saml-idps", s.d.organizations.getOrganizationSamlIdps, s.org["id"]) or []
    if not idps:
        s.add("MEDIUM", "ORG-SSO-02", "Identity & Access", "SAML enabled without an IdP",
              "SAML is enabled but no identity provider is configured.",
              "Configure the IdP or disable SAML.")
    roles = s.call("saml-roles", s.d.organizations.getOrganizationSamlRoles, s.org["id"]) or []
    full = [r.get("role") for r in roles if lower(r.get("orgAccess")) == "full"]
    if len(full) > 2:
        s.add("LOW", "ORG-SSO-03", "Identity & Access", "Many SAML roles grant full org access",
              f"{len(full)} SAML roles have full access: {', '.join(map(str, full))}.",
              "Apply least privilege; map most roles to read-only or network-scoped access.")
    return True


def check_admins(s: Scope, login_sec: dict | None, saml_enabled: bool) -> None:
    admins = s.call("admins", s.d.organizations.getOrganizationAdmins, s.org["id"])
    if admins is None:
        return
    cat = "Identity & Access"
    mfa_enforced = bool(login_sec and login_sec.get("enforceTwoFactorAuth"))
    full_admins = [a for a in admins if lower(a.get("orgAccess")) == "full"]

    if len(full_admins) > s.cfg.max_full_admins:
        s.add("MEDIUM", "ORG-ADM-01", cat, "Too many full organization admins",
              f"{len(full_admins)} admins have full org access (threshold {s.cfg.max_full_admins}).",
              "Reduce full-access admins; use read-only or network-scoped privileges where possible.")
    elif len(full_admins) == 1:
        s.add("LOW", "ORG-ADM-02", cat, "Only one full organization admin",
              "Losing this account would lock you out of the organization.",
              "Maintain a second, protected break-glass full admin account.")

    for a in admins:
        who = f"{a.get('name') or ''} <{a.get('email')}>".strip()
        access = lower(a.get("orgAccess"))
        sso = "securex" in lower(a.get("authenticationMethod")) or "cisco" in lower(a.get("authenticationMethod"))

        if not a.get("twoFactorAuthEnabled") and not sso:
            sev = "LOW" if mfa_enforced else ("HIGH" if access == "full" else "MEDIUM")
            note = (" (2FA is enforced org-wide; the user will be forced to enroll at next login)"
                    if mfa_enforced else "")
            s.add(sev, "ORG-ADM-03", cat, "Admin without two-factor authentication",
                  f"{who} (orgAccess={access}) has no 2FA enrolled{note}.",
                  "Require 2FA for every admin account.", resource=a.get("email", ""))

        last = parse_time(a.get("lastActive"))
        age = days_since(last)
        if age is not None and age > s.cfg.inactive_days:
            s.add("MEDIUM", "ORG-ADM-04", cat, "Inactive admin account",
                  f"{who} last active {age} days ago (threshold {s.cfg.inactive_days}).",
                  "Remove or disable admin accounts that are no longer used.",
                  resource=a.get("email", ""))

        status = lower(a.get("accountStatus"))
        if status and status != "ok":
            s.add("LOW", "ORG-ADM-05", cat, f"Admin account status '{status}'",
                  f"{who} has account status '{status}'.",
                  "Clean up locked, unverified or pending admin invitations.",
                  resource=a.get("email", ""))

        if a.get("hasApiKey") and access == "full":
            s.add("INFO", "ORG-ADM-06", cat, "Full admin has an API key",
                  f"{who} has an API key with full org privileges.",
                  "Use dedicated read-only service accounts for automation; rotate keys regularly.",
                  resource=a.get("email", ""))

        if s.cfg.trusted_domains:
            domain = lower(a.get("email")).rsplit("@", 1)[-1]
            if domain not in s.cfg.trusted_domains:
                sev = "MEDIUM" if access in ("full", "enterprise") else "LOW"
                s.add(sev, "ORG-ADM-07", cat, "Admin from untrusted email domain",
                      f"{who} (orgAccess={access}) is outside trusted domains.",
                      "Verify third-party/partner access is still required and properly scoped.",
                      resource=a.get("email", ""))

    if saml_enabled and len(full_admins) > 2:
        s.add("INFO", "ORG-ADM-08", cat, "Local admins exist alongside SAML",
              f"{len(admins)} local Dashboard admins exist although SAML SSO is enabled.",
              "Keep only break-glass local accounts and manage the rest through the IdP.")


def check_org_snmp(s: Scope) -> None:
    snmp = s.call("org-snmp", s.d.organizations.getOrganizationSnmp, s.org["id"])
    if not snmp:
        return
    cat = "Management Plane"
    if snmp.get("v2cEnabled"):
        s.add("MEDIUM", "ORG-SNMP-01", cat, "SNMPv2c enabled on Dashboard SNMP",
              "SNMPv2c uses a cleartext community string.",
              "Disable v2c and use SNMPv3 with SHA/AES.")
    if snmp.get("v3Enabled"):
        if lower(snmp.get("v3AuthMode")) == "md5":
            s.add("MEDIUM", "ORG-SNMP-02", cat, "SNMPv3 uses MD5 authentication",
                  "MD5 is considered weak.", "Use SHA authentication.")
        if lower(snmp.get("v3PrivMode")) == "des":
            s.add("MEDIUM", "ORG-SNMP-03", cat, "SNMPv3 uses DES privacy",
                  "DES encryption is weak.", "Use AES128 privacy.")
    if (snmp.get("v2cEnabled") or snmp.get("v3Enabled")) and not snmp.get("peerIps"):
        s.add("MEDIUM", "ORG-SNMP-04", cat, "Dashboard SNMP not restricted to peer IPs",
              "SNMP polling of the Dashboard is allowed from any source.",
              "Restrict SNMP to your NMS IP addresses.")


def check_third_party_vpn(s: Scope) -> None:
    resp = s.call("third-party-vpn", s.d.appliance.getOrganizationApplianceVpnThirdPartyVPNPeers,
                  s.org["id"])
    if not resp:
        return
    cat = "VPN"
    for p in resp.get("peers", []):
        name = p.get("name") or p.get("publicIp") or "peer"
        preset = lower(p.get("ipsecPoliciesPreset"))
        if lower(p.get("ikeVersion")) in ("1", "ikev1"):
            s.add("MEDIUM", "ORG-VPN-01", cat, "Third-party VPN peer uses IKEv1",
                  f"Peer '{name}' uses IKEv1.", "Migrate to IKEv2.", resource=name)
        if preset == "default":
            s.add("HIGH", "ORG-VPN-02", cat, "Third-party VPN peer uses default IPsec policy",
                  f"Peer '{name}' uses the 'Default' preset (3DES/SHA1/DH group 2, no PFS).",
                  "Use a custom policy: AES-256/GCM, SHA-256+, DH group 14+ (19/20 preferred), PFS on.",
                  resource=name)
        pol = p.get("ipsecPolicies") or {}
        weak = []
        for key in ("ikeCipherAlgo", "childCipherAlgo"):
            weak += [f"{key}={v}" for v in pol.get(key, []) if lower(v) in WEAK_IPSEC["cipher"]]
        for key in ("ikeAuthAlgo", "childAuthAlgo", "ikePrfAlgo"):
            weak += [f"{key}={v}" for v in pol.get(key, []) if lower(v) in WEAK_IPSEC["auth"]]
        for key in ("ikeDiffieHellmanGroup", "childPfsGroup"):
            weak += [f"{key}={v}" for v in pol.get(key, []) if lower(v) in WEAK_IPSEC["dh"]]
        if pol.get("childPfsGroup") in (["disabled"], ["off"], []) and preset == "custom":
            weak.append("PFS disabled")
        if weak and preset != "default":
            s.add("HIGH", "ORG-VPN-03", cat, "Third-party VPN peer allows weak crypto",
                  f"Peer '{name}': {', '.join(weak)}.",
                  "Remove DES/3DES/MD5/SHA1 and DH groups 1/2/5; enable PFS.", resource=name)
        secret = p.get("secret")
        if isinstance(secret, str) and secret and len(secret) < 20:
            s.add("MEDIUM", "ORG-VPN-04", cat, "Third-party VPN pre-shared key is short",
                  f"Peer '{name}' PSK is {len(secret)} characters.",
                  "Use a random PSK of at least 20-32 characters, or certificates.", resource=name)
        if not p.get("networkTags") or "all" in [lower(t) for t in p.get("networkTags", [])]:
            s.add("INFO", "ORG-VPN-05", cat, "Third-party VPN peer available to all networks",
                  f"Peer '{name}' is reachable from all MX networks.",
                  "Scope peers with network tags to only the sites that need them.", resource=name)


def check_vpn_firewall(s: Scope) -> None:
    resp = s.call("vpn-firewall", s.d.appliance.getOrganizationApplianceVpnVpnFirewallRules,
                  s.org["id"])
    if not resp:
        return
    rules = [r for r in resp.get("rules", []) if lower(r.get("comment")) != "default rule"]
    if not rules:
        s.add("LOW", "ORG-VPN-06", "VPN", "No site-to-site VPN firewall rules",
              "All traffic between AutoVPN/3rd-party VPN sites is allowed (default allow).",
              "Segment inter-site traffic with Organization-wide site-to-site VPN firewall rules.")
    for r in rules:
        if (lower(r.get("policy")) == "allow" and is_any(r.get("srcCidr"))
                and is_any(r.get("destCidr")) and parse_ports(r.get("destPort")) is None
                and lower(r.get("protocol")) == "any"):
            s.add("LOW", "ORG-VPN-07", "VPN", "Any/any allow rule in VPN firewall",
                  f"Rule '{r.get('comment') or '(no comment)'}' allows all traffic.",
                  "Replace with specific allow rules.")


def check_air_marshal(s: Scope, networks: dict[str, str]) -> None:
    resp = s.call("air-marshal",
                  s.d.wireless.getOrganizationWirelessAirMarshalSettingsByNetwork,
                  s.org["id"], total_pages="all")
    if not resp:
        return
    items = resp.get("items", resp) if isinstance(resp, dict) else resp
    for item in items:
        net_id = item.get("networkId", "")
        if net_id not in networks:
            continue
        if lower(item.get("defaultPolicy")) == "allow":
            ns = Scope(s.d, s.cfg, s.out, s.org, {"id": net_id, "name": networks[net_id]})
            ns.add("INFO", "WL-AM-01", "Wireless",
                   "Air Marshal default policy allows unknown SSIDs",
                   "Clients are allowed to associate with unknown/rogue SSIDs seen by your APs.",
                   "Review Air Marshal: set the default policy to block clients from connecting "
                   "to rogue SSIDs and add containment rules for spoofed corporate SSIDs.")


def check_switch_ports(s: Scope, networks: dict[str, str]) -> None:
    switches = s.call("switch-ports", s.d.switch.getOrganizationSwitchPortsBySwitch,
                      s.org["id"], total_pages="all")
    if not switches:
        return
    cat = "Switching"
    for sw in switches:
        ports = sw.get("ports") or []
        trunk_all, native1, access_vlan1, no_bpdu = [], [], [], []
        for p in ports:
            if not p.get("enabled", True):
                continue
            pid = str(p.get("portId"))
            ptype = lower(p.get("type"))
            if ptype == "trunk":
                if lower(p.get("allowedVlans")) in ("all", "1-4094"):
                    trunk_all.append(pid)
                if str(p.get("vlan")) == "1":
                    native1.append(pid)
            elif ptype == "access":
                if str(p.get("vlan")) == "1":
                    access_vlan1.append(pid)
                if lower(p.get("stpGuard")) != "bpdu guard":
                    no_bpdu.append(pid)
        name = sw.get("name") or sw.get("serial")
        net = sw.get("network") or {}
        if net.get("id") not in networks:
            continue
        f_scope = Scope(s.d, s.cfg, s.out, s.org,
                        {"id": net["id"], "name": net.get("name") or networks[net["id"]]})

        def short(lst: list[str]) -> str:
            return ", ".join(lst[:12]) + (" ..." if len(lst) > 12 else "")

        if trunk_all:
            f_scope.add("LOW", "SW-PORT-01", cat, "Trunk ports allow all VLANs",
                        f"Switch {name}: {len(trunk_all)} trunk port(s) allow all VLANs ({short(trunk_all)}).",
                        "Prune allowed VLANs on trunks to only what is required.", resource=name)
        if native1:
            f_scope.add("LOW", "SW-PORT-02", cat, "Trunk ports use native VLAN 1",
                        f"Switch {name}: {len(native1)} trunk port(s) with native VLAN 1 ({short(native1)}).",
                        "Use an unused, dedicated native VLAN to mitigate VLAN hopping.", resource=name)
        if access_vlan1:
            f_scope.add("LOW", "SW-PORT-03", cat, "Access ports in VLAN 1",
                        f"Switch {name}: {len(access_vlan1)} enabled access port(s) in default VLAN 1 ({short(access_vlan1)}).",
                        "Move access ports to purpose-specific VLANs; disable unused ports.", resource=name)
        if no_bpdu:
            f_scope.add("LOW", "SW-PORT-04", cat, "Access ports without BPDU guard",
                        f"Switch {name}: {len(no_bpdu)} access port(s) without BPDU guard ({short(no_bpdu)}).",
                        "Enable BPDU guard on edge/access ports.", resource=name)


# --------------------------------------------------------------------------- #
# Network-level checks (all product types)
# --------------------------------------------------------------------------- #

def check_network_settings(s: Scope) -> None:
    st = s.call("network-settings", s.d.networks.getNetworkSettings, s.net["id"])
    if not st:
        return
    cat = "Management Plane"
    if st.get("localStatusPageEnabled"):
        auth = ((st.get("localStatusPage") or {}).get("authentication") or {})
        if not auth.get("enabled"):
            s.add("MEDIUM", "NET-MGMT-01", cat, "Local status page without authentication",
                  "Device local status pages are reachable without a password.",
                  "Enable local status page authentication or disable the local status page.")
        if st.get("remoteStatusPageEnabled"):
            s.add("MEDIUM", "NET-MGMT-02", cat, "Remote access to local status page enabled",
                  "Local status pages can be reached via the device's LAN/WAN IP.",
                  "Disable 'Remote device status pages' unless strictly required.")


def check_network_snmp(s: Scope) -> None:
    snmp = s.call("network-snmp", s.d.networks.getNetworkSnmp, s.net["id"])
    if not snmp:
        return
    if lower(snmp.get("access")) == "community":
        s.add("MEDIUM", "NET-SNMP-01", "Management Plane", "Device SNMPv2c community access enabled",
              "Devices answer SNMP v1/v2c with a cleartext community string.",
              "Switch to SNMPv3 users ('access: users') or disable SNMP.")


def check_syslog(s: Scope) -> None:
    resp = s.call("syslog", s.d.networks.getNetworkSyslogServers, s.net["id"])
    if resp is None:
        return
    servers = resp.get("servers", [])
    if not servers:
        s.add("MEDIUM", "NET-LOG-01", "Logging & Monitoring", "No syslog server configured",
              "Event, security and flow logs are not exported to a SIEM/log store.",
              "Configure a syslog server (Network-wide > General > Reporting).")
        return
    if "appliance" in s.net.get("productTypes", []):
        roles = {lower(r) for srv in servers for r in srv.get("roles", [])}
        if not any("security" in r or "ids" in r for r in roles):
            s.add("LOW", "NET-LOG-02", "Logging & Monitoring", "Security events not sent to syslog",
                  "Syslog is configured but no server receives 'Security events'/'IDS alerts'.",
                  "Add the 'Security events' role to a syslog server.")


def check_alerts(s: Scope) -> None:
    al = s.call("alerts", s.d.networks.getNetworkAlertsSettings, s.net["id"])
    if not al:
        return
    cat = "Logging & Monitoring"
    dd = al.get("defaultDestinations") or {}
    if not (dd.get("emails") or dd.get("allAdmins") or dd.get("snmp") or dd.get("httpServerIds")):
        s.add("MEDIUM", "NET-ALERT-01", cat, "No default alert recipients",
              "Alerts have no default destination (email, all admins, SNMP or webhook).",
              "Configure default alert recipients or a webhook to your ticketing/SIEM system.")
    wanted = {
        "settingsChanged": "Configuration settings are changed",
        "rogueAp": "Rogue AP detected",
        "rogueDhcp": "Rogue DHCP server detected",
        "ampMalwareDetected": "AMP malware detected",
        "ampMalwareBlocked": "AMP malware blocked",
        "vpnConnectivityChange": "VPN connectivity changed",
    }
    disabled = [wanted[a["type"]] for a in al.get("alerts", [])
                if a.get("type") in wanted and not a.get("enabled")]
    if disabled:
        s.add("LOW", "NET-ALERT-02", cat, "Security-relevant alerts disabled",
              "Disabled: " + "; ".join(disabled) + ".",
              "Enable these alerts so changes and threats are noticed.")


def check_firmware(s: Scope) -> None:
    fw = s.call("firmware", s.d.networks.getNetworkFirmwareUpgrades, s.net["id"])
    if not fw:
        return
    cat = "Firmware"
    for product, info in (fw.get("products") or {}).items():
        cur = (info or {}).get("currentVersion") or {}
        if not cur:
            continue
        cur_name = cur.get("shortName") or cur.get("firmware") or "unknown"
        rtype = lower(cur.get("releaseType"))
        if rtype == "beta":
            s.add("LOW", "FW-01", cat, f"{product} running beta firmware",
                  f"{product} runs {cur_name} (beta).",
                  "Run stable firmware in production unless a beta fix is needed.", resource=product)
        cur_date = parse_time(cur.get("releaseDate"))
        newer_stable = [
            v for v in (info.get("availableVersions") or [])
            if lower(v.get("releaseType")) == "stable"
            and cur_date and (parse_time(v.get("releaseDate")) or cur_date) > cur_date
        ]
        if newer_stable:
            latest = max(newer_stable, key=lambda v: parse_time(v.get("releaseDate")) or cur_date)
            s.add("MEDIUM", "FW-02", cat, f"{product} firmware not on latest stable",
                  f"{product} runs {cur_name}; newer stable available: "
                  f"{latest.get('shortName') or latest.get('firmware')}.",
                  "Schedule an upgrade to the latest stable release (security fixes).",
                  resource=product)
        age = days_since(cur_date)
        if age is not None and age > s.cfg.firmware_max_age_days:
            s.add("MEDIUM", "FW-03", cat, f"{product} firmware is old",
                  f"{product} runs {cur_name}, released {age} days ago.",
                  "Upgrade to a current stable firmware.", resource=product)


# --------------------------------------------------------------------------- #
# Appliance (MX) checks
# --------------------------------------------------------------------------- #

def check_mx_l3_firewall(s: Scope) -> None:
    resp = s.call("mx-l3-firewall", s.d.appliance.getNetworkApplianceFirewallL3FirewallRules,
                  s.net["id"])
    if not resp:
        return
    cat = "Firewall"
    rules = [r for r in resp.get("rules", []) if lower(r.get("comment")) != "default rule"]
    if not any(lower(r.get("policy")) == "deny" for r in rules):
        s.add("LOW", "MX-FW-01", cat, "No outbound/inter-VLAN deny rules",
              "The MX L3 firewall only relies on the default allow-any rule.",
              "Implement egress filtering and inter-VLAN segmentation (deny by default where possible).")
    for idx, r in enumerate(rules, 1):
        if (lower(r.get("policy")) == "allow" and lower(r.get("protocol")) == "any"
                and is_any(r.get("srcCidr")) and is_any(r.get("destCidr"))
                and parse_ports(r.get("destPort")) is None):
            s.add("MEDIUM", "MX-FW-02", cat, "Explicit any/any allow rule",
                  f"Rule #{idx} '{r.get('comment') or '(no comment)'}' allows all traffic, making "
                  "rules below it ineffective.",
                  "Remove or narrow the rule.", resource=f"rule {idx}")
    no_comment = [str(i) for i, r in enumerate(rules, 1) if not r.get("comment")]
    if no_comment:
        s.add("INFO", "MX-FW-03", cat, "Firewall rules without description",
              f"Rules without comment: #{', #'.join(no_comment)}.",
              "Document the business purpose of each rule.")
    if rules and not any(r.get("syslogEnabled") for r in rules):
        s.add("INFO", "MX-FW-04", cat, "No firewall rules log to syslog",
              "None of the custom L3 rules have syslog enabled.",
              "Enable syslog on deny rules for visibility.")


def check_mx_inbound(s: Scope) -> None:
    resp = s.call("mx-inbound-firewall",
                  s.d.appliance.getNetworkApplianceFirewallInboundFirewallRules, s.net["id"])
    if not resp:
        return
    for idx, r in enumerate(resp.get("rules", []), 1):
        if lower(r.get("comment")) == "default rule":
            continue
        if lower(r.get("policy")) == "allow" and is_any(r.get("srcCidr")):
            ports = parse_ports(r.get("destPort"))
            risky = risky_in(ports)
            sev = "HIGH" if risky else "MEDIUM"
            s.add(sev, "MX-IN-01", "Firewall", "Inbound rule allows any source",
                  f"Inbound rule #{idx} '{r.get('comment') or ''}' allows any source to "
                  f"{r.get('destCidr')} port {r.get('destPort')}"
                  + (f" (sensitive: {', '.join(risky)})" if risky else "") + ".",
                  "Restrict inbound rules to known source IPs.", resource=f"inbound rule {idx}")


def check_mx_port_forwarding(s: Scope) -> None:
    resp = s.call("mx-port-forwarding",
                  s.d.appliance.getNetworkApplianceFirewallPortForwardingRules, s.net["id"])
    if not resp:
        return
    for r in resp.get("rules", []):
        if not is_any(r.get("allowedIps")):
            continue
        ports = parse_ports(r.get("publicPort"))
        risky = risky_in(ports)
        name = r.get("name") or f"{r.get('protocol')}/{r.get('publicPort')}"
        s.add("HIGH" if risky else "MEDIUM", "MX-NAT-01", "Firewall",
              "Port forward open to the internet",
              f"Port forward '{name}' exposes {r.get('protocol')}/{r.get('publicPort')} -> "
              f"{r.get('lanIp')}:{r.get('localPort')} to any source"
              + (f" (sensitive: {', '.join(risky)})" if risky else "") + ".",
              "Restrict 'Allowed remote IPs', or publish the service through VPN/ZTNA instead.",
              resource=name)


def check_mx_nat(s: Scope) -> None:
    one = s.call("mx-1to1-nat", s.d.appliance.getNetworkApplianceFirewallOneToOneNatRules,
                 s.net["id"]) or {}
    for r in one.get("rules", []):
        for ai in r.get("allowedInbound", []) or []:
            if is_any(ai.get("allowedIps")):
                ports = None if lower(ai.get("protocol")) == "any" else \
                    parse_ports(",".join(map(str, ai.get("destinationPorts") or ["any"])))
                risky = risky_in(ports)
                s.add("HIGH" if risky else "MEDIUM", "MX-NAT-02", "Firewall",
                      "1:1 NAT allows inbound from any source",
                      f"1:1 NAT '{r.get('name') or r.get('publicIp')}' ({r.get('publicIp')} -> "
                      f"{r.get('lanIp')}) allows {ai.get('protocol')} "
                      f"{ai.get('destinationPorts')} from any IP"
                      + (f" (sensitive: {', '.join(risky)})" if risky else "") + ".",
                      "Restrict allowed remote IPs and ports.", resource=r.get("publicIp", ""))
    many = s.call("mx-1tomany-nat", s.d.appliance.getNetworkApplianceFirewallOneToManyNatRules,
                  s.net["id"]) or {}
    for r in many.get("rules", []):
        for pr in r.get("portRules", []) or []:
            if is_any(pr.get("allowedIps")):
                risky = risky_in(parse_ports(pr.get("publicPort")))
                s.add("HIGH" if risky else "MEDIUM", "MX-NAT-03", "Firewall",
                      "1:many NAT port rule open to any source",
                      f"1:many NAT {r.get('publicIp')} '{pr.get('name') or ''}' exposes "
                      f"{pr.get('protocol')}/{pr.get('publicPort')} -> {pr.get('localIp')} to any IP"
                      + (f" (sensitive: {', '.join(risky)})" if risky else "") + ".",
                      "Restrict allowed remote IPs.", resource=r.get("publicIp", ""))


def check_mx_services(s: Scope) -> None:
    svcs = s.call("mx-firewalled-services",
                  s.d.appliance.getNetworkApplianceFirewallFirewalledServices, s.net["id"])
    if not svcs:
        return
    for svc in svcs:
        name, access = lower(svc.get("service")), lower(svc.get("access"))
        if access != "unrestricted":
            continue
        if name in ("web", "snmp"):
            s.add("HIGH", "MX-SVC-01", "Management Plane",
                  f"MX {name.upper()} service reachable from the internet",
                  f"The MX '{name}' service on the WAN is unrestricted.",
                  "Set the service to 'blocked' or restrict it to specific management IPs.",
                  resource=name)
        elif name == "icmp":
            s.add("INFO", "MX-SVC-02", "Management Plane", "MX answers ICMP from any source",
                  "WAN ping is unrestricted.", "Restrict ICMP to monitoring IPs if not needed.")


def check_mx_threat(s: Scope) -> None:
    cat = "Threat Protection"
    ids = s.call("mx-ids", s.d.appliance.getNetworkApplianceSecurityIntrusion, s.net["id"])
    if ids:
        mode = lower(ids.get("mode"))
        if mode == "disabled":
            s.add("HIGH", "MX-IPS-01", cat, "Intrusion detection/prevention disabled",
                  "Snort IDS/IPS is disabled on the MX.",
                  "Enable intrusion prevention (requires Advanced Security license).")
        elif mode == "detection":
            s.add("MEDIUM", "MX-IPS-02", cat, "IDS in detection-only mode",
                  "Threats are logged but not blocked.", "Set mode to 'prevention'.")
        if mode != "disabled" and lower(ids.get("idsRulesets")) == "connectivity":
            s.add("LOW", "MX-IPS-03", cat, "IDS ruleset 'connectivity'",
                  "The least strict IDS ruleset is in use.",
                  "Use the 'balanced' or 'security' ruleset.")
    amp = s.call("mx-amp", s.d.appliance.getNetworkApplianceSecurityMalware, s.net["id"])
    if amp and lower(amp.get("mode")) != "enabled":
        s.add("HIGH", "MX-AMP-01", cat, "Advanced Malware Protection disabled",
              "AMP file inspection is disabled on the MX.",
              "Enable AMP (requires Advanced Security license).")
    cf = s.call("mx-content-filtering", s.d.appliance.getNetworkApplianceContentFiltering,
                s.net["id"])
    if cf is not None and not cf.get("blockedUrlCategories"):
        s.add("MEDIUM", "MX-CF-01", cat, "No URL categories blocked",
              "Content filtering does not block any category (e.g. malware, phishing).",
              "Block at least security-related categories (Malware sites, Phishing, Spyware, "
              "Botnets) or use Umbrella/Secure Access DNS security.")


def check_mx_mode(s: Scope) -> None:
    """Passthrough MX does not enforce NAT/L3 firewall - make that visible."""
    st = s.call("mx-settings", s.d.appliance.getNetworkApplianceSettings, s.net["id"])
    if st and lower((st.get("deploymentMode"))) == "passthrough":
        s.add("INFO", "MX-MODE-01", "Firewall", "MX in passthrough/VPN-concentrator mode",
              "NAT/L3 firewall features are not applied in passthrough mode.",
              "Ensure an upstream firewall protects this segment.")


# --------------------------------------------------------------------------- #
# Wireless (MR) checks
# --------------------------------------------------------------------------- #

def check_ssids(s: Scope) -> None:
    ssids = s.call("ssids", s.d.wireless.getNetworkWirelessSsids, s.net["id"])
    if not ssids:
        return
    cat = "Wireless"
    for ssid in ssids:
        if not ssid.get("enabled"):
            continue
        name = ssid.get("name") or f"SSID {ssid.get('number')}"
        auth = lower(ssid.get("authMode"))
        enc = lower(ssid.get("encryptionMode"))
        wpa = lower(ssid.get("wpaEncryptionMode"))
        splash = lower(ssid.get("splashPage"))
        mode = lower(ssid.get("ipAssignmentMode"))
        is_open = auth in ("open", "open-with-radius", "open-enhanced", "open-with-nac")
        has_splash = splash not in ("", "none")

        if enc == "wep":
            s.add("CRITICAL", "WL-SSID-01", cat, "SSID uses WEP",
                  f"'{name}' uses WEP, which is trivially broken.",
                  "Use WPA3 (or WPA2/WPA3 transition) with 802.1X or a strong PSK.", resource=name)
        if auth == "open" and not has_splash:
            s.add("HIGH", "WL-SSID-02", cat, "Open SSID without any access control",
                  f"'{name}' is open with no splash page; traffic is unencrypted.",
                  "Use WPA2/3, or Enhanced Open (OWE) with a splash page for guest networks.",
                  resource=name)
        elif auth == "open":
            s.add("MEDIUM", "WL-SSID-03", cat, "Open (unencrypted) guest SSID",
                  f"'{name}' is open with a '{ssid.get('splashPage')}' splash page; over-the-air "
                  "traffic is unencrypted.",
                  "Use Enhanced Open (OWE) or WPA3/WPA2-PSK for guests.", resource=name)
        if "wpa1" in wpa:
            sev = "HIGH" if wpa == "wpa1 only" else "MEDIUM"
            s.add(sev, "WL-SSID-04", cat, "SSID allows WPA1/TKIP",
                  f"'{name}' WPA mode is '{ssid.get('wpaEncryptionMode')}'.",
                  "Use 'WPA2 only' or WPA3.", resource=name)
        if auth == "psk":
            psk = ssid.get("psk")
            if isinstance(psk, str) and psk:
                issues = psk_weakness(psk, name, s.cfg.min_psk_length)
                if issues:
                    s.add("HIGH" if len(psk) < 10 else "MEDIUM", "WL-SSID-05", cat,
                          "Weak Wi-Fi pre-shared key",
                          f"'{name}' PSK is weak: {', '.join(issues)}. (Value not shown.)",
                          f"Use a random passphrase of {s.cfg.min_psk_length}+ characters and "
                          "rotate it regularly.", resource=name)
            if mode == "bridge mode":
                s.add("LOW", "WL-SSID-06", cat, "Shared PSK on bridged (internal) SSID",
                      f"'{name}' bridges clients onto the LAN with a shared PSK.",
                      "Use 802.1X (WPA2/3-Enterprise) or iPSK for internal networks.", resource=name)
        if (is_open or has_splash) and mode in ("bridge mode", "layer 3 roaming"):
            s.add("HIGH", "WL-SSID-07", cat, "Guest/open SSID bridged into the LAN",
                  f"'{name}' is open/splash but bridged ('{ssid.get('ipAssignmentMode')}').",
                  "Use NAT mode or a dedicated guest VLAN with ACLs; enable client isolation.",
                  resource=name)
        if (is_open or has_splash) and mode == "bridge mode" and not ssid.get("lanIsolationEnabled"):
            s.add("MEDIUM", "WL-SSID-08", cat, "Client isolation disabled on guest SSID",
                  f"'{name}' clients can reach each other.",
                  "Enable LAN isolation on guest SSIDs.", resource=name)
        if "802.1x" in auth or "8021x" in auth:
            if not ssid.get("radiusServers") and auth == "8021x-radius":
                s.add("MEDIUM", "WL-SSID-09", cat, "802.1X SSID without RADIUS servers",
                      f"'{name}' is set to 802.1X-RADIUS but has no RADIUS servers.",
                      "Configure redundant RADIUS servers.", resource=name)

        # Guest / PSK SSIDs should not reach the LAN
        if is_open or has_splash or auth == "psk":
            fw = s.call(f"ssid-{ssid.get('number')}-l3",
                        s.d.wireless.getNetworkWirelessSsidFirewallL3FirewallRules,
                        s.net["id"], ssid.get("number"))
            if fw and fw.get("allowLanAccess") and (is_open or has_splash):
                s.add("HIGH", "WL-SSID-10", cat, "Guest SSID allows wireless clients LAN access",
                      f"'{name}' has 'Wireless clients accessing LAN' set to allow.",
                      "Deny LAN access on the SSID's L3 firewall for guest networks.", resource=name)


# --------------------------------------------------------------------------- #
# Switch (MS) checks
# --------------------------------------------------------------------------- #

def check_switch_network(s: Scope) -> None:
    cat = "Switching"
    stp = s.call("switch-stp", s.d.switch.getNetworkSwitchStp, s.net["id"])
    if stp is not None and not stp.get("rstpEnabled"):
        s.add("MEDIUM", "SW-STP-01", cat, "Spanning tree (RSTP) disabled",
              "Loops or rogue switches may disrupt the network.", "Enable RSTP.")
    dhcp = s.call("switch-dhcp-policy", s.d.switch.getNetworkSwitchDhcpServerPolicy, s.net["id"])
    if dhcp:
        if lower(dhcp.get("defaultPolicy")) == "allow":
            s.add("MEDIUM", "SW-DHCP-01", cat, "Rogue DHCP servers not blocked",
                  "DHCP server policy default is 'allow'.",
                  "Set the DHCP server guard default policy to 'block' and allow-list "
                  "legitimate DHCP servers.")
        alerts = dhcp.get("alerts") or {}
        if not (alerts.get("email") or {}).get("enabled"):
            s.add("LOW", "SW-DHCP-02", cat, "No alert for new DHCP servers",
                  "DHCP server guard email alerts are disabled.",
                  "Enable alerts when new DHCP servers are seen.")
    pols = s.call("switch-access-policies", s.d.switch.getNetworkSwitchAccessPolicies, s.net["id"])
    if pols is not None and not pols:
        s.add("INFO", "SW-NAC-01", cat, "No 802.1X/MAB access policies",
              "No port access policies are defined in this switch network.",
              "Consider 802.1X/MAB port authentication for user-facing ports.")


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

NETWORK_CHECKS: list[tuple[str | None, Callable[[Scope], None]]] = [
    (None, check_network_settings),
    (None, check_network_snmp),
    (None, check_syslog),
    (None, check_alerts),
    (None, check_firmware),
    ("appliance", check_mx_l3_firewall),
    ("appliance", check_mx_inbound),
    ("appliance", check_mx_port_forwarding),
    ("appliance", check_mx_nat),
    ("appliance", check_mx_services),
    ("appliance", check_mx_threat),
    ("appliance", check_mx_mode),
    ("wireless", check_ssids),
    ("switch", check_switch_network),
]


def audit_network(dashboard, cfg: AuditConfig, out: Collector, org: dict, net: dict) -> None:
    s = Scope(dashboard, cfg, out, org, net)
    products = set(net.get("productTypes", []))
    for product, fn in NETWORK_CHECKS:
        if product is None or product in products:
            try:
                fn(s)
            except Exception as e:  # keep going on unexpected payloads
                out.skip(Skipped(s.label, fn.__name__, f"check failed: {type(e).__name__}: {e}"))


def audit_org(dashboard, cfg: AuditConfig, out: Collector, org: dict,
              network_ids: set[str], network_tags: set[str], workers: int,
              progress: Callable[[str], None]) -> None:
    s = Scope(dashboard, cfg, out, org)
    progress(f"[org] {org.get('name')} ({org.get('id')})")

    if not (org.get("api") or {}).get("enabled", True):
        s.add("INFO", "ORG-API-00", "Management Plane", "API access disabled",
              "Dashboard API access is disabled for this organization.", "-")
        return

    login_sec = check_login_security(s)
    saml = check_saml(s)
    check_admins(s, login_sec, saml)
    check_org_snmp(s)
    check_third_party_vpn(s)
    check_vpn_firewall(s)

    networks = s.call("networks", dashboard.organizations.getOrganizationNetworks,
                      org["id"], total_pages="all") or []
    if network_ids:
        networks = [n for n in networks if n["id"] in network_ids]
    if network_tags:
        networks = [n for n in networks if network_tags & set(n.get("tags", []))]
    names = {n["id"]: n["name"] for n in networks}

    if any("wireless" in n.get("productTypes", []) for n in networks):
        check_air_marshal(s, names)
    if any("switch" in n.get("productTypes", []) for n in networks):
        check_switch_ports(s, names)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(audit_network, dashboard, cfg, out, org, n): n for n in networks}
        for fut in as_completed(futures):
            n = futures[fut]
            progress(f"  [net] {n.get('name')} {sorted(n.get('productTypes', []))}")
            fut.result()


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-SEV_RANK[f.severity], f.org_name,
                                           f.network_name, f.check_id, f.resource))


def summary_counts(findings: list[Finding]) -> dict[str, int]:
    return {sev: sum(1 for f in findings if f.severity == sev) for sev in reversed(SEVERITIES)}


def render_text(findings: list[Finding], skipped: list[Skipped], verbose: bool) -> str:
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    colors = {"CRITICAL": "\033[1;37;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[33m",
              "LOW": "\033[36m", "INFO": "\033[2m"}
    reset = "\033[0m" if color else ""
    buf = io.StringIO()
    buf.write(f"\nMeraki Security Audit - {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
    buf.write("=" * 72 + "\n")
    counts = summary_counts(findings)
    buf.write("  ".join(f"{k}: {v}" for k, v in counts.items()) + "\n\n")
    for f in findings:
        c = colors[f.severity] if color else ""
        where = f.org_name + (f" / {f.network_name}" if f.network_name else "")
        buf.write(f"{c}[{f.severity}]{reset} {f.check_id}  {f.title}\n")
        buf.write(f"    Scope : {where}\n")
        buf.write(f"    Detail: {f.detail}\n")
        buf.write(f"    Fix   : {f.recommendation}\n\n")
    if skipped:
        buf.write(f"{len(skipped)} check(s) skipped (not applicable, unlicensed, or no permission).")
        if verbose:
            buf.write("\n")
            for sk in skipped:
                buf.write(f"  - {sk.scope}: {sk.check}: {sk.reason}\n")
        else:
            buf.write(" Use --verbose to list them.\n")
    return buf.getvalue()


def render_markdown(findings: list[Finding], skipped: list[Skipped]) -> str:
    def esc(v: str) -> str:
        return str(v).replace("|", "\\|").replace("\n", " ")
    lines = ["# Meraki Security Audit", "",
             f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", "",
             "## Summary", "", "| Severity | Count |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in summary_counts(findings).items()]
    lines += ["", "## Findings", "",
              "| Severity | ID | Organization | Network | Finding | Detail | Recommendation |",
              "|---|---|---|---|---|---|---|"]
    lines += [f"| {f.severity} | {f.check_id} | {esc(f.org_name)} | {esc(f.network_name)} | "
              f"{esc(f.title)} | {esc(f.detail)} | {esc(f.recommendation)} |" for f in findings]
    if skipped:
        lines += ["", "## Skipped checks", "", "| Scope | Check | Reason |", "|---|---|---|"]
        lines += [f"| {esc(s.scope)} | {s.check} | {esc(s.reason)} |" for s in skipped]
    return "\n".join(lines) + "\n"


def render_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    cols = list(Finding.__dataclass_fields__)
    w = csv.DictWriter(buf, fieldnames=cols)
    w.writeheader()
    for f in findings:
        w.writerow(asdict(f))
    return buf.getvalue()


def render_json(findings: list[Finding], skipped: list[Skipped]) -> str:
    return json.dumps({
        "tool": "meraki_audit", "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(),
        "summary": summary_counts(findings),
        "findings": [asdict(f) for f in findings],
        "skipped": [asdict(s) for s in skipped],
    }, indent=2)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

TLS_HELP = """
TLS verification failed. A corporate proxy is probably re-signing HTTPS traffic with an
internal root CA that Python does not trust. Fix it with one of these:

  1. Trust the operating system's certificate store (works if the corporate CA is in the
     macOS Keychain / Windows store, which is usually the case on managed machines):
         pip install truststore
     and run the script again. It is picked up automatically.

  2. Point the script at the corporate root CA (PEM format):
         python meraki_audit.py --ca-bundle /path/to/corp-root-ca.pem
     On macOS you can export it from the Keychain, for example:
         security find-certificate -a -p -c "<Corp Root CA name>" \\
             /Library/Keychains/System.keychain > corp-root-ca.pem

Do not disable certificate verification. The API key travels in every request.
"""


def redact_proxy(url: str) -> str:
    return re.sub(r"//[^@/]+@", "//***@", url)


def configure_transport(args) -> tuple[str, str, str]:
    """Return (proxy, ca_bundle, description) and set up OS trust if available."""
    proxy = args.proxy or os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    ca_bundle = (args.ca_bundle or os.environ.get("MERAKI_CA_BUNDLE")
                 or os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE") or "")
    if ca_bundle:
        if not os.path.isfile(ca_bundle):
            sys.exit(f"error: CA bundle not found: {ca_bundle}")
        return proxy, ca_bundle, f"trusting CA bundle {ca_bundle}"
    if not args.no_system_certs:
        try:
            import truststore
            truststore.inject_into_ssl()
            return proxy, "", "using the operating system trust store (truststore)"
        except ImportError:
            pass
    return proxy, "", "using the bundled certifi CA list"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Read-only security audit of Cisco Meraki organizations.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--api-key", default=None,
                   help="Dashboard API key (default: $MERAKI_DASHBOARD_API_KEY)")
    p.add_argument("--base-url", default="https://api.meraki.com/api/v1",
                   help="API base URL (e.g. https://api.meraki.cn/api/v1 for China)")
    p.add_argument("--org-id", action="append", default=[],
                   help="Organization ID to audit (repeatable; default: all accessible)")
    p.add_argument("--network-id", action="append", default=[],
                   help="Only audit these network IDs (repeatable)")
    p.add_argument("--network-tag", action="append", default=[],
                   help="Only audit networks with this tag (repeatable)")
    p.add_argument("--format", choices=["text", "markdown", "json", "csv"], default="text")
    p.add_argument("-o", "--output", help="Write report to file instead of stdout")
    p.add_argument("--min-severity", choices=SEVERITIES, default="INFO",
                   help="Hide findings below this severity")
    p.add_argument("--fail-on", choices=SEVERITIES, default=None,
                   help="Exit with code 2 if any finding is at or above this severity")
    p.add_argument("--trusted-domain", action="append", default=[],
                   help="Admin email domain considered internal (repeatable)")
    p.add_argument("--inactive-days", type=int, default=90,
                   help="Flag admins inactive longer than this")
    p.add_argument("--max-full-admins", type=int, default=5)
    p.add_argument("--min-psk-length", type=int, default=12)
    p.add_argument("--firmware-max-age-days", type=int, default=365)
    p.add_argument("--workers", type=int, default=4,
                   help="Parallel network audits per org (API is limited to ~10 req/s/org)")
    net = p.add_argument_group("proxy / TLS")
    net.add_argument("--proxy", default=None,
                     help="HTTPS proxy URL, e.g. http://proxy.corp:8080 "
                          "(default: $HTTPS_PROXY / $https_proxy if set)")
    net.add_argument("--ca-bundle", default=None,
                     help="PEM file with the CA(s) to trust, e.g. your corporate TLS-inspection "
                          "root (default: $MERAKI_CA_BUNDLE, $REQUESTS_CA_BUNDLE or $SSL_CERT_FILE)")
    net.add_argument("--no-system-certs", action="store_true",
                     help="Do not use the OS trust store (macOS Keychain / Windows cert store) "
                          "even if the 'truststore' package is installed")
    p.add_argument("-v", "--verbose", action="store_true", help="List skipped checks")
    p.add_argument("-q", "--quiet", action="store_true", help="No progress output on stderr")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None, dashboard=None) -> int:
    args = build_parser().parse_args(argv)
    api_key = args.api_key or os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if dashboard is None and not api_key:
        print("error: set MERAKI_DASHBOARD_API_KEY or pass --api-key", file=sys.stderr)
        return 1

    if dashboard is None:
        proxy, ca_bundle, tls_note = configure_transport(args)
        if not args.quiet:
            print(f"[tls] {tls_note}" + (f"; proxy {redact_proxy(proxy)}" if proxy else ""),
                  file=sys.stderr)
        dashboard = meraki.DashboardAPI(
            api_key=api_key,
            base_url=args.base_url,
            certificate_path=ca_bundle,
            requests_proxy=proxy,
            suppress_logging=True,
            output_log=False,
            print_console=False,
            smart_flow_logging=False,
            wait_on_rate_limit=True,
            maximum_retries=8,
            caller="MerakiSecurityAudit Community",
        )

    cfg = AuditConfig(
        inactive_days=args.inactive_days,
        max_full_admins=args.max_full_admins,
        min_psk_length=args.min_psk_length,
        firmware_max_age_days=args.firmware_max_age_days,
        trusted_domains=[d.lower().lstrip("@") for d in args.trusted_domain],
    )
    out = Collector()
    progress = (lambda m: None) if args.quiet else (lambda m: print(m, file=sys.stderr, flush=True))

    try:
        orgs = dashboard.organizations.getOrganizations()
    except Exception as e:  # API, connection, TLS or proxy failures
        msg = _api_error_message(e) if isinstance(e, meraki.APIError) else f"{type(e).__name__}: {e}"
        print(f"error: cannot list organizations: {msg}", file=sys.stderr)
        text = f"{msg} {e}".lower()
        if "certificate_verify_failed" in text or "certificate verify failed" in text:
            print(TLS_HELP, file=sys.stderr)
        elif any(k in text for k in ("proxy", "407", "connection refused", "connecterror",
                                      "name or service not known", "nodename nor servname")):
            print("hint: cannot connect. Check --proxy / $HTTPS_PROXY (add credentials if the "
                  "proxy needs them: http://user:pass@proxy:8080).", file=sys.stderr)
        return 1
    if args.org_id:
        wanted = set(map(str, args.org_id))
        orgs = [o for o in orgs if str(o["id"]) in wanted]
        missing = wanted - {str(o["id"]) for o in orgs}
        if missing:
            print(f"warning: no access to org(s): {', '.join(sorted(missing))}", file=sys.stderr)
    if not orgs:
        print("error: no organizations to audit", file=sys.stderr)
        return 1

    for org in orgs:
        audit_org(dashboard, cfg, out, org, set(args.network_id), set(args.network_tag),
                  args.workers, progress)

    findings = sort_findings(f for f in out.findings
                             if SEV_RANK[f.severity] >= SEV_RANK[args.min_severity])
    if args.format == "json":
        report = render_json(findings, out.skipped)
    elif args.format == "csv":
        report = render_csv(findings)
    elif args.format == "markdown":
        report = render_markdown(findings, out.skipped)
    else:
        report = render_text(findings, out.skipped, args.verbose)

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            fh.write(report)
        progress(f"Report written to {args.output} ({len(findings)} findings)")
    else:
        sys.stdout.write(report)

    if args.fail_on and any(SEV_RANK[f.severity] >= SEV_RANK[args.fail_on] for f in findings):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
