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
import ipaddress
import json
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

try:
    import meraki
except ImportError:  # pragma: no cover
    sys.exit("The Meraki SDK is required: pip install meraki")

__version__ = "1.0.0"
__license__ = "MIT"

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
    item: str = ""  # the part of `detail` specific to this resource
    # The general explanation (detail minus item). Used to print it once per group;
    # not exported because `detail` already contains it.
    why: str = field(default="", repr=False, metadata={"export": False})


def finding_dict(f: Finding) -> dict:
    return {k: v for k, v in asdict(f).items()
            if Finding.__dataclass_fields__[k].metadata.get("export", True)}


EXPORT_FIELDS = [k for k, v in Finding.__dataclass_fields__.items() if v.metadata.get("export", True)]


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
    min_password_length: int = 12
    password_history_min: int = 4
    firmware_max_age_days: int = 365
    log_days: int = 30
    trusted_domains: list[str] = field(default_factory=list)
    trusted_webhook_domains: list[str] = field(default_factory=list)


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
            detail: str, recommendation: str, resource: str = "", item: str = "") -> None:
        """`item` is what is specific to this resource (names, counts, ports); `detail`
        is then the general explanation. The exported detail is both joined."""
        full = f"{item} {detail}".strip() if item else detail
        self.out.add(Finding(
            severity=severity, check_id=check_id, category=category,
            title=title, detail=full, recommendation=recommendation,
            org_id=str(self.org.get("id", "")), org_name=self.org.get("name", ""),
            network_id=self.net.get("id", ""), network_name=self.net.get("name", ""),
            resource=resource, item=item, why=detail if item else "",
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


def parse_vlans(spec: Any) -> set[int] | None:
    """Return the VLAN IDs in a Meraki allowed-VLAN list, or None for 'all'."""
    s = lower(spec)
    if s in ("", "all", "1-4094", "1-4095"):
        return None
    vlans: set[int] = set()
    for part in s.split(","):
        a, _, b = part.strip().partition("-")
        if a.strip().isdigit() and (not b or b.strip().isdigit()):
            vlans.update(range(int(a), int(b or a) + 1))
    return vlans


def compact_vlans(vlans: Iterable[int]) -> str:
    """{10, 11, 12, 40} -> '10-12,40'."""
    out: list[str] = []
    for v in sorted(set(vlans)):
        if out and "-" not in out[-1] and int(out[-1]) == v - 1:
            out[-1] = f"{v - 1}-{v}"
        elif out and "-" in out[-1] and int(out[-1].split("-")[1]) == v - 1:
            out[-1] = f"{out[-1].split('-')[0]}-{v}"
        else:
            out.append(str(v))
    return ",".join(out)


# --- firewall rule coverage (used to find rules hidden by an earlier rule) -- #

class _Unparseable(Exception):
    pass


def _port_set(spec: Any) -> set[int] | None:
    """Exact port set for a rule field; None means any. Raises on unknown syntax."""
    s = lower(spec)
    if s in ("", "any", "all"):
        return None
    ports: set[int] = set()
    for part in s.split(","):
        a, _, b = part.strip().partition("-")
        if not (a.strip().isdigit() and (not b or b.strip().isdigit())):
            raise _Unparseable(spec)
        lo, hi = int(a), int(b or a)
        if lo <= 1 and hi >= 65535:
            return None
        ports.update(range(lo, hi + 1))
    return ports


def _addr_items(spec: Any) -> list | None:
    """CIDR list as ip_network objects (or literal strings such as VLAN(10).*,
    FQDNs); None means any."""
    if is_any(spec):
        return None
    items = []
    for part in str(spec).split(","):
        part = part.strip()
        try:
            items.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            items.append(part.lower())
    return items


def _addr_covers(earlier: list | None, later: list | None) -> bool:
    if earlier is None:
        return True
    if later is None:
        return False

    def item_covered(b) -> bool:
        for a in earlier:
            if isinstance(a, str) or isinstance(b, str):
                if a == b:
                    return True
            elif a.version == b.version and b.subnet_of(a):
                return True
        return False

    return all(item_covered(b) for b in later)


def rule_covers(earlier: dict, later: dict) -> bool:
    """True when every packet matched by `later` is matched by `earlier` first.

    Structural, not semantic: VLAN(x).* and the CIDR it maps to are treated as
    unrelated, so this can miss shadowing (false negative) but should not
    invent it."""
    ep, lp = lower(earlier.get("protocol")) or "any", lower(later.get("protocol")) or "any"
    if ep != "any" and ep != lp:
        return False
    if not (_addr_covers(_addr_items(earlier.get("srcCidr")), _addr_items(later.get("srcCidr")))
            and _addr_covers(_addr_items(earlier.get("destCidr")), _addr_items(later.get("destCidr")))):
        return False
    if ep in ("icmp", "icmp6"):
        return True
    try:
        for fld in ("srcPort", "destPort"):
            e, l = _port_set(earlier.get(fld)), _port_set(later.get(fld))
            if e is not None and (l is None or not l <= e):
                return False
    except _Unparseable:
        return False
    return True


def is_any_any_allow(r: dict) -> bool:
    return (lower(r.get("policy")) == "allow" and lower(r.get("protocol")) in ("any", "")
            and is_any(r.get("srcCidr")) and is_any(r.get("destCidr"))
            and _safe_port_set(r.get("destPort")) is None)


def _safe_port_set(spec: Any) -> set[int] | None | bool:
    try:
        return _port_set(spec)
    except _Unparseable:
        return False


def shadowed_rules(rules: list[dict]) -> list[tuple[int, int]]:
    """(later_index, earlier_index) pairs, 1-based, for rules that can never
    match because an earlier rule covers all of their traffic. An earlier
    any/any allow is skipped: that is already its own finding."""
    out = []
    for j, later in enumerate(rules):
        for i in range(j):
            earlier = rules[i]
            if is_any_any_allow(earlier):
                continue
            if rule_covers(earlier, later):
                out.append((j + 1, i + 1))
                break
    return out


def rule_label(idx: int, r: dict) -> str:
    return f"#{idx} {lower(r.get('policy')) or '?'} '{r.get('comment') or '(no comment)'}'"


def report_shadowed(s: Scope, rules: list[dict], check_id: str, category: str,
                    what: str) -> None:
    for j, i in shadowed_rules(rules):
        later, earlier = rules[j - 1], rules[i - 1]
        conflict = lower(later.get("policy")) != lower(earlier.get("policy"))
        if conflict:
            s.add("MEDIUM", check_id, category, f"{what} rule never matches (conflicting earlier rule)",
                  f"Rule {rule_label(j, later)} is fully covered by rule {rule_label(i, earlier)}. "
                  "Rules are evaluated top-down and the first match wins, so the later rule's "
                  f"{lower(later.get('policy'))} never takes effect.",
                  "Move the more specific rule above the broader one, or remove it if it is "
                  "obsolete.", resource=f"rule {j}")
        else:
            s.add("INFO", check_id, category, f"Redundant {what.lower()} rule",
                  f"Rule {rule_label(j, later)} is fully covered by rule {rule_label(i, earlier)} "
                  "with the same action, so it never matches.",
                  "Remove the redundant rule to keep the rule set reviewable.", resource=f"rule {j}")


def is_uplink_port(p: dict) -> bool:
    tags = {lower(t) for t in p.get("tags") or []}
    return "uplink" in tags or "uplink" in lower(p.get("name"))


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
    # enforceStrongPasswords is deprecated (false is ignored); the policy is minimumPasswordLength.
    min_len = ls.get("minimumPasswordLength")
    if min_len is None:
        s.out.skip(Skipped(s.label, "password-length", "minimumPasswordLength not returned by the API"))
    elif min_len < s.cfg.min_password_length:
        mfa = ls.get("enforceTwoFactorAuth")
        s.add("MEDIUM" if mfa else "HIGH", "ORG-LS-02", cat, "Minimum password length too short",
              f"Admin passwords need only {min_len} characters (threshold "
              f"{s.cfg.min_password_length}){'' if mfa else ', and 2FA is not enforced'}.",
              f"Organization > Settings > Security: set the minimum password length to "
              f">= {s.cfg.min_password_length} (NIST SP 800-63B: 15 when the password is the only "
              "factor).")
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
              f"Enable 'Force users to choose a password different from the last N passwords' "
              f"with N >= {s.cfg.password_history_min}.")
    elif (ls.get("numDifferentPasswords") or 0) < s.cfg.password_history_min:
        s.add("LOW", "ORG-LS-10", cat, "Short password history",
              f"New passwords only have to differ from the last "
              f"{ls.get('numDifferentPasswords') or 0} password(s).",
              f"Raise the password history to >= {s.cfg.password_history_min}.")
    if ls.get("enforcePasswordExpiration"):
        s.add("INFO", "ORG-LS-11", cat, "Periodic password expiration enforced",
              f"Admins must change their password every {ls.get('passwordExpirationDays')} days. "
              "NIST SP 800-63B advises against forced periodic changes: they push users toward "
              "predictable passwords.",
              "Prefer long passwords + 2FA and force a change only on suspected compromise, "
              "unless a policy you must follow requires expiry.")
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


def check_admins(s: Scope, login_sec: dict | None, saml_enabled: bool) -> list[dict] | None:
    admins = s.call("admins", s.d.organizations.getOrganizationAdmins, s.org["id"])
    if admins is None:
        return None
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
                  f"Admin has no 2FA enrolled{note}.",
                  "Require 2FA for every admin account.", resource=a.get("email", ""),
                  item=f"{who} (orgAccess={access}).")

        last = parse_time(a.get("lastActive"))
        age = days_since(last)
        if age is not None and age > s.cfg.inactive_days:
            s.add("MEDIUM", "ORG-ADM-04", cat, "Inactive admin account",
                  f"Not active for more than {s.cfg.inactive_days} days.",
                  "Remove or disable admin accounts that are no longer used.",
                  resource=a.get("email", ""), item=f"{who} last active {age} days ago.")

        status = lower(a.get("accountStatus"))
        if status and status != "ok":
            s.add("LOW", "ORG-ADM-05", cat, f"Admin account status '{status}'",
                  f"Account status is '{status}'.",
                  "Clean up locked, unverified or pending admin invitations.",
                  resource=a.get("email", ""), item=f"{who}.")

        if a.get("hasApiKey") and access == "full":
            s.add("INFO", "ORG-ADM-06", cat, "Full admin has an API key",
                  "Has an API key with full org privileges.",
                  "Use dedicated read-only service accounts for automation; rotate keys regularly.",
                  resource=a.get("email", ""), item=f"{who}.")

        if s.cfg.trusted_domains:
            domain = lower(a.get("email")).rsplit("@", 1)[-1]
            if domain not in s.cfg.trusted_domains:
                sev = "MEDIUM" if access in ("full", "enterprise") else "LOW"
                s.add(sev, "ORG-ADM-07", cat, "Admin from untrusted email domain",
                      "Email domain is outside the trusted domains.",
                      "Verify third-party/partner access is still required and properly scoped.",
                      resource=a.get("email", ""), item=f"{who} (orgAccess={access}).")

    if saml_enabled and len(full_admins) > 2:
        s.add("INFO", "ORG-ADM-08", cat, "Local admins exist alongside SAML",
              f"{len(admins)} local Dashboard admins exist although SAML SSO is enabled.",
              "Keep only break-glass local accounts and manage the rest through the IdP.")
    return admins


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
                  "Uses IKEv1.", "Migrate to IKEv2.", resource=name)
        if preset == "default":
            s.add("HIGH", "ORG-VPN-02", cat, "Third-party VPN peer uses default IPsec policy",
                  "Uses the 'Default' preset (3DES/SHA1/DH group 2, no PFS).",
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
                  "Weak algorithms are allowed.",
                  "Remove DES/3DES/MD5/SHA1 and DH groups 1/2/5; enable PFS.", resource=name,
                  item=f"{', '.join(weak)}.")
        secret = p.get("secret")
        if isinstance(secret, str) and secret and len(secret) < 20:
            s.add("MEDIUM", "ORG-VPN-04", cat, "Third-party VPN pre-shared key is short",
                  "A short PSK can be brute-forced offline from a captured IKE exchange.",
                  "Use a random PSK of at least 20-32 characters, or certificates.", resource=name,
                  item=f"PSK is {len(secret)} characters.")
        if not p.get("networkTags") or "all" in [lower(t) for t in p.get("networkTags", [])]:
            s.add("INFO", "ORG-VPN-05", cat, "Third-party VPN peer available to all networks",
                  "Reachable from all MX networks.",
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
            s.add("HIGH", "ORG-VPN-07", "VPN", "Any/any allow rule in VPN firewall",
                  f"Rule '{r.get('comment') or '(no comment)'}' allows all traffic.",
                  "Replace with specific allow rules.")
    report_shadowed(s, rules, "ORG-VPN-08", "VPN", "VPN firewall")


# Organization-wide group policies (Security > Group Policy, MX 26.1.2+): firewall
# rulesets defined once and enforced on MX VLANs, SGTs or network VPN-inbound targets.
# Network L3 firewall rules do not apply to a VLAN that is an enforcement target.

_OGP_MAPPABLE = {"src": {"addressRanges", "ports"},
                 "dst": {"addressRanges", "ports", "services"}}
_VLAN_IFACE = re.compile(r"^(?P<net>.+)_vlan_(?P<vlan>\d+)$")


def _items(resp: Any) -> list[dict]:
    if isinstance(resp, dict):
        return resp.get("items") or []
    return resp or []


def ogp_as_l3(rule: dict) -> dict | None:
    """Express an org-wide rule as a network L3 rule (srcCidr/destCidr/ports/protocol)
    so rule_covers() can compare it. None when it uses criteria an L3 rule has no
    field for (VLANs, objects, apps, FQDNs, countries, SGTs, several services)."""
    out = {"policy": lower(rule.get("policy")), "comment": rule.get("name"), "protocol": "any"}
    for side, cidr, port in (("src", "srcCidr", "srcPort"), ("dst", "destCidr", "destPort")):
        blk = rule.get("sources" if side == "src" else "destinations") or {}
        mc = set(blk.get("matchCriteria") or []) - {"any"}
        crit = blk.get("criteria") or {}
        if mc - _OGP_MAPPABLE[side]:
            return None
        out[cidr] = ",".join(crit.get("addressRanges") or []) if "addressRanges" in mc else "Any"
        out[port] = ",".join(crit.get("ports") or []) if "ports" in mc else "Any"
        if "services" in mc:
            svcs = crit.get("services") or []
            if len(svcs) != 1 or "ports" in mc:
                return None
            out["protocol"] = lower(svcs[0].get("protocol")) or "any"
            out[port] = ",".join(svcs[0].get("ports") or []) or "Any"
        if not out[cidr]:
            return None
    return out


def check_org_group_policies(s: Scope) -> dict[str, dict[int, str]]:
    """Returns {network id: {VLAN id: policy name}} for VLANs enforced by an org-wide policy."""
    org_id, cat = s.org["id"], "Firewall"
    o = s.d.organizations
    policies = s.call("org-group-policies", o.getOrganizationPoliciesGlobalGroupPolicies,
                      org_id, total_pages="all")
    if policies is None:
        return {}
    policies = _items(policies)
    if not policies:
        return {}
    rulesets = _items(s.call("org-fw-rulesets", o.getOrganizationPoliciesGlobalFirewallRulesets,
                             org_id, total_pages="all"))
    rules_resp = s.call("org-fw-rules", o.getOrganizationPoliciesGlobalFirewallRulesetsRules,
                        org_id, total_pages="all")
    attach_resp = s.call("org-group-policy-rulesets",
                         o.getOrganizationPoliciesGlobalGroupPoliciesFirewallRulesetsAssignments,
                         org_id, total_pages="all")
    if rules_resp is None or attach_resp is None:
        return {}  # skipped already recorded; rule checks would be guesses without these
    vlan_resp = s.call("org-group-policy-vlans",
                       s.d.appliance.getOrganizationPoliciesGlobalGroupPoliciesApplianceVlansAssignments,
                       org_id, total_pages="all")
    sgt_resp = s.call("org-group-policy-sgts",
                      o.getOrganizationPoliciesGlobalGroupPoliciesAdaptivePolicyGroupsAssignments,
                      org_id, total_pages="all")
    net_resp = s.call("org-group-policy-networks",
                      o.getOrganizationPoliciesGlobalGroupPoliciesNetworksAssignments,
                      org_id, total_pages="all")
    targets_known = None not in (vlan_resp, sgt_resp, net_resp)

    pol_name = {p.get("policyId"): p.get("name") or p.get("policyId") for p in policies}
    rs_name = {r.get("rulesetId"): r.get("name") or r.get("rulesetId") for r in rulesets}
    by_ruleset: dict[str, list[dict]] = {}
    for r in _items(rules_resp):
        by_ruleset.setdefault(r.get("rulesetId"), []).append(r)
        rs_name.setdefault(r.get("rulesetId"), r.get("rulesetId"))
    attached: dict[str, list[str]] = {}  # ruleset id -> policy ids
    pol_rulesets: dict[str, list[str]] = {}
    for a in _items(attach_resp):
        attached.setdefault(a.get("rulesetId"), []).append(a.get("policyId"))
        pol_rulesets.setdefault(a.get("policyId"), []).append(a.get("rulesetId"))

    targets: dict[str, list[str]] = {}
    vlans: dict[str, dict[int, str]] = {}
    for a in _items(vlan_resp):
        m = _VLAN_IFACE.match(str(a.get("interfaceId", "")))
        targets.setdefault(a.get("policyId"), []).append(
            f"VLAN {m['vlan']} ({m['net']})" if m else str(a.get("interfaceId")))
        if m:
            vlans.setdefault(m["net"], {})[int(m["vlan"])] = pol_name.get(a.get("policyId"), "?")
    for a in _items(sgt_resp):
        targets.setdefault(a.get("policyId"), []).append(f"SGT {a.get('adaptivePolicyGroupId')}")
    for a in _items(net_resp):
        pid = (a.get("policy") or {}).get("id")
        net = a.get("network") or {}
        targets.setdefault(pid, []).append(
            f"{(a.get('firewall') or {}).get('type', 'network')} on {net.get('name') or net.get('id')}")

    def where(rs_id: str) -> str:
        return ", ".join(sorted(f"'{pol_name.get(p, p)}'" for p in attached.get(rs_id, [])))

    for pid, name in pol_name.items():
        tg = targets.get(pid, [])
        if targets_known and not tg:
            s.add("INFO", "ORG-OGP-04", cat, "Org-wide group policy has no enforcement targets",
                  "The policy is not applied to any VLAN, SGT or network, so its rules have no effect.",
                  "Assign enforcement targets or delete the policy.", resource=f"policy {name}",
                  item=f"Policy '{name}':")
        if tg and not pol_rulesets.get(pid):
            s.add("LOW", "ORG-OGP-03", cat, "Org-wide group policy has targets but no rulesets",
                  "Network firewall rules no longer apply to these targets, and Meraki does not "
                  "document what an MX enforces for a policy without rulesets.",
                  "Attach a ruleset (ending in an explicit deny where possible), or verify the "
                  "behaviour with Security & SD-WAN > Appliance status > Tools > Firewall logging.",
                  resource=f"policy {name}",
                  item=f"Policy '{name}' is enforced on {_short(sorted(tg))}.")

    for rs_id, rname in rs_name.items():
        res = f"ruleset {rname}"
        if not attached.get(rs_id):
            s.add("INFO", "ORG-OGP-05", cat, "Org-wide firewall ruleset not used by any policy",
                  "The ruleset is not attached to a policy, so it is not enforced.",
                  "Attach it to a policy or delete it.", resource=res, item=f"Ruleset '{rname}':")
            continue
        rules = sorted(by_ruleset.get(rs_id, []), key=lambda r: r.get("priority") or 0)
        if not rules:
            s.add("HIGH", "ORG-OGP-02", cat, "Empty org-wide ruleset attached to a policy",
                  "An empty ruleset attached to a policy is enforced as an allow-any-to-any rule "
                  "(Meraki Org-wide Group Policy troubleshooting guide).",
                  "Add rules to the ruleset or detach it.", resource=res,
                  item=f"Ruleset '{rname}' (policy {where(rs_id)}):")
            continue
        disabled = [r.get("name") or r.get("ruleId") for r in rules if r.get("enabled") is False]
        if disabled:
            s.add("INFO", "ORG-OGP-07", cat, "Disabled org-wide firewall rules",
                  "Disabled rules are not enforced and make the ruleset harder to review.",
                  "Remove rules that are no longer needed.", resource=res,
                  item=f"Ruleset '{rname}': {_short(disabled)}.")
        active = [r for r in rules if r.get("enabled") is not False]
        no_log = [r.get("name") or r.get("ruleId") for r in active
                  if lower(r.get("policy")) == "deny" and not (r.get("logging") or {}).get("enabled")]
        if no_log:
            s.add("LOW", "ORG-OGP-06", cat, "Org-wide deny rules do not log",
                  "Blocked traffic matching these rules leaves no syslog record.",
                  "Enable logging on deny rules.", resource=res,
                  item=f"Ruleset '{rname}': {_short(no_log)}.")
        l3 = [ogp_as_l3(r) for r in active]
        for idx, (r, m) in enumerate(zip(active, l3), 1):
            if m and is_any_any_allow(m):
                s.add("HIGH", "ORG-OGP-01", cat, "Any/any allow rule in org-wide ruleset",
                      "It allows all traffic from every enforcement target of the policy, and the "
                      "network firewall rules no longer apply to those targets.",
                      "Remove or narrow the rule.", resource=f"{res} rule {idx}",
                      item=f"Rule '{r.get('name') or '(no name)'}' in ruleset '{rname}' "
                           f"(policy {where(rs_id)}):")
        for j, later in enumerate(l3):
            if later is None:
                continue
            for i in range(j):
                earlier = l3[i]
                if earlier is None or is_any_any_allow(earlier) or not rule_covers(earlier, later):
                    continue
                conflict = earlier["policy"] != later["policy"]
                s.add("MEDIUM" if conflict else "INFO", "ORG-OGP-08", cat,
                      "Org-wide rule never matches" + (" (conflicting earlier rule)" if conflict else ""),
                      f"Rule {rule_label(j + 1, later)} in ruleset '{rname}' is fully covered by rule "
                      f"{rule_label(i + 1, earlier)}, so its {later['policy']} never takes effect.",
                      "Move the more specific rule above the broader one, or remove it.",
                      resource=f"{res} rule {j + 1}")
                break
    return vlans


def _who(a: dict) -> str:
    return f"{a.get('name') or ''} <{a.get('email')}>".strip()


def _untrusted(s: Scope, email: Any) -> bool:
    if not s.cfg.trusted_domains or not email:
        return False
    return lower(email).rsplit("@", 1)[-1] not in s.cfg.trusted_domains


def _short(items: Iterable[Any], n: int = 5) -> str:
    items = sorted({str(i) for i in items if i})
    return ", ".join(items[:n]) + (f" (+{len(items) - n} more)" if len(items) > n else "")


def check_api_usage(s: Scope, admins: list[dict] | None) -> None:
    """Who actually uses the Dashboard API, from the org's API request log."""
    cat = "Identity & Access"
    days = max(1, min(s.cfg.log_days, 31))  # API request log keeps 31 days
    span = days * 86400
    org_id = s.org["id"]
    get = s.d.organizations.getOrganizationApiRequests
    by_id = {str(a.get("id")): a for a in admins or []}

    # 1) API keys with no requests in the window -> candidates for revocation.
    for a in admins or []:
        if not a.get("hasApiKey") or not a.get("id"):
            continue
        reqs = s.call("api-requests", get, org_id, adminId=a["id"], timespan=span,
                      perPage=3, total_pages=1)
        if reqs is not None and not reqs:
            full = lower(a.get("orgAccess")) == "full"
            s.add("MEDIUM" if full else "LOW", "ORG-API-01", cat, "API key not used recently",
                  f"Has an API key but made no API requests to this org in the last {days} days.",
                  "Revoke unused API keys (My profile > API access). An idle key with org access "
                  "is only useful to whoever steals it.", resource=a.get("email", ""),
                  item=f"{_who(a)} (orgAccess={lower(a.get('orgAccess'))}).")

    # 2) Write requests: who changes config through the API, and from where.
    writes: dict[str, list[dict]] = {}
    for method in ("POST", "PUT", "DELETE"):
        reqs = s.call("api-requests", get, org_id, method=method, timespan=span,
                      perPage=1000, total_pages=5)
        for r in reqs or []:
            writes.setdefault(str(r.get("adminId")), []).append(r)
    for admin_id, reqs in sorted(writes.items(), key=lambda kv: -len(kv[1])):
        a = by_id.get(admin_id)
        who = _who(a) if a else f"admin id {admin_id} (not a current org admin)"
        methods = {}
        for r in reqs:
            methods[r.get("method")] = methods.get(r.get("method"), 0) + 1
        sev = "LOW" if (a is None or _untrusted(s, (a or {}).get("email"))) else "INFO"
        s.add(sev, "ORG-API-02", cat, "Configuration changed via the API",
              f"{who} made {len(reqs)} write request(s) in the last {days} days "
              f"({', '.join(f'{m} {n}' for m, n in sorted(methods.items()))}). "
              f"Source IPs: {_short(r.get('sourceIp') for r in reqs)}. "
              f"User agents: {_short((r.get('userAgent') for r in reqs), 3)}.",
              "Confirm each integration is known and owned. Use a dedicated service account per "
              "integration and restrict API keys to known source IPs.",
              resource=(a or {}).get("email", admin_id))

    # 3) Deprecated API v0.
    v0 = s.call("api-requests", get, org_id, version=0, timespan=span, perPage=100, total_pages=1)
    if v0:
        who = _short(_who(by_id[str(r.get("adminId"))]) if str(r.get("adminId")) in by_id
                     else f"admin id {r.get('adminId')}" for r in v0)
        s.add("LOW", "ORG-API-03", cat, "Deprecated Dashboard API v0 still in use",
              f"API v0 requests in the last {days} days from: {who}. "
              f"User agents: {_short((r.get('userAgent') for r in v0), 3)}.",
              "Migrate these integrations to API v1. v0 is end-of-life and gets no fixes.")


# Change-log pages/labels that touch security controls. Matched on "page label".
SECURITY_CHANGE_AREAS: list[tuple[str, re.Pattern]] = [
    ("Identity & access", re.compile(
        r"\badmin|two.?factor|\b2fa\b|login|password|saml|\bidp\b|\bsso\b|\bapi\b|lockout|"
        r"idle timeout", re.I)),
    ("Firewall & threat protection", re.compile(
        r"firewall|port forward|1:1|1:many|\bnat\b|inbound|content filter|intrusion|malware|"
        r"\bamp\b|threat|spoof", re.I)),
    ("VPN", re.compile(r"\bvpn\b|anyconnect|ipsec", re.I)),
    ("Logging & monitoring", re.compile(r"syslog|snmp|alert|webhook", re.I)),
    ("Wireless & port authentication", re.compile(
        r"\bpsk\b|encryption|authentication|radius|splash|802\.1x|access polic", re.I)),
]
DISABLED_VALUES = {"false", "disabled", "off", "none", "0", "\"false\"", "\"disabled\""}


def check_config_changes(s: Scope, admins: list[dict] | None, saml_enabled: bool,
                         network_names: dict[str, str] | None) -> list[dict] | None:
    """Review the org change log. Old/new values are never reported: they can
    contain PSKs and other secrets. Returns the in-scope changes."""
    days = max(1, min(s.cfg.log_days, 365))
    changes = s.call("config-changes", s.d.organizations.getOrganizationConfigurationChanges,
                     s.org["id"], timespan=days * 86400, perPage=5000, total_pages=4)
    if changes is None:
        return None
    if not changes:
        return []
    if network_names is not None:  # --network-id/--network-tag: keep org-wide + in-scope
        changes = [c for c in changes if not c.get("networkId") or c["networkId"] in network_names]
    cat = "Change Log"
    admin_ids = {str(a.get("id")) for a in admins or []}

    def area(c: dict) -> str | None:
        text = f"{c.get('page') or ''} {c.get('label') or ''}"
        return next((name for name, rx in SECURITY_CHANGE_AREAS if rx.search(text)), None)

    def line(c: dict) -> str:
        where = f" [{c['networkName']}]" if c.get("networkName") else ""
        return (f"{str(c.get('ts') or '')[:10]} {c.get('adminEmail') or c.get('adminName') or '?'}: "
                f"{c.get('page') or ''} / {c.get('label') or ''}{where}")

    def examples(cs: list[dict], n: int = 5) -> str:
        cs = sorted(cs, key=lambda c: str(c.get("ts") or ""), reverse=True)
        return "; ".join(line(c) for c in cs[:n]) + (f"; ... (+{len(cs) - n} more)" if len(cs) > n else "")

    # Security controls switched off.
    off = [c for c in changes if area(c) and lower(c.get("newValue")) in DISABLED_VALUES
           and lower(c.get("oldValue")) not in DISABLED_VALUES]
    if off:
        s.add("MEDIUM", "ORG-CHG-01", cat, "Security settings turned off recently",
              f"{len(off)} change(s) in the last {days} days set a security-related setting to "
              f"off/disabled: {examples(off)}.",
              "Confirm each change was approved and is still needed; revert otherwise.")

    # Changes by people who are no longer (or never were) org admins.
    if admins is not None:
        unknown: dict[str, list[dict]] = {}
        for c in changes:
            if c.get("adminId") and str(c["adminId"]) not in admin_ids:
                unknown.setdefault(c.get("adminEmail") or c.get("adminName") or str(c["adminId"]), []).append(c)
        for who, cs in sorted(unknown.items()):
            note = (" SAML-authenticated admins are not listed as org admins, so this may be a "
                    "SAML user." if saml_enabled else "")
            s.add("INFO" if saml_enabled else "LOW", "ORG-CHG-02", cat,
                  "Changes by an account that is not a current org admin",
                  f"{who} made {len(cs)} change(s) in the last {days} days but is not in the org "
                  f"admin list (removed, network-scoped, or external).{note} Recent: {examples(cs, 3)}.",
                  "Confirm who this is. If the account was removed, review what it changed before "
                  "removal.", resource=who)

    # Changes by admins outside the trusted domains.
    outside: dict[str, list[dict]] = {}
    for c in changes:
        if _untrusted(s, c.get("adminEmail")):
            outside.setdefault(c["adminEmail"], []).append(c)
    for who, cs in sorted(outside.items()):
        sec = [c for c in cs if area(c)]
        s.add("MEDIUM" if sec else "LOW", "ORG-CHG-03", cat,
              "Changes by an admin outside trusted domains",
              f"{who} made {len(cs)} change(s) in the last {days} days, {len(sec)} to security "
              f"settings. Recent: {examples(sec or cs, 3)}.",
              "Verify the third party's changes were requested and reviewed.", resource=who)

    # Summary of security-relevant changes, so a reviewer can scan them.
    by_area: dict[str, list[dict]] = {}
    for c in changes:
        a = area(c)
        if a:
            by_area.setdefault(a, []).append(c)
    for a, cs in sorted(by_area.items()):
        s.add("INFO", "ORG-CHG-04", cat, f"Recent changes: {a}",
              f"{len(cs)} change(s) in the last {days} days by "
              f"{len({c.get('adminEmail') or c.get('adminName') for c in cs})} admin(s). "
              f"Most recent: {examples(cs)}.",
              "Review against approved change requests.", resource=a)
    return changes


SUPPORT_SETTING_RX = re.compile(r"meraki support|support access", re.I)
SUPPORT_ADMIN_RX = re.compile(r"meraki support|@meraki\.com$", re.I)
TRUE_VALUES = {"true", "enabled", "on", "1", "yes", "checked", "blocked"}
FALSE_VALUES = {"false", "disabled", "off", "0", "no", "unchecked", "unblocked", "allowed"}


def _support_blocked(c: dict) -> bool | None:
    """Whether a change to the support-access setting left support blocked.
    None if the value is not recognised."""
    v = lower(c.get("newValue")).strip('"')
    on = True if v in TRUE_VALUES else False if v in FALSE_VALUES else None
    if on is None:
        return None
    label = lower(f"{c.get('page') or ''} {c.get('label') or ''}")
    return on if "block" in label else not on


def check_support_access(s: Scope, changes: list[dict] | None) -> None:
    """Meraki Support access (Organization > Settings > 'Block Meraki Support').
    The Dashboard API does not expose this setting, so it is inferred from the
    change log; old/new values are used for the decision but never reported."""
    cat = "Identity & Access"
    days = max(1, min(s.cfg.log_days, 365))
    manual = ("not exposed by the Dashboard API; verify Organization > Settings > "
              "'Meraki Support Access' manually")
    if changes is None:
        s.out.skip(Skipped(s.label, "support-access", f"{manual} (change log unavailable)"))
        return

    toggles = sorted((c for c in changes if not c.get("networkId")
                      and SUPPORT_SETTING_RX.search(f"{c.get('page') or ''} {c.get('label') or ''}")),
                     key=lambda c: str(c.get("ts") or ""))
    latest = toggles[-1] if toggles else None
    blocked = _support_blocked(latest) if latest else None
    if latest and blocked is False:
        who = latest.get("adminEmail") or latest.get("adminName") or "?"
        s.add("MEDIUM", "ORG-SUP-01", cat, "Meraki Support access unblocked",
              f"{who} allowed Meraki Support to access the organization on "
              f"{str(latest.get('ts') or '')[:10]} (last change to this setting in the "
              f"last {days} days).",
              "Organization > Settings > Meraki Support Access: tick 'Block Meraki Support' "
              "again once the support case is closed.", resource=who)
    elif blocked is None:
        seen = " (a change was logged but its value was not recognised)" if latest else ""
        s.out.skip(Skipped(s.label, "support-access", f"{manual}{seen}"))

    by_support: dict[str, list[dict]] = {}
    for c in changes:
        who = c.get("adminEmail") or c.get("adminName") or ""
        if (SUPPORT_ADMIN_RX.search(lower(c.get("adminEmail")))
                or SUPPORT_ADMIN_RX.search(lower(c.get("adminName")))):
            by_support.setdefault(who, []).append(c)
    for who, cs in sorted(by_support.items()):
        cs = sorted(cs, key=lambda c: str(c.get("ts") or ""), reverse=True)
        recent = "; ".join(f"{str(c.get('ts') or '')[:10]} {c.get('page') or ''} / "
                           f"{c.get('label') or ''}" for c in cs[:3])
        s.add("LOW", "ORG-SUP-02", cat, "Configuration changed by Meraki Support",
              f"{who} made {len(cs)} change(s) in the last {days} days. Recent: {recent}.",
              "Match each change to an open support case you requested.", resource=who)


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
        trunks: list[dict] = []
        in_use: dict[int, list[str]] = {}
        for p in ports:
            if not p.get("enabled", True):
                continue
            pid = str(p.get("portId"))
            ptype = lower(p.get("type"))
            if ptype == "trunk":
                trunks.append(p)
                if lower(p.get("allowedVlans")) in ("all", "1-4094"):
                    trunk_all.append(pid)
                if str(p.get("vlan")) == "1":
                    native1.append(pid)
            elif ptype == "access":
                if str(p.get("vlan")) == "1":
                    access_vlan1.append(pid)
                for key in ("vlan", "voiceVlan"):
                    if str(p.get(key) or "").isdigit():
                        in_use.setdefault(int(p[key]), []).append(pid)
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
                        "Trunks carry every VLAN, so a mis-patched or compromised neighbour reaches all of them.",
                        "Prune allowed VLANs on trunks to only what is required.", resource=name,
                        item=f"{len(trunk_all)} trunk port(s): {short(trunk_all)}.")
        if native1:
            f_scope.add("LOW", "SW-PORT-02", cat, "Trunk ports use native VLAN 1",
                        "Native VLAN 1 on trunks enables double-tagging VLAN hopping.",
                        "Use an unused, dedicated native VLAN to mitigate VLAN hopping.", resource=name,
                        item=f"{len(native1)} trunk port(s): {short(native1)}.")
        if access_vlan1:
            f_scope.add("LOW", "SW-PORT-03", cat, "Access ports in VLAN 1",
                        "Enabled access ports are in the default VLAN 1.",
                        "Move access ports to purpose-specific VLANs; disable unused ports.", resource=name,
                        item=f"{len(access_vlan1)} access port(s): {short(access_vlan1)}.")
        if no_bpdu:
            f_scope.add("LOW", "SW-PORT-04", cat, "Access ports without BPDU guard",
                        "A switch plugged into these ports can join or disrupt spanning tree.",
                        "Enable BPDU guard on edge/access ports.", resource=name,
                        item=f"{len(no_bpdu)} access port(s): {short(no_bpdu)}.")
        check_uplink_vlans(f_scope, name, trunks, in_use)


def check_uplink_vlans(s: Scope, switch: str, trunks: list[dict],
                       in_use: dict[int, list[str]]) -> None:
    """Uplink trunk must carry every VLAN that access ports on the switch use.

    The uplink is a trunk tagged 'uplink' or named '*uplink*'; failing that,
    the switch's only trunk. Anything else is recorded as skipped, not guessed.
    """
    uplinks = [p for p in trunks if is_uplink_port(p)] or (trunks if len(trunks) == 1 else [])
    if not uplinks:
        if len(trunks) > 1 and in_use:
            s.out.skip(Skipped(s.label, "switch-uplink-vlans",
                               f"{switch}: {len(trunks)} trunk ports and none tagged/named "
                               "'uplink'; tag the uplink port to enable this check"))
        return
    for up in uplinks:
        allowed = parse_vlans(up.get("allowedVlans"))
        if allowed is None:
            continue
        if str(up.get("vlan") or "").isdigit():
            allowed = allowed | {int(up["vlan"])}  # native VLAN is carried untagged
        missing = {v: pids for v, pids in in_use.items() if v not in allowed}
        if not missing:
            continue
        pid = str(up.get("portId"))
        used = "; ".join(f"VLAN {v}: port(s) {', '.join(sorted(pids, key=lambda x: (len(x), x))[:8])}"
                         + (" ..." if len(pids) > 8 else "")
                         for v, pids in sorted(missing.items()))
        s.add("HIGH", "SW-TRUNK-01", "Switching",
              "Uplink trunk does not carry VLANs used on this switch",
              "Devices on those ports get link and PoE but cannot reach anything beyond "
              "this switch.",
              "Add the missing VLANs to the uplink's allowed VLANs and to the far end of the "
              "link. Ignore if this switch routes those VLANs itself (MS layer-3 interface).",
              resource=f"{switch} port {pid}",
              item=f"Uplink allows VLANs '{up.get('allowedVlans')}' (native {up.get('vlan')}), "
                   f"but enabled access ports use {compact_vlans(missing)} ({used}).")


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


def webhook_host(url: Any) -> tuple[str, str, str]:
    """(scheme, hostname, "scheme://host[:port]") of a webhook URL. Only these are ever
    reported: the path, query and user info of webhook URLs often carry tokens (Slack,
    Teams, SIEM collectors)."""
    try:
        u = urlsplit(str(url or "").strip())
        host = (u.hostname or "").lower()
        port = u.port
    except ValueError:
        return "", "", "?"
    if not host:
        return u.scheme.lower(), "", "?"
    shown = f"[{host}]" if ":" in host else host
    scheme = u.scheme.lower()
    return scheme, host, f"{scheme}://{shown}{f':{port}' if port else ''}"


def _host_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _host_trusted(host: str, domains: list[str]) -> bool:
    ip = _host_ip(host)
    if ip is not None:
        return not ip.is_global  # internal receiver
    return any(host == d or host.endswith("." + d) for d in domains)


def check_webhooks(s: Scope) -> None:
    """Webhook receivers (HTTP servers) that alerts are POSTed to. The API never returns
    the shared secret, so only the payload template is checked for sending it."""
    servers = s.call("webhooks", s.d.networks.getNetworkWebhooksHttpServers, s.net["id"])
    servers = [h for h in servers or [] if h.get("enabled", True) is not False]
    if not servers:
        return
    cat = "Logging & Monitoring"
    templates = s.call("webhook-templates", s.d.networks.getNetworkWebhooksPayloadTemplates,
                       s.net["id"])
    by_tid = {t.get("payloadTemplateId"): t for t in templates or []}
    alerts = s.call("alerts", s.d.networks.getNetworkAlertsSettings, s.net["id"])
    used: set[str] | None = None
    if alerts is not None:
        used = set((alerts.get("defaultDestinations") or {}).get("httpServerIds") or [])
        for a in alerts.get("alerts") or []:
            if a.get("enabled"):
                used |= set((a.get("alertDestinations") or {}).get("httpServerIds") or [])

    for h in servers:
        scheme, host, shown = webhook_host(h.get("url"))
        res = h.get("name") or shown
        where = f"Webhook '{res}' posts to {shown}."
        ip = _host_ip(host)
        if scheme == "http":
            internal = ip is not None and not ip.is_global
            s.add("MEDIUM" if internal else "HIGH", "NET-HOOK-01", cat,
                  "Webhook receiver uses plain HTTP",
                  "Alert payloads (device names, client MACs and IPs, admin emails, the shared "
                  "secret) are sent unencrypted and can be read or changed on the path.",
                  "Use an https:// URL for the receiver.", resource=res, item=where)
        tpl = by_tid.get((h.get("payloadTemplate") or {}).get("payloadTemplateId"))
        if tpl and lower(tpl.get("type")) == "custom":
            text = (str(tpl.get("body") or "") + " " +
                    " ".join(f"{x.get('name')} {x.get('template')}" for x in tpl.get("headers") or []))
            if "sharedsecret" not in text.lower():
                s.add("MEDIUM", "NET-HOOK-02", cat, "Webhook payload does not include the shared secret",
                      "Its custom payload template does not use {{sharedSecret}} in the body or "
                      "headers, so the receiver cannot tell real Meraki alerts from forged ones.",
                      "Set a shared secret on the HTTP server and send it in the template (e.g. "
                      "an 'Authorization: Bearer {{sharedSecret}}' header); have the receiver "
                      "reject requests without it.", resource=res,
                      item=f"{where[:-1]} with template '{tpl.get('name')}'.")
        if s.cfg.trusted_webhook_domains and not _host_trusted(host, s.cfg.trusted_webhook_domains):
            s.add("MEDIUM", "NET-HOOK-03", cat, "Webhook receiver outside trusted domains",
                  "Alert data is sent to a host that is not in --trusted-webhook-domain.",
                  "Confirm the receiver is a known, contracted service. Otherwise remove it.",
                  resource=res, item=where)
        elif not s.cfg.trusted_webhook_domains and ip is not None and ip.is_global:
            s.add("INFO", "NET-HOOK-05", cat, "Webhook receiver addressed by public IP",
                  "Receivers addressed by a bare public IP are often test endpoints left behind, "
                  "and the TLS certificate cannot be checked against a name.",
                  "Use a DNS name with a valid certificate, or remove the receiver.",
                  resource=res, item=where)
        if used is not None and h.get("id") not in used:
            s.add("INFO", "NET-HOOK-04", cat, "Webhook receiver not used by network alerts",
                  "No enabled network alert and no default destination sends to it (sensor or "
                  "camera alert profiles can still use it).",
                  "Remove receivers that are no longer needed.", resource=res, item=where)


def check_webhook_logs(s: Scope, network_names: dict[str, str], filtered: bool) -> None:
    """Failed webhook deliveries in the org webhook log: alerts that never arrived."""
    days = max(1, min(s.cfg.log_days, 30))  # the webhook log keeps 30 days
    logs = s.call("webhook-logs", s.d.organizations.getOrganizationWebhooksLogs, s.org["id"],
                  timespan=days * 86400, perPage=1000, total_pages=5)
    if not logs:
        return
    stats: dict[tuple[str, str], list[int]] = {}  # (networkId, receiver) -> [sent, failed]
    codes: dict[tuple[str, str], set[str]] = {}
    for e in logs:
        nid = str(e.get("networkId") or "")
        if filtered and nid and nid not in network_names:
            continue
        key = (nid, webhook_host(e.get("url"))[2])
        st = stats.setdefault(key, [0, 0])
        st[0] += 1
        code = e.get("responseCode")
        if not (isinstance(code, int) and 200 <= code < 300):
            st[1] += 1
            codes.setdefault(key, set()).add(str(code or "no response"))
    for (nid, recv), (sent, failed) in sorted(stats.items()):
        if not failed:
            continue
        net = network_names.get(nid, nid)
        s.add("MEDIUM" if failed == sent else "LOW", "ORG-HOOK-01", "Logging & Monitoring",
              "Webhook deliveries failing",
              "Alerts sent to this receiver were not accepted, so they were lost unless "
              "another destination also got them.",
              "Check the receiver is up and accepts the payload, or fix/remove the webhook.",
              resource=f"{recv} [{net}]" if net else recv,
              item=f"{failed} of {sent} webhook(s) to {recv}"
                   f"{f' from network {net}' if net else ''} failed in the last {days} days "
                   f"(responses: {', '.join(sorted(codes.get((nid, recv), set())))}).")


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
                  "Beta firmware is less tested.",
                  "Run stable firmware in production unless a beta fix is needed.", resource=product,
                  item=f"Runs {cur_name}.")
        cur_date = parse_time(cur.get("releaseDate"))
        newer_stable = [
            v for v in (info.get("availableVersions") or [])
            if lower(v.get("releaseType")) == "stable"
            and cur_date and (parse_time(v.get("releaseDate")) or cur_date) > cur_date
        ]
        if newer_stable:
            latest = max(newer_stable, key=lambda v: parse_time(v.get("releaseDate")) or cur_date)
            s.add("MEDIUM", "FW-02", cat, f"{product} firmware not on latest stable",
                  "A newer stable release is available.",
                  "Schedule an upgrade to the latest stable release (security fixes).",
                  resource=product,
                  item=f"Runs {cur_name}; latest stable "
                       f"{latest.get('shortName') or latest.get('firmware')}.")
        age = days_since(cur_date)
        if age is not None and age > s.cfg.firmware_max_age_days:
            s.add("MEDIUM", "FW-03", cat, f"{product} firmware is old",
                  f"Firmware is older than {s.cfg.firmware_max_age_days} days.",
                  "Upgrade to a current stable firmware.", resource=product,
                  item=f"Runs {cur_name}, released {age} days ago.")


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
    ogp = getattr(s, "ogp_vlans", None) or {}
    note = (" These rules do not apply to VLAN(s) "
            + ", ".join(f"{v} (org-wide policy '{p}')" for v, p in sorted(ogp.items()))
            + "; see the ORG-OGP findings for those.") if ogp else ""
    if not any(lower(r.get("policy")) == "deny" for r in rules):
        s.add("LOW", "MX-FW-01", cat, "No outbound/inter-VLAN deny rules",
              "The MX L3 firewall only relies on the default allow-any rule." + note,
              "Implement egress filtering and inter-VLAN segmentation (deny by default where possible).")
    for idx, r in enumerate(rules, 1):
        if (lower(r.get("policy")) == "allow" and lower(r.get("protocol")) == "any"
                and is_any(r.get("srcCidr")) and is_any(r.get("destCidr"))
                and parse_ports(r.get("destPort")) is None):
            s.add("HIGH", "MX-FW-02", cat, "Explicit any/any allow rule",
                  f"Rule #{idx} '{r.get('comment') or '(no comment)'}' allows all traffic, making "
                  "rules below it ineffective." + note,
                  "Remove or narrow the rule.", resource=f"rule {idx}")
    report_shadowed(s, rules, "MX-FW-05", cat, "Firewall")
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
              "Reachable from any internet source.",
              "Restrict 'Allowed remote IPs', or publish the service through VPN/ZTNA instead.",
              resource=name,
              item=f"{r.get('protocol')}/{r.get('publicPort')} -> "
                   f"{r.get('lanIp')}:{r.get('localPort')}"
                   + (f" (sensitive: {', '.join(risky)})" if risky else "") + ".")


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


def check_mx_spoofing(s: Scope) -> None:
    fw = s.call("mx-firewall-settings", s.d.appliance.getNetworkApplianceFirewallSettings,
                s.net["id"])
    mode = lower(((fw or {}).get("spoofingProtection") or {}).get("ipSourceGuard", {}).get("mode"))
    if mode and mode != "block":
        s.add("LOW", "MX-SPOOF-01", "Firewall", "IP spoofing protection not blocking",
              f"MX IP source guard mode is '{mode}': traffic with spoofed source addresses is "
              "logged but still forwarded.",
              "Set Security & SD-WAN > Firewall > IP source address spoofing protection to "
              "'Block'.")


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

def _radius_without_radsec(servers: Iterable[dict], flag: Callable[[dict], Any]) -> list[str]:
    """Hosts of RADIUS servers that report RadSec as off. Servers whose response has no
    RadSec field (older API/firmware) are left out: their state is unknown."""
    return [str(r.get("host") or "?") for r in servers or [] if flag(r) is False]


def _radsec_finding(s: Scope, check_id: str, cat: str, what: str, hosts: list[str],
                    fix: str, resource: str) -> None:
    def public(h: str) -> bool:
        try:
            return ipaddress.ip_address(h).is_global
        except ValueError:
            return False  # hostname: can't tell where it is
    pub = [h for h in hosts if public(h)]
    sev = "MEDIUM" if pub else "LOW"
    where = (f" {_short(pub)} is on the public internet, so RADIUS crosses it unencrypted."
             if pub else "")
    s.add(sev, check_id, cat, "RADIUS without RadSec (RADIUS over plain UDP)",
          "Classic RADIUS hides only the password (MD5 with the shared secret); usernames, "
          "MACs and other attributes travel in clear text, and the MD5 integrity check is "
          "open to Blast-RADIUS (CVE-2024-3596) forgery on the path.",
          fix, resource=resource, item=f"{what} sends RADIUS to {_short(hosts)} over UDP.{where}")


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
                  "WEP is trivially broken.",
                  "Use WPA3 (or WPA2/WPA3 transition) with 802.1X or a strong PSK.", resource=name)
        if auth == "open" and not has_splash:
            s.add("HIGH", "WL-SSID-02", cat, "Open SSID without any access control",
                  "Open with no splash page; traffic is unencrypted.",
                  "Use WPA2/3, or Enhanced Open (OWE) with a splash page for guest networks.",
                  resource=name)
        elif auth == "open":
            s.add("MEDIUM", "WL-SSID-03", cat, "Open (unencrypted) guest SSID",
                  "Over-the-air traffic is unencrypted.",
                  "Use Enhanced Open (OWE) or WPA3/WPA2-PSK for guests.", resource=name,
                  item=f"Splash page: {ssid.get('splashPage')}.")
        if "wpa1" in wpa:
            sev = "HIGH" if wpa == "wpa1 only" else "MEDIUM"
            s.add(sev, "WL-SSID-04", cat, "SSID allows WPA1/TKIP",
                  "WPA1/TKIP is deprecated and weak.",
                  "Use 'WPA2 only' or WPA3.", resource=name,
                  item=f"WPA mode: {ssid.get('wpaEncryptionMode')}.")
        if auth == "psk":
            psk = ssid.get("psk")
            if isinstance(psk, str) and psk:
                issues = psk_weakness(psk, name, s.cfg.min_psk_length)
                if issues:
                    s.add("HIGH" if len(psk) < 10 else "MEDIUM", "WL-SSID-05", cat,
                          "Weak Wi-Fi pre-shared key",
                          "The PSK is checked locally and never shown in the report.",
                          f"Use a random passphrase of {s.cfg.min_psk_length}+ characters and "
                          "rotate it regularly.", resource=name,
                  item=f"PSK is weak: {', '.join(issues)}.")
            if mode == "bridge mode":
                s.add("LOW", "WL-SSID-06", cat, "Shared PSK on bridged (internal) SSID",
                      "Bridges clients onto the LAN with a shared PSK.",
                      "Use 802.1X (WPA2/3-Enterprise) or iPSK for internal networks.", resource=name)
        if (is_open or has_splash) and mode in ("bridge mode", "layer 3 roaming"):
            s.add("HIGH", "WL-SSID-07", cat, "Guest/open SSID bridged into the LAN",
                  "Open/splash SSID puts guests on the LAN.",
                  "Use NAT mode or a dedicated guest VLAN with ACLs; enable client isolation.",
                  resource=name,
                  item=f"IP assignment: {ssid.get('ipAssignmentMode')}.")
        if (is_open or has_splash) and mode == "bridge mode" and not ssid.get("lanIsolationEnabled"):
            s.add("MEDIUM", "WL-SSID-08", cat, "Client isolation disabled on guest SSID",
                  "Guest clients can reach each other.",
                  "Enable LAN isolation on guest SSIDs.", resource=name)
        if "802.1x" in auth or "8021x" in auth:
            if not ssid.get("radiusServers") and auth == "8021x-radius":
                s.add("MEDIUM", "WL-SSID-09", cat, "802.1X SSID without RADIUS servers",
                      "Set to 802.1X-RADIUS but has no RADIUS servers.",
                      "Configure redundant RADIUS servers.", resource=name)
        plain = _radius_without_radsec(ssid.get("radiusServers"), lambda r: r.get("radsecEnabled"))
        if plain:
            _radsec_finding(s, "WL-RADSEC-01", cat, f"SSID '{name}'", plain,
                            "Enable RadSec (RADIUS over TLS) on the SSID's RADIUS servers; it "
                            "requires the Meraki cloud RADIUS proxy and a RadSec-capable server. "
                            "Otherwise keep RADIUS on a trusted, private path.", resource=name)

        # Guest / PSK SSIDs should not reach the LAN
        if is_open or has_splash or auth == "psk":
            fw = s.call(f"ssid-{ssid.get('number')}-l3",
                        s.d.wireless.getNetworkWirelessSsidFirewallL3FirewallRules,
                        s.net["id"], ssid.get("number"))
            if fw and fw.get("allowLanAccess") and (is_open or has_splash):
                s.add("HIGH", "WL-SSID-10", cat, "Guest SSID allows wireless clients LAN access",
                      "'Wireless clients accessing LAN' is set to allow.",
                      "Deny LAN access on the SSID's L3 firewall for guest networks.", resource=name)


def check_ap_bluetooth(s: Scope) -> None:
    bt = s.call("ap-bluetooth", s.d.wireless.getNetworkWirelessBluetoothSettings, s.net["id"])
    if not bt:
        return
    cat = "Wireless"
    if bt.get("scanningEnabled"):
        s.add("LOW", "WL-BT-01", cat, "AP Bluetooth scanning enabled",
              "Access points scan for nearby Bluetooth/BLE devices and report them to Dashboard.",
              "Disable Bluetooth scanning (Wireless > Bluetooth settings) unless it is used "
              "for location analytics or asset tracking.")
    if bt.get("advertisingEnabled"):
        s.add("LOW", "WL-BT-02", cat, "AP BLE beacon advertising enabled",
              "Access points broadcast BLE iBeacon advertisements.",
              "Disable beacon advertising unless an app relies on it.")


def check_ap_usb(s: Scope) -> None:
    profiles = s.call("ap-usb-ports", s.d.wireless.getNetworkWirelessEthernetPortsProfiles,
                      s.net["id"])
    if not profiles:
        return
    for p in profiles:
        enabled = [u.get("name") or "USB" for u in (p.get("usbPorts") or []) if u.get("enabled")]
        if not enabled:
            continue
        name = p.get("name") or f"profile {p.get('profileId')}"
        aps = len(p.get("assignments") or [])
        scope = "default profile" if p.get("isDefault") else f"assigned to {aps} AP(s)"
        s.add("LOW", "WL-USB-01", "Wireless", "AP USB port enabled",
              "AP USB port is enabled in the port profile.",
              "Disable the AP USB port in the port profile unless a USB device is required.",
              resource=name, item=f"Profile '{name}' ({scope}): {_short(enabled)}.")


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
        check_dai(s, dhcp.get("arpInspection"))
    pols = s.call("switch-access-policies", s.d.switch.getNetworkSwitchAccessPolicies, s.net["id"])
    if pols is not None and not pols:
        s.add("INFO", "SW-NAC-01", cat, "No 802.1X/MAB access policies",
              "No port access policies are defined in this switch network.",
              "Consider 802.1X/MAB port authentication for user-facing ports.")
    for pol in pols or []:
        check_access_policy(s, pol)


def check_dai(s: Scope, dai: dict | None) -> None:
    """Dynamic ARP Inspection: network-wide state, then per-port 'Trusted DAI'.
    daiTrusted is only in the per-switch port list, so those calls are made only
    when DAI is on (with DAI off, trusted ports have no effect)."""
    if dai is None:  # field absent: older API/firmware, state unknown
        return
    cat = "Switching"
    if not dai.get("enabled"):
        s.add("MEDIUM", "SW-DAI-01", cat, "Dynamic ARP Inspection disabled",
              "Switches do not validate ARP against DHCP snooping bindings, so any client can "
              "spoof the gateway's or another host's IP (ARP poisoning / man-in-the-middle).",
              "Switching > DHCP servers & ARP: enable Dynamic ARP Inspection, mark only uplinks "
              "and trunks to other switches/routers as Trusted DAI, and add static-IP hosts "
              "as trusted servers.")
        return
    unsupported = dai.get("unsupportedModels") or []
    if unsupported:
        s.add("LOW", "SW-DAI-02", cat, "Switch models that cannot enforce DAI",
              f"DAI is enabled, but these models in the network do not support it and do not "
              f"inspect ARP: {_short(unsupported)}.",
              "Replace these switches or keep untrusted clients off them.")

    devices = s.call("network-devices", s.d.networks.getNetworkDevices, s.net["id"]) or []
    switches = [d for d in devices if lower(d.get("productType")) == "switch"
                or (not d.get("productType") and lower(d.get("model")).startswith("ms"))]
    for sw in switches:
        name = sw.get("name") or sw.get("serial")
        ports = s.call(f"switch-ports-{sw.get('serial')}", s.d.switch.getDeviceSwitchPorts,
                       sw.get("serial"))
        if not ports:
            continue
        enabled = [p for p in ports if p.get("enabled", True)]
        if not any("daiTrusted" in p for p in enabled):
            continue  # field not reported: state unknown
        trusted_access = [str(p.get("portId")) for p in enabled
                          if p.get("daiTrusted") and lower(p.get("type")) == "access"]
        if trusted_access:
            s.add("MEDIUM", "SW-DAI-03", cat, "Access ports set to Trusted DAI",
                  "These ports skip ARP inspection, so a client on them can still ARP-spoof.",
                  "Untick Trusted DAI on access ports; trust only uplinks and inter-switch or "
                  "router trunks. Use DAI trusted servers for static-IP hosts.", resource=name,
                  item=f"{len(trusted_access)} access port(s): {_short(trusted_access, 12)}.")
        if (any(lower(p.get("type")) == "trunk" for p in enabled)
                and not any(p.get("daiTrusted") for p in enabled
                            if lower(p.get("type")) == "trunk" or is_uplink_port(p))):
            s.add("INFO", "SW-DAI-04", cat, "DAI enabled but no trusted uplink",
                  "The switch has trunk ports but none is Trusted DAI, so ARP from upstream "
                  "switches/routers is inspected and may be dropped.",
                  "Mark the uplink trunk as Trusted DAI.", resource=name)


def check_access_policy(s: Scope, pol: dict) -> None:
    cat = "Switching"
    name = pol.get("name") or f"#{pol.get('accessPolicyNumber', '?')}"
    res = f"access policy {name}"
    if lower(pol.get("hostMode")) == "multi-host":
        s.add("MEDIUM", "SW-NAC-02", cat, "802.1X access policy in Multi-Host mode",
              "Once the first device on a port authenticates, every other device on that "
              "port (e.g. behind a hub or a phone's PC port) is admitted without "
              "authenticating.",
              "Use Single-Host, Multi-Domain (phone + PC) or Multi-Auth so each device "
              "authenticates.", resource=res)
    if "radiusServers" in pol:
        servers = pol.get("radiusServers") or []
        if not servers:
            s.add("MEDIUM", "SW-NAC-03", cat, "Access policy has no RADIUS servers",
                  f"Access policy '{name}' ({pol.get('accessPolicyType')}) has no RADIUS servers.",
                  "Configure at least two RADIUS servers.", resource=res)
        elif len(servers) == 1:
            s.add("LOW", "SW-NAC-03", cat, "Access policy relies on a single RADIUS server",
                  f"Access policy '{name}' has one RADIUS server ({servers[0].get('host', '?')}). "
                  "If it is unreachable, ports fall back to critical-auth behaviour or deny access.",
                  "Add a second RADIUS server, ideally at another site.", resource=res)
    servers = [*(pol.get("radiusServers") or []), *(pol.get("radiusAccountingServers") or [])]
    plain = _radius_without_radsec(
        servers, lambda r: (r.get("radsec") or {}).get("enabled") if "radsec" in r else None)
    if plain:
        _radsec_finding(s, "SW-RADSEC-01", cat, f"Access policy '{name}'", sorted(set(plain)),
                        "Enable RadSec on the access policy's RADIUS servers (switch firmware "
                        "and RADIUS server must support it), or keep RADIUS on a trusted, "
                        "private management path.", resource=res)
    if pol.get("radiusAccountingEnabled") is False:
        s.add("LOW", "SW-NAC-04", cat, "RADIUS accounting disabled on access policy",
              f"Access policy '{name}' does not send RADIUS accounting, so there is no record "
              "of which device was on which port and when.",
              "Enable RADIUS accounting and point it at the same RADIUS/NAC servers.",
              resource=res)
    crit = (pol.get("radius") or {}).get("criticalAuth") or {}
    if crit.get("dataVlanId") not in (None, ""):
        s.add("LOW", "SW-NAC-05", cat, "Access policy fails open when RADIUS is unreachable",
              f"Access policy '{name}' puts clients into data VLAN {crit['dataVlanId']} when no "
              "RADIUS server answers (critical auth). Anyone who can cut access to RADIUS gets "
              "unauthenticated network access.",
              "Confirm this availability trade-off is intended and that the critical VLAN is "
              "restricted. Otherwise remove it.", resource=res)


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

NETWORK_CHECKS: list[tuple[str | None, Callable[[Scope], None]]] = [
    (None, check_network_settings),
    (None, check_network_snmp),
    (None, check_syslog),
    (None, check_alerts),
    (None, check_webhooks),
    (None, check_firmware),
    ("appliance", check_mx_l3_firewall),
    ("appliance", check_mx_inbound),
    ("appliance", check_mx_port_forwarding),
    ("appliance", check_mx_nat),
    ("appliance", check_mx_services),
    ("appliance", check_mx_threat),
    ("appliance", check_mx_mode),
    ("appliance", check_mx_spoofing),
    ("wireless", check_ssids),
    ("wireless", check_ap_bluetooth),
    ("wireless", check_ap_usb),
    ("switch", check_switch_network),
]


def audit_network(dashboard, cfg: AuditConfig, out: Collector, org: dict, net: dict,
                  ogp_vlans: dict[int, str] | None = None) -> None:
    s = Scope(dashboard, cfg, out, org, net)
    s.ogp_vlans = ogp_vlans or {}
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
    admins = check_admins(s, login_sec, saml)
    check_api_usage(s, admins)
    check_org_snmp(s)
    check_third_party_vpn(s)
    check_vpn_firewall(s)
    try:
        ogp_vlans = check_org_group_policies(s)
    except Exception as e:  # keep going on unexpected payloads
        out.skip(Skipped(s.label, "check_org_group_policies", f"check failed: {type(e).__name__}: {e}"))
        ogp_vlans = {}

    networks = s.call("networks", dashboard.organizations.getOrganizationNetworks,
                      org["id"], total_pages="all") or []
    if network_ids:
        networks = [n for n in networks if n["id"] in network_ids]
    if network_tags:
        networks = [n for n in networks if network_tags & set(n.get("tags", []))]
    names = {n["id"]: n["name"] for n in networks}
    changes = check_config_changes(s, admins, saml, names if (network_ids or network_tags) else None)
    check_support_access(s, changes)
    check_webhook_logs(s, names, bool(network_ids or network_tags))

    if any("wireless" in n.get("productTypes", []) for n in networks):
        check_air_marshal(s, names)
    if any("switch" in n.get("productTypes", []) for n in networks):
        check_switch_ports(s, names)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(audit_network, dashboard, cfg, out, org, n, ogp_vlans.get(n["id"])): n
                   for n in networks}
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


@dataclass
class Group:
    """Findings of one check that share severity, title and fix."""
    findings: list[Finding]

    @property
    def first(self) -> Finding:
        return self.findings[0]

    @property
    def common_detail(self) -> str | None:
        """The explanation shared by every finding, or None if they differ."""
        whys = {f.why if f.item else f.detail for f in self.findings}
        return next(iter(whys)) if len(whys) == 1 else None

    def affected(self, f: Finding) -> str:
        where = f.org_name + (f" / {f.network_name}" if f.network_name else "")
        what = f.item if (f.item and self.common_detail is not None) else (
            "" if self.common_detail is not None else f.detail)
        return " - ".join(x for x in (where, f.resource, what) if x)


def group_findings(findings: list[Finding], enabled: bool = True) -> list[Group]:
    """Keeps the input order (sorted by severity), each group at its first finding."""
    if not enabled:
        return [Group([f]) for f in findings]
    groups: dict[tuple, Group] = {}
    for f in findings:
        key = (f.severity, f.check_id, f.title, f.recommendation)
        groups.setdefault(key, Group([])).findings.append(f)
    return list(groups.values())


def _summary_line(findings: list[Finding], groups: list[Group]) -> str:
    line = "  ".join(f"{k}: {v}" for k, v in summary_counts(findings).items())
    if len(groups) < len(findings):
        line += f"   ({len(findings)} findings in {len(groups)} distinct issues)"
    return line


def render_text(findings: list[Finding], skipped: list[Skipped], verbose: bool,
                group: bool = True) -> str:
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    colors = {"CRITICAL": "\033[1;37;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[33m",
              "LOW": "\033[36m", "INFO": "\033[2m"}
    reset = "\033[0m" if color else ""
    groups = group_findings(findings, group)
    buf = io.StringIO()
    buf.write(f"\nMeraki Security Audit - {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
    buf.write("=" * 72 + "\n")
    buf.write(_summary_line(findings, groups) + "\n\n")
    for g in groups:
        f = g.first
        c = colors[f.severity] if color else ""
        n = len(g.findings)
        buf.write(f"{c}[{f.severity}]{reset} {f.check_id}  {f.title}"
                  + (f"  ({n} affected)" if n > 1 else "") + "\n")
        if n == 1:
            where = f.org_name + (f" / {f.network_name}" if f.network_name else "")
            buf.write(f"    Scope : {where}" + (f" - {f.resource}" if f.resource else "") + "\n")
            buf.write(f"    Detail: {f.detail}\n")
            buf.write(f"    Fix   : {f.recommendation}\n\n")
            continue
        if g.common_detail:
            buf.write(f"    Detail: {g.common_detail}\n")
        buf.write(f"    Fix   : {f.recommendation}\n")
        buf.write("    Affected:\n")
        for x in g.findings:
            buf.write(f"      - {g.affected(x)}\n")
        buf.write("\n")
    if skipped:
        buf.write(f"{len(skipped)} check(s) skipped (not applicable, unlicensed, or no permission).")
        if verbose:
            buf.write("\n")
            for sk in skipped:
                buf.write(f"  - {sk.scope}: {sk.check}: {sk.reason}\n")
        else:
            buf.write(" Use --verbose to list them.\n")
    return buf.getvalue()


def render_markdown(findings: list[Finding], skipped: list[Skipped], group: bool = True) -> str:
    def esc(v: str) -> str:
        return str(v).replace("|", "\\|").replace("\n", " ")
    groups = group_findings(findings, group)
    lines = ["# Meraki Security Audit", "",
             f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", "",
             "## Summary", "", "| Severity | Count |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in summary_counts(findings).items()]
    if len(groups) < len(findings):
        lines += ["", f"{len(findings)} findings in {len(groups)} distinct issues."]
    lines += ["", "## Findings", "",
              "| Severity | ID | Finding | Affected | Detail | Recommendation |",
              "|---|---|---|---|---|---|"]
    for g in groups:
        f = g.first
        if len(g.findings) == 1:
            where = f.org_name + (f" / {f.network_name}" if f.network_name else "")
            affected, detail = " - ".join(x for x in (where, f.resource) if x), f.detail
        else:
            affected = "<br>".join(f"{esc(g.affected(x))}" for x in g.findings)
            detail = g.common_detail or ""
        lines.append(f"| {f.severity} | {f.check_id} | {esc(f.title)}"
                     + (f" ({len(g.findings)})" if len(g.findings) > 1 else "")
                     + f" | {esc(affected) if len(g.findings) == 1 else affected} | "
                     f"{esc(detail)} | {esc(f.recommendation)} |")
    if skipped:
        lines += ["", "## Skipped checks", "", "| Scope | Check | Reason |", "|---|---|---|"]
        lines += [f"| {esc(s.scope)} | {s.check} | {esc(s.reason)} |" for s in skipped]
    return "\n".join(lines) + "\n"


def render_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=EXPORT_FIELDS)
    w.writeheader()
    for f in findings:
        w.writerow(finding_dict(f))
    return buf.getvalue()


def render_json(findings: list[Finding], skipped: list[Skipped]) -> str:
    return json.dumps({
        "tool": "meraki_audit", "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(),
        "summary": summary_counts(findings),
        "findings": [finding_dict(f) for f in findings],
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
    p.add_argument("--trusted-webhook-domain", action="append", default=[],
                   help="Domain webhook receivers may post to, incl. subdomains (repeatable; "
                        "private IPs always count as trusted)")
    p.add_argument("--inactive-days", type=int, default=90,
                   help="Flag admins inactive longer than this")
    p.add_argument("--max-full-admins", type=int, default=5)
    p.add_argument("--min-psk-length", type=int, default=12)
    p.add_argument("--min-password-length", type=int, default=12,
                   help="Minimum Dashboard admin password length")
    p.add_argument("--password-history", type=int, default=4,
                   help="Minimum number of previous passwords that may not be reused")
    p.add_argument("--firmware-max-age-days", type=int, default=365)
    p.add_argument("--log-days", type=int, default=30,
                   help="Look-back for the API request log (max 31) and change log (max 365)")
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
    p.add_argument("--no-group", action="store_true",
                   help="text/markdown: one entry per finding instead of grouping the same issue "
                        "across networks and devices")
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
        min_password_length=args.min_password_length,
        password_history_min=args.password_history,
        firmware_max_age_days=args.firmware_max_age_days,
        log_days=args.log_days,
        trusted_domains=[d.lower().lstrip("@") for d in args.trusted_domain],
        trusted_webhook_domains=[d.lower().lstrip(".") for d in args.trusted_webhook_domain],
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
        report = render_markdown(findings, out.skipped, group=not args.no_group)
    else:
        report = render_text(findings, out.skipped, args.verbose, group=not args.no_group)

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
