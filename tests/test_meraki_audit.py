"""Offline tests for meraki_audit using a fake Dashboard API object."""

import json
import os
import sys
import time
from types import SimpleNamespace

import meraki
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import meraki_audit as ma  # noqa: E402

ORG = {"id": "1", "name": "Acme", "api": {"enabled": True}}
NET = {"id": "N1", "name": "HQ", "productTypes": ["appliance", "switch", "wireless"], "tags": ["prod"]}
NET2 = {"id": "N2", "name": "Lab", "productTypes": ["wireless"], "tags": ["lab"]}


class NotFound(meraki.APIError):
    def __init__(self):  # bypass SDK constructor
        self.status, self.message = 404, {"errors": ["Not found"]}


def insecure() -> dict:
    old = int(time.time()) - 200 * 86400
    return {
        "getOrganizations": [ORG],
        "getOrganizationLoginSecurity": {"enforceTwoFactorAuth": False, "enforceStrongPasswords": False,
                                         "enforceAccountLockout": False, "enforceIdleTimeout": False,
                                         "enforceDifferentPasswords": False, "enforceLoginIpRanges": False,
                                         "apiAuthentication": {"ipRestrictionsForKeys": {"enabled": False}}},
        "getOrganizationSaml": {"enabled": False},
        "getOrganizationAdmins": [
            {"name": "A", "email": "a@acme.com", "orgAccess": "full", "twoFactorAuthEnabled": False,
             "lastActive": old, "accountStatus": "ok", "hasApiKey": True, "authenticationMethod": "Email"},
            {"name": "V", "email": "v@vendor.io", "orgAccess": "full", "twoFactorAuthEnabled": True,
             "lastActive": int(time.time()), "accountStatus": "unverified", "authenticationMethod": "Email"},
        ],
        "getOrganizationSnmp": {"v2cEnabled": True, "v3Enabled": True, "v3AuthMode": "MD5",
                                "v3PrivMode": "DES", "peerIps": None},
        "getOrganizationApplianceVpnThirdPartyVPNPeers": {"peers": [
            {"name": "partner", "publicIp": "1.2.3.4", "ikeVersion": "1", "ipsecPoliciesPreset": "default",
             "secret": "short", "networkTags": ["all"]}]},
        "getOrganizationApplianceVpnVpnFirewallRules": {"rules": [{"comment": "Default rule", "policy": "allow"}]},
        "getOrganizationNetworks": [NET, NET2],
        "getOrganizationWirelessAirMarshalSettingsByNetwork": {"items": [
            {"networkId": "N1", "defaultPolicy": "allow"}, {"networkId": "N2", "defaultPolicy": "allow"}]},
        "getOrganizationSwitchPortsBySwitch": [{"name": "sw1", "serial": "Q1", "network": {"id": "N1", "name": "HQ"},
            "ports": [{"portId": "1", "enabled": True, "type": "trunk", "vlan": 1, "allowedVlans": "all"},
                      {"portId": "2", "enabled": True, "type": "access", "vlan": 1, "stpGuard": "disabled"}]}],
        "getNetworkSettings": {"localStatusPageEnabled": True, "remoteStatusPageEnabled": True,
                               "localStatusPage": {"authentication": {"enabled": False}}},
        "getNetworkSnmp": {"access": "community", "communityString": "public"},
        "getNetworkSyslogServers": {"servers": []},
        "getNetworkAlertsSettings": {"defaultDestinations": {"emails": [], "allAdmins": False},
                                     "alerts": [{"type": "settingsChanged", "enabled": False}]},
        "getNetworkFirmwareUpgrades": {"products": {"appliance": {
            "currentVersion": {"shortName": "MX 16.1", "releaseType": "stable", "releaseDate": "2021-01-01T00:00:00Z"},
            "availableVersions": [{"shortName": "MX 19.1", "releaseType": "stable", "releaseDate": "2025-06-01T00:00:00Z"}]}}},
        "getNetworkApplianceFirewallL3FirewallRules": {"rules": [
            {"comment": "", "policy": "allow", "protocol": "any", "srcCidr": "Any", "destCidr": "Any", "destPort": "Any"},
            {"comment": "Default rule", "policy": "allow", "protocol": "Any", "srcCidr": "Any", "destCidr": "Any"}]},
        "getNetworkApplianceFirewallInboundFirewallRules": NotFound(),
        "getNetworkApplianceFirewallPortForwardingRules": {"rules": [
            {"name": "rdp", "protocol": "tcp", "publicPort": "3389", "localPort": "3389",
             "lanIp": "10.0.0.5", "allowedIps": ["any"]}]},
        "getNetworkApplianceFirewallOneToOneNatRules": {"rules": [
            {"name": "web", "publicIp": "5.5.5.5", "lanIp": "10.0.0.6",
             "allowedInbound": [{"protocol": "tcp", "destinationPorts": ["22"], "allowedIps": ["any"]}]}]},
        "getNetworkApplianceFirewallOneToManyNatRules": {"rules": []},
        "getNetworkApplianceFirewallFirewalledServices": [{"service": "web", "access": "unrestricted"},
                                                          {"service": "ICMP", "access": "unrestricted"}],
        "getNetworkApplianceSecurityIntrusion": {"mode": "disabled"},
        "getNetworkApplianceSecurityMalware": {"mode": "disabled"},
        "getNetworkApplianceContentFiltering": {"blockedUrlCategories": []},
        "getNetworkApplianceSettings": {"deploymentMode": "routed"},
        "getNetworkWirelessSsids": [
            {"number": 0, "name": "Guest", "enabled": True, "authMode": "open", "splashPage": "None",
             "ipAssignmentMode": "Bridge mode", "lanIsolationEnabled": False},
            {"number": 1, "name": "Corp", "enabled": True, "authMode": "psk", "encryptionMode": "wpa",
             "wpaEncryptionMode": "WPA1 and WPA2", "psk": "corp1234", "ipAssignmentMode": "Bridge mode"},
            {"number": 2, "name": "Old", "enabled": True, "authMode": "psk", "encryptionMode": "wep", "psk": "x"},
            {"number": 3, "name": "Unconfigured SSID 4", "enabled": False, "authMode": "open"},
        ],
        "getNetworkWirelessSsidFirewallL3FirewallRules": {"allowLanAccess": True, "rules": []},
        "getNetworkSwitchStp": {"rstpEnabled": False},
        "getNetworkSwitchDhcpServerPolicy": {"defaultPolicy": "allow", "alerts": {"email": {"enabled": False}}},
        "getNetworkSwitchAccessPolicies": [],
    }


def hardened() -> dict:
    now = int(time.time())
    today = time.strftime("%Y-%m-%dT00:00:00Z")
    return {
        "getOrganizations": [ORG],
        "getOrganizationLoginSecurity": {"enforceTwoFactorAuth": True, "enforceStrongPasswords": True,
                                         "enforceAccountLockout": True, "accountLockoutAttempts": 5,
                                         "enforceIdleTimeout": True, "idleTimeoutMinutes": 15,
                                         "enforceDifferentPasswords": True, "enforceLoginIpRanges": True,
                                         "apiAuthentication": {"ipRestrictionsForKeys": {"enabled": True}}},
        "getOrganizationSaml": {"enabled": True},
        "getOrganizationSamlIdps": [{"idpId": "x"}],
        "getOrganizationSamlRoles": [{"role": "netops", "orgAccess": "read-only"}],
        "getOrganizationAdmins": [
            {"name": n, "email": f"{n}@acme.com", "orgAccess": "full", "twoFactorAuthEnabled": True,
             "lastActive": now, "accountStatus": "ok", "authenticationMethod": "Email"} for n in ("a", "b")],
        "getOrganizationSnmp": {"v2cEnabled": False, "v3Enabled": True, "v3AuthMode": "SHA",
                                "v3PrivMode": "AES128", "peerIps": ["10.1.1.1"]},
        "getOrganizationApplianceVpnThirdPartyVPNPeers": {"peers": []},
        "getOrganizationApplianceVpnVpnFirewallRules": {"rules": [
            {"comment": "block lab", "policy": "deny", "protocol": "any", "srcCidr": "10.9.0.0/16",
             "destCidr": "Any", "destPort": "Any"},
            {"comment": "Default rule", "policy": "allow"}]},
        "getOrganizationNetworks": [NET],
        "getOrganizationWirelessAirMarshalSettingsByNetwork": {"items": [{"networkId": "N1", "defaultPolicy": "block"}]},
        "getOrganizationSwitchPortsBySwitch": [{"name": "sw1", "network": {"id": "N1"}, "ports": [
            {"portId": "1", "enabled": True, "type": "trunk", "vlan": 999, "allowedVlans": "10,20"},
            {"portId": "2", "enabled": True, "type": "access", "vlan": 10, "stpGuard": "bpdu guard"}]}],
        "getNetworkSettings": {"localStatusPageEnabled": True, "remoteStatusPageEnabled": False,
                               "localStatusPage": {"authentication": {"enabled": True}}},
        "getNetworkSnmp": {"access": "users"},
        "getNetworkSyslogServers": {"servers": [{"host": "10.1.1.2", "roles": ["Security events", "Flows"]}]},
        "getNetworkAlertsSettings": {"defaultDestinations": {"allAdmins": True},
                                     "alerts": [{"type": "settingsChanged", "enabled": True}]},
        "getNetworkFirmwareUpgrades": {"products": {"appliance": {
            "currentVersion": {"shortName": "MX 19.1", "releaseType": "stable", "releaseDate": today},
            "availableVersions": []}}},
        "getNetworkApplianceFirewallL3FirewallRules": {"rules": [
            {"comment": "deny iot->corp", "policy": "deny", "protocol": "any", "srcCidr": "10.50.0.0/24",
             "destCidr": "10.0.0.0/8", "destPort": "Any", "syslogEnabled": True},
            {"comment": "Default rule", "policy": "allow"}]},
        "getNetworkApplianceFirewallInboundFirewallRules": {"rules": []},
        "getNetworkApplianceFirewallPortForwardingRules": {"rules": [
            {"name": "https", "protocol": "tcp", "publicPort": "443", "allowedIps": ["203.0.113.0/24"]}]},
        "getNetworkApplianceFirewallOneToOneNatRules": {"rules": []},
        "getNetworkApplianceFirewallOneToManyNatRules": {"rules": []},
        "getNetworkApplianceFirewallFirewalledServices": [{"service": "web", "access": "blocked"},
                                                          {"service": "SNMP", "access": "blocked"},
                                                          {"service": "ICMP", "access": "restricted"}],
        "getNetworkApplianceSecurityIntrusion": {"mode": "prevention", "idsRulesets": "security"},
        "getNetworkApplianceSecurityMalware": {"mode": "enabled"},
        "getNetworkApplianceContentFiltering": {"blockedUrlCategories": [{"id": "x", "name": "Malware sites"}]},
        "getNetworkApplianceSettings": {"deploymentMode": "routed"},
        "getNetworkWirelessSsids": [
            {"number": 0, "name": "Corp", "enabled": True, "authMode": "8021x-radius",
             "encryptionMode": "wpa-eap", "wpaEncryptionMode": "WPA3 Transition Mode",
             "radiusServers": [{"host": "10.1.1.3"}], "ipAssignmentMode": "Bridge mode"},
            {"number": 1, "name": "Guest", "enabled": True, "authMode": "psk", "encryptionMode": "wpa",
             "wpaEncryptionMode": "WPA2 only", "psk": "Tr0ub4dor&3-Horse-Staple!", "ipAssignmentMode": "NAT mode"},
        ],
        "getNetworkWirelessSsidFirewallL3FirewallRules": {"allowLanAccess": False, "rules": []},
        "getNetworkSwitchStp": {"rstpEnabled": True},
        "getNetworkSwitchDhcpServerPolicy": {"defaultPolicy": "block", "alerts": {"email": {"enabled": True}}},
        "getNetworkSwitchAccessPolicies": [{"name": "dot1x"}],
    }


class FakeDashboard:
    def __init__(self, data: dict):
        def make(name):
            def fn(*args, **kwargs):
                if name not in data:
                    raise NotFound()
                val = data[name]
                if isinstance(val, Exception):
                    raise val
                return val
            return fn
        ns = SimpleNamespace(**{k: make(k) for k in data})
        self.organizations = self.networks = self.appliance = self.wireless = self.switch = ns
        # make missing methods raise NotFound instead of AttributeError
        for attr in ("getOrganizationSamlIdps", "getOrganizationSamlRoles"):
            if not hasattr(ns, attr):
                setattr(ns, attr, make(attr))


def run(data, *args, capsys=None):
    rc = ma.main(["--format", "json", "-q", *args], dashboard=FakeDashboard(data))
    out = json.loads(capsys.readouterr().out)
    return rc, out, {f["check_id"] for f in out["findings"]}


def test_insecure_org_flags_expected_issues(capsys):
    rc, out, ids = run(insecure(), "--trusted-domain", "acme.com", "--fail-on", "HIGH", capsys=capsys)
    assert rc == 2
    expected = {
        "ORG-LS-01", "ORG-LS-02", "ORG-LS-03", "ORG-LS-05", "ORG-LS-09", "ORG-SSO-01",
        "ORG-ADM-03", "ORG-ADM-04", "ORG-ADM-05", "ORG-ADM-06", "ORG-ADM-07",
        "ORG-SNMP-01", "ORG-SNMP-02", "ORG-SNMP-03", "ORG-SNMP-04",
        "ORG-VPN-01", "ORG-VPN-02", "ORG-VPN-04", "ORG-VPN-06", "WL-AM-01",
        "SW-PORT-01", "SW-PORT-02", "SW-PORT-03", "SW-PORT-04",
        "NET-MGMT-01", "NET-MGMT-02", "NET-SNMP-01", "NET-LOG-01", "NET-ALERT-01", "NET-ALERT-02",
        "FW-02", "FW-03", "MX-FW-01", "MX-FW-02", "MX-NAT-01", "MX-NAT-02", "MX-SVC-01", "MX-SVC-02",
        "MX-IPS-01", "MX-AMP-01", "MX-CF-01",
        "WL-SSID-01", "WL-SSID-02", "WL-SSID-04", "WL-SSID-05", "WL-SSID-06", "WL-SSID-07",
        "WL-SSID-08", "WL-SSID-10", "SW-STP-01", "SW-DHCP-01", "SW-DHCP-02", "SW-NAC-01",
    }
    assert expected - ids == set(), f"missing: {sorted(expected - ids)}"
    # disabled SSIDs are ignored
    assert not any("Unconfigured" in f["detail"] for f in out["findings"])
    # inbound firewall 404 is recorded as skipped, not a crash
    assert any(s["check"] == "mx-inbound-firewall" for s in out["skipped"])


def test_secrets_never_in_report(capsys):
    _, out, _ = run(insecure(), capsys=capsys)
    blob = json.dumps(out)
    for secret in ("corp1234", "public", '"short"'):
        assert secret not in blob


def test_hardened_org_is_clean(capsys):
    rc, out, ids = run(hardened(), "--fail-on", "LOW", capsys=capsys)
    assert rc == 0, out["findings"]
    assert ids == set()


def test_network_tag_filter_scopes_org_wide_checks(capsys):
    _, out, _ = run(insecure(), "--network-tag", "lab", capsys=capsys)
    nets = {f["network_name"] for f in out["findings"] if f["network_name"]}
    assert nets == {"Lab"}


@pytest.mark.parametrize("fmt", ["text", "markdown", "csv"])
def test_other_formats_render(fmt, capsys):
    assert ma.main(["--format", fmt, "-q"], dashboard=FakeDashboard(insecure())) == 0
    assert "WEP" in capsys.readouterr().out


def test_helpers():
    assert ma.parse_ports("Any") is None
    assert ma.parse_ports("80,443,8000-8002") == {80, 443, 8000, 8001, 8002}
    assert ma.parse_ports("1-65535") is None
    assert ma.is_any(["any"]) and ma.is_any("0.0.0.0/0") and not ma.is_any("10.0.0.0/8")
    assert ma.parse_time("2019-01-28 14:58:56 -0800").year == 2019
    assert ma.parse_time(0) is None
    assert ma.psk_weakness("Tr0ub4dor&3-Horse-Staple!", "Guest", 12) == []
