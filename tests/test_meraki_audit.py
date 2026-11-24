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
        "getNetworkWirelessBluetoothSettings": {"scanningEnabled": True, "advertisingEnabled": True},
        "getNetworkWirelessEthernetPortsProfiles": [
            {"profileId": "1", "name": "Default", "isDefault": True, "ports": [],
             "usbPorts": [{"name": "usb port", "enabled": True}]},
            {"profileId": "2", "name": "Locked", "isDefault": False, "ports": [],
             "usbPorts": [{"name": "usb port", "enabled": False}]}],
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
        "getNetworkApplianceFirewallSettings": {"spoofingProtection": {"ipSourceGuard": {"mode": "block"}}},
        "getNetworkWirelessSsids": [
            {"number": 0, "name": "Corp", "enabled": True, "authMode": "8021x-radius",
             "encryptionMode": "wpa-eap", "wpaEncryptionMode": "WPA3 Transition Mode",
             "radiusServers": [{"host": "10.1.1.3"}], "ipAssignmentMode": "Bridge mode"},
            {"number": 1, "name": "Guest", "enabled": True, "authMode": "psk", "encryptionMode": "wpa",
             "wpaEncryptionMode": "WPA2 only", "psk": "Tr0ub4dor&3-Horse-Staple!", "ipAssignmentMode": "NAT mode"},
        ],
        "getNetworkWirelessSsidFirewallL3FirewallRules": {"allowLanAccess": False, "rules": []},
        "getNetworkWirelessBluetoothSettings": {"scanningEnabled": False, "advertisingEnabled": False},
        "getNetworkWirelessEthernetPortsProfiles": [
            {"profileId": "1", "name": "Default", "isDefault": True, "ports": [],
             "usbPorts": [{"name": "usb port", "enabled": False}]}],
        "getNetworkSwitchStp": {"rstpEnabled": True},
        "getNetworkSwitchDhcpServerPolicy": {"defaultPolicy": "block", "alerts": {"email": {"enabled": True}}},
        "getNetworkSwitchAccessPolicies": [{
            "name": "dot1x", "accessPolicyType": "802.1x", "hostMode": "Multi-Domain",
            "radiusServers": [{"host": "10.1.1.3"}, {"host": "10.2.1.3"}],
            "radiusAccountingEnabled": True,
            "radius": {"criticalAuth": {"dataVlanId": None}, "failedAuthVlanId": None}}],
    }


class FakeDashboard:
    """Returns data[name]; a callable value is called with the request kwargs, an
    exception value is raised, and an unknown method raises 404."""

    def __init__(self, data: dict):
        class NS:
            def __getattr__(_, name):
                def fn(*args, **kwargs):
                    if name not in data:
                        raise NotFound()
                    val = data[name]
                    if isinstance(val, Exception):
                        raise val
                    return val(*args, **kwargs) if callable(val) else val
                return fn
        self.organizations = self.networks = self.appliance = self.wireless = self.switch = NS()


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
        "WL-SSID-08", "WL-SSID-10", "WL-BT-01", "WL-BT-02", "WL-USB-01",
        "SW-STP-01", "SW-DHCP-01", "SW-DHCP-02", "SW-NAC-01",
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


def test_uplink_missing_in_use_vlan(capsys):
    data = hardened()
    data["getOrganizationSwitchPortsBySwitch"] = [{"name": "idf1", "network": {"id": "N1"}, "ports": [
        {"portId": "8", "enabled": True, "type": "trunk", "vlan": 999, "allowedVlans": "10,20,30",
         "name": "Uplink to core"},
        {"portId": "9", "enabled": True, "type": "trunk", "vlan": 999, "allowedVlans": "10,40",
         "name": "AP"},
        {"portId": "1", "enabled": True, "type": "access", "vlan": 40, "stpGuard": "bpdu guard"},
        {"portId": "2", "enabled": True, "type": "access", "vlan": 10, "voiceVlan": 50,
         "stpGuard": "bpdu guard"},
        {"portId": "3", "enabled": False, "type": "access", "vlan": 60}]}]
    _, out, ids = run(data, capsys=capsys)
    trunk = [f for f in out["findings"] if f["check_id"] == "SW-TRUNK-01"]
    assert len(trunk) == 1 and ids == {"SW-TRUNK-01"}
    assert trunk[0]["severity"] == "HIGH" and trunk[0]["resource"] == "idf1 port 8"
    assert "40,50" in trunk[0]["detail"] and "60" not in trunk[0]["detail"]


def test_uplink_ambiguous_is_skipped_not_guessed(capsys):
    data = hardened()
    data["getOrganizationSwitchPortsBySwitch"] = [{"name": "idf1", "network": {"id": "N1"}, "ports": [
        {"portId": "8", "enabled": True, "type": "trunk", "vlan": 999, "allowedVlans": "10"},
        {"portId": "9", "enabled": True, "type": "trunk", "vlan": 999, "allowedVlans": "10"},
        {"portId": "1", "enabled": True, "type": "access", "vlan": 40, "stpGuard": "bpdu guard"}]}]
    _, out, ids = run(data, capsys=capsys)
    assert ids == set()
    assert any(s["check"] == "switch-uplink-vlans" for s in out["skipped"])


def test_single_trunk_is_uplink_and_native_counts(capsys):
    data = hardened()
    data["getOrganizationSwitchPortsBySwitch"] = [{"name": "sw", "network": {"id": "N1"}, "ports": [
        {"portId": "1", "enabled": True, "type": "trunk", "vlan": 10, "allowedVlans": "20"},
        {"portId": "2", "enabled": True, "type": "access", "vlan": 10, "stpGuard": "bpdu guard"}]}]
    assert run(data, capsys=capsys)[2] == set()


def test_shadowed_firewall_rules(capsys):
    data = hardened()
    data["getNetworkApplianceFirewallL3FirewallRules"] = {"rules": [
        {"comment": "web out", "policy": "allow", "protocol": "tcp", "srcCidr": "10.0.0.0/8",
         "srcPort": "Any", "destCidr": "Any", "destPort": "80,443", "syslogEnabled": True},
        {"comment": "block lab web", "policy": "deny", "protocol": "tcp", "srcCidr": "10.9.0.0/16",
         "srcPort": "Any", "destCidr": "Any", "destPort": "443"},
        {"comment": "dup", "policy": "allow", "protocol": "tcp", "srcCidr": "10.1.2.3",
         "srcPort": "Any", "destCidr": "Any", "destPort": "80"},
        {"comment": "not covered: any port", "policy": "deny", "protocol": "tcp", "srcCidr": "10.9.0.0/16",
         "srcPort": "Any", "destCidr": "Any", "destPort": "Any"},
        {"comment": "not covered: VLAN syntax", "policy": "deny", "protocol": "any",
         "srcCidr": "VLAN(30).*", "destCidr": "Any", "destPort": "Any"},
        {"comment": "Default rule", "policy": "allow", "protocol": "Any", "srcCidr": "Any", "destCidr": "Any"}]}
    _, out, ids = run(data, capsys=capsys)
    fw = sorted((f["resource"], f["severity"]) for f in out["findings"] if f["check_id"] == "MX-FW-05")
    assert fw == [("rule 2", "MEDIUM"), ("rule 3", "INFO")]
    assert ids == {"MX-FW-05"}


def test_shadow_after_any_any_not_double_reported(capsys):
    _, out, ids = run(insecure(), capsys=capsys)
    assert "MX-FW-02" in ids and "MX-FW-05" not in ids


def test_rule_covers_edge_cases():
    r = lambda **kw: {"policy": "allow", "protocol": "any", "srcCidr": "Any", "destCidr": "Any",
                      "srcPort": "Any", "destPort": "Any", **kw}
    assert ma.rule_covers(r(destPort="1-1024"), r(protocol="udp", destPort="53"))
    assert not ma.rule_covers(r(protocol="tcp"), r(protocol="udp"))
    assert not ma.rule_covers(r(destPort="1-1024"), r(destPort="1000-2000"))
    assert ma.rule_covers(r(srcCidr="10.0.0.0/8,192.168.0.0/16"), r(srcCidr="192.168.1.0/24,10.5.0.0/16"))
    assert not ma.rule_covers(r(srcCidr="10.0.0.0/8"), r(srcCidr="10.0.0.0/8,172.16.0.0/12"))
    assert ma.rule_covers(r(protocol="icmp", srcCidr="10.0.0.0/8"), r(protocol="icmp", srcCidr="10.1.1.1"))
    assert not ma.rule_covers(r(destPort="weird"), r(destPort="80"))


def test_access_policy_design(capsys):
    data = hardened()
    data["getNetworkSwitchAccessPolicies"] = [{
        "name": "desks", "accessPolicyType": "Hybrid authentication", "hostMode": "Multi-Host",
        "radiusServers": [{"host": "10.1.1.3"}], "radiusAccountingEnabled": False,
        "radius": {"criticalAuth": {"dataVlanId": 10}}}]
    _, out, ids = run(data, capsys=capsys)
    assert ids == {"SW-NAC-02", "SW-NAC-03", "SW-NAC-04", "SW-NAC-05"}
    assert "10.1.1.3" in json.dumps(out)


def test_vlan_helpers():
    assert ma.parse_vlans("all") is None and ma.parse_vlans("1-4094") is None
    assert ma.parse_vlans("1,10-12") == {1, 10, 11, 12}
    assert ma.compact_vlans({40, 10, 11, 12, 50}) == "10-12,40,50"


def test_spoofing_protection_log_only(capsys):
    data = hardened()
    data["getNetworkApplianceFirewallSettings"] = {"spoofingProtection": {"ipSourceGuard": {"mode": "log"}}}
    assert run(data, capsys=capsys)[2] == {"MX-SPOOF-01"}


def with_admin_ids(data, keys=False):
    data["getOrganizationAdmins"][0].update(id="A1", hasApiKey=keys)
    data["getOrganizationAdmins"][1].update(id="B1", hasApiKey=keys)
    return data


def test_api_usage(capsys):
    data = with_admin_ids(hardened(), keys=True)
    calls = []

    def api_requests(org_id, **kw):
        calls.append(kw)
        if kw.get("adminId") == "A1":
            return []
        if kw.get("adminId") == "B1":
            return [{"adminId": "B1", "method": "GET"}]
        if kw.get("method") == "POST":
            return [{"adminId": "B1", "method": "POST", "sourceIp": "198.51.100.7", "userAgent": "terraform"}] * 3
        if kw.get("method") == "PUT":
            return [{"adminId": "X9", "method": "PUT", "sourceIp": "203.0.113.9", "userAgent": "curl"}]
        if kw.get("version") == 0:
            return [{"adminId": "B1", "userAgent": "legacy-script"}]
        return []

    data["getOrganizationApiRequests"] = api_requests
    _, out, ids = run(data, "--log-days", "90", capsys=capsys)
    assert ids - {"ORG-ADM-06"} == {"ORG-API-01", "ORG-API-02", "ORG-API-03"}
    by = {(f["check_id"], f["resource"]): f for f in out["findings"]}
    assert by[("ORG-API-01", "a@acme.com")]["severity"] == "MEDIUM"
    assert ("ORG-API-01", "b@acme.com") not in by
    assert by[("ORG-API-02", "b@acme.com")]["severity"] == "INFO"
    assert "POST 3" in by[("ORG-API-02", "b@acme.com")]["detail"]
    assert "198.51.100.7" in by[("ORG-API-02", "b@acme.com")]["detail"]
    assert by[("ORG-API-02", "X9")]["severity"] == "LOW"
    assert all(c["timespan"] == 31 * 86400 for c in calls)  # API log keeps 31 days


def changes_fixture():
    return [
        {"ts": "2026-11-20T10:00:00Z", "adminId": "A1", "adminEmail": "a@acme.com",
         "page": "Organization settings", "label": "Two-factor authentication",
         "oldValue": "true", "newValue": "false"},
        {"ts": "2026-11-19T10:00:00Z", "adminId": "G1", "adminEmail": "gone@acme.com",
         "page": "Firewall", "label": "L3 firewall rules", "networkId": "N1", "networkName": "HQ",
         "oldValue": "[]", "newValue": "[...]"},
        {"ts": "2026-11-18T10:00:00Z", "adminId": "V1", "adminEmail": "x@vendor.io",
         "page": "Access control", "label": "PSK", "networkId": "N1", "networkName": "HQ",
         "oldValue": "OldSecretPsk123", "newValue": "NewSecretPsk456"},
        {"ts": "2026-11-17T10:00:00Z", "adminId": "A1", "adminEmail": "a@acme.com",
         "page": "Network-wide settings", "label": "Syslog servers", "networkId": "N9",
         "networkName": "Other", "oldValue": "x", "newValue": "y"},
        {"ts": "2026-11-16T10:00:00Z", "adminId": "A1", "adminEmail": "a@acme.com",
         "page": "Switch ports", "label": "Port name", "networkId": "N1", "networkName": "HQ",
         "oldValue": "a", "newValue": "b"},
    ]


def test_config_changes(capsys):
    data = with_admin_ids(hardened())
    data["getOrganizationConfigurationChanges"] = changes_fixture()
    _, out, ids = run(data, "--trusted-domain", "acme.com", capsys=capsys)
    assert ids == {"ORG-CHG-01", "ORG-CHG-02", "ORG-CHG-03", "ORG-CHG-04"}
    f = {(x["check_id"], x["resource"]): x for x in out["findings"]}
    assert "Two-factor" in f[("ORG-CHG-01", "")]["detail"]
    # SAML is enabled in the hardened fixture, so unknown admins are only INFO
    assert f[("ORG-CHG-02", "gone@acme.com")]["severity"] == "INFO"
    assert f[("ORG-CHG-03", "x@vendor.io")]["severity"] == "MEDIUM"
    areas = {r for (c, r) in f if c == "ORG-CHG-04"}
    assert areas == {"Identity & access", "Firewall & threat protection",
                     "Logging & monitoring", "Wireless & port authentication"}
    blob = json.dumps(out)
    assert "SecretPsk" not in blob and "Port name" not in blob


def test_config_changes_respect_network_filter(capsys):
    data = with_admin_ids(hardened())
    data["getOrganizationConfigurationChanges"] = changes_fixture()
    _, out, _ = run(data, "--network-id", "N1", capsys=capsys)
    assert "Syslog" not in json.dumps(out)


def test_ap_usb_reports_only_enabled_profiles(capsys):
    _, out, _ = run(insecure(), "--network-tag", "prod", capsys=capsys)
    usb = [f for f in out["findings"] if f["check_id"] == "WL-USB-01"]
    assert [f["resource"] for f in usb] == ["Default"]
    assert "default profile" in usb[0]["detail"]
