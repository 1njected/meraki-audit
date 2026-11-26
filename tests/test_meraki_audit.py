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
        "getOrganizationLoginSecurity": {"enforceTwoFactorAuth": False, "minimumPasswordLength": 8,
                                         "enforcePasswordExpiration": True, "passwordExpirationDays": 30,
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
        "getNetworkWebhooksHttpServers": [
            {"id": "h1", "name": "ticketing", "enabled": True,
             "url": "http://hooks.vendor.io/in/TOKEN123?key=abc",
             "payloadTemplate": {"payloadTemplateId": "wpt_9", "name": "Mine"}}],
        "getNetworkWebhooksPayloadTemplates": [
            {"payloadTemplateId": "wpt_9", "type": "custom", "name": "Mine",
             "headers": [{"name": "Content-Type", "template": "application/json"}],
             "body": "{\"alert\": \"{{alertTypeId}}\"}"}],
        "getOrganizationWebhooksLogs": [
            {"networkId": "N1", "url": "http://hooks.vendor.io/in/TOKEN123?key=abc", "responseCode": 500},
            {"networkId": "N1", "url": "http://hooks.vendor.io/in/TOKEN123?key=abc", "responseCode": None}],
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
        "getNetworkSwitchDhcpServerPolicy": {"defaultPolicy": "allow", "alerts": {"email": {"enabled": False}},
                                             "arpInspection": {"enabled": False}},
        "getNetworkSwitchAccessPolicies": [],
    }


def hardened() -> dict:
    now = int(time.time())
    today = time.strftime("%Y-%m-%dT00:00:00Z")
    return {
        "getOrganizations": [ORG],
        "getOrganizationLoginSecurity": {"enforceTwoFactorAuth": True, "minimumPasswordLength": 14,
                                         "numDifferentPasswords": 5, "enforcePasswordExpiration": False,
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
        "getNetworkAlertsSettings": {"defaultDestinations": {"allAdmins": True, "httpServerIds": ["h1"]},
                                     "alerts": [{"type": "settingsChanged", "enabled": True}]},
        "getNetworkWebhooksHttpServers": [
            {"id": "h1", "name": "siem", "enabled": True, "url": "https://siem.acme.com/meraki",
             "payloadTemplate": {"payloadTemplateId": "wpt_00001", "name": "Meraki (included)"}}],
        "getNetworkWebhooksPayloadTemplates": [
            {"payloadTemplateId": "wpt_00001", "type": "included", "name": "Meraki (included)"}],
        "getOrganizationWebhooksLogs": [{"networkId": "N1", "url": "https://siem.acme.com/meraki",
                                         "responseCode": 200}],
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
             "radiusServers": [{"host": "10.1.1.3", "radsecEnabled": True}], "ipAssignmentMode": "Bridge mode"},
            {"number": 1, "name": "Guest", "enabled": True, "authMode": "psk", "encryptionMode": "wpa",
             "wpaEncryptionMode": "WPA2 only", "psk": "Tr0ub4dor&3-Horse-Staple!", "ipAssignmentMode": "NAT mode"},
        ],
        "getNetworkWirelessSsidFirewallL3FirewallRules": {"allowLanAccess": False, "rules": []},
        "getNetworkWirelessBluetoothSettings": {"scanningEnabled": False, "advertisingEnabled": False},
        "getNetworkWirelessEthernetPortsProfiles": [
            {"profileId": "1", "name": "Default", "isDefault": True, "ports": [],
             "usbPorts": [{"name": "usb port", "enabled": False}]}],
        "getNetworkSwitchStp": {"rstpEnabled": True},
        "getNetworkSwitchDhcpServerPolicy": {"defaultPolicy": "block", "alerts": {"email": {"enabled": True}},
                                             "arpInspection": {"enabled": True, "unsupportedModels": []}},
        "getNetworkDevices": [{"serial": "Q1", "name": "sw1", "model": "MS250-48", "productType": "switch"},
                              {"serial": "Q2", "name": "ap1", "model": "MR46", "productType": "wireless"}],
        "getDeviceSwitchPorts": [
            {"portId": "1", "enabled": True, "type": "trunk", "daiTrusted": True},
            {"portId": "2", "enabled": True, "type": "access", "daiTrusted": False}],
        "getNetworkSwitchAccessPolicies": [{
            "name": "dot1x", "accessPolicyType": "802.1x", "hostMode": "Multi-Domain",
            "radiusServers": [{"host": "10.1.1.3", "radsec": {"enabled": True}},
                              {"host": "10.2.1.3", "radsec": {"enabled": True}}],
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
        "ORG-LS-01", "ORG-LS-02", "ORG-LS-03", "ORG-LS-05", "ORG-LS-09", "ORG-LS-11", "ORG-SSO-01",
        "ORG-ADM-03", "ORG-ADM-04", "ORG-ADM-05", "ORG-ADM-06", "ORG-ADM-07",
        "ORG-SNMP-01", "ORG-SNMP-02", "ORG-SNMP-03", "ORG-SNMP-04",
        "ORG-VPN-01", "ORG-VPN-02", "ORG-VPN-04", "ORG-VPN-06", "WL-AM-01",
        "SW-PORT-01", "SW-PORT-02", "SW-PORT-03", "SW-PORT-04",
        "NET-MGMT-01", "NET-MGMT-02", "NET-SNMP-01", "NET-LOG-01", "NET-ALERT-01", "NET-ALERT-02",
        "FW-02", "FW-03", "MX-FW-01", "MX-FW-02", "MX-NAT-01", "MX-NAT-02", "MX-SVC-01", "MX-SVC-02",
        "MX-IPS-01", "MX-AMP-01", "MX-CF-01",
        "WL-SSID-01", "WL-SSID-02", "WL-SSID-04", "WL-SSID-05", "WL-SSID-06", "WL-SSID-07",
        "WL-SSID-08", "WL-SSID-10", "WL-BT-01", "WL-BT-02", "WL-USB-01",
        "NET-HOOK-01", "NET-HOOK-02", "NET-HOOK-04", "ORG-HOOK-01",
        "SW-STP-01", "SW-DHCP-01", "SW-DHCP-02", "SW-NAC-01", "SW-DAI-01",
    }
    assert expected - ids == set(), f"missing: {sorted(expected - ids)}"
    # disabled SSIDs are ignored
    assert not any("Unconfigured" in f["detail"] for f in out["findings"])
    # inbound firewall 404 is recorded as skipped, not a crash
    assert any(s["check"] == "mx-inbound-firewall" for s in out["skipped"])


def test_secrets_never_in_report(capsys):
    _, out, _ = run(insecure(), capsys=capsys)
    blob = json.dumps(out)
    for secret in ("corp1234", "public", '"short"', "TOKEN123", "key=abc"):
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
            return [{"adminId": "X9", "method": "PUT", "sourceIp": "93.184.216.34", "userAgent": "curl"}]
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


def support_changes(new_value="false"):
    return [
        {"ts": "2026-11-01T10:00:00Z", "adminId": "A1", "adminEmail": "a@acme.com",
         "page": "Organization settings", "label": "Block Meraki Support",
         "oldValue": "false", "newValue": "true"},
        {"ts": "2026-11-10T10:00:00Z", "adminId": "A1", "adminEmail": "a@acme.com",
         "page": "Organization settings", "label": "Block Meraki Support",
         "oldValue": "true", "newValue": new_value},
        {"ts": "2026-11-11T10:00:00Z", "adminName": "Meraki Support", "adminEmail": "",
         "page": "Firewall", "label": "L3 firewall rules", "networkId": "N1", "networkName": "HQ",
         "oldValue": "[]", "newValue": "[...]"},
    ]


def test_support_access_unblocked_and_support_changes(capsys):
    data = with_admin_ids(hardened())
    data["getOrganizationConfigurationChanges"] = support_changes("false")
    _, out, ids = run(data, capsys=capsys)
    assert {"ORG-SUP-01", "ORG-SUP-02"} <= ids
    sup = next(f for f in out["findings"] if f["check_id"] == "ORG-SUP-01")
    assert sup["severity"] == "MEDIUM" and "2026-11-10" in sup["detail"]
    assert not any(s["check"] == "support-access" for s in out.get("skipped", []))


def test_support_access_blocked_is_quiet(capsys):
    data = with_admin_ids(hardened())
    data["getOrganizationConfigurationChanges"] = support_changes("true")[:2]
    _, out, ids = run(data, capsys=capsys)
    assert not {"ORG-SUP-01", "ORG-SUP-02"} & ids
    assert not any(s["check"] == "support-access" for s in out.get("skipped", []))


def test_support_access_unknown_is_skipped(capsys):
    _, out, ids = run(hardened(), capsys=capsys)
    assert "ORG-SUP-01" not in ids
    assert any(s["check"] == "support-access" for s in out["skipped"])


def test_radsec(capsys):
    data = hardened()
    data["getNetworkWirelessSsids"][0]["radiusServers"] = [
        {"host": "10.1.1.3", "radsecEnabled": False}, {"host": "93.184.216.34", "radsecEnabled": False},
        {"host": "10.9.9.9"}]  # no field: unknown, not reported
    pol = data["getNetworkSwitchAccessPolicies"][0]
    pol["radiusServers"][1]["radsec"] = {"enabled": False}
    pol["radiusAccountingServers"] = [{"host": "10.2.1.3", "radsec": {"enabled": False}}]
    _, out, ids = run(data, capsys=capsys)
    f = {x["check_id"]: x for x in out["findings"] if "RADSEC" in x["check_id"]}
    assert set(f) == {"WL-RADSEC-01", "SW-RADSEC-01"}
    assert f["WL-RADSEC-01"]["severity"] == "MEDIUM"  # public RADIUS server
    assert "93.184.216.34" in f["WL-RADSEC-01"]["detail"] and "10.9.9.9" not in f["WL-RADSEC-01"]["detail"]
    assert f["SW-RADSEC-01"]["severity"] == "LOW"
    assert f["SW-RADSEC-01"]["detail"].count("10.2.1.3") == 1


def test_dai_trusted_ports(capsys):
    data = hardened()
    data["getNetworkSwitchDhcpServerPolicy"]["arpInspection"]["unsupportedModels"] = ["MS120-8"]
    calls = []
    data["getDeviceSwitchPorts"] = lambda serial: calls.append(serial) or [
        {"portId": "1", "enabled": True, "type": "trunk", "daiTrusted": False},
        {"portId": "5", "enabled": True, "type": "access", "daiTrusted": True},
        {"portId": "6", "enabled": False, "type": "access", "daiTrusted": True}]
    _, out, ids = run(data, capsys=capsys)
    f = {x["check_id"]: x for x in out["findings"] if x["check_id"].startswith("SW-DAI")}
    assert set(f) == {"SW-DAI-02", "SW-DAI-03", "SW-DAI-04"}
    assert f["SW-DAI-03"]["item"] == "1 access port(s): 5."  # disabled port 6 ignored
    assert calls == ["Q1"]  # only switches are queried


def test_dai_disabled_skips_port_calls(capsys):
    data = hardened()
    data["getNetworkSwitchDhcpServerPolicy"]["arpInspection"] = {"enabled": False}
    data["getDeviceSwitchPorts"] = lambda serial: pytest.fail("ports fetched with DAI off")
    _, out, ids = run(data, capsys=capsys)
    assert {i for i in ids if i.startswith("SW-DAI")} == {"SW-DAI-01"}


def test_password_policy(capsys):
    data = hardened()
    data["getOrganizationLoginSecurity"].update(minimumPasswordLength=10, numDifferentPasswords=2)
    _, out, ids = run(data, capsys=capsys)
    f = {x["check_id"]: x for x in out["findings"]}
    assert f["ORG-LS-02"]["severity"] == "MEDIUM"  # 2FA enforced in the hardened fixture
    assert "ORG-LS-10" in ids and "ORG-LS-11" not in ids
    _, out, ids = run(data, "--min-password-length", "10", "--password-history", "2", capsys=capsys)
    assert not {"ORG-LS-02", "ORG-LS-10"} & ids


def test_password_length_without_mfa_is_high(capsys):
    _, out, _ = run(insecure(), capsys=capsys)
    f = next(x for x in out["findings"] if x["check_id"] == "ORG-LS-02")
    assert f["severity"] == "HIGH" and "only 8 characters" in f["detail"]


def run_text(data, *args, capsys=None):
    ma.main(["-q", *args], dashboard=FakeDashboard(data))
    return capsys.readouterr().out


def test_grouped_text_lists_affected_once(capsys):
    data = insecure()  # N1 and N2 both have the same open SSIDs
    out = run_text(data, capsys=capsys)
    block = out.split("WL-SSID-02  Open SSID without any access control")[1].split("\n\n")[0]
    assert "(2 affected)" in block
    assert "Detail: Open with no splash page" in block
    assert "Acme / HQ - Guest" in block and "Acme / Lab - Guest" in block
    assert out.count("WL-SSID-02") == 1
    assert "distinct issues" in out


def test_grouping_keeps_item_specific_text(capsys):
    data = insecure()
    data["getOrganizationNetworks"] = [NET, {**NET2, "productTypes": ["wireless", "switch"]}]
    data["getOrganizationSwitchPortsBySwitch"].append(
        {"name": "sw2", "serial": "Q2", "network": {"id": "N2", "name": "Lab"},
         "ports": [{"portId": str(i), "enabled": True, "type": "access", "vlan": 1,
                    "stpGuard": "disabled"} for i in (7, 8)]})
    out = run_text(data, capsys=capsys)
    block = out.split("SW-PORT-04  Access ports without BPDU guard")[1].split("\n\n")[0]
    assert "Detail: A switch plugged into these ports" in block
    assert "Acme / HQ - sw1 - 1 access port(s): 2." in block
    assert "Acme / Lab - sw2 - 2 access port(s): 7, 8." in block


def test_no_group_and_json_unchanged(capsys):
    out = run_text(insecure(), "--no-group", capsys=capsys)
    assert out.count("WL-SSID-02") == 2 and "affected" not in out
    _, js, _ = run(insecure(), capsys=capsys)
    ssid = [f for f in js["findings"] if f["check_id"] == "WL-SSID-02"]
    assert len(ssid) == 2 and "why" not in ssid[0]


def test_markdown_grouped(capsys):
    ma.main(["-q", "--format", "markdown"], dashboard=FakeDashboard(insecure()))
    md = capsys.readouterr().out
    row = next(l for l in md.splitlines() if "| WL-SSID-02 |" in l)
    assert "(2)" in row and "Acme / HQ - Guest<br>Acme / Lab - Guest" in row


def test_webhooks(capsys):
    data = insecure()
    _, out, _ = run(data, "--trusted-webhook-domain", "acme.com", capsys=capsys)
    hooks = {f["check_id"]: f for f in out["findings"] if "HOOK" in f["check_id"]}
    assert hooks["NET-HOOK-01"]["severity"] == "HIGH"
    assert hooks["NET-HOOK-03"]["resource"] == "ticketing"
    assert "http://hooks.vendor.io" in hooks["NET-HOOK-01"]["detail"]
    log = hooks["ORG-HOOK-01"]
    assert log["severity"] == "MEDIUM" and "2 of 2" in log["detail"]
    assert "500" in log["detail"] and "no response" in log["detail"]


def test_webhooks_trust_and_ips(capsys):
    data = hardened()
    data["getNetworkWebhooksHttpServers"] = [
        {"id": "h1", "name": "siem", "url": "https://siem.acme.com/x",
         "payloadTemplate": {"payloadTemplateId": "wpt_00001"}},
        {"id": "h2", "name": "internal", "url": "http://10.1.1.9:8080/x",
         "payloadTemplate": {"payloadTemplateId": "wpt_00001"}},
        {"id": "h3", "name": "spoof", "url": "https://acme.com.evil.io/x",
         "payloadTemplate": {"payloadTemplateId": "wpt_00001"}},
        {"id": "h4", "name": "off", "enabled": False, "url": "http://8.8.8.8/x"}]
    data["getNetworkAlertsSettings"] = {"defaultDestinations": {"allAdmins": True,
                                                                "httpServerIds": ["h1", "h2", "h3"]},
                                        "alerts": []}
    data["getOrganizationWebhooksLogs"] = [
        {"networkId": "N1", "url": "https://siem.acme.com/x", "responseCode": 200},
        {"networkId": "N1", "url": "https://siem.acme.com/x", "responseCode": 404}]
    _, out, ids = run(data, "--trusted-webhook-domain", "acme.com", capsys=capsys)
    by = {(f["check_id"], f["resource"]): f for f in out["findings"]}
    assert by[("NET-HOOK-01", "internal")]["severity"] == "MEDIUM"   # private IP over HTTP
    assert ("NET-HOOK-03", "spoof") in by                              # suffix, not substring
    assert ("NET-HOOK-03", "siem") not in by and ("NET-HOOK-03", "internal") not in by
    assert not any(f["resource"] == "off" for f in out["findings"])   # disabled receiver ignored
    assert by[("ORG-HOOK-01", "https://siem.acme.com [HQ]")]["severity"] == "LOW"
    assert ids == {"NET-HOOK-01", "NET-HOOK-03", "ORG-HOOK-01"}


def test_webhook_template_with_secret_header_is_ok(capsys):
    data = hardened()
    data["getNetworkWebhooksHttpServers"][0]["payloadTemplate"] = {"payloadTemplateId": "wpt_1"}
    data["getNetworkWebhooksPayloadTemplates"] = [
        {"payloadTemplateId": "wpt_1", "type": "custom", "name": "c",
         "headers": [{"name": "Authorization", "template": "Bearer {{sharedSecret}}"}], "body": "{}"}]
    _, _, ids = run(data, capsys=capsys)
    assert ids == set()
    data["getNetworkWebhooksPayloadTemplates"][0]["headers"] = []
    _, _, ids = run(data, capsys=capsys)
    assert ids == {"NET-HOOK-02"}


def test_webhook_public_ip_info(capsys):
    data = hardened()
    data["getNetworkWebhooksHttpServers"][0]["url"] = "https://8.8.8.8/x"
    _, _, ids = run(data, capsys=capsys)
    assert ids == {"NET-HOOK-05"}
    assert ma.webhook_host("https://u:p@[2001:db8::1]:8443/t?k=v") == (
        "https", "2001:db8::1", "https://[2001:db8::1]:8443")


def ogp_rule(rid, rs, name, policy, prio, src=None, dst=None, enabled=True, log=True):
    def side(c):
        if not c:
            return {"matchCriteria": ["any"], "criteria": {}}
        return {"matchCriteria": list(c), "criteria": c}
    return {"ruleId": rid, "rulesetId": rs, "name": name, "policy": policy, "priority": prio,
            "enabled": enabled, "logging": {"enabled": log}, "sources": side(src), "destinations": side(dst)}


def org_group_policies(data):
    data["getOrganizationPoliciesGlobalGroupPolicies"] = {"items": [
        {"policyId": "P1", "name": "Stores"}, {"policyId": "P2", "name": "NoRules"},
        {"policyId": "P3", "name": "Orphan"}, {"policyId": "P4", "name": "EmptyRs"}]}
    data["getOrganizationPoliciesGlobalFirewallRulesets"] = {"items": [
        {"rulesetId": "R1", "name": "store-out"}, {"rulesetId": "R2", "name": "empty"},
        {"rulesetId": "R3", "name": "unused"}]}
    data["getOrganizationPoliciesGlobalFirewallRulesetsRules"] = {"items": [
        ogp_rule("1", "R1", "web", "allow", 1, src={"addressRanges": ["10.0.0.0/8"]},
                 dst={"services": [{"protocol": "tcp", "ports": ["80", "443"]}]}),
        ogp_rule("2", "R1", "block lab web", "deny", 2, src={"addressRanges": ["10.9.0.0/16"]},
                 dst={"services": [{"protocol": "tcp", "ports": ["443"]}]}, log=False),
        ogp_rule("3", "R1", "gmail", "deny", 3, dst={"applications": [{"id": "meraki:layer7/application/5"}]}),
        ogp_rule("4", "R1", "old", "deny", 4, enabled=False),
        ogp_rule("5", "R1", "allow all", "allow", 5),
        ogp_rule("6", "R3", "anything", "allow", 1)]}
    data["getOrganizationPoliciesGlobalGroupPoliciesFirewallRulesetsAssignments"] = {"items": [
        {"assignmentId": "A1", "rulesetId": "R1", "policyId": "P1", "priority": 1},
        {"assignmentId": "A2", "rulesetId": "R2", "policyId": "P4", "priority": 1}]}
    data["getOrganizationPoliciesGlobalGroupPoliciesApplianceVlansAssignments"] = {"items": [
        {"assignmentId": "V1", "policyId": "P1", "interfaceId": "N1_vlan_20"},
        {"assignmentId": "V2", "policyId": "P2", "interfaceId": "N1_vlan_30"},
        {"assignmentId": "V3", "policyId": "P4", "interfaceId": "N2_vlan_40"}]}
    data["getOrganizationPoliciesGlobalGroupPoliciesAdaptivePolicyGroupsAssignments"] = {"items": []}
    data["getOrganizationPoliciesGlobalGroupPoliciesNetworksAssignments"] = {"items": []}
    return data


def test_org_group_policies(capsys):
    _, out, ids = run(org_group_policies(hardened()), capsys=capsys)
    ogp = {(f["check_id"], f["severity"], f["resource"]) for f in out["findings"]
           if f["check_id"].startswith("ORG-OGP")}
    assert ogp == {
        ("ORG-OGP-01", "HIGH", "ruleset store-out rule 4"),     # 4th active rule ('old' is disabled)
        ("ORG-OGP-02", "HIGH", "ruleset empty"),
        ("ORG-OGP-03", "LOW", "policy NoRules"),
        ("ORG-OGP-04", "INFO", "policy Orphan"),
        ("ORG-OGP-05", "INFO", "ruleset unused"),               # its any/any rule is not enforced
        ("ORG-OGP-06", "LOW", "ruleset store-out"),
        ("ORG-OGP-07", "INFO", "ruleset store-out"),
        ("ORG-OGP-08", "MEDIUM", "ruleset store-out rule 2"),   # deny 10.9/16:443 under allow 10/8:80,443
    }
    assert ids == {f[0] for f in ogp}
    no_log = next(f for f in out["findings"] if f["check_id"] == "ORG-OGP-06")
    assert "block lab web" in no_log["detail"] and "gmail" not in no_log["detail"]


def test_org_group_policy_vlans_annotate_network_firewall(capsys):
    _, out, _ = run(org_group_policies(insecure()), capsys=capsys)
    fw = next(f for f in out["findings"] if f["check_id"] == "MX-FW-02" and f["network_id"] == "N1")
    assert fw["severity"] == "HIGH"
    assert "20 (org-wide policy 'Stores')" in fw["detail"] and "30 (org-wide policy 'NoRules')" in fw["detail"]


def test_org_group_policies_unavailable_is_skipped(capsys):
    _, out, ids = run(hardened(), "-v", capsys=capsys)
    assert not any(i.startswith("ORG-OGP") for i in ids)
    assert any(s["check"] == "org-group-policies" for s in out["skipped"])


def test_ogp_as_l3():
    assert ma.ogp_as_l3(ogp_rule("1", "R", "x", "allow", 1)) == {
        "policy": "allow", "comment": "x", "protocol": "any",
        "srcCidr": "Any", "srcPort": "Any", "destCidr": "Any", "destPort": "Any"}
    assert ma.ogp_as_l3(ogp_rule("1", "R", "x", "deny", 1, dst={"fqdns": ["*.example.com"]})) is None
    two = {"services": [{"protocol": "tcp", "ports": ["22"]}, {"protocol": "udp", "ports": ["53"]}]}
    assert ma.ogp_as_l3(ogp_rule("1", "R", "x", "deny", 1, dst=two)) is None


def test_all_firewall_any_any_rules_are_high(capsys):
    data = org_group_policies(insecure())
    data["getOrganizationApplianceVpnVpnFirewallRules"] = {"rules": [
        {"comment": "open", "policy": "allow", "protocol": "any", "srcCidr": "Any", "destCidr": "Any",
         "destPort": "Any"}, {"comment": "Default rule", "policy": "allow"}]}
    _, out, _ = run(data, capsys=capsys)
    sev = {f["check_id"]: f["severity"] for f in out["findings"]
           if f["check_id"] in ("MX-FW-02", "ORG-VPN-07", "ORG-OGP-01", "ORG-OGP-02")}
    assert sev == dict.fromkeys(("MX-FW-02", "ORG-VPN-07", "ORG-OGP-01", "ORG-OGP-02"), "HIGH")
