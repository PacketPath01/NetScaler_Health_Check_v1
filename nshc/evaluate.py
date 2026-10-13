"""Apply the workbook checks and the extra deployment findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from nshc.advisories import AS_OF, Advisory, assess, recommended_build
from nshc.catalog import CheckDef
from nshc.cleanup import inventory_notes
from nshc.hardening import notes as hardening_notes
from nshc.parse import Appliance, IpDetail
from nshc.performance import notes as performance_notes

FAIL = "fail"
PASS = "pass"
NA = "na"
REVIEW = "review"


@dataclass
class Outcome:
    id: str
    title: str
    focus: str
    status: str
    risk: str
    wording: str
    evidence: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    kind: str = "check"
    likelihood: int | None = None
    impact: int | None = None


def evaluate(app: Appliance, checks: list[CheckDef]) -> list[Outcome]:
    outcomes: list[Outcome] = []
    for check in checks:
        if app.platform not in check.platforms:
            outcomes.append(_outcome(check, NA, [f"Platform is {app.platform}; this check targets {', '.join(check.platforms)}."]))
            continue
        status, evidence = _run(app, check.id)
        outcomes.append(_outcome(check, status, evidence))
    outcomes.extend(_extras(app))
    outcomes.extend(_advisories(app))
    return outcomes


def _outcome(check: CheckDef, status: str, evidence: list[str]) -> Outcome:
    risk = check.risk if status in {FAIL, REVIEW} else "INFO"
    return Outcome(
        id=check.id,
        title=check.title,
        focus=check.focus,
        status=status,
        risk=risk,
        wording=check.wording or check.title,
        evidence=evidence,
        resources=check.resources,
        likelihood=check.likelihood,
        impact=check.impact,
    )


def _yes(value: str) -> bool:
    return value.upper() in {"ENABLED", "ON", "YES", "SECUREONLY"}


def _off(value: str) -> bool:
    return value.upper() in {"DISABLED", "OFF", "NO"}


def _nsips(app: Appliance) -> list[IpDetail]:
    return [ip for ip in app.ips if "netscaler" in ip.type.lower()]


def _managed(app: Appliance) -> list[IpDetail]:
    return [ip for ip in app.ips if ip.management and _yes(ip.management) and "netscaler" not in ip.type.lower()]


def _profiles(app: Appliance, protocol: str, state: str) -> list[str]:
    return [item.name for item in app.ssl_profiles if item.protocols.get(protocol, "").upper() == state]


def _alarm_unset(app: Appliance, name: str) -> bool | None:
    row = app.snmp_alarms.get(name)
    if row is None:
        return None
    return "UNSET" in row.split()


def _alarm_enabled(app: Appliance, name: str) -> bool | None:
    row = app.snmp_alarms.get(name)
    if row is None:
        return None
    return "ENABLED" in row.split()


def _sys(app: Appliance, key: str) -> str:
    return app.system.get(key, "")


def _bound_profiles(app: Appliance) -> set[str]:
    return {profile for _, profile in app.ssl_vservers}


def _aaa_stack(app: Appliance) -> bool:
    return bool(app.auth_vservers or app.vpn_vservers or app.saml_sp or app.saml_idp or app.features.get("AAA") or app.features.get("SSLVPN"))


def _run(app: Appliance, check_id: str) -> tuple[str, list[str]]:
    version = app.version
    supported = bool(version and version.train in {(13, 1), (14, 1)})
    if check_id in {"nshc000001", "nshc004001"}:
        if version is None:
            return REVIEW, ["No build number was found in ns.conf or show ns version."]
        if supported:
            return PASS, [f"Build {version.label} is on a supported train."]
        return FAIL, [f"Build {version.label} is on an end-of-life train. Move to {recommended_build(version)}."]

    if check_id == "nshc000002":
        return (FAIL, ["L3 mode is ON."]) if app.mode_on("L3") else (PASS, ["L3 mode is OFF."])
    if check_id == "nshc000003":
        return (FAIL, ["L2 mode is ON."]) if app.mode_on("L2") else (PASS, ["L2 mode is OFF."])
    if check_id == "nshc000004":
        return (FAIL, ["Edge mode is ON."]) if app.mode_on("Edge") else (PASS, ["Edge mode is OFF."])
    if check_id == "nshc000005":
        if app.mode_on("MBF"):
            return FAIL, ["MAC-based forwarding is ON. Leave it ON only for a cloud VPX that requires it."]
        return PASS, ["MAC-based forwarding is OFF."]
    if check_id == "nshc000006":
        return (FAIL, ["Surge Protection (SP) is enabled."]) if app.features.get("SP") else (PASS, ["Surge Protection is off."])
    if check_id == "nshc000007":
        return (FAIL, ["Web Logging (WL) is enabled."]) if app.features.get("WL") else (PASS, ["Web Logging is off."])
    if check_id == "nshc000008":
        if app.ha_nodes <= 0:
            return REVIEW, ["show HA node was not in the collector."]
        if app.ha_nodes < 2:
            return FAIL, ["Only the local HA node is present. The appliance is standalone."]
        return PASS, [f"{app.ha_nodes} HA nodes are present."]
    if check_id == "nshc000009":
        if app.ha_nodes < 2:
            return NA, ["Fail-safe applies to an HA pair. This appliance is not in HA."]
        if app.fail_safe == "ON":
            return PASS, ["Fail-safe mode is ON."]
        return FAIL, [f"Fail-safe mode is {app.fail_safe or 'not reported'}."]
    if check_id in {"nshc000010", "nshc000011"}:
        if app.route_monitors == 0:
            return NA, ["No HA route monitors were found, so maxFlips does not apply."]
        if app.ha_maxflips:
            return PASS, ["HA maxFlips is configured."]
        return FAIL, ["Route monitors exist and HA maxFlips / maxFlipsTime were not found."]
    if check_id == "nshc000012":
        weak = [item["name"] for item in app.interfaces if not item["name"].startswith("LO") and "HAMON" not in item["flags"] and "UP" in item["flags"]]
        if not app.interfaces:
            return REVIEW, ["show interface was not collected."]
        if weak:
            return FAIL, [f"HA monitoring is off on up interfaces: {', '.join(weak)}."]
        return PASS, ["Up data interfaces include HA monitoring."]
    if check_id == "nshc000013":
        if app.syslog_servers:
            return PASS, [f"{app.syslog_servers} remote syslog or nslog action(s) are configured."]
        return FAIL, ["No remote syslog or nslog action was found."]
    if check_id == "nshc000014":
        return (PASS, [f"{app.snmp_traps_generic} generic trap destination(s)."]) if app.snmp_traps_generic else (FAIL, ["No generic SNMP trap destination."])
    if check_id == "nshc000015":
        return (PASS, [f"{app.snmp_traps_specific} specific trap destination(s)."]) if app.snmp_traps_specific else (FAIL, ["No specific SNMP trap destination."])
    if check_id == "nshc000016":
        return _threshold(app, "CPU-USAGE", "CPU")
    if check_id == "nshc000017":
        return _threshold(app, "MEMORY", "memory")
    if check_id == "nshc000018":
        return _threshold(app, "DISK-USAGE-HIGH", "disk")
    if check_id == "nshc000019":
        return _license_alarm(app, "POOLED-LICENSE-CHECKOUT-FAILURE")
    if check_id == "nshc000020":
        return _license_alarm(app, "POOLED-LICENSE-ONGRACE")
    if check_id == "nshc000021":
        return _license_alarm(app, "POOLED-LICENSE-PARTIAL")
    if check_id == "nshc000022":
        if app.snmp_communities:
            return FAIL, [f"{app.snmp_communities} SNMP v1/v2 community is configured. Use SNMPv3 authPriv instead."]
        return PASS, ["No SNMP v1/v2 community was found."]
    if check_id == "nshc000023":
        nsroot = next((user for user in app.users if user["name"] == "nsroot"), None)
        if nsroot is None:
            return REVIEW, ["nsroot was not listed in show system user."]
        if nsroot["external"] == "ENABLED":
            return FAIL, ["External authentication is enabled for nsroot."]
        return PASS, ["External authentication is disabled for nsroot."]
    if check_id == "nshc000024":
        others = [user["name"] for user in app.users if user["name"] != "nsroot"]
        if others:
            return PASS, [f"Local accounts besides nsroot: {', '.join(others)}. Confirm one is dedicated to NetScaler Console."]
        return FAIL, ["Only nsroot is defined. Create a dedicated local account for NetScaler Console."]
    if check_id == "nshc000025":
        return (PASS, [f"{app.snmp_managers} SNMP manager(s)."]) if app.snmp_managers else (FAIL, ["No SNMP manager restriction is configured."])
    if check_id == "nshc000026":
        prompt = app.prompt.strip().strip('"').strip()
        if "%h" in prompt or "%u" in prompt or "%s" in prompt:
            return PASS, ["CLI prompt includes hostname, user, or HA state."]
        return FAIL, ["CLI prompt is empty or does not identify the appliance."]
    if check_id == "nshc000027":
        raw = _sys(app, "minpasswordlen")
        if not raw:
            return REVIEW, ["Minimum password length was not in show system parameter."]
        if int(float(raw)) < 12:
            return FAIL, [f"Minimum password length is {raw}. Use 12 or more."]
        return PASS, [f"Minimum password length is {raw}."]
    if check_id == "nshc000028":
        value = _sys(app, "strongpassword").lower()
        if value in {"enablelocal", "enableall", "enabled"}:
            return PASS, [f"strongpassword is {value}."]
        if not value:
            return REVIEW, ["strongpassword was not reported."]
        return FAIL, [f"strongpassword is {value}. Set it to enablelocal."]
    if check_id == "nshc000029":
        value = _sys(app, "forcepasswordchange")
        if value.upper() == "ENABLED":
            return PASS, ["forcePasswordChange is ENABLED."]
        return FAIL, [f"forcePasswordChange is {value or 'not set'}."]
    if check_id == "nshc000030":
        return _nsip_flag(app, lambda ip: not _yes(ip.restrict) or not _off(ip.ftp) or not _off(ip.telnet) or ip.gui.upper() not in {"SECUREONLY"}, "NSIP is missing one or more of restrictAccess, FTP disabled, Telnet disabled, and GUI SECUREONLY.")
    if check_id == "nshc000031":
        return _nsip_flag(app, lambda ip: ip.gui.upper() != "SECUREONLY", "Management GUI is not SECUREONLY.")
    if check_id == "nshc000032":
        return _nsip_flag(app, lambda ip: not _yes(ip.restrict), "restrictAccess is not enabled on the NSIP.")
    if check_id == "nshc000033":
        return _nsip_flag(app, lambda ip: not _off(ip.telnet), "Telnet is enabled on the NSIP.")
    if check_id == "nshc000034":
        return _nsip_flag(app, lambda ip: not _off(ip.ftp), "FTP is enabled on the NSIP.")
    if check_id == "nshc000035":
        return _nsip_flag(app, lambda ip: _off(ip.snmp), "SNMP is disabled on the NSIP.", passing="SNMP is enabled on the NSIP.")
    if check_id == "nshc000036":
        raw = _sys(app, "timeout")
        if not raw:
            return REVIEW, ["Management session timeout was not reported."]
        if int(float(raw)) > 600:
            return FAIL, [f"Management session timeout is {raw} seconds. 600 seconds is the recommended maximum."]
        return PASS, [f"Management session timeout is {raw} seconds."]
    if check_id == "nshc000037":
        if app.cookie_version == "1":
            return PASS, ["Cookie version is 1."]
        if app.cookie_version == "":
            return REVIEW, ["Cookie version was not reported."]
        return FAIL, [f"Cookie version is {app.cookie_version}. Enable version 1."]
    if check_id == "nshc000038":
        return _http_flag(app, "dropinvalidhttprequests", "drop invalid HTTP requests")
    if check_id == "nshc000039":
        return _http_flag(app, "markhttp/0.9requestsasinvalid", "mark HTTP/0.9 invalid")
    if check_id == "nshc000040":
        return _http_flag(app, "markconnectrequestsasinvalid", "mark CONNECT invalid")
    if check_id == "nshc000041":
        value = app.tcp.get("windowscalingstatus", "")
        if value.upper() == "ENABLED":
            return PASS, ["TCP window scaling is enabled."]
        if not value:
            return REVIEW, ["TCP window scaling was not reported."]
        return FAIL, [f"TCP window scaling is {value}."]
    if check_id == "nshc000042":
        value = app.tcp.get("selectiveacknowledgement(sack)status", "")
        if value.upper() == "ENABLED":
            return PASS, ["TCP SACK is enabled."]
        if not value:
            return REVIEW, ["TCP SACK was not reported."]
        return FAIL, [f"TCP SACK is {value}."]
    if check_id == "nshc000043":
        if app.deny_reneg in {"NONSECURE", "ALL"}:
            return PASS, [f"Global denySSLReneg is {app.deny_reneg}."]
        weak = [item.name for item in app.ssl_profiles if item.reneg and item.reneg not in {"NONSECURE", "ALL"}]
        if weak:
            return FAIL, [f"SSL renegotiation is not restricted on: {', '.join(weak)}."]
        if not app.deny_reneg:
            return REVIEW, ["denySSLReneg was not reported."]
        return FAIL, [f"Global denySSLReneg is {app.deny_reneg}."]
    if check_id == "nshc000044":
        if app.default_profile == "ENABLED":
            return PASS, ["SSL default profile is enabled."]
        if not app.default_profile:
            return REVIEW, ["SSL default profile state was not reported."]
        return FAIL, ["SSL default profile is not enabled. Bind profiles before enabling it; the change cannot be reversed."]
    if check_id in {"nshc000045", "nshc000057", "nshc000060"}:
        physical = [item for item in app.interfaces if not item["name"].startswith("LO")]
        if app.channels == 0 and len(physical) <= 1:
            return NA, ["This appliance has a single data interface and no LACP channel."]
        if check_id == "nshc000060" and app.channels == 0:
            return FAIL, ["No LACP channel is configured."]
        if check_id == "nshc000045":
            return REVIEW, ["Confirm HA monitoring is enabled on the LACP channel itself."]
        return REVIEW, ["Confirm member interfaces of each LACP channel are not individually HA-monitored."]
    if check_id == "nshc000046":
        if not (app.saml_sp or app.saml_idp):
            return NA, ["No SAML SP or IdP object is configured."]
        if app.saml_relay:
            return PASS, ["A relay-state setting was found on a SAML object."]
        return FAIL, [f"SAML is configured ({len(app.saml_sp)} SP, {len(app.saml_idp)} IdP) and no relay-state rule was found."]
    if check_id == "nshc000047":
        return _protocol(app, "SSLv3")
    if check_id == "nshc000048":
        return _protocol(app, "TLSv1.0")
    if check_id == "nshc000049":
        return _protocol(app, "TLSv1.1")
    if check_id == "nshc000050":
        weak = [
            item.name
            for item in app.ssl_profiles
            if item.protocols and item.protocols.get("TLSv1.2") == "DISABLED" and item.protocols.get("TLSv1.3") == "DISABLED"
        ]
        if not app.ssl_profiles:
            return REVIEW, ["No SSL profiles were collected."]
        if weak:
            return FAIL, [f"Profiles with neither TLS 1.2 nor TLS 1.3: {', '.join(weak)}."]
        return PASS, ["Every reported SSL profile allows TLS 1.2 or TLS 1.3."]
    if check_id == "nshc000051":
        bound = _bound_profiles(app)
        missing = [item.name for item in app.ssl_profiles if item.name in bound and item.protocols.get("TLSv1.3") == "DISABLED"]
        if not bound:
            return REVIEW, ["No SSL virtual server profile binding was collected."]
        if missing:
            return REVIEW, [f"TLS 1.3 is not enabled on bound profiles: {', '.join(missing)}. Enable it after an application compatibility check."]
        return PASS, ["TLS 1.3 is enabled on the SSL profiles bound to virtual servers."]
    if check_id == "nshc000052":
        return (PASS, ["KEK use was found in the saved configuration."]) if app.kek_present else (FAIL, ["No KEK indicator was found."])
    if check_id == "nshc000053":
        if app.enhanced_feedback in {"NO", "DISABLED"}:
            return PASS, ["Enhanced authentication feedback is off."]
        if app.enhanced_feedback in {"YES", "ENABLED"}:
            return FAIL, ["Enhanced authentication feedback is on and can reveal why a login failed."]
        return REVIEW, ["Enhanced authentication feedback was not reported."]
    if check_id == "nshc000054":
        bound = _bound_profiles(app) or {"ns_default_ssl_profile_frontend"}
        missing = [item.name for item in app.ssl_profiles if item.name in bound and item.hsts == "DISABLED" and "Back-End" not in item.role]
        if missing:
            return FAIL, [f"HSTS is disabled on: {', '.join(missing)}."]
        if not app.ssl_profiles:
            return REVIEW, ["SSL profiles were not collected."]
        return PASS, ["HSTS is enabled on the frontend profiles bound to virtual servers."]
    if check_id == "nshc000055":
        if not app.features.get("SSLVPN") and not app.vpn_vservers:
            return NA, ["SSL VPN is not in use."]
        if app.vpn_auth.upper() == "DENY":
            return PASS, ["Gateway default authorization is DENY."]
        if not app.vpn_auth:
            return REVIEW, ["VPN default authorization was not reported."]
        return FAIL, [f"Gateway default authorization is {app.vpn_auth}."]
    if check_id == "nshc000056":
        if version and (version.train > (14, 1) or (version.train == (14, 1) and (version.build, version.sub) >= (4, 0))):
            return PASS, [f"{version.label} includes RFC 5961 TCP spoofing protection."]
        attack = app.tcp.get("synattackdetectionenable/disable", "")
        if attack.upper() == "ENABLED":
            return PASS, ["SYN attack detection is enabled. Confirm the release-specific TCP spoofing control as well."]
        return REVIEW, ["This build may need the explicit TCP spoofing defense. Confirm it in the TCP parameters."]
    if check_id == "nshc000058":
        crowded = []
        for vlan in app.vlans:
            data = [name for name in vlan["interfaces"] if not str(name).startswith("LO")]
            if len(data) > 1:
                crowded.append(f"VLAN {vlan['id']} ({', '.join(data)})")
        if not app.vlans:
            return REVIEW, ["show vlan was not collected."]
        if crowded:
            return FAIL, [f"VLANs bound to more than one data interface: {'; '.join(crowded)}."]
        return PASS, ["Each VLAN is bound to a single data interface."]
    if check_id == "nshc000059":
        snips = [ip.address for ip in app.ips if "SNIP" in ip.type.upper()]
        if not snips:
            return NA, ["No SNIP was found."]
        if app.vlan_ip_binds:
            return PASS, [f"{app.vlan_ip_binds} VLAN IP binding(s) are in ns.conf."]
        return FAIL, [f"{len(snips)} SNIP(s) have no VLAN IP binding in ns.conf."]
    if check_id == "nshc000061":
        dh = [item.name for item in app.ssl_profiles if item.dh == "ENABLED"]
        if dh:
            return FAIL, [f"DH is enabled on: {', '.join(dh)}. Prefer ECDHE."]
        if not app.ssl_profiles:
            return REVIEW, ["SSL profiles were not collected."]
        return PASS, ["No SSL profile reported DH as enabled."]
    if check_id == "nshc000062":
        return (PASS, [f"{app.acls} ACL(s) are configured."]) if app.acls else (FAIL, ["No extended ACL was found for the management plane."])
    if check_id == "nshc000063":
        return (PASS, [f"{app.pbrs} policy-based route(s)."]) if app.pbrs else (REVIEW, ["No PBR was found. Use one if management traffic must stay on the management network."])
    if check_id == "nshc000064":
        exposed = _managed(app)
        kinds = sorted({ip.type for ip in exposed} | set(app.config_mgmt_non_nsip))
        if not app.ips and not kinds:
            return REVIEW, ["Per-IP management flags were not collected."]
        if kinds:
            return FAIL, [f"Management access is enabled on non-NSIP addresses: {', '.join(kinds)}."]
        return PASS, ["Management access is limited to the NSIP."]
    if check_id == "nshc000065":
        return (FAIL, [f"{app.loopback_services} service reference(s) to 127.0.0.1."]) if app.loopback_services else (PASS, ["No loopback-bound service was found."])
    if check_id == "nshc000066":
        if app.console_present:
            return PASS, ["A NetScaler Console or ADM collector indicator is present. Confirm the account it uses."]
        return REVIEW, ["No NetScaler Console registration was obvious in this bundle. Confirm how the estate is managed."]
    if check_id == "nshc000067":
        if app.cert_links:
            return PASS, [f"{app.cert_links} certificate link(s) are configured."]
        if len(app.certificates) > 2:
            return FAIL, ["Server certificates are installed and no certificate link was found."]
        return REVIEW, ["Certificate links could not be confirmed."]
    if check_id == "nshc000068":
        weak = _profiles(app, "SSLv3", "ENABLED") + _profiles(app, "TLSv1.0", "ENABLED") + _profiles(app, "TLSv1.1", "ENABLED")
        internal = [name for name in weak if "backend" in name or "internal" in name or name.startswith("ns_default")]
        if app.default_profile == "ENABLED" and not internal:
            return PASS, ["Default SSL profile is enabled and the default profiles do not allow SSLv3, TLS 1.0, or TLS 1.1."]
        if internal:
            return FAIL, [f"Default or internal profiles still allow older protocols: {', '.join(internal)}."]
        return REVIEW, ["Review SSL settings on nshttps and nsrpcs internal services."]
    if check_id == "nshc000069":
        if app.default_cert_bound:
            return FAIL, ["ns-server-certificate is still bound. Replace it with a CA-signed certificate."]
        return PASS, ["The factory ns-server-certificate was not seen bound in show ssl service."]
    if check_id == "nshc000070":
        names = [cipher for _, cipher in app.cipher_binds]
        if not names:
            return REVIEW, ["Cipher bindings were not present as bind ssl ... -cipherName in ns.conf."]
        default_alias = sorted({cipher for cipher in names if cipher.upper() == "DEFAULT"})
        custom = sorted({cipher for cipher in names if not _recommended_cipher(cipher) and cipher.upper() != "DEFAULT"})
        if custom:
            return REVIEW, [f"Custom or unexpected cipher names are bound: {', '.join(custom)}."]
        if default_alias:
            return REVIEW, ["The DEFAULT cipher alias is bound. Prefer the built-in HIGH and TLS1.3 groups, which are narrower."]
        return PASS, ["Bound ciphers are HIGH, TLS 1.3, or TLS 1.2 ECDHE suites."]
    if check_id == "nshc000071":
        if not app.uithemes and not app.vpn_vservers:
            return NA, ["No VPN portal theme or VPN virtual server was found."]
        stale = [theme for theme in app.uithemes if theme.lower() not in {"rfwebui"}]
        if stale:
            return FAIL, [f"Portal themes other than RfWebUI: {', '.join(stale)}."]
        if app.uithemes:
            return PASS, ["Portal themes use RfWebUI."]
        return REVIEW, ["A VPN virtual server exists and no -uitheme was found in ns.conf."]
    if check_id == "nshc000072":
        return REVIEW, ["Before the next upgrade, compare customized files under /etc with the NetScaler upgrade notes and keep a copy off the appliance."]
    if check_id == "nshc000073":
        if app.hostname and app.hostname.lower() not in {"ns", "nsroot"}:
            return PASS, [f"Hostname is {app.hostname}."]
        return FAIL, ["Hostname is still the default. Set a unique hostname and match it on the management certificate."]
    if check_id == "nshc000074":
        if not _aaa_stack(app):
            return NA, ["No Gateway or AAA authentication flow was found."]
        if app.login_encryption == "ENABLED":
            return PASS, ["AAA login encryption is enabled."]
        if app.login_encryption == "DISABLED":
            return FAIL, ["AAA login encryption is disabled. Test it before enabling it on an nFactor flow."]
        return REVIEW, ["Login encryption was not reported."]
    if check_id == "nshc000075":
        return _optional_security_feature(app, "AppFw", app.appfw_policies, "Web Application Firewall")
    if check_id == "nshc000076":
        return _optional_security_feature(app, "Bot", app.bot_policies, "Bot Management")
    if check_id == "nshc000077":
        if not _aaa_stack(app):
            return NA, ["No AAA or Gateway authentication flow was found."]
        if any("maxlogin" in key or "failedlogin" in key for key in app.aaa):
            return PASS, ["AAA login-attempt limits are configured."]
        return FAIL, ["maxLoginAttempts and failedLoginTimeout were not found. Set both to match the identity-provider lockout policy."]
    if check_id == "nshc001001":
        return (FAIL, ["A MAC move was recorded in the collected command output."]) if app.mac_moves else (PASS, ["No MAC move was seen in the collected show output."])
    if check_id == "nshc001002":
        if app.var_avail_mb is None:
            return REVIEW, ["/var free space was not in stat system or df."]
        if app.var_avail_mb < 5120:
            return FAIL, [f"/var has {app.var_avail_mb:.0f} MB free. Keep at least 5 GB free."]
        return PASS, [f"/var has {app.var_avail_mb:.0f} MB free."]
    if check_id == "nshc001003":
        if app.uptime_days is None:
            return REVIEW, ["Uptime was not collected."]
        if app.uptime_days > 365:
            return FAIL, [f"Uptime is {app.uptime_days:.0f} days. Plan a controlled reboot."]
        return PASS, [f"Uptime is {app.uptime_days:.1f} days."]
    if check_id == "nshc001004":
        if app.mem_used_pct is None:
            return REVIEW, ["Memory utilization was not in the collector."]
        if app.mem_used_pct >= 85:
            return FAIL, [f"Memory in use is {app.mem_used_pct:.1f}% at collection time."]
        return PASS, [f"Memory in use is {app.mem_used_pct:.1f}% at collection time. This is a single snapshot."]
    if check_id == "nshc001005":
        value = app.packet_cpu_pct if app.packet_cpu_pct is not None else app.cpu_pct
        if value is None:
            return REVIEW, ["CPU utilization was not in the collector."]
        label = "Packet CPU" if app.packet_cpu_pct is not None else "CPU"
        if value >= 80:
            return FAIL, [f"{label} is {value:.1f}% at collection time."]
        return PASS, [f"{label} is {value:.1f}% at collection time. This is a single snapshot."]
    if check_id == "nshc001006":
        if app.platform != "VPX":
            return NA, ["The 4 GB per vCPU guidance is for VPX."]
        if not app.mem_used_mb or not app.mem_used_pct or not app.ncpu:
            return REVIEW, ["VPX memory or vCPU count was not available."]
        total = app.mem_used_mb / (app.mem_used_pct / 100)
        per = total / app.ncpu
        if per < 4096:
            return FAIL, [f"About {per:.0f} MB of RAM per vCPU ({app.ncpu} vCPU, about {total:.0f} MB total). Use at least 4 GB per vCPU."]
        return PASS, [f"About {per:.0f} MB of RAM per vCPU."]
    if check_id == "nshc002001":
        if app.ha_nodes < 2:
            return NA, ["HA heartbeats apply to an HA pair."]
        quiet = [item["name"] for item in app.interfaces if not item["name"].startswith("LO") and "HEARTBEAT" not in item["flags"]]
        if quiet:
            return FAIL, [f"No HA heartbeat flag on: {', '.join(quiet)}."]
        return PASS, ["Data interfaces show the HA heartbeat flag."]
    if check_id == "nshc002003":
        if app.config_consistent == "NO":
            return FAIL, ["show configstatus reports the running configuration is not the saved configuration."]
        if app.config_consistent == "YES":
            return PASS, ["Running and saved configuration are consistent."]
        return REVIEW, ["show configstatus was not collected."]
    if check_id == "nshc003001":
        if app.ntp_servers and app.ntp_enabled:
            return PASS, [f"{app.ntp_servers} NTP server(s), synchronization enabled."]
        if app.ntp_servers:
            return FAIL, [f"{app.ntp_servers} NTP server(s) are configured and synchronization is not enabled."]
        return FAIL, ["No NTP server is configured."]
    if check_id == "nshc000078":
        return _http_desync(app)
    if check_id == "nshc000079":
        return _ecc_curves(app)
    if check_id == "nshc000080":
        return _profile_reneg(app)
    if check_id == "nshc000081":
        return _default_routes(app, 4, missing=True)
    if check_id == "nshc000082":
        return _default_routes(app, 6, missing=True)
    if check_id == "nshc000083":
        return _default_routes(app, 4, missing=False)
    if check_id == "nshc000084":
        return _default_routes(app, 6, missing=False)
    if check_id in {"nshc004002", "nshc006001", "nshc006002", "nshc006003", "nshc007001", "nshc008001", "nshc009001", "nshc010001", "nshc011001", "nshc012001", "nshc013001", "nshc014001"}:
        return NA, ["This check is for the SDX Management Service. The collector is an ADC instance bundle."]
    return REVIEW, ["No automated detector is defined for this check yet."]


def _threshold(app: Appliance, alarm: str, label: str) -> tuple[str, list[str]]:
    unset = _alarm_unset(app, alarm)
    if unset is None:
        return REVIEW, [f"SNMP alarm {alarm} was not in show snmp alarm."]
    if unset:
        return FAIL, [f"SNMP alarm {alarm} has no threshold, so {label} alerts will not fire."]
    return PASS, [f"SNMP alarm {alarm} has a threshold."]


def _license_alarm(app: Appliance, alarm: str) -> tuple[str, list[str]]:
    enabled = _alarm_enabled(app, alarm)
    if enabled is None:
        return REVIEW, [f"SNMP alarm {alarm} was not listed."]
    if enabled:
        return PASS, [f"SNMP alarm {alarm} is enabled."]
    return FAIL, [f"SNMP alarm {alarm} is not enabled."]


def _nsip_flag(app: Appliance, bad, message: str, passing: str = "NSIP management flags meet this check.") -> tuple[str, list[str]]:
    nsips = _nsips(app)
    if not nsips:
        return REVIEW, ["show ns ip <address> details were not in the collector, so the effective NSIP flags are unknown."]
    failed = [ip for ip in nsips if bad(ip)]
    if failed:
        described = [
            f"{ip.address}: gui={ip.gui or 'n/a'}, telnet={ip.telnet or 'n/a'}, ftp={ip.ftp or 'n/a'}, restrictAccess={ip.restrict or 'n/a'}, snmp={ip.snmp or 'n/a'}"
            for ip in failed
        ]
        return FAIL, [message, *described]
    return PASS, [passing]


def _http_desync(app: Appliance) -> tuple[str, list[str]]:
    profiles = (app.inventory or {}).get("http_profiles") or []
    weak = []
    for profile in profiles:
        missing = []
        for key, label in (
            ("drop_invalid", "drop invalid requests"),
            ("http09", "HTTP/0.9"),
            ("connect", "CONNECT"),
            ("crlf", "extra CRLF"),
        ):
            if profile.get(key) == "DISABLED":
                missing.append(label)
        if missing:
            weak.append(f"{profile['name']} ({', '.join(missing)})")
    if weak:
        return FAIL, [f"HTTP profiles are missing desync protections: {', '.join(weak)}."]
    if profiles:
        return PASS, ["HTTP profiles drop invalid requests, HTTP/0.9, CONNECT, and extra CRLF."]
    return REVIEW, ["show ns httpProfile was not in the collector."]


def _ecc_curves(app: Appliance) -> tuple[str, list[str]]:
    trusted = {"P_256", "P_384", "P_521", "X_25519", "X25519", "X25519_MLKEM768", "ALL"}
    groups = (app.inventory or {}).get("ecc_curves") or []
    if not groups:
        return REVIEW, ["ECC curve bindings were not in ns.conf. The appliance default list still includes P_224."]
    weak = [f"{item['name']} ({', '.join(curve for curve in item['curves'] if curve.upper() not in trusted)})" for item in groups if any(curve.upper() not in trusted for curve in item["curves"])]
    if weak:
        return FAIL, [f"ECC curves outside P-256, P-384, P-521, and X25519 are bound: {', '.join(weak[:8])}." + (" …" if len(weak) > 8 else "")]
    return PASS, ["Bound ECC curves are P-256, P-384, P-521, or X25519."]


def _profile_reneg(app: Appliance) -> tuple[str, list[str]]:
    reported = [item for item in app.ssl_profiles if item.reneg]
    if not reported:
        return REVIEW, ["Per-profile SSL renegotiation was not in show ssl profile."]
    weak = [item.name for item in reported if item.reneg not in {"NONSECURE", "ALL"}]
    if weak:
        return FAIL, [f"SSL profiles do not limit renegotiation to NONSECURE or ALL: {', '.join(weak)}."]
    return PASS, ["SSL profiles deny renegotiation except NONSECURE or ALL."]


def _default_routes(app: Appliance, family: int, missing: bool) -> tuple[str, list[str]]:
    data = app.inventory or {}
    if family == 6:
        if not data.get("ipv6_in_use"):
            return NA, ["IPv6 is not in use beyond link-local and loopback."]
        defaults = [item for item in data.get("routes6") or [] if item.get("network", "").lower() in {"::/0", "0::/0"}]
        label = "IPv6"
    else:
        routes = data.get("routes") or []
        if not routes:
            return REVIEW, ["The IPv4 route table was not in the collector."]
        defaults = [
            item
            for item in routes
            if item.get("network") == "0.0.0.0"
            and item.get("netmask") in {"0.0.0.0", "0"}
            and item.get("state", "UP") in {"UP", ""}
            and item.get("type") in {"STATIC", "DYNAMIC"}
        ]
        label = "IPv4"
    if missing:
        if defaults:
            return PASS, [f"{len(defaults)} {label} default route(s) are present."]
        return FAIL, [f"No {label} default route is configured."]
    if len(defaults) > 1:
        return FAIL, [f"{len(defaults)} {label} default routes are installed. Confirm this is intentional equal-cost multipath."]
    return PASS, [f"{len(defaults)} {label} default route is installed."]


def _http_flag(app: Appliance, key: str, label: str) -> tuple[str, list[str]]:
    value = app.http_param.get(key, "")
    if not value:
        return REVIEW, [f"{label} was not reported."]
    if value.upper() in {"OFF", "DISABLED", "NO"}:
        return FAIL, [f"{label} is {value}."]
    return PASS, [f"{label} is {value}."]


def _protocol(app: Appliance, protocol: str) -> tuple[str, list[str]]:
    enabled = _profiles(app, protocol, "ENABLED")
    if not app.ssl_profiles:
        return REVIEW, ["SSL profiles were not collected."]
    if enabled:
        return FAIL, [f"{protocol} is enabled on: {', '.join(enabled)}."]
    return PASS, [f"{protocol} is disabled on the reported SSL profiles."]


def _recommended_cipher(name: str) -> bool:
    upper = name.upper().replace("TLSV", "TLS")
    return upper in {"HIGH", "TLS1.3", "TLS1.2"} or upper.startswith("TLS1.2-ECDHE") or upper.startswith("TLS1.3")


def _optional_security_feature(app: Appliance, feature: str, policies: int, label: str) -> tuple[str, list[str]]:
    if app.features.get(feature) and policies:
        return PASS, [f"{label} is enabled and {policies} policy object(s) exist. Confirm they cover the intended virtual servers."]
    if app.features.get(feature):
        return REVIEW, [f"{label} is enabled and no policy was found. Confirm whether protection is enforced here or on another device."]
    return REVIEW, [f"{label} is not enabled. Discuss whether NetScaler should enforce it or whether another control already does."]


def _extras(app: Appliance) -> list[Outcome]:
    extras: list[Outcome] = []
    expiring = [cert for cert in app.certificates if cert.days is not None and cert.days <= 45 and cert.name not in {"ns-server-certificate", "ns-sftrust-certificate"}]
    if expiring:
        evidence = [f"{cert.name}: {cert.days} days to expiration" for cert in expiring]
        soon = any(cert.days is not None and cert.days <= 14 for cert in expiring)
        extras.append(_extra("nshc-x-cert-expiry", "Certificate expiration", "Security", FAIL if soon else REVIEW, "HIGH" if soon else "MEDIUM", "Renew certificates that expire inside the next maintenance window, then link the new chain.", evidence))
    weak_ldap = [item["name"] for item in app.ldap if item["secure"] in {"SSL", "TLS"} and item["validate"] == "NO"]
    clear_ldap = [item["name"] for item in app.ldap if item["secure"] in {"PLAINTEXT", "TLS"} or item["port"] == "389"]
    if clear_ldap:
        extras.append(_extra("nshc-x-ldap-clear", "LDAP transport", "Security", FAIL, "HIGH", "Use LDAPS on port 636 and validate the directory certificate.", [f"LDAP actions not on validated LDAPS: {', '.join(clear_ldap)}."]))
    elif weak_ldap:
        extras.append(_extra("nshc-x-ldap-validate", "LDAP server certificate validation", "Security", FAIL, "MEDIUM", "LDAPS is in use. Enable directory certificate validation so a substituted directory server is rejected.", [f"Validation is off for: {', '.join(weak_ldap)}."]))
    if app.snmp_noauth:
        extras.append(_extra("nshc-x-snmp-noauth", "SNMPv3 without authentication", "Security", FAIL, "MEDIUM", "SNMPv3 groups use noAuthNoPriv. Move collectors to authPriv.", [f"{app.snmp_noauth} noAuthNoPriv SNMP group reference(s) in ns.conf."]))
    if app.var_avail_mb is not None and 5120 <= app.var_avail_mb < 7168:
        extras.append(_extra("nshc-x-var-upgrade", "/var space for a firmware upgrade", "System", REVIEW, "MEDIUM", "The health-check minimum is 5 GB free. The upgrade guide asks for about 7 GB free in /var before a firmware install.", [f"/var has {app.var_avail_mb:.0f} MB free."]))
    if app.syslog_udp or app.syslog_tcp:
        extras.append(_extra(
            "nshc-x-syslog-transport",
            "Syslog transport",
            "Security",
            REVIEW,
            "MEDIUM",
            "Audit syslog is leaving the appliance without TLS. Send it over TLS on the management network. UDP is the NetScaler default when -transport is omitted.",
            [f"Syslog actions: {app.syslog_udp} UDP, {app.syslog_tcp} TCP, {app.syslog_tls} TLS."],
        ))
    peers = app.ha_nodes >= 2 or app.gslb_sites >= 1
    if peers and app.rpc_secure == "OFF":
        extras.append(_extra(
            "nshc-x-rpc-secure",
            "RPC encryption between peers",
            "Security",
            FAIL,
            "MEDIUM",
            "HA or GSLB is configured and RPC secure is off. Turn on secure RPC, validate the peer certificate, and rotate the RPC node password. This report does not read that password.",
            ["Secure is OFF."],
        ))
    elif peers and app.rpc_secure == "ON" and app.rpc_validate == "NO":
        extras.append(_extra("nshc-x-rpc-cert", "HA RPC certificate validation", "Security", REVIEW, "LOW", "RPC is encrypted. Also validate the peer certificate so the HA session is tied to a known node.", ["Secure is ON and ValidateCert is NO."]))
    if app.skipped_keys:
        extras.append(_extra("nshc-x-bundle-keys", "Private keys inside the support bundle", "Security", REVIEW, "HIGH", "This collector contains private key files. Store the bundle in the encrypted report workflow, restrict who can read it, and delete it when the engagement is done. Key material was not copied into this report.", [f"{len(app.skipped_keys)} key file name(s) were seen and skipped."]))
    small_keys = [cert.name for cert in app.certificates if cert.key_bits is not None and cert.key_bits < 2048]
    if small_keys:
        extras.append(_extra("nshc-x-keysize", "Certificate key size", "Security", FAIL, "HIGH", "Replace certificates with RSA keys smaller than 2048 bits.", [f"Certificates under 2048 bits: {', '.join(small_keys)}."]))
    for note in inventory_notes(app):
        extras.append(_from_note(note))
    for note in hardening_notes(app):
        extras.append(_from_note(note))
    for note in performance_notes(app):
        extras.append(_from_note(note))
    return extras


def _from_note(note) -> Outcome:
    return _extra(note.id, note.title, note.focus, note.status, note.risk, note.wording, note.evidence, note.resources)


def _extra(
    check_id: str,
    title: str,
    focus: str,
    status: str,
    risk: str,
    wording: str,
    evidence: list[str],
    resources: list[str] | None = None,
) -> Outcome:
    return Outcome(
        id=check_id,
        title=title,
        focus=focus,
        status=status,
        risk=risk,
        wording=wording,
        evidence=evidence,
        resources=list(resources or []),
        kind="extra",
    )


def _advisories(app: Appliance) -> list[Outcome]:
    rows: list[Advisory] = assess(app)
    outcomes: list[Outcome] = []
    affected = [row for row in rows if row.status == "affected" and row.bulletin != "lifecycle"]
    target = recommended_build(app.version)
    if affected and app.version is not None:
        names = ", ".join(row.bulletin for row in affected)
        outcomes.append(
            Outcome(
                id="nshc-adv-upgrade",
                title=f"Upgrade firmware to {target}",
                focus="Security advisory",
                status=FAIL,
                risk="CRITICAL" if any(row.severity == "CRITICAL" for row in affected) else "HIGH",
                wording=(
                    f"Build {app.version.label} matches {len(affected)} open Citrix security bulletin(s): {names}. "
                    f"Upgrade to {target}. Advisory data is dated {AS_OF}. Read each bulletin for its configuration precondition before the change window."
                ),
                evidence=[f"{row.bulletin}: {', '.join(row.cves)} — {row.title}" for row in affected],
                resources=[
                    "https://support.citrix.com/",
                ],
                kind="advisory",
            )
        )
    for row in rows:
        if row.status == "affected" and row.bulletin == "lifecycle":
            outcomes.append(
                Outcome(
                    id="nshc-adv-eol",
                    title=row.title,
                    focus="Security advisory",
                    status=FAIL,
                    risk="HIGH",
                    wording=row.summary + " " + row.fixed,
                    evidence=[row.precondition],
                    kind="advisory",
                )
            )
        elif row.status == "addressed":
            outcomes.append(
                Outcome(
                    id=f"nshc-adv-{row.bulletin.lower()}",
                    title=row.title,
                    focus="Security advisory",
                    status=PASS,
                    risk="INFO",
                    wording=f"{row.bulletin} is addressed on this build. {row.summary}",
                    evidence=row.cves,
                    kind="advisory",
                )
            )
    return outcomes
