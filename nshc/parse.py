"""Turn collector text into one appliance snapshot.

Show-command output is preferred over ns.conf because ns.conf omits defaults.
Evidence stored here is limited to names, states, and numbers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from nshc.bundle import CollectedNode
from nshc.version import NSVersion, parse_version

_EXEC = re.compile(r"(?m)^exec: ")


@dataclass
class IpDetail:
    address: str
    type: str
    management: str = ""
    telnet: str = ""
    ftp: str = ""
    gui: str = ""
    snmp: str = ""
    restrict: str = ""
    ssh: str = ""


@dataclass
class SslProfile:
    name: str
    role: str
    protocols: dict[str, str]
    hsts: str = ""
    dh: str = ""
    reneg: str = ""
    ciphers: list[str] = field(default_factory=list)
    ocsp: str = ""
    session_reuse: str = ""
    server_auth: str = ""
    hsts_max_age: int | None = None


@dataclass
class Certificate:
    name: str
    days: int | None
    key_bits: int | None = None


@dataclass
class Appliance:
    source: str
    hostname: str
    version: NSVersion | None
    platform: str
    license_type: str
    files_seen: list[str]
    skipped_keys: list[str]
    features: dict[str, bool]
    modes: dict[str, bool]
    ips: list[IpDetail]
    ssl_profiles: list[SslProfile]
    ssl_vservers: list[tuple[str, str]]
    certificates: list[Certificate]
    users: list[dict[str, str]]
    interfaces: list[dict[str, str]]
    vlans: list[dict[str, object]]
    saml_sp: list[str]
    saml_idp: list[str]
    saml_relay: bool
    ldap: list[dict[str, str]]
    snmp_alarms: dict[str, str]
    system: dict[str, str]
    aaa: dict[str, str]
    http_param: dict[str, str]
    tcp: dict[str, str]
    vpn_auth: str
    prompt: str
    ntp_servers: int
    ntp_enabled: bool
    syslog_servers: int
    syslog_udp: int
    syslog_tcp: int
    syslog_tls: int
    snmp_communities: int
    snmp_managers: int
    snmp_traps_generic: int
    snmp_traps_specific: int
    snmp_noauth: int
    appfw_policies: int
    bot_policies: int
    acls: int
    pbrs: int
    channels: int
    ha_nodes: int
    fail_safe: str
    config_consistent: str
    cookie_version: str
    default_profile: str
    deny_reneg: str
    login_encryption: str
    enhanced_feedback: str
    rpc_secure: str
    rpc_validate: str
    var_avail_mb: float | None
    mem_used_mb: float | None
    mem_used_pct: float | None
    cpu_pct: float | None
    packet_cpu_pct: float | None
    ncpu: int | None
    uptime_days: float | None
    kek_present: bool
    default_cert_bound: bool
    portal_themes: list[str]
    cipher_binds: list[str]
    vlan_ip_binds: int
    route_monitors: int
    loopback_services: int
    mac_moves: bool
    console_present: bool
    cert_links: int
    ha_maxflips: bool
    gslb_sites: int
    auth_vservers: int
    vpn_vservers: int
    uithemes: list[str]
    config_mgmt_non_nsip: list[str]
    inventory: dict
    notes: list[str] = field(default_factory=list)

    @property
    def feature_on(self) -> set[str]:
        return {name for name, enabled in self.features.items() if enabled}

    def mode_on(self, acronym: str) -> bool:
        return bool(self.modes.get(acronym))


def parse_node(node: CollectedNode) -> Appliance:
    nsconf = node.files.get("nsconfig/ns.conf", "")
    show = _split_exec(node.files.get("shell/showcmds.txt", ""))
    stat = node.files.get("shell/statcmds.txt", "")
    version = parse_version(_first(show, "show ns version")) or parse_version(nsconf[:400])
    hardware = _first(show, "show ns hardware")
    uname = node.files.get("shell/uname-a.out", "")
    hostname = _hostname(nsconf, uname, show)
    platform = _platform(hardware, uname, nsconf)
    license = _search(r"License Type:\s*(.+)", _first(show, "show ns license")) or ""
    ips = _ip_details(show)
    profiles = _ssl_profiles(show)
    syslog_udp, syslog_tcp, syslog_tls = _syslog_transport(nsconf)
    return Appliance(
        source=node.name,
        hostname=hostname,
        version=version,
        platform=platform,
        license_type=license.strip(),
        files_seen=sorted(node.files),
        skipped_keys=list(node.skipped_keys),
        features=_on_off_table(_first(show, "show ns feature")),
        modes=_on_off_table(_first(show, "show ns mode")),
        ips=ips,
        ssl_profiles=profiles,
        ssl_vservers=_ssl_vservers(_first(show, "show ssl vserver")),
        certificates=_certificates(_first(show, "show ssl certKey")),
        users=_users(_first(show, "show system user")),
        interfaces=_interfaces(_first(show, "show interface")),
        vlans=_vlans(_first(show, "show vlan")),
        saml_sp=_names(_first(show, "show authentication samlAction")),
        saml_idp=_names(_first(show, "show authentication samlIdPProfile")),
        saml_relay="relay" in (
            _first(show, "show authentication samlAction") + _first(show, "show authentication samlIdPProfile")
        ).lower(),
        ldap=_ldap(_first(show, "show authentication ldapAction")),
        snmp_alarms=_snmp_alarms(_first(show, "show snmp alarm")),
        system=_labeled(_first(show, "show system parameter")),
        aaa=_labeled(_first(show, "show aaa parameter")),
        http_param=_labeled(_first(show, "show ns httpParam") + "\n" + _first(show, "show ns httpProfile")),
        tcp=_labeled(_first(show, "show ns tcpParam")),
        vpn_auth=_search(r"Authorization action\s*:\s*(\S+)", _first(show, "show vpn parameter")) or "",
        prompt=_search(r"PromptString:\s*(.*)", _first(show, "show cli prompt")) or "",
        ntp_servers=len(re.findall(r"NTP Server:", _first(show, "show ntp server"))),
        ntp_enabled=(_search(r"NTP Status:\s*(\S+)", _first(show, "show ntp sync")) or "").upper() == "ENABLED",
        syslog_servers=_count_objects(_first(show, "show audit syslogAction")) + _count_objects(_first(show, "show audit nslogAction")),
        syslog_udp=syslog_udp,
        syslog_tcp=syslog_tcp,
        syslog_tls=syslog_tls,
        snmp_communities=_count_objects(_first(show, "show snmp community")),
        snmp_managers=_count_objects(_first(show, "show snmp manager")),
        snmp_traps_generic=len(re.findall(r"Trap type:\s*GENERIC", _first(show, "show snmp trap"), re.I)),
        snmp_traps_specific=len(re.findall(r"Trap type:\s*SPECIFIC", _first(show, "show snmp trap"), re.I)),
        snmp_noauth=len(re.findall(r"(?im)^add snmp group\s+\S+\s+noAuthNoPriv\b", nsconf)),
        appfw_policies=_count_objects(_first(show, "show appfw policy")),
        bot_policies=_count_objects(_first(show, "show bot policy")),
        acls=_count_objects(_first(show, "show ns acl")),
        pbrs=_count_objects(_first(show, "show ns pbr")) or len(re.findall(r"(?im)^add ns pbr\b", nsconf)),
        channels=_count_objects(_first(show, "show channel")),
        ha_nodes=len(re.findall(r"Node ID:", _first(show, "show HA node"))),
        fail_safe=(_search(r"Fail-Safe Mode:\s*(\S+)", _first(show, "show HA node")) or "").upper(),
        config_consistent=(_search(r"Consistent:\s*(\S+)", _first(show, "show configstatus")) or "").upper(),
        cookie_version=_search(r"Cookie version:\s*(\S+)", _first(show, "show ns param")) or "",
        default_profile=(_search(r"Default profile\s*:\s*(\S+)", _first(show, "show ssl parameter")) or "").upper(),
        deny_reneg=(_search(r"Deny SSL Renegotiation\s*:\s*(\S+)", _first(show, "show ssl parameter")) or "").upper(),
        login_encryption=(_search(r"Login Encryption:\s*(\S+)", _first(show, "show aaa parameter")) or "").upper(),
        enhanced_feedback=(_search(r"EnableEnhancedAuthFeedback:\s*(\S+)", _first(show, "show aaa parameter")) or "").upper(),
        rpc_secure=(_search(r"Secure:\s*(\S+)", _first(show, "show ns rpcNode")) or "").upper(),
        rpc_validate=(_search(r"ValidateCert:\s*(\S+)", _first(show, "show ns rpcNode")) or "").upper(),
        var_avail_mb=_float(_search(r"/var Available \(MB\)\s+(\d+)", stat) or _df_var(node.files.get("shell/df-akin.out", ""))),
        mem_used_mb=_float(_search(r"Memory usage \(MB\)\s+(\d+)", stat)),
        mem_used_pct=_float(_search(r"InUse Memory \(%\)\s+([\d.]+)", stat)),
        cpu_pct=_float(_search(r"CPU usage \(%\)\s+([\d.]+)", stat)),
        packet_cpu_pct=_float(_search(r"Packet CPU usage \(%\)\s+([\d.]+)", stat)),
        ncpu=_int(_search(r"Number of CPUs\s+(\d+)", stat)),
        uptime_days=_uptime(node.files.get("shell/uptime.out", "")),
        kek_present=bool(re.search(r"(?i)\b-kek\b|KEK", nsconf)) or "kek" in _first(show, "show ns encryptionKey").lower(),
        default_cert_bound="ns-server-certificate" in _first(show, "show ssl service"),
        portal_themes=re.findall(r"(?im)^add (?:vpn|authentication) portaltheme\s+(\S+)(?:.*-uitheme\s+(\S+))?", nsconf),
        cipher_binds=re.findall(r"(?im)^bind ssl \S+\s+(\S+)\s+-cipherName\s+(\S+)", nsconf),
        vlan_ip_binds=len(re.findall(r"(?im)^bind vlan\s+\S+\s+-ipaddress\b", nsconf)),
        route_monitors=len(re.findall(r"(?i)routeMonitor", nsconf)),
        loopback_services=len(re.findall(r"127\.0\.0\.1", _first(show, "show service"))),
        mac_moves=bool(re.search(r"(?i)mac move", node.files.get("shell/showcmds.txt", ""))),
        console_present=_console(show, nsconf),
        cert_links=_count_objects(_first(show, "show ssl certLink")),
        ha_maxflips=bool(re.search(r"(?i)maxFlips", nsconf + _first(show, "show HA node"))),
        gslb_sites=_count_objects(_first(show, "show gslb site")),
        auth_vservers=len(re.findall(r"(?im)^add authentication vserver\b", nsconf)),
        vpn_vservers=len(re.findall(r"(?im)^add vpn vserver\b", nsconf))
        or _count_objects(_first(show, "show vpn vserver")),
        uithemes=re.findall(r"(?i)-uitheme\s+(\S+)", nsconf),
        config_mgmt_non_nsip=_config_mgmt(nsconf),
        inventory=_inventory(nsconf, show, stat),
        notes=list(node.notes),
    )


def _syslog_transport(nsconf: str) -> tuple[int, int, int]:
    """Count syslog actions by transport. An omitted -transport is UDP on NetScaler."""
    udp = tcp = tls = 0
    for line in nsconf.splitlines():
        if not re.match(r"(?i)add audit syslogAction\b", line):
            continue
        match = re.search(r"(?i)-transport\s+(\S+)", line)
        kind = match.group(1).upper() if match else "UDP"
        if "SSL" in kind or "TLS" in kind:
            tls += 1
        elif kind == "TCP":
            tcp += 1
        else:
            udp += 1
    return udp, tcp, tls


def _blocks(text: str) -> list[str]:
    parts = re.split(r"(?m)(?=^\d+\)\s+)", text or "")
    return [part.strip() for part in parts if re.match(r"^\d+\)\s+", part.strip())]


def _block_map(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for block in _blocks(text):
        match = re.match(r"\d+\)\s+(\S+)", block)
        if match and match.group(1) not in found:
            found[match.group(1)] = block
    return found


def _flag_names(nsconf: str, pattern: str) -> set[str]:
    return {match.group(1) for match in re.finditer(pattern, nsconf, re.I | re.M)}


def _inventory(nsconf: str, show: dict[str, list[str]], stat: str = "") -> dict:
    """Names, binds, routes, and PBRs used for cleanup and routing advice.

    Show output supplies state. ns.conf supplies references. Addresses stay in
    the encrypted report and are not written to the console summary.
    """
    service_show = _block_map(_first(show, "show service"))
    services = []
    for match in re.finditer(r"(?im)^add service\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", nsconf):
        name, server, protocol, port = match.groups()
        block = service_show.get(name, "")
        services.append(
            {
                "name": name,
                "server": server,
                "protocol": protocol,
                "port": port,
                "state": (_search(r"State:\s*(\S+)", block) or "").upper(),
                "kind": "service",
            }
        )
    for match in re.finditer(r"(?im)^add gslb service\s+(\S+)\s+(\S+)", nsconf):
        name, server = match.group(1), match.group(2)
        services.append({"name": name, "server": server, "protocol": "GSLB", "port": "", "state": "", "kind": "gslb-service"})

    groups = []
    group_members: dict[str, int] = {}
    for match in re.finditer(r"(?im)^add serviceGroup\s+(\S+)\s+(\S+)", nsconf):
        groups.append({"name": match.group(1), "protocol": match.group(2)})
        group_members.setdefault(match.group(1), 0)
    for match in re.finditer(r"(?im)^bind serviceGroup\s+(\S+)\s+(\S+)", nsconf):
        if not match.group(2).startswith("-"):
            group_members[match.group(1)] = group_members.get(match.group(1), 0) + 1

    lb_children: dict[str, list[str]] = {}
    for match in re.finditer(r"(?im)^bind lb vserver\s+(\S+)\s+(\S+)", nsconf):
        child = match.group(2)
        if not child.startswith("-"):
            lb_children.setdefault(match.group(1), []).append(child)
    gslb_children: dict[str, int] = {}
    for match in re.finditer(r"(?im)^bind gslb vserver\s+(\S+)\s+(\S+)", nsconf):
        if not match.group(2).startswith("-"):
            gslb_children[match.group(1)] = gslb_children.get(match.group(1), 0) + 1
    cs_default = _flag_names(nsconf, r"^bind cs vserver\s+\S+\s+-lbvserver\s+(\S+)")
    cs_default_parents = _flag_names(nsconf, r"^bind cs vserver\s+(\S+)\s+-lbvserver\b")
    cs_policy_parents = _flag_names(nsconf, r"^bind cs vserver\s+(\S+)\s+-policyName\b")
    vpn_bound = _flag_names(nsconf, r"^bind vpn vserver\s+(\S+)\b")
    auth_bound = _flag_names(nsconf, r"^bind authentication vserver\s+(\S+)\b")
    targets = _flag_names(nsconf, r"-targetLBVserver\s+(\S+)") | _flag_names(nsconf, r"-backupVServer\s+(\S+)") | cs_default
    disabled = _flag_names(nsconf, r"^disable (?:lb vserver|cs vserver|gslb vserver|cr vserver|vpn vserver|authentication vserver|service|server)\s+(\S+)")

    vservers = []
    specs = (
        ("lb", r"(?im)^add lb vserver\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", "show lb vserver"),
        ("cs", r"(?im)^add cs vserver\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", "show cs vserver"),
        ("gslb", r"(?im)^add gslb vserver\s+(\S+)\s+(\S+)", "show gslb vserver"),
        ("cr", r"(?im)^add cr vserver\s+(\S+)", "show cr vserver"),
        ("vpn", r"(?im)^add vpn vserver\s+(\S+)(?:\s+\S+\s+(\S+)\s+(\d+))?", "show vpn vserver"),
        ("auth", r"(?im)^add authentication vserver\s+(\S+)(?:\s+\S+\s+(\S+)\s+(\d+))?", "show authentication vserver"),
    )
    for kind, pattern, command in specs:
        shown = _block_map(_first(show, command))
        for match in re.finditer(pattern, nsconf):
            name = match.group(1)
            address, port = _endpoint(match)
            block = shown.get(name, "")
            bound_text = _search(r"No\. of Bound Services\s*:\s*(\d+)", block)
            protocol = match.group(2).upper() if kind in {"lb", "cs", "gslb"} else ""
            vservers.append(
                {
                    "name": name,
                    "kind": kind,
                    "protocol": protocol,
                    "address": address,
                    "port": port,
                    "state": (_search(r"State:\s*(\S+)", block) or "").upper(),
                    "show_bound": int(bound_text) if bound_text and bound_text.isdigit() else None,
                    "config_children": lb_children.get(name, []) if kind == "lb" else [],
                    "gslb_children": gslb_children.get(name, 0),
                    "cs_policies": name in cs_policy_parents,
                    "cs_default": name in cs_default_parents,
                    "vpn_bound": name in vpn_bound,
                    "auth_bound": name in auth_bound,
                    "targeted": name in targets,
                    "disabled": name in disabled,
                }
            )

    servers = []
    for match in re.finditer(r"(?im)^add server\s+(\S+)\s+(\S+)", nsconf):
        name, address = match.group(1), match.group(2)
        add_line = match.group(0)
        total = len(re.findall(rf"(?i)(?<!\S){re.escape(name)}(?!\S)", nsconf))
        on_add = len(re.findall(rf"(?i)(?<!\S){re.escape(name)}(?!\S)", add_line))
        servers.append({"name": name, "address": address, "referenced": total > on_add, "disabled": name in disabled})

    monitors = []
    for match in re.finditer(r"(?im)^add lb monitor\s+(\S+)", nsconf):
        name = match.group(1)
        total = len(re.findall(rf"(?i)(?<!\S){re.escape(name)}(?!\S)", nsconf))
        monitors.append({"name": name, "referenced": total > 1})

    routes = _routes(_first(show, "show route"), nsconf)
    routes6 = _routes6(_first(show, "show route6"), nsconf)
    pbrs = _pbrs(_first(show, "show ns pbr"), nsconf)
    for service in services:
        service["disabled"] = service["name"] in disabled
    for group in groups:
        group["members"] = group_members.get(group["name"], 0)
        group["bound"] = any(group["name"] in children for children in lb_children.values())
    bound_services = {child for children in lb_children.values() for child in children}
    for match in re.finditer(r"(?im)^bind gslb vserver\s+\S+\s+(\S+)", nsconf):
        if not match.group(1).startswith("-"):
            bound_services.add(match.group(1))
    return {
        "services": services,
        "groups": groups,
        "vservers": vservers,
        "servers": servers,
        "monitors": monitors,
        "routes": routes,
        "routes6": routes6,
        "ipv6_in_use": _ipv6_in_use(routes6, nsconf),
        "http_profiles": _http_profiles(_first(show, "show ns httpProfile")),
        "ecc_curves": _ecc_curves(nsconf),
        "pbrs": pbrs,
        "bound_services": sorted(bound_services),
        "disabled": sorted(disabled),
        "hit_counters": bool(re.search(r"(?i)stat (?:lb|cs|vpn|authentication) vserver\b", stat)),
        "posture": _posture(nsconf, show, stat),
        "tcp_profiles": _tcp_profiles(_first(show, "show ns tcpProfile")),
        "profile_refs": _profile_refs(nsconf, show),
        "flush_off": _flush_disabled(_first(show, "show lb vserver"), "lb")
        + _flush_disabled(_first(show, "show cs vserver"), "cs"),
        "cip_enabled": _cip_enabled(nsconf),
        "monitor_binds": _monitor_binds(nsconf),
    }


def _routes(show_route: str, nsconf: str) -> list[dict]:
    rows = []
    for match in re.finditer(
        r"(?m)^\d+\)\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)\s+\S+\s+(\S+)",
        show_route or "",
    ):
        network, netmask, gateway, state, route_type = match.groups()
        rows.append(
            {
                "network": network,
                "netmask": netmask,
                "gateway": gateway,
                "state": state.upper(),
                "type": route_type.upper(),
            }
        )
    if rows:
        return rows
    for match in re.finditer(r"(?im)^add route\s+(\S+)\s+(\S+)\s+(\S+)", nsconf):
        rows.append(
            {
                "network": match.group(1),
                "netmask": match.group(2),
                "gateway": match.group(3),
                "state": "UP",
                "type": "STATIC",
            }
        )
    return rows


def _routes6(show_route6: str, nsconf: str) -> list[dict]:
    rows = []
    for match in re.finditer(r"(?m)^\d+\)\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)", show_route6 or ""):
        rows.append({"network": match.group(1), "gateway": match.group(2), "flags": match.group(3).upper()})
    if rows:
        return rows
    for match in re.finditer(r"(?im)^add route6\s+(\S+)\s+(\S+)", nsconf):
        rows.append({"network": match.group(1), "gateway": match.group(2), "flags": "S"})
    return rows


def _ipv6_in_use(routes6: list[dict], nsconf: str) -> bool:
    for route in routes6:
        network = route["network"].lower()
        if network.startswith("::1") or network.startswith("fe80"):
            continue
        return True
    for match in re.finditer(r"(?im)^add ns ip6\s+(\S+)", nsconf):
        address = match.group(1).lower()
        if not address.startswith("fe80") and not address.startswith("::1"):
            return True
    return False


def _http_profiles(text: str) -> list[dict]:
    profiles = []
    for chunk in re.split(r"(?m)(?=^\d+\))", text or ""):
        name = _search(r"Name:\s*(\S+)", chunk)
        if not name:
            continue
        profiles.append(
            {
                "name": name,
                "drop_invalid": _flag(chunk, "Drop invalid HTTP requests"),
                "http09": _flag(chunk, "Mark HTTP/0.9 requests as invalid"),
                "connect": _flag(chunk, "Mark CONNECT requests as invalid"),
                "crlf": _flag(chunk, "Drop extra CRLF"),
                "http2": _line_flag(chunk, "HTTP/2"),
                "http3": _line_flag(chunk, "HTTP/3"),
                "host_header": _line_flag(chunk, "Host header validation"),
                "max_header": _int(_search(r"Maximum header length\s*:\s*(\d+)", chunk)),
                "max_field": _int(_search(r"Maximum header field length\s*:\s*(\d+)", chunk)),
            }
        )
    return profiles


def _tcp_profiles(text: str) -> list[dict]:
    profiles = []
    for chunk in re.split(r"(?m)(?=^\d+\))", text or ""):
        name = _search(r"Name:\s*(\S+)", chunk)
        if not name:
            continue
        profiles.append(
            {
                "name": name,
                "window_scaling": _line_flag(chunk, "Window Scaling status"),
                "buffer_size": _int(_search(r"TCP Buffer Size:\s*(\d+)", chunk)),
                "max_burst": _int(_search(r"Maximum TCP segments allowed in a burst:\s*(\d+)", chunk)),
            }
        )
    return profiles


def _profile_refs(nsconf: str, show: dict[str, list[str]]) -> dict[str, list[str]]:
    ssl = set(re.findall(r"(?i)-sslProfile\s+(\S+)", nsconf))
    ssl.update(profile for _vserver, profile in _ssl_vservers(_first(show, "show ssl vserver")))
    ssl.update(re.findall(r"(?i)Profile Name\s*:\s*(\S+)", _first(show, "show ssl service")))
    return {
        "tcp": sorted(set(re.findall(r"(?i)-tcpProfileName\s+(\S+)", nsconf))),
        "http": sorted(set(re.findall(r"(?i)-httpProfileName\s+(\S+)", nsconf))),
        "ssl": sorted(ssl),
    }


def _flush_disabled(text: str, kind: str) -> list[dict]:
    rows = []
    for chunk in re.split(r"(?m)(?=^\d+\))", text or ""):
        name = _search(r"^\d+\)\s+(\S+)", chunk)
        flush = (_search(r"Down state flush:\s*(\S+)", chunk) or "").upper()
        if name and flush == "DISABLED":
            rows.append({"kind": kind, "name": name})
    return rows


def _cip_enabled(nsconf: str) -> list[str]:
    names = []
    pattern = r"(?im)^(?:add|set) (?:service|lb vserver|cs vserver|vpn vserver)\s+(\S+).*-cip\s+ENABLED\b"
    for match in re.finditer(pattern, nsconf):
        name = match.group(1)
        if name.lower().startswith("ns"):
            continue
        names.append(name)
    return list(dict.fromkeys(names))


def _monitor_binds(nsconf: str) -> list[dict]:
    types = {
        "ping": "PING",
        "tcp": "TCP",
        "udp": "UDP",
        "http": "HTTP",
        "https": "HTTP",
        "http-ecv": "HTTP",
        "https-ecv": "HTTP",
        "tcp-ecv": "TCP",
        "ping-default": "PING",
        "tcp-default": "TCP",
    }
    for match in re.finditer(r"(?im)^add lb monitor\s+(\S+)\s+(\S+)", nsconf):
        types[match.group(1).lower()] = match.group(2).upper()
    rows = []
    for match in re.finditer(r"(?im)^bind (service|serviceGroup)\s+(\S+)\s+-monitorName\s+(\S+)", nsconf):
        monitor = match.group(3)
        rows.append(
            {
                "kind": "service" if match.group(1).lower() == "service" else "group",
                "name": match.group(2),
                "monitor": monitor,
                "monitor_type": types.get(monitor.lower(), ""),
            }
        )
    return rows


def _line_flag(chunk: str, label: str) -> str:
    match = re.search(rf"(?m)^\s*{re.escape(label)}\s*:\s*(ENABLED|DISABLED)\b", chunk, re.I)
    return match.group(1).upper() if match else ""


def _posture(nsconf: str, show: dict[str, list[str]], stat: str) -> dict:
    """Counts and states for the extra hardening checks. Values are not secrets."""
    config = nsconf or ""
    aaa = _first(show, "show aaa parameter")
    nsparam = _first(show, "show ns param")
    license_text = _first(show, "show ns license") + "\n" + _first(show, "show ns laslicense")
    capacity = _first(show, "show ns capacity")
    ha = _first(show, "show HA node")
    syslog_params = _first(show, "show audit syslogParams") + "\n" + _first(show, "show system parameter")
    return {
        "headers": _header_hits(config),
        "https_redirects": len(re.findall(r"(?im)^add (?:responder|rewrite) action\b.*https://", config)),
        "aaa_httponly": (_search(r"HttpOnly Cookie\s*:\s*(\S+)", aaa) or "").upper(),
        "aaa_csp": (_search(r"CSP Header\s*:\s*(\S+)", aaa) or "").upper(),
        "persistence_secure": (_search(r"Persistence Cookie Secure Flag\s*:\s*(\S+)", nsparam) or "").upper(),
        "timezone": _search(r"Timezone\s*:\s*(\S+)", nsparam) or "",
        "appfw_cookies": _appfw_cookies(_first(show, "show appfw profile")),
        "factors": _auth_factors(config),
        "auth_binds": len(re.findall(r"(?im)^bind (?:authentication|vpn) vserver\b", config)),
        "owned": _owned_subnets(config),
        "acl_rules": _acl_rules(config),
        "cert_monitor_off": _cert_monitor_off(_first(show, "show ssl certKey")),
        "limit_identifiers": len(re.findall(r"(?m)^\d+\)\s+Name:", _first(show, "show ns limitIdentifier"))),
        "tcp_rate": _int(_search(r"TCP threshold:\s*(\d+)", _first(show, "show ns rateControl"))),
        "dns_up": len(re.findall(r"(?i)State:\s*UP\b", _first(show, "show dns nameServer"))),
        "dns_down": len(re.findall(r"(?i)State:\s*DOWN\b", _first(show, "show dns nameServer"))),
        "license_days": _license_days(license_text),
        "bandwidth": _bandwidth(capacity),
        "ha_versions": re.findall(r"(?i)(?:NetScaler Version|Version)\s*:\s*(\S+)", ha),
        "ha_sync": [item.upper() for item in re.findall(r"(?i)Sync State\s*:\s*(\S+)", ha)],
        "cluster_nodes": len(re.findall(r"(?i)Node ID\s*:", _first(show, "show cluster node"))),
        "interfaces": _interface_health(_first(show, "show interface")),
        "vlans": _vlan_layout(_first(show, "show vlan")),
        "vmac": bool(re.search(r"(?i)\bvmac\b", _first(show, "show interface") + "\n" + config))
        or bool(re.search(r"(?m)^\d+\)\s+Name:", _first(show, "show vrID"))),
        "backups": len(re.findall(r"(?im)^(?:add|set) system backup\b|^create backup\b", config)),
        "monitors": _monitor_tuning(config),
        "appflow_collectors": len(re.findall(r"(?im)^add appflow collector\b", config)),
        "appflow_binds": len(re.findall(r"(?im)^bind appflow\b", config)),
        "analytics_profiles": len(re.findall(r"(?im)^add analytics profile\b", config)),
        "audit_hash": (_search(r"(?i)(?:Audit )?Log ?Hash(?:ing)?\s*:\s*(\S+)", syslog_params) or "").upper(),
        "cores_collected": bool(re.search(r"(?i)(?:/var/core|core dump|nscore)", stat + "\n" + config)),
        "packet_engine_collected": bool(re.search(r"(?i)Packet CPU|Number of CPUs", stat)),
    }


_HEADER_MARKERS = {
    "X-Content-Type-Options": ("x-content-type-options", "nosniff"),
    "X-Frame-Options": ("x-frame-options", "frame-ancestors"),
    "Referrer-Policy": ("referrer-policy",),
    "Content-Security-Policy": ("content-security-policy",),
    "Permissions-Policy": ("permissions-policy", "feature-policy"),
}


def _header_hits(config: str) -> list[str]:
    lowered = config.lower()
    return [name for name, markers in _HEADER_MARKERS.items() if any(marker in lowered for marker in markers)]


def _appfw_cookies(text: str) -> dict[str, int]:
    counts = {"profiles": 0, "samesite_off": 0, "samesite_on": 0, "flags_none": 0, "flags_secure": 0}
    for chunk in re.split(r"(?m)(?=^\d+\)\s+Name:)", text or ""):
        if not _search(r"Name:\s*(\S+)", chunk):
            continue
        counts["profiles"] += 1
        insert = (_search(r"InsertCookieSamesiteAttribute\s*:\s*(\S+)", chunk) or "").upper()
        if insert == "OFF":
            counts["samesite_off"] += 1
        elif insert == "ON":
            counts["samesite_on"] += 1
        flags = (_search(r"AddCookieFlags\s*:\s*(\S+)", chunk) or "").lower()
        if flags == "none":
            counts["flags_none"] += 1
        elif "secure" in flags or "httponly" in flags:
            counts["flags_secure"] += 1
    return counts


def _auth_factors(config: str) -> dict[str, int]:
    kinds = {
        "radius": r"^add authentication radiusAction\b",
        "oauth": r"^add authentication OAuthAction\b",
        "saml": r"^add authentication saml(?:Action|IdPProfile)\b",
        "cert": r"^add authentication certAction\b",
        "push": r"^add authentication push\w*\b",
        "webauth": r"^add authentication webAuthAction\b",
        "ldap": r"^add authentication ldapAction\b",
        "tacacs": r"^add authentication tacacsAction\b",
        "epa": r"^add authentication epaAction\b",
        "local": r"^add authentication (?:localAction|localPolicy)\b",
    }
    return {name: len(re.findall(rf"(?im){pattern}", config)) for name, pattern in kinds.items()}


def _owned_subnets(config: str) -> list[dict[str, str]]:
    rows = []
    for match in re.finditer(r"(?im)^add ns ip\s+(\S+)\s+(\S+)(.*)$", config):
        kind = (_search(r"-type\s+(\S+)", match.group(3)) or "").upper()
        rows.append({"address": match.group(1), "mask": match.group(2), "type": kind})
    return rows


def _acl_rules(config: str) -> list[dict[str, str]]:
    rows = []
    for match in re.finditer(r"(?im)^add ns (?:simple)?acl\d?\s+\S+\s+(ALLOW|DENY)\b(.*)$", config):
        rest = match.group(2)
        source = _search(r"-srcIP\s+(\S+)", rest) or "*"
        rows.append({"action": match.group(1).upper(), "source": source})
    return rows


def _cert_monitor_off(text: str) -> int:
    skipped = {"ns-server-certificate", "ns-sftrust-certificate"}
    count = 0
    for chunk in re.split(r"(?m)(?=^\d+\)\s+Name:)", text or ""):
        name = _search(r"Name:\s*(\S+)", chunk)
        if not name or name in skipped:
            continue
        if (_search(r"Certificate Expiry Monitor\s*:\s*(\S+)", chunk) or "").upper() == "DISABLED":
            count += 1
    return count


def _license_days(text: str) -> int | None:
    match = re.search(r"(?i)(?:Days to expiration|License days remaining|Days to expiry)\s*[:=]?\s*(-?\d+)", text or "")
    if not match:
        return None
    return int(match.group(1))


def _bandwidth(text: str) -> dict[str, int]:
    values = {}
    for label, key in (("Maximum Bandwidth", "maximum"), ("Actual Bandwidth", "actual"), ("Configured Bandwidth", "configured")):
        match = re.search(rf"(?i){label}\s*:\s*(\d+)\s*(Gbps|Mbps|bps)", text or "")
        if not match:
            continue
        number = int(match.group(1))
        unit = match.group(2).lower()
        scale = {"bps": 1, "mbps": 1_000_000, "gbps": 1_000_000_000}[unit]
        values[key] = number * scale
    return values


def _interface_health(text: str) -> list[dict]:
    rows = []
    for chunk in re.split(r"(?m)(?=^\d+\)\s+Interface\s+)", text or ""):
        name = _search(r"Interface\s+(\S+)", chunk)
        if not name:
            continue
        flags = _search(r"<([^>]+)>", chunk) or ""

        def grab(pattern: str, body: str = chunk) -> int:
            found = _search(pattern, body)
            return int(found) if found and found.isdigit() else 0

        rows.append(
            {
                "name": name,
                "up": "UP" in flags.upper(),
                "dot1q": "802.1q" in flags.lower(),
                "native_vlan": _search(r"native vlan=(\d+)", chunk) or "",
                "rx_errs": grab(r"RX:.*?Errs\((\d+)\)"),
                "rx_drops": grab(r"RX:.*?Drops\((\d+)\)"),
                "tx_errs": grab(r"TX:.*?Errs\((\d+)\)"),
                "tx_drops": grab(r"TX:.*?Drops\((\d+)\)"),
            }
        )
    return rows


def _vlan_layout(text: str) -> list[dict]:
    rows = []
    for chunk in re.split(r"(?m)(?=^\d+\)\s+VLAN ID:)", text or ""):
        vlan_id = _search(r"VLAN ID:\s*(\d+)", chunk)
        if not vlan_id:
            continue
        interfaces = (_search(r"Interfaces\s*:\s*(.+)", chunk) or "").split()
        rows.append({"id": vlan_id, "interfaces": interfaces, "tagall": bool(re.search(r"(?i)tagall", chunk))})
    return rows


def _monitor_tuning(config: str) -> list[dict]:
    rows = []
    for match in re.finditer(r"(?im)^(add|set) lb monitor\s+(\S+)(.*)$", config):
        rest = match.group(3)
        rows.append(
            {
                "name": match.group(2),
                "interval": _int(_search(r"-interval\s+(\d+)", rest)),
                "downtime": _int(_search(r"-downTime\s+(\d+)", rest)),
                "retries": _int(_search(r"-retries\s+(\d+)", rest)),
                "alert_retries": _int(_search(r"-alertRetries\s+(\d+)", rest)),
            }
        )
    return rows


def _flag(chunk: str, label: str) -> str:
    match = re.search(rf"{re.escape(label)}\s*:?\s*(ENABLED|DISABLED)", chunk, re.I)
    return match.group(1).upper() if match else ""


def _ecc_curves(nsconf: str) -> list[dict]:
    grouped: dict[str, list[str]] = {}
    for match in re.finditer(r"(?im)^bind ssl \S+\s+(\S+)\s+-eccCurveName\s+(\S+)", nsconf):
        grouped.setdefault(match.group(1), []).append(match.group(2))
    return [{"name": name, "curves": curves} for name, curves in grouped.items()]


def _pbrs(show_pbr: str, nsconf: str) -> list[dict]:
    rows = []
    for block in _blocks(show_pbr):
        name = _search(r"Name:\s*(\S+)", block) or ""
        if not name:
            continue
        hits = _search(r"Hits:\s*(\d+)", block)
        rows.append(
            {
                "name": name,
                "hits": int(hits) if hits is not None else None,
                "active": (_search(r"Active Status:\s*(\S+)", block) or "").upper(),
                "applied": (_search(r"Applied Status:\s*(\S+)", block) or "").upper(),
                "nexthop": _search(r"NextHop:\s*(\S+)", block) or "",
            }
        )
    if rows:
        return rows
    for match in re.finditer(r"(?im)^add ns pbr\s+(\S+).*?-nextHop\s+(\S+)", nsconf):
        rows.append(
            {
                "name": match.group(1),
                "hits": None,
                "active": "ENABLED",
                "applied": "",
                "nexthop": match.group(2),
            }
        )
    return rows


def _endpoint(match: re.Match[str]) -> tuple[str, str]:
    values = [group for group in match.groups() if group]
    address = next((value for value in values if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value)), "")
    port = values[-1] if values and values[-1].isdigit() else ""
    return address, port


def _config_mgmt(nsconf: str) -> list[str]:
    found: list[str] = []
    for line in nsconf.splitlines():
        if not re.match(r"(?i)add ns ip\s+", line):
            continue
        if not re.search(r"(?i)-mgmtAccess\s+ENABLED\b", line):
            continue
        match = re.search(r"(?i)-type\s+(\S+)", line)
        kind = match.group(1).upper() if match else "NSIP"
        if kind != "NSIP":
            found.append(kind)
    return found


def _split_exec(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    parts = _EXEC.split(text)
    for part in parts[1:]:
        lines = part.splitlines()
        if not lines:
            continue
        command = lines[0].strip()
        body: list[str] = []
        for line in lines[1:]:
            if line.strip() == "Done":
                break
            body.append(line)
        sections.setdefault(command, []).append("\n".join(body).strip())
    return sections


def _first(sections: dict[str, list[str]], command: str) -> str:
    bodies = sections.get(command) or []
    return bodies[0] if bodies else ""


def _search(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text or "", re.I)
    return match.group(1).strip() if match else None


def _float(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _int(value: str | None) -> int | None:
    number = _float(value)
    return int(number) if number is not None else None


def _hostname(nsconf: str, uname: str, show: dict[str, list[str]]) -> str:
    configured = _search(r"(?m)^set ns hostName\s+(\S+)", nsconf)
    if configured:
        return configured
    shown = _search(r"Hostname:\s*(\S+)", _first(show, "show ns hostName"))
    if shown:
        return shown
    match = re.search(r"FreeBSD\s+(\S+)", uname)
    return match.group(1) if match else ""


def _platform(hardware: str, uname: str, nsconf: str) -> str:
    blob = f"{hardware}\n{uname}\n{nsconf[:300]}".upper()
    if "SDX" in blob and "SVM" in blob:
        return "SDX"
    if re.search(r"\bBLX\b", blob):
        return "BLX"
    if "VIRTUAL" in blob or "VPX" in blob or "XEN" in blob:
        return "VPX"
    if "MPX" in blob:
        return "MPX"
    return "VPX"


def _on_off_table(text: str) -> dict[str, bool]:
    found: dict[str, bool] = {}
    for line in text.splitlines():
        match = re.search(r"\s([A-Za-z][A-Za-z0-9_]*)\s+(ON|OFF)\s*$", line)
        if match:
            found[match.group(1)] = match.group(2) == "ON"
    return found


def _ip_details(show: dict[str, list[str]]) -> list[IpDetail]:
    details: list[IpDetail] = []
    for command, bodies in show.items():
        if not re.match(r"show ns ip \S+", command):
            continue
        body = bodies[0]
        fields = {}
        for line in body.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            fields[key.strip().lower()] = value.strip()
        address = fields.get("ip", "")
        if not address:
            continue
        details.append(
            IpDetail(
                address=address,
                type=fields.get("type", ""),
                management=fields.get("management access", ""),
                telnet=fields.get("telnet", ""),
                ftp=fields.get("ftp", ""),
                gui=fields.get("gui", ""),
                snmp=fields.get("snmp", ""),
                restrict=fields.get("restrict access", ""),
                ssh=fields.get("ssh", ""),
            )
        )
    return details


def _ssl_profiles(show: dict[str, list[str]]) -> list[SslProfile]:
    text = _first(show, "show ssl profile")
    profiles: list[SslProfile] = []
    chunks = re.split(r"(?m)(?=^\d+\)\s+Name:)", text)
    for chunk in chunks:
        name = _search(r"Name:\s*(\S+)", chunk)
        if not name:
            continue
        role = _search(r"\(([^)]+)\)", chunk) or ""
        protocols = {
            key: value.upper()
            for key, value in re.findall(
                r"(SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3):\s*(ENABLED|DISABLED)",
                chunk,
                re.I,
            )
        }
        profiles.append(
            SslProfile(
                name=name,
                role=role,
                protocols=protocols,
                hsts=(_search(r"HSTS:\s*(ENABLED|DISABLED)", chunk) or "").upper(),
                dh=(_search(r"\bDH:\s*(ENABLED|DISABLED)", chunk) or "").upper(),
                reneg=(_search(r"Deny SSL Renegotiation\s+(\S+)", chunk) or "").upper(),
                ciphers=re.findall(r"Cipher Name:\s*(\S+)", chunk),
                ocsp=(_search(r"OCSP Stapling\s*:\s*(ENABLED|DISABLED)", chunk) or "").upper(),
                session_reuse=(_search(r"Session Reuse:\s*(ENABLED|DISABLED)", chunk) or "").upper(),
                server_auth=(_search(r"Server Auth:\s*(ENABLED|DISABLED)", chunk) or "").upper(),
                hsts_max_age=_int(_search(r"HSTS Max-Age:\s*(\d+)", chunk)),
            )
        )
    return profiles


def _ssl_vservers(text: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    current = ""
    for line in text.splitlines():
        name = _search(r"VServer Name:\s*(\S+)", line)
        profile = _search(r"Profile Name\s*:\s*(\S+)", line)
        if name:
            current = name
        if profile and current:
            pairs.append((current, profile))
            current = ""
    return pairs


def _certificates(text: str) -> list[Certificate]:
    certs: list[Certificate] = []
    for chunk in re.split(r"(?m)(?=^\d+\)\s+Name:)", text):
        name = _search(r"Name:\s*(\S+)", chunk)
        if not name:
            continue
        days = _int(_search(r"Days to expiration:\s*(-?\d+)", chunk))
        bits = _int(_search(r"Public Key size:\s*(\d+)", chunk))
        certs.append(Certificate(name=name, days=days, key_bits=bits))
    return certs


def _users(text: str) -> list[dict[str, str]]:
    users: list[dict[str, str]] = []
    for chunk in re.split(r"(?m)(?=^\d+\)\s+User name:)", text):
        name = _search(r"User name:\s*(\S+)", chunk)
        if not name:
            continue
        users.append(
            {
                "name": name,
                "external": (_search(r"External Authentication:\s*(\S+)", chunk) or "").upper(),
                "timeout": _search(r"Timeout:\s*(\d+)", chunk) or "",
            }
        )
    return users


def _interfaces(text: str) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    chunks = re.split(r"(?m)(?=^\d+\)\s+Interface )", text)
    for chunk in chunks:
        name = _search(r"Interface\s+(\S+)", chunk)
        flags = _search(r"<([^>]+)>", chunk) or ""
        if not name:
            continue
        items.append({"name": name, "flags": flags})
    return items


def _vlans(text: str) -> list[dict[str, object]]:
    vlans: list[dict[str, object]] = []
    chunks = re.split(r"(?m)(?=^\d+\)\s+VLAN ID:)", text)
    for chunk in chunks:
        vlan_id = _search(r"VLAN ID:\s*(\d+)", chunk)
        if not vlan_id:
            continue
        interfaces = _search(r"Interfaces\s*:\s*(.+)", chunk) or ""
        vlans.append({"id": vlan_id, "interfaces": interfaces.split()})
    return vlans


def _names(text: str) -> list[str]:
    return re.findall(r"(?m)^\d+\)\s+Name:\s*(\S+)", text)


def _ldap(text: str) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    for chunk in re.split(r"(?m)(?=^\d+\)\s+Name:)", text):
        name = _search(r"Name:\s*(\S+)", chunk)
        if not name:
            continue
        actions.append(
            {
                "name": name,
                "port": _search(r"Port:\s*(\d+)", chunk) or "",
                "secure": (_search(r"Secure Type:\s*(\S+)", chunk) or "").upper(),
                "validate": (_search(r"Validate LDAP Server Certificate:\s*(\S+)", chunk) or "").upper(),
            }
        )
    return actions


def _snmp_alarms(text: str) -> dict[str, str]:
    alarms: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"\s*\d+\)\s+(\S+)\s+(.*)$", line)
        if not match:
            continue
        alarms[match.group(1).upper()] = match.group(2)
    return alarms


def _labeled(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for key, value in re.findall(r"([A-Za-z][A-Za-z0-9 ./()+_/-]*?):\s*(\S+)", text or ""):
        values[re.sub(r"\s+", "", key).lower()] = value
    return values


def _count_objects(text: str) -> int:
    if not text.strip():
        return 0
    numbered = re.findall(r"(?m)^\d+\)", text)
    if numbered:
        return len(numbered)
    named = re.findall(r"(?m)^\s*Name:\s*\S+", text)
    return len(named)


def _df_var(text: str) -> str | None:
    for line in text.splitlines():
        if line.strip().endswith("/var"):
            parts = line.split()
            if len(parts) >= 4:
                return _to_mb(parts[3])
    return None


def _to_mb(token: str) -> str | None:
    match = re.match(r"([\d.]+)([KMGT])?", token, re.I)
    if not match:
        return None
    number = float(match.group(1))
    unit = (match.group(2) or "B").upper()
    scale = {"B": 1 / (1024 * 1024), "K": 1 / 1024, "M": 1, "G": 1024, "T": 1024 * 1024}
    return str(number * scale[unit])


def _uptime(text: str) -> float | None:
    match = re.search(r"up\s+(?:(\d+)\s+days?)?(?:,\s*)?(?:(\d+):(\d+))?", text)
    if not match or not any(match.groups()):
        return None
    days = int(match.group(1) or 0)
    hours = int(match.group(2) or 0)
    return days + hours / 24


def _console(show: dict[str, list[str]], nsconf: str) -> bool:
    central = _first(show, "show ns centralmanagementserver")
    service = _first(show, "show service")
    if central.strip() and "ERROR" not in central.upper():
        if re.search(r"(?i)ip|server|name", central):
            return True
    return bool(re.search(r"(?i)adm_|mas_|netscaler console|centralmanagement", service + nsconf))
