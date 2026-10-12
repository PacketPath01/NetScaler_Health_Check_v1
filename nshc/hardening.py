"""Extra security, routing, and operational checks beyond the workbook.

Each check uses show-command output or ns.conf. Missing collector data becomes
a review, not a guess. Evidence is counts, names, and states.
"""

from __future__ import annotations

import ipaddress

from nshc.cleanup import Note
from nshc.parse import Appliance, SslProfile

_MFA = ("radius", "oauth", "saml", "cert", "push", "webauth")
_SYNC_OK = {"SUCCESS", "ENABLED", "SUCCESSFUL"}
_FACTORY = {"ns-server-certificate", "ns-sftrust-certificate"}


def notes(app: Appliance) -> list[Note]:
    posture = (app.inventory or {}).get("posture") or {}
    return [
        _headers(app, posture),
        _cookies(app, posture),
        _https_redirect(app, posture),
        _ocsp(app),
        _mfa(app, posture),
        _management(posture),
        _cert_monitor(posture),
        _rate_limit(app, posture),
        _vmac(app, posture),
        _default_route_network(app, posture),
        _ha_sync(app, posture),
        _interface_errors(posture),
        _vlan(app, posture),
        _backup(posture),
        _dns(posture),
        _timezone(posture),
        _license(posture),
        _packet_engine(app, posture),
        _cores(posture),
        _monitors(posture),
        _visibility(app, posture),
        _http_versions(app),
        _audit_hash(posture),
        _hybrid(app),
    ]


def _note(check_id: str, title: str, focus: str, status: str, risk: str, wording: str, evidence: list[str]) -> Note:
    return Note(id=check_id, title=title, focus=focus, status=status, risk=risk, wording=wording, evidence=evidence)


def _headers(app: Appliance, posture: dict) -> Note:
    wanted = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Content-Security-Policy",
        "Permissions-Policy",
    ]
    found = set(posture.get("headers") or [])
    if (posture.get("aaa_csp") or "").upper() == "ENABLED":
        found.add("Content-Security-Policy")
    missing = [name for name in wanted if name not in found]
    public = _public_vservers(app)
    if not public:
        return _note(
            "nshc-x-headers",
            "Security response headers",
            "Security",
            "na",
            "INFO",
            "No HTTP or SSL virtual server was found to score.",
            ["Responder and rewrite header actions were not required."],
        )
    if not missing:
        return _note(
            "nshc-x-headers",
            "Security response headers",
            "Security",
            "pass",
            "INFO",
            "The five response headers are present in the saved configuration or the AAA CSP header is enabled.",
            [f"Found: {', '.join(wanted)}."],
        )
    evidence = [f"Found: {', '.join(sorted(found)) or 'none'}.", f"Not found: {', '.join(missing)}."]
    if posture.get("aaa_csp") == "ENABLED":
        evidence.append("The AAA CSP header covers the login UI. Public virtual servers still need their own header actions.")
    return _note(
        "nshc-x-headers",
        "Security response headers",
        "Security",
        "review",
        "MEDIUM",
        "Insert nosniff, a frame control, Referrer-Policy, a content security policy, and Permissions-Policy with a rewrite or responder action on public virtual servers. A header set only by the backend is acceptable when the application owner documents it.",
        evidence,
    )


def _cookies(app: Appliance, posture: dict) -> Note:
    cookies = posture.get("appfw_cookies") or {}
    gaps: list[str] = []
    if (app.cookie_version or "").strip() == "0":
        gaps.append("Persistence cookie version is 0, so the ADC does not mark that cookie HttpOnly.")
    if posture.get("persistence_secure") == "DISABLED":
        gaps.append("The persistence cookie secure flag is disabled.")
    if posture.get("aaa_httponly") == "DISABLED":
        gaps.append("The AAA HttpOnly cookie setting is disabled.")
    if cookies.get("samesite_off"):
        gaps.append(f"{cookies['samesite_off']} application firewall profile(s) do not insert SameSite.")
    if cookies.get("flags_none"):
        gaps.append(f"{cookies['flags_none']} application firewall profile(s) add no Secure or HttpOnly cookie flag.")
    if not gaps:
        return _note(
            "nshc-x-cookies",
            "Secure cookie flags",
            "Security",
            "pass",
            "INFO",
            "Persistence and AAA cookies are marked to stay on HTTPS, and SameSite insertion is not left off.",
            ["Cookie version, the persistence secure flag, AAA HttpOnly, and application-firewall SameSite were reviewed."],
        )
    return _note(
        "nshc-x-cookies",
        "Secure cookie flags",
        "Security",
        "review",
        "MEDIUM",
        "Set cookie version 1, enable the persistence secure flag and AAA HttpOnly, and insert SameSite Lax or Strict on Gateway and AAA cookies.",
        gaps,
    )


def _https_redirect(app: Appliance, posture: dict) -> Note:
    http_vs = [
        item["name"]
        for item in (app.inventory or {}).get("vservers") or []
        if item.get("kind") in {"lb", "cs"} and item.get("protocol") == "HTTP" and not item.get("disabled")
    ]
    if not http_vs:
        return _note(
            "nshc-x-https-redirect",
            "HTTP to HTTPS redirect",
            "Security",
            "pass",
            "INFO",
            "No enabled HTTP load-balancing or content-switching virtual server was found.",
            ["Nothing in this configuration is listening for cleartext HTTP."],
        )
    redirects = int(posture.get("https_redirects") or 0)
    listed = ", ".join(http_vs[:8])
    extra = f" and {len(http_vs) - 8} more" if len(http_vs) > 8 else ""
    if redirects == 0:
        return _note(
            "nshc-x-https-redirect",
            "HTTP to HTTPS redirect",
            "Security",
            "fail",
            "HIGH",
            "Add an explicit redirect to HTTPS for every public HTTP virtual server. Internal HTTP that must stay cleartext should be documented.",
            [f"{len(http_vs)} HTTP virtual server(s) and no HTTPS redirect action: {listed}{extra}."],
        )
    return _note(
        "nshc-x-https-redirect",
        "HTTP to HTTPS redirect",
        "Security",
        "review",
        "MEDIUM",
        "HTTPS redirect actions exist. Confirm each public HTTP virtual server is bound to one.",
        [f"{redirects} redirect action(s). HTTP virtual servers: {listed}{extra}."],
    )


def _ocsp(app: Appliance) -> Note:
    frontend = [item for item in app.ssl_profiles if _frontend(item)]
    if not app.ssl_profiles:
        return _note(
            "nshc-x-ocsp",
            "OCSP stapling",
            "Security",
            "review",
            "MEDIUM",
            "SSL profiles were not in the collector, so OCSP stapling was not scored.",
            ["show ssl profile was missing."],
        )
    disabled = [item.name for item in frontend if item.ocsp == "DISABLED"]
    unknown = [item.name for item in frontend if not item.ocsp]
    if disabled:
        listed = ", ".join(disabled[:8])
        extra = f" and {len(disabled) - 8} more" if len(disabled) > 8 else ""
        return _note(
            "nshc-x-ocsp",
            "OCSP stapling",
            "Security",
            "fail",
            "MEDIUM",
            "Enable OCSP stapling on frontend SSL profiles that serve public certificates, and bind an OCSP responder.",
            [f"OCSP stapling is disabled on: {listed}{extra}."],
        )
    if unknown:
        return _note(
            "nshc-x-ocsp",
            "OCSP stapling",
            "Security",
            "review",
            "LOW",
            "Frontend profiles did not report an OCSP stapling state.",
            [f"State missing on {len(unknown)} frontend profile(s)."],
        )
    if not frontend:
        return _note(
            "nshc-x-ocsp",
            "OCSP stapling",
            "Security",
            "na",
            "INFO",
            "No frontend SSL profile was collected.",
            ["Backend profiles are not scored for stapling."],
        )
    return _note(
        "nshc-x-ocsp",
        "OCSP stapling",
        "Security",
        "pass",
        "INFO",
        "Frontend SSL profiles have OCSP stapling enabled.",
        [f"{len(frontend)} frontend profile(s)."],
    )


def _mfa(app: Appliance, posture: dict) -> Note:
    if app.vpn_vservers <= 0 and app.auth_vservers <= 0:
        return _note(
            "nshc-x-mfa",
            "Gateway and admin MFA",
            "Security",
            "na",
            "INFO",
            "No Gateway or AAA virtual server was configured.",
            ["MFA was not required by this configuration."],
        )
    factors = posture.get("factors") or {}
    capable = sum(factors.get(name, 0) for name in _MFA)
    evidence = [
        "Actions: "
        + ", ".join(f"{name} {factors.get(name, 0)}" for name in (*_MFA, "ldap", "tacacs", "local", "epa"))
        + f". Authentication binds: {posture.get('auth_binds', 0)}."
    ]
    if capable == 0:
        return _note(
            "nshc-x-mfa",
            "Gateway and admin MFA",
            "Security",
            "fail",
            "HIGH",
            "Gateway or AAA is configured with only LDAP or local authentication. Add a second factor and require it on the logon policies. Keep a local break-glass admin and require MFA for day-to-day administration.",
            evidence,
        )
    if not posture.get("auth_binds"):
        return _note(
            "nshc-x-mfa",
            "Gateway and admin MFA",
            "Security",
            "fail",
            "HIGH",
            "Second-factor actions exist, but no authentication policy is bound to a Gateway or AAA virtual server.",
            evidence,
        )
    evidence.append("SAML or OAuth still depends on the identity provider to require MFA. TACACS or RADIUS is the usual second factor for admin logon.")
    return _note(
        "nshc-x-mfa",
        "Gateway and admin MFA",
        "Security",
        "review",
        "MEDIUM",
        "A second-factor style action is bound. Confirm the Gateway logon and day-to-day admin logon both require it.",
        evidence,
    )


def _management(posture: dict) -> Note:
    owned = posture.get("owned") or []
    nsips = [item for item in owned if item.get("type") == "NSIP"] or owned[:1]
    rules = posture.get("acl_rules") or []
    wide = [item for item in rules if item.get("action") == "ALLOW" and _wide_source(item.get("source", ""))]
    private = _all_private(nsips)
    evidence = [f"{len(rules)} ACL rule(s), {len(wide)} of them allow any source."]
    if nsips and not private:
        evidence.append("A management address is outside the private ranges.")
        return _note(
            "nshc-x-mgmt-exposure",
            "Management reachability",
            "Security",
            "fail",
            "HIGH",
            "Keep management off the public internet. Limit SSH, NITRO, and the GUI with a source ACL, and do not publish that address through NAT.",
            evidence,
        )
    if wide:
        return _note(
            "nshc-x-mgmt-exposure",
            "Management reachability",
            "Security",
            "fail",
            "HIGH",
            "An allow ACL matches any source. Replace it with the management subnets that actually administer the appliance.",
            evidence,
        )
    if not nsips:
        evidence.append("No NSIP was parsed from ns.conf, so reachability could not be confirmed.")
    else:
        evidence.append("The management address is in a private range. This bundle cannot see an upstream NAT or firewall.")
    return _note(
        "nshc-x-mgmt-exposure",
        "Management reachability",
        "Security",
        "review",
        "MEDIUM",
        "Confirm the management IP is not reachable from the internet. restrictAccess and SecureOnly do not replace a source ACL.",
        evidence,
    )


def _cert_monitor(posture: dict) -> Note:
    disabled = int(posture.get("cert_monitor_off") or 0)
    if disabled:
        return _note(
            "nshc-x-cert-monitor",
            "Certificate expiry monitoring",
            "Security",
            "review",
            "MEDIUM",
            "Enable the certificate expiry monitor on every production certificate and send the SNMP trap to the operations team. The report's expiry list is only a point-in-time check.",
            [f"{disabled} certificate(s) have the expiry monitor disabled."],
        )
    return _note(
        "nshc-x-cert-monitor",
        "Certificate expiry monitoring",
        "Security",
        "pass",
        "INFO",
        "Production certificates have the expiry monitor enabled.",
        ["No disabled expiry monitor was seen outside the factory certificates."],
    )


def _rate_limit(app: Appliance, posture: dict) -> Note:
    limits = int(posture.get("limit_identifiers") or 0)
    exposed = app.vpn_vservers > 0 or app.auth_vservers > 0 or bool(_public_vservers(app))
    if limits:
        return _note(
            "nshc-x-rate-limit",
            "Login and application rate limiting",
            "Security",
            "pass",
            "INFO",
            "Rate-limit identifiers are configured. Confirm they are bound to authentication and other high-risk virtual servers.",
            [f"{limits} limit identifier(s)."],
        )
    if not exposed:
        return _note(
            "nshc-x-rate-limit",
            "Login and application rate limiting",
            "Security",
            "na",
            "INFO",
            "No Gateway, AAA, or public virtual server was found.",
            ["Rate limiting was not scored."],
        )
    tcp = posture.get("tcp_rate")
    evidence = ["No limit identifier was configured."]
    if tcp == 0:
        evidence.append("The global TCP rate-control threshold is 0.")
    return _note(
        "nshc-x-rate-limit",
        "Login and application rate limiting",
        "Security",
        "review",
        "MEDIUM",
        "Add a rate limit on Gateway and AAA logon endpoints and on other high-risk applications. A global TCP threshold does not protect a single login URL.",
        evidence,
    )


def _vmac(app: Appliance, posture: dict) -> Note:
    peers = app.ha_nodes >= 2 or int(posture.get("cluster_nodes") or 0) >= 2
    if not peers:
        return _note(
            "nshc-x-vmac",
            "VMAC for failover",
            "Networking",
            "na",
            "INFO",
            "The appliance is standalone, so a virtual MAC is not required for HA failover.",
            ["One node was collected."],
        )
    if posture.get("vmac"):
        return _note(
            "nshc-x-vmac",
            "VMAC for failover",
            "Networking",
            "pass",
            "INFO",
            "A virtual MAC or VRID is configured.",
            ["VMAC or VRID was present."],
        )
    return _note(
        "nshc-x-vmac",
        "VMAC for failover",
        "Networking",
        "fail",
        "HIGH",
        "Configure a VMAC on the interfaces or channels that carry the default route and critical virtual servers so failover does not depend on a gratuitous ARP.",
        ["HA or a cluster is configured and no VMAC or VRID was found."],
    )


def _default_route_network(app: Appliance, posture: dict) -> Note:
    routes = (app.inventory or {}).get("routes") or []
    defaults = [
        route
        for route in routes
        if route.get("network") in {"0.0.0.0", "0"} and str(route.get("netmask")) in {"0.0.0.0", "0"} and route.get("state", "UP") in {"", "UP"}
    ]
    if not defaults:
        return _note(
            "nshc-x-default-net",
            "Default route network",
            "Networking",
            "na",
            "INFO",
            "No IPv4 default route was present to score. The missing-default check covers that case.",
            ["No default route."],
        )
    nsips = [item for item in posture.get("owned") or [] if item.get("type") in {"", "NSIP"}]
    on_management = [route for route in defaults if _gateway_on_management(route.get("gateway", ""), nsips)]
    if on_management:
        return _note(
            "nshc-x-default-net",
            "Default route network",
            "Networking",
            "review",
            "HIGH",
            "The default gateway sits on the management subnet. Move production default routing onto a data network. On MPX and SDX that means off the 0/x management interfaces.",
            [f"{len(on_management)} default route(s) use the management subnet."],
        )
    return _note(
        "nshc-x-default-net",
        "Default route network",
        "Networking",
        "pass",
        "INFO",
        "The default gateway is not on the management IP subnet.",
        [f"{len(defaults)} default route(s)."],
    )


def _ha_sync(app: Appliance, posture: dict) -> Note:
    if app.ha_nodes < 2:
        return _note(
            "nshc-x-ha-sync",
            "HA version and configuration sync",
            "Networking",
            "na",
            "INFO",
            "A single node has no HA peer to compare.",
            ["HA node count is under 2."],
        )
    versions = posture.get("ha_versions") or []
    sync = posture.get("ha_sync") or []
    evidence = [f"Versions collected: {len(versions)}. Sync states: {', '.join(sync) or 'none'}."]
    if len(set(versions)) > 1:
        return _note(
            "nshc-x-ha-sync",
            "HA version and configuration sync",
            "Networking",
            "fail",
            "HIGH",
            "HA peers are not on the same firmware. Match the builds before failover, then confirm configuration sync.",
            evidence,
        )
    if sync and any(item not in _SYNC_OK for item in sync):
        return _note(
            "nshc-x-ha-sync",
            "HA version and configuration sync",
            "Networking",
            "fail",
            "HIGH",
            "HA configuration sync is not successful. Correct sync before a change window.",
            evidence,
        )
    if not versions and not sync:
        return _note(
            "nshc-x-ha-sync",
            "HA version and configuration sync",
            "Networking",
            "review",
            "MEDIUM",
            "Peer firmware and sync state were not in show HA node. Compare them before failover.",
            evidence,
        )
    return _note(
        "nshc-x-ha-sync",
        "HA version and configuration sync",
        "Networking",
        "pass",
        "INFO",
        "HA peers report the same firmware and a successful sync.",
        evidence,
    )


def _interface_errors(posture: dict) -> Note:
    rows = [item for item in posture.get("interfaces") or [] if not str(item.get("name", "")).upper().startswith("LO/")]
    if not rows:
        return _note(
            "nshc-x-if-errors",
            "Interface errors",
            "Networking",
            "review",
            "LOW",
            "show interface was not collected, so error counters and utilization were not scored.",
            ["No interface block was parsed."],
        )
    noisy = []
    for item in rows:
        errors = item["rx_errs"] + item["tx_errs"]
        drops = item["rx_drops"] + item["tx_drops"]
        if item.get("up") and (errors or drops):
            noisy.append(f"{item['name']}: errors {errors}, drops {drops}")
    evidence = ["stat interface was not collected, so utilization is not scored. Show counters are cumulative since boot."]
    if noisy:
        evidence.extend(noisy[:8])
        return _note(
            "nshc-x-if-errors",
            "Interface errors",
            "Networking",
            "review",
            "MEDIUM",
            "Review interfaces with errors or drops. Confirm the counters are still increasing before you replace a cable or transceiver.",
            evidence,
        )
    return _note(
        "nshc-x-if-errors",
        "Interface errors",
        "Networking",
        "pass",
        "INFO",
        "Up interfaces reported no receive or transmit errors or drops.",
        evidence,
    )


def _vlan(app: Appliance, posture: dict) -> Note:
    shared = []
    for vlan in posture.get("vlans") or []:
        data = [name for name in vlan.get("interfaces") or [] if not str(name).upper().startswith("LO/")]
        if len(data) >= 2 and not vlan.get("tagall"):
            shared.append(f"VLAN {vlan['id']} includes {', '.join(data[:6])} without tagall")
    if app.mac_moves:
        shared.append("MAC moves were reported.")
    if shared:
        return _note(
            "nshc-x-vlan",
            "Native VLAN and L2 loops",
            "Networking",
            "review",
            "MEDIUM",
            "Confirm tagall on trunks, keep a single native VLAN, and clear any L2 loop. MAC moves are a signal to check with the switch team.",
            shared,
        )
    native = [item["name"] for item in posture.get("interfaces") or [] if item.get("native_vlan") == "1" and not str(item["name"]).upper().startswith("LO/")]
    evidence = ["No VLAN with two data interfaces was missing tagall."]
    if native:
        evidence.append(f"Native VLAN 1 is still set on: {', '.join(native[:6])}.")
    return _note(
        "nshc-x-vlan",
        "Native VLAN and L2 loops",
        "Networking",
        "pass",
        "INFO",
        "No shared untagged VLAN or MAC move was found. Confirm native VLAN 1 is intentional on a single access interface.",
        evidence,
    )


def _backup(posture: dict) -> Note:
    count = int(posture.get("backups") or 0)
    if count:
        return _note(
            "nshc-x-backup",
            "Configuration backup",
            "Operations",
            "pass",
            "INFO",
            "A backup command is in the saved configuration. Confirm the last run succeeded and the copy is off the appliance.",
            [f"{count} backup command(s)."],
        )
    return _note(
        "nshc-x-backup",
        "Configuration backup",
        "Operations",
        "review",
        "MEDIUM",
        "No backup schedule is in ns.conf. Confirm NetScaler Console or an external job has a recent successful backup stored off the appliance.",
        ["No add system backup or create backup command was saved."],
    )


def _dns(posture: dict) -> Note:
    up = int(posture.get("dns_up") or 0)
    down = int(posture.get("dns_down") or 0)
    if up == 0 and down == 0:
        return _note(
            "nshc-x-dns",
            "ADC name servers",
            "Operations",
            "fail",
            "MEDIUM",
            "Configure at least two reachable name servers on the appliance. Authentication, OCSP, and GSLB depend on them.",
            ["show dns nameServer listed no servers."],
        )
    if down:
        return _note(
            "nshc-x-dns",
            "ADC name servers",
            "Operations",
            "fail",
            "MEDIUM",
            "A name server on the appliance is down. Restore it or remove it so lookups do not wait on a dead server.",
            [f"{up} up, {down} down."],
        )
    return _note(
        "nshc-x-dns",
        "ADC name servers",
        "Operations",
        "pass",
        "INFO",
        "Name servers on the appliance are up.",
        [f"{up} name server(s) up."],
    )


def _timezone(posture: dict) -> Note:
    zone = posture.get("timezone") or ""
    if not zone or zone.upper() in {"NONE", "UNSET", "UNSPECIFIED"}:
        return _note(
            "nshc-x-timezone",
            "Appliance timezone",
            "Operations",
            "fail",
            "LOW",
            "Set the appliance timezone. NTP synchronizes the clock and does not choose the zone used in logs and certificates.",
            ["Timezone was not set."],
        )
    return _note(
        "nshc-x-timezone",
        "Appliance timezone",
        "Operations",
        "pass",
        "INFO",
        "A timezone is set. Confirm it is the zone the operations team uses.",
        [f"Timezone: {zone}."],
    )


def _license(posture: dict) -> Note:
    days = posture.get("license_days")
    bandwidth = posture.get("bandwidth") or {}
    evidence = []
    if days is None:
        evidence.append("show ns license did not include an expiration date. Pooled and LAS licenses expire on the license server.")
    else:
        evidence.append(f"License days remaining: {days}.")
    ratio = None
    if bandwidth.get("maximum") and bandwidth.get("actual") is not None:
        ratio = bandwidth["actual"] / bandwidth["maximum"]
        evidence.append(f"Licensed bandwidth in use: {ratio:.0%}.")
    if days is not None and days < 0:
        status, risk = "fail", "HIGH"
        wording = "The license is past its expiration. Renew it before features drop to the default set."
    elif days is not None and days <= 30:
        status, risk = "fail", "HIGH"
        wording = "The license expires inside 30 days. Renew it and confirm the license server if this is a pooled or LAS entitlement."
    elif (days is not None and days <= 90) or (ratio is not None and ratio >= 0.85):
        status, risk = "review", "MEDIUM"
        wording = "Review license expiration and headroom. A pooled or LAS entitlement can expire even when the appliance does not show a date."
    elif days is None:
        status, risk = "review", "MEDIUM"
        wording = "Confirm the license server expiration and the bandwidth headroom. This collector did not include an on-box expiration date."
    else:
        status, risk = "pass", "INFO"
        wording = "The on-box license has more than 90 days remaining and bandwidth headroom."
    return _note("nshc-x-license", "License expiration and headroom", "Operations", status, risk, wording, evidence)


def _packet_engine(app: Appliance, posture: dict) -> Note:
    if app.packet_cpu_pct is None and app.ncpu is None and not posture.get("packet_engine_collected"):
        return _note(
            "nshc-x-ppe",
            "Packet engine",
            "Operations",
            "review",
            "LOW",
            "Packet-engine CPU and memory were not in the collector. The workbook still scores them when stat system -detail is present.",
            ["stat system -detail did not include packet CPU."],
        )
    evidence = []
    if app.packet_cpu_pct is not None:
        evidence.append(f"Packet CPU {app.packet_cpu_pct:.0f}%.")
    if app.ncpu is not None:
        evidence.append(f"CPUs {app.ncpu}.")
    if app.mem_used_pct is not None:
        evidence.append(f"Memory in use {app.mem_used_pct:.0f}%.")
    hot = (app.packet_cpu_pct or 0) >= 80 or (app.mem_used_pct or 0) >= 85
    if hot:
        return _note(
            "nshc-x-ppe",
            "Packet engine",
            "Operations",
            "review",
            "MEDIUM",
            "Packet CPU or memory is high. Compare it with the workbook CPU, memory, and RAM-per-vCPU checks before adding traffic.",
            evidence or ["Counters were only partly collected."],
        )
    return _note(
        "nshc-x-ppe",
        "Packet engine",
        "Operations",
        "pass",
        "INFO",
        "Packet CPU and memory are under the review thresholds.",
        evidence or ["Counters were present."],
    )


def _cores(posture: dict) -> Note:
    if posture.get("cores_collected"):
        return _note(
            "nshc-x-cores",
            "Crash history",
            "Operations",
            "review",
            "MEDIUM",
            "The collector mentions a core or crash record. Review /var/core and ns.log on the appliance before the change window. This report does not copy crash contents.",
            ["A core or crash reference was seen."],
        )
    return _note(
        "nshc-x-cores",
        "Crash history",
        "Operations",
        "review",
        "LOW",
        "This collector does not include /var/core. Review crash and core history on the appliance before an upgrade.",
        ["No core listing was in the support bundle."],
    )


def _monitors(posture: dict) -> Note:
    rows = posture.get("monitors") or []
    aggressive = []
    for item in rows:
        reasons = []
        if item.get("interval") is not None and item["interval"] <= 2:
            reasons.append(f"interval {item['interval']}s")
        if item.get("downtime") is not None and item["downtime"] <= 5:
            reasons.append(f"downtime {item['downtime']}s")
        if item.get("retries") is not None and item["retries"] < 2:
            reasons.append(f"retries {item['retries']}")
        if item.get("alert_retries") == 0:
            reasons.append("alertRetries 0")
        if reasons:
            aggressive.append(f"{item['name']}: {', '.join(reasons)}")
    if aggressive:
        return _note(
            "nshc-x-monitors",
            "Monitor timing",
            "Operations",
            "review",
            "MEDIUM",
            "Short intervals, a downtime of 5 seconds or less, or a single retry will mark services down during a brief loss. Confirm retries and alertRetries on the monitors bound to production services.",
            aggressive[:8],
        )
    if not rows:
        return _note(
            "nshc-x-monitors",
            "Monitor timing",
            "Operations",
            "pass",
            "INFO",
            "No custom monitor timing was saved. Built-in monitors keep the appliance defaults. Confirm those defaults on production services.",
            ["retries and alertRetries are omitted from ns.conf when they are left at the default."],
        )
    return _note(
        "nshc-x-monitors",
        "Monitor timing",
        "Operations",
        "pass",
        "INFO",
        "Saved monitor timing is not aggressive. Confirm retries and alertRetries, which stay at the default when they are omitted from ns.conf.",
        [f"{len(rows)} custom monitor command(s)."],
    )


def _visibility(app: Appliance, posture: dict) -> Note:
    collectors = int(posture.get("appflow_collectors") or 0)
    binds = int(posture.get("appflow_binds") or 0)
    analytics = int(posture.get("analytics_profiles") or 0)
    if collectors == 0 and analytics == 0:
        if not _public_vservers(app) and app.vpn_vservers <= 0:
            return _note(
                "nshc-x-appflow",
                "AppFlow and analytics",
                "Visibility",
                "na",
                "INFO",
                "No public virtual server was found to export.",
                ["AppFlow was not scored."],
            )
        return _note(
            "nshc-x-appflow",
            "AppFlow and analytics",
            "Visibility",
            "review",
            "LOW",
            "No AppFlow collector or analytics profile is configured. Add insight export where the operations team needs request and Gateway visibility.",
            ["Nothing was saved."],
        )
    if binds == 0:
        return _note(
            "nshc-x-appflow",
            "AppFlow and analytics",
            "Visibility",
            "review",
            "LOW",
            "Analytics or an AppFlow collector is configured. Confirm the profile or policy is bound to the virtual servers you need to see.",
            [f"{collectors} AppFlow collector(s), {analytics} analytics profile(s), no AppFlow bind."],
        )
    return _note(
        "nshc-x-appflow",
        "AppFlow and analytics",
        "Visibility",
        "pass",
        "INFO",
        "AppFlow is bound. Confirm the collector is receiving data.",
        [f"{collectors} collector(s) and {binds} bind(s)."],
    )


def _http_versions(app: Appliance) -> Note:
    profiles = (app.inventory or {}).get("http_profiles") or []
    if not profiles:
        return _note(
            "nshc-x-http2",
            "HTTP/2 and HTTP/3",
            "Visibility",
            "review",
            "LOW",
            "HTTP profiles were not collected.",
            ["show ns httpProfile was missing."],
        )
    http2_on = sum(1 for item in profiles if item.get("http2") == "ENABLED")
    http3_on = sum(1 for item in profiles if item.get("http3") == "ENABLED")
    http3_seen = sum(1 for item in profiles if item.get("http3"))
    evidence = [f"HTTP/2 enabled on {http2_on} of {len(profiles)} profile(s)."]
    if http3_seen:
        evidence.append(f"HTTP/3 enabled on {http3_on} of {len(profiles)} profile(s).")
    else:
        evidence.append("HTTP/3 was not listed on the HTTP profiles.")
    if http2_on:
        return _note(
            "nshc-x-http2",
            "HTTP/2 and HTTP/3",
            "Visibility",
            "pass",
            "INFO",
            "HTTP/2 is enabled on at least one HTTP profile. Enable it on the public profiles whose clients support it. HTTP/3 stays optional.",
            evidence,
        )
    return _note(
        "nshc-x-http2",
        "HTTP/2 and HTTP/3",
        "Visibility",
        "review",
        "LOW",
        "HTTP/2 is disabled on the collected HTTP profiles. Enable it where clients and servers support it. Treat HTTP/3 as optional.",
        evidence,
    )


def _audit_hash(posture: dict) -> Note:
    state = posture.get("audit_hash") or ""
    if state == "ENABLED":
        return _note(
            "nshc-x-audit-hash",
            "Audit log hashing",
            "Visibility",
            "pass",
            "INFO",
            "Audit log hashing is enabled.",
            ["Hashing is enabled."],
        )
    if state == "DISABLED":
        return _note(
            "nshc-x-audit-hash",
            "Audit log hashing",
            "Visibility",
            "fail",
            "LOW",
            "Enable audit log hashing so exported logs can be checked for tampering.",
            ["Hashing is disabled."],
        )
    return _note(
        "nshc-x-audit-hash",
        "Audit log hashing",
        "Visibility",
        "review",
        "LOW",
        "This build's audit parameters did not show a log-hashing control. Enable hashing when the release provides it.",
        ["No audit-log hash field was collected."],
    )


def _hybrid(app: Appliance) -> Note:
    curves = (app.inventory or {}).get("ecc_curves") or []
    names = [curve.upper() for item in curves for curve in item.get("curves") or []]
    hybrid = [name for name in names if "MLKEM" in name or "KYBER" in name]
    if not curves:
        return _note(
            "nshc-x-pq",
            "Post-quantum hybrid key exchange",
            "Security",
            "review",
            "LOW",
            "No ECC curve bind was saved. Confirm the frontend profiles offer a hybrid post-quantum key exchange such as X25519MLKEM768 on current 13.1 and 14.1 builds.",
            ["No bind ssl ... -eccCurveName lines were found."],
        )
    if not hybrid:
        return _note(
            "nshc-x-pq",
            "Post-quantum hybrid key exchange",
            "Security",
            "review",
            "LOW",
            "Bind a hybrid post-quantum curve such as X25519MLKEM768 on frontend SSL profiles, ahead of the classical curves. This is readiness, not a replacement for the current TLS profile.",
            ["No ML-KEM or Kyber curve is bound."],
        )
    return _note(
        "nshc-x-pq",
        "Post-quantum hybrid key exchange",
        "Security",
        "pass",
        "INFO",
        "A hybrid post-quantum curve is bound. Confirm the public frontend profiles include it.",
        [f"Hybrid curves bound: {len(hybrid)}."],
    )


def _frontend(profile: SslProfile) -> bool:
    role = profile.role.lower()
    name = profile.name.lower()
    if "backend" in role or "backend" in name:
        return False
    if "frontend" in role or "frontend" in name:
        return True
    return "frontend" in role or role == ""


def _public_vservers(app: Appliance) -> list[dict]:
    return [
        item
        for item in (app.inventory or {}).get("vservers") or []
        if item.get("kind") in {"lb", "cs", "vpn", "auth"} and item.get("protocol", "SSL") in {"HTTP", "SSL", "SSL_BRIDGE", "SSL_TCP", ""}
    ]


def _wide_source(source: str) -> bool:
    token = source.strip().lower()
    return token in {"", "*", "any", "0.0.0.0", "0", "::", "::/0"}


def _all_private(rows: list[dict]) -> bool:
    if not rows:
        return False
    for item in rows:
        try:
            address = ipaddress.ip_address(item.get("address", "").split("%")[0])
        except ValueError:
            return False
        if not address.is_private and not address.is_loopback:
            return False
    return True


def _gateway_on_management(gateway: str, nsips: list[dict]) -> bool:
    try:
        target = ipaddress.ip_address(gateway)
    except ValueError:
        return False
    for item in nsips:
        try:
            network = ipaddress.ip_network(f"{item['address']}/{item['mask']}", strict=False)
        except ValueError:
            continue
        if target in network and network.prefixlen < 32:
            return True
    return False
