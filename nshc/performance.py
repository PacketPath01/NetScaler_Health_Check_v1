"""Performance and common-configuration findings.

A check is emitted only when the bundle shows the problem. Healthy and
uncollected settings stay out of the report. Each finding says why it matters
and cites a Citrix document.
"""

from __future__ import annotations

from nshc.cleanup import Note
from nshc.parse import Appliance

_HEADER_DEFAULT = 24820
_BUFFER_REVIEW = 8 * 1024 * 1024
_HSTS_YEAR = 31_536_000
_WAN = {"nstcp_default_wan_profile"}
_LAN_NO_SCALING = {"nstcp_default_tcp_lnp"}
_WEAK_MONITORS = {"PING", "TCP", "UDP"}
_WEB_PROTOCOLS = {"HTTP", "SSL", "SSL_BRIDGE", "HTTPS"}

_TCP_DOC = "https://docs.netscaler.com/en-us/citrix-adc/current-release/system/tcp-configurations.html"
_HEADER_DOC = "https://support.citrix.com/external/article/CTX584254/what-is-maximum-http-header-length-on-ne.html"
_SERVER_AUTH_DOC = "https://docs.netscaler.com/en-us/citrix-adc/current-release/ssl/server-authentication.html"
_HSTS_DOC = "https://docs.netscaler.com/en-us/citrix-adc/current-release/ssl/how-to-articles/ssl-support-for-hsts.html"
_HOST_DOC = "https://docs.netscaler.com/en-us/citrix-adc/current-release/system/http-configurations.html"
_FLUSH_DOC = "https://support.citrix.com/external/article/CTX124710/citrix-netscaler-down-state-flush-featur.html"
_CS_DOC = "https://docs.netscaler.com/en-us/citrix-adc/current-release/content-switching/basic-configuration.html"
_MONITOR_DOC = "https://docs.netscaler.com/en-us/citrix-adc/current-release/load-balancing/load-balancing-customizing-monitors.html"
_SSL_DOC = "https://docs.netscaler.com/en-us/citrix-adc/current-release/ssl/ssl-profiles/ssl-enabling-the-default-profile.html"


def notes(app: Appliance) -> list[Note]:
    data = app.inventory or {}
    found = [
        _window_scaling(data),
        _tcp_buffer(data),
        _tcp_burst(data),
        _session_reuse(app, data),
        _header_limit(data),
        _server_auth(app, data),
        _host_header(data),
        _hsts_age(app, data),
        _down_flush(data),
        _client_ip(data),
        _cs_default(data),
        _app_monitor(data),
    ]
    return [item for item in found if item is not None]


def _note(check_id: str, title: str, focus: str, status: str, risk: str, wording: str, evidence: list[str], resources: list[str]) -> Note:
    return Note(
        id=check_id,
        title=title,
        focus=focus,
        status=status,
        risk=risk,
        wording=wording,
        evidence=evidence,
        resources=resources,
    )


def _window_scaling(data: dict) -> Note | None:
    weak = [
        item["name"]
        for item in _tcp_in_use(data)
        if item.get("window_scaling") == "DISABLED" and item["name"].lower() not in _LAN_NO_SCALING
    ]
    if not weak:
        return None
    return _note(
        "nshc-x-tcp-ws",
        "TCP window scaling is off",
        "Performance",
        "review",
        "LOW",
        "Window scaling lets a connection use more than 64 KB in flight. With it off, throughput stays low on anything beyond a tiny LAN. Enable it on the TCP profile bound to the virtual server. The built-in LAN profile leaves it off on purpose and is not listed.",
        [f"Window scaling is disabled on: {_join(weak)}."],
        [_TCP_DOC],
    )


def _tcp_buffer(data: dict) -> Note | None:
    large = []
    for item in _tcp_in_use(data):
        size = item.get("buffer_size")
        if item["name"].lower() in _WAN or not isinstance(size, int) or size <= _BUFFER_REVIEW:
            continue
        large.append(f"{item['name']} ({size // (1024 * 1024)} MB)")
    if not large:
        return None
    return _note(
        "nshc-x-tcp-buffer",
        "TCP buffer is large enough to exhaust memory",
        "Performance",
        "review",
        "MEDIUM",
        "Each connection can hold this much receive buffer. On a small virtual appliance a few dozen connections can consume the packet-engine memory. Keep the buffer near the bandwidth-delay product, and leave the built-in WAN profile unchanged if that profile is the one you meant to use.",
        [f"Receive buffer above 8 MB: {_join(large)}."],
        [_TCP_DOC],
    )


def _tcp_burst(data: dict) -> Note | None:
    small = [
        f"{item['name']} (burst {item['max_burst']})"
        for item in _tcp_in_use(data)
        if item["name"].lower() not in _WAN and isinstance(item.get("max_burst"), int) and item["max_burst"] <= 2
    ]
    if not small:
        return None
    return _note(
        "nshc-x-tcp-burst",
        "TCP burst is capped at two segments",
        "Performance",
        "review",
        "LOW",
        "maxBurst is how many segments the appliance may send back to back. A cap of two segments limits throughput. Raise it on profiles that serve ordinary web or Gateway traffic. The built-in WAN profile uses a small burst on purpose and is not listed.",
        [f"Burst of 2 or less: {_join(small)}."],
        [_TCP_DOC],
    )


def _session_reuse(app: Appliance, data: dict) -> Note | None:
    names = _ssl_in_use(app, data)
    off = [
        item.name
        for item in app.ssl_profiles
        if item.name in names and item.session_reuse == "DISABLED" and "dtls" not in item.name.lower() and "dtls" not in item.role.lower()
    ]
    if not off:
        return None
    return _note(
        "nshc-x-ssl-reuse",
        "SSL session reuse is disabled",
        "Performance",
        "review",
        "MEDIUM",
        "Session reuse completes the next handshake from a cached session instead of a full negotiation. Turning it off raises CPU use on every new connection. The product default is enabled. Leave it off only when an application requires a unique session, such as a DTLS service that the platform cannot reuse.",
        [f"Session reuse is disabled on: {_join(off)}."],
        [_SSL_DOC],
    )


def _header_limit(data: dict) -> Note | None:
    wide = []
    for item in _http_in_use(data, include_default=True):
        sizes = [item.get("max_header"), item.get("max_field")]
        over = [size for size in sizes if isinstance(size, int) and size > _HEADER_DEFAULT]
        if over:
            wide.append(f"{item['name']} ({max(over)} bytes)")
    if not wide:
        return None
    return _note(
        "nshc-x-http-header",
        "HTTP header limit is above the product default",
        "Performance",
        "review",
        "MEDIUM",
        "The default maximum header length is 24820 bytes. A higher limit uses more memory per request and gives a header flood more room. CTX584254 documents that default. Set the profile to the largest header the application actually sends.",
        [f"Above 24820 bytes: {_join(wide)}."],
        [_HEADER_DOC],
    )


def _server_auth(app: Appliance, data: dict) -> Note | None:
    if not _web_backends(data):
        return None
    names = _ssl_in_use(app, data)
    off = [item.name for item in app.ssl_profiles if item.name in names and _backend(item.role) and item.server_auth == "DISABLED"]
    if not off:
        return None
    return _note(
        "nshc-x-server-auth",
        "Backend SSL does not check the server certificate",
        "Configuration",
        "review",
        "MEDIUM",
        "Server authentication is off on a backend SSL profile that is in use. The appliance will accept any certificate from the server. Enable server authentication and bind the CA that signed the server certificate. Leave it off only for a lab server that does not have a certificate you trust.",
        [f"Server authentication is disabled on: {_join(off)}."],
        [_SERVER_AUTH_DOC],
    )


def _host_header(data: dict) -> Note | None:
    off = [item["name"] for item in _http_in_use(data, include_default=False) if item.get("host_header") == "DISABLED"]
    if not off:
        return None
    return _note(
        "nshc-x-host-header",
        "Host header validation is off",
        "Configuration",
        "review",
        "MEDIUM",
        "With host-header validation off, a request can name a host the virtual server does not serve. Enable it on the HTTP profile bound to each public virtual server. The factory default profile ships with this off, so it is listed only when a profile is explicitly bound.",
        [f"Host header validation is disabled on: {_join(off)}."],
        [_HOST_DOC],
    )


def _hsts_age(app: Appliance, data: dict) -> Note | None:
    names = _ssl_in_use(app, data)
    short = []
    for item in app.ssl_profiles:
        if item.name not in names or item.hsts != "ENABLED" or _backend(item.role):
            continue
        if item.hsts_max_age is None or item.hsts_max_age >= _HSTS_YEAR:
            continue
        days = item.hsts_max_age // 86400
        short.append(f"{item.name} ({days} days)")
    if not short:
        return None
    return _note(
        "nshc-x-hsts-age",
        "HSTS max-age is under one year",
        "Configuration",
        "review",
        "LOW",
        "HSTS is enabled, and max-age is below 31536000 seconds (one year). Browsers stop forcing HTTPS when that timer ends. A max-age of zero removes the policy. Citrix documents the max-age setting. Raise it to at least one year on public virtual servers, which is also what the HSTS preload list expects.",
        [f"HSTS max-age under one year: {_join(short)}."],
        [_HSTS_DOC],
    )


def _down_flush(data: dict) -> Note | None:
    rows = data.get("flush_off") or []
    if not rows:
        return None
    labels = [f"{item['name']} ({item['kind']})" for item in rows]
    return _note(
        "nshc-x-flush",
        "Down state flush is disabled",
        "Configuration",
        "review",
        "MEDIUM",
        "Down state flush is off, so connections that were already open stay on a server or virtual server after it goes down. Clients keep using the failed server until they close those connections. CTX124710 describes the setting. Enable it unless an application must finish an in-flight request on that same server.",
        [f"Down state flush is disabled on: {_join(labels)}."],
        [_FLUSH_DOC],
    )


def _client_ip(data: dict) -> Note | None:
    names = data.get("cip_enabled") or []
    if not names:
        return None
    return _note(
        "nshc-x-client-ip",
        "Client IP insertion is enabled",
        "Configuration",
        "review",
        "LOW",
        "The appliance inserts the client address into an HTTP header. That is useful only when this appliance is the hop that writes the header and the server trusts that header from this appliance alone. Confirm the header is overwritten here, and that a client cannot supply its own value from the internet.",
        [f"Client IP insertion is enabled on: {_join(names)}."],
        [_TCP_DOC],
    )


def _cs_default(data: dict) -> Note | None:
    missing = [
        item
        for item in data.get("vservers") or []
        if item.get("kind") == "cs" and not item.get("cs_default") and not item.get("disabled")
    ]
    if not missing:
        return None
    blackhole = [item["name"] for item in missing if not item.get("cs_policies")]
    named = [item["name"] for item in missing]
    if blackhole:
        return _note(
            "nshc-x-cs-default",
            "Content switching has no target",
            "Configuration",
            "fail",
            "MEDIUM",
            "A content-switching virtual server with no policy and no default load-balancing virtual server cannot send traffic anywhere. Bind a default load-balancing virtual server, or bind a policy that selects one.",
            [f"No policy and no default target: {_join(blackhole)}."],
            [_CS_DOC],
        )
    return _note(
        "nshc-x-cs-default",
        "Content switching has no default target",
        "Configuration",
        "review",
        "MEDIUM",
        "Requests that match no content-switching policy are dropped when the virtual server has no default load-balancing target. Set a default target for that traffic, or confirm the policies cover every request you intend to accept.",
        [f"No default load-balancing virtual server: {_join(named)}."],
        [_CS_DOC],
    )


def _app_monitor(data: dict) -> Note | None:
    protocols = {}
    for service in data.get("services") or []:
        protocols[("service", service["name"])] = (service.get("protocol") or "").upper()
    for group in data.get("groups") or []:
        protocols[("group", group["name"])] = (group.get("protocol") or "").upper()
    by_target: dict[tuple[str, str], list[str]] = {}
    for bind in data.get("monitor_binds") or []:
        key = (bind.get("kind"), bind.get("name"))
        by_target.setdefault(key, []).append((bind.get("monitor_type") or "").upper())
    weak = []
    for key, kinds in by_target.items():
        if protocols.get(key, "") not in _WEB_PROTOCOLS:
            continue
        if not kinds or any(kind not in _WEAK_MONITORS for kind in kinds):
            continue
        weak.append(key[1])
    if not weak:
        return None
    return _note(
        "nshc-x-app-monitor",
        "Web service is monitored only by TCP or PING",
        "Configuration",
        "review",
        "MEDIUM",
        "A TCP or PING monitor stays up when the process is listening but the application is not answering. Bind an HTTP or HTTPS monitor that requests a URL the application must serve. This is listed only when a monitor is explicitly bound.",
        [f"HTTP or SSL objects with only a TCP, UDP, or PING monitor: {_join(weak)}."],
        [_MONITOR_DOC],
    )


def _tcp_in_use(data: dict) -> list[dict]:
    refs = {name.lower() for name in (data.get("profile_refs") or {}).get("tcp") or []}
    if _has_traffic(data):
        refs.add("nstcp_default_profile")
    return [item for item in data.get("tcp_profiles") or [] if item.get("name", "").lower() in refs]


def _http_in_use(data: dict, include_default: bool) -> list[dict]:
    refs = {name.lower() for name in (data.get("profile_refs") or {}).get("http") or []}
    if include_default:
        refs.add("nshttp_default_profile")
    return [item for item in data.get("http_profiles") or [] if item.get("name", "").lower() in refs]


def _ssl_in_use(app: Appliance, data: dict) -> set[str]:
    names = set((data.get("profile_refs") or {}).get("ssl") or [])
    names.update(profile for _vserver, profile in app.ssl_vservers)
    return names


def _has_traffic(data: dict) -> bool:
    return any(item.get("kind") in {"lb", "cs", "vpn"} for item in data.get("vservers") or [])


def _web_backends(data: dict) -> bool:
    for service in data.get("services") or []:
        if (service.get("protocol") or "").upper() in {"SSL", "SSL_BRIDGE", "SSL_TCP"}:
            return True
    for group in data.get("groups") or []:
        if (group.get("protocol") or "").upper() in {"SSL", "SSL_BRIDGE", "SSL_TCP"}:
            return True
    return False


def _backend(role: str) -> bool:
    return "back" in (role or "").lower()


def _join(names: list[str], limit: int = 6) -> str:
    unique = list(dict.fromkeys(names))
    shown = unique[:limit]
    extra = len(unique) - len(shown)
    text = ", ".join(shown)
    if extra:
        text += f", and {extra} more"
    return text
