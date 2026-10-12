"""Cleanup candidates and routing-table checks.

Hit counters for virtual servers are not in a standard support bundle, so an
object is "inactive" only when nothing in the saved configuration refers to it,
it is administratively disabled, or it is down with no services. Routing checks
compare static next hops and backend addresses with connected subnets.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from nshc.parse import Appliance


@dataclass
class Note:
    id: str
    title: str
    focus: str
    status: str
    risk: str
    wording: str
    evidence: list[str] = field(default_factory=list)


def inventory_notes(app: Appliance) -> list[Note]:
    data = app.inventory or {}
    return [_cleanup(data), _routing(data, app)]


def _cleanup(data: dict) -> Note:
    bound = set(data.get("bound_services") or [])
    application: list[str] = []
    platform: list[str] = []
    disabled_services: list[str] = []
    for service in data.get("services") or []:
        name = service["name"]
        if service.get("disabled"):
            disabled_services.append(name)
            continue
        if name in bound:
            continue
        if _platform_service(name):
            platform.append(name)
        else:
            application.append(name)

    empty_groups = [
        group["name"]
        for group in data.get("groups") or []
        if group.get("members", 0) == 0 or not group.get("bound")
    ]
    idle_vservers: list[str] = []
    disabled_vservers: list[str] = []
    empty_targets: list[str] = []
    for vserver in data.get("vservers") or []:
        if _vserver_in_use(vserver):
            if vserver.get("disabled"):
                disabled_vservers.append(f"{vserver['name']} ({vserver['kind']})")
            elif (
                vserver.get("kind") == "lb"
                and not vserver.get("config_children")
                and not vserver.get("show_bound")
            ):
                empty_targets.append(vserver["name"])
            continue
        label = f"{vserver['name']} ({vserver['kind']}/{vserver.get('state') or 'state not collected'})"
        if vserver.get("disabled"):
            disabled_vservers.append(f"{vserver['name']} ({vserver['kind']})")
        else:
            idle_vservers.append(label)

    unused_servers = [item["name"] for item in data.get("servers") or [] if not item.get("referenced") and not item.get("disabled")]
    disabled_servers = [item["name"] for item in data.get("servers") or [] if item.get("disabled")]
    unused_monitors = [item["name"] for item in data.get("monitors") or [] if not item.get("referenced")]

    evidence: list[str] = []
    if application:
        evidence.append("Services not bound to a virtual server: " + _join(application))
    if platform:
        evidence.append("Unbound Console or system services. Confirm the collector still needs them: " + _join(platform))
    if empty_groups:
        evidence.append("Service groups with no members, or not bound to a virtual server: " + _join(empty_groups))
    if idle_vservers:
        evidence.append("Virtual servers with no services and no content-switching or backup reference: " + _join(idle_vservers))
    if empty_targets:
        evidence.append("Content switching or a backup reference points at these virtual servers, and they have no services: " + _join(empty_targets))
    if disabled_vservers or disabled_services or disabled_servers:
        evidence.append(
            "Administratively disabled: "
            + _join([*disabled_vservers, *disabled_services, *disabled_servers])
        )
    if unused_servers:
        evidence.append("Servers not referenced by a service: " + _join(unused_servers))
    if unused_monitors:
        evidence.append("Custom monitors not bound to a service or group: " + _join(unused_monitors))

    if not evidence:
        counters = (
            "Policy and virtual-server hit counters were not in this collector, so a referenced object can still be idle."
            if not data.get("hit_counters")
            else "Hit counters were collected. Confirm a low counter is not a standby or seasonal virtual server before removing it."
        )
        return Note(
            id="nshc-x-unused",
            title="Services and virtual servers in use",
            focus="Cleanup",
            status="pass",
            risk="INFO",
            wording="Every configured service and virtual server is referenced. No cleanup candidate was found from the saved configuration.",
            evidence=["No unbound services, idle virtual servers, unused servers, or unused custom monitors were found.", counters],
        )
    evidence.append(
        "This bundle has no per-virtual-server or policy hit counters. A quiet object can still be a backup, a disaster-recovery listener, or a seasonal application. Confirm with the owner, remove only what is retired, and save the configuration."
    )
    return Note(
        id="nshc-x-unused",
        title="Services and virtual servers to review for cleanup",
        focus="Cleanup",
        status="review",
        risk="MEDIUM",
        wording="These objects look inactive in the saved configuration. Review them with the application owner before you remove anything.",
        evidence=evidence,
    )


def _routing(data: dict, app: Appliance) -> Note:
    routes = data.get("routes") or []
    pbrs = data.get("pbrs") or []
    if not routes and not pbrs:
        return Note(
            id="nshc-x-route",
            title="Routing table",
            focus="Routing",
            status="review",
            risk="LOW",
            wording="The collector did not include a route table or policy-based routes, so reachability was not checked.",
            evidence=["show route and show ns pbr were empty, and ns.conf has no add route or add ns pbr lines."],
        )

    parsed = []
    for route in routes:
        network = _network(route.get("network", ""), route.get("netmask", ""))
        parsed.append({**route, "net": network, "gateway_ip": _ip(route.get("gateway", ""))})
    connected = [item["net"] for item in parsed if item["type"] in {"DIRECT", "PERMANENT"} and item["state"] in {"UP", ""} and item["net"] is not None]
    owned = {_ip(ip.address) for ip in app.ips}
    owned.update(item["gateway_ip"] for item in parsed if item["type"] in {"DIRECT", "PERMANENT"} and item["gateway_ip"] is not None)
    owned.discard(None)

    evidence: list[str] = []
    hard = False
    for item in parsed:
        if item["type"] not in {"STATIC", "DYNAMIC"}:
            continue
        label = f"{item['network']}/{item['netmask']} via {item['gateway']} ({item['state'] or 'unknown'}, {item['type']})"
        if item["state"] not in {"UP", ""}:
            hard = True
            evidence.append(f"Static route is down: {label}.")
        gateway = item["gateway_ip"]
        if gateway is None:
            continue
        if gateway in owned:
            hard = True
            evidence.append(f"Next hop is an address on this appliance: {label}.")
        elif connected and not any(gateway in net for net in connected):
            hard = True
            evidence.append(f"Next hop is not on a connected subnet: {label}.")

    for backend in _backends(data):
        address = backend["ip"]
        if address in owned or address.is_loopback:
            continue
        match = _longest(address, parsed)
        if match is None or match["state"] not in {"UP", ""}:
            hard = True
            via = "no matching route" if match is None else f"longest match {match['network']}/{match['netmask']} is {match['state']}"
            evidence.append(f"Backend {backend['name']} ({address}) has {via}.")

    prefixes: dict[tuple[str, str], list[str]] = {}
    for item in parsed:
        if item["type"] not in {"STATIC", "DYNAMIC"} or item["state"] not in {"UP", ""}:
            continue
        prefixes.setdefault((item["network"], item["netmask"]), []).append(item["gateway"])
    for (network, netmask), gateways in sorted(prefixes.items()):
        if len(gateways) > 1 and not (network == "0.0.0.0" and netmask in {"0.0.0.0", "0"}):
            evidence.append(f"More than one static route covers {network}/{netmask} via {', '.join(gateways)}. Confirm that equal-cost multipath is intended.")

    for pbr in pbrs:
        hop = _ip(pbr.get("nexthop", ""))
        label = pbr.get("name") or "unnamed"
        applied = pbr.get("applied") or ""
        active = pbr.get("active") or ""
        if hop is not None and connected and hop not in owned and not any(hop in net for net in connected):
            hard = True
            evidence.append(f"Policy-based route {label} next hop {pbr.get('nexthop')} is not on a connected subnet.")
        if active in {"ENABLED", ""} and applied.startswith("NOT"):
            hits = pbr.get("hits")
            hit_text = "no hit count" if hits is None else f"{hits} hits"
            evidence.append(f"Policy-based route {label} is enabled but not applied ({hit_text}). It is not steering traffic. Remove it if it was a test, or apply the set only after the next hop is confirmed.")
        elif pbr.get("hits") == 0 and applied.startswith("APPLIED") and (app.uptime_days or 0) >= 1:
            evidence.append(f"Policy-based route {label} is applied and still shows 0 hits after {app.uptime_days:.0f} days. It may be unused. Hit counters reset when the appliance reboots.")

    if not evidence:
        return Note(
            id="nshc-x-route",
            title="Routing table",
            focus="Routing",
            status="pass",
            risk="INFO",
            wording="Static next hops sit on connected subnets, and each configured backend matches an up route.",
            evidence=["No unreachable next hop, down static route, or unrouted backend was found."],
        )
    return Note(
        id="nshc-x-route",
        title="Routing table review",
        focus="Routing",
        status="fail" if hard else "review",
        risk="HIGH" if hard else "MEDIUM",
        wording="Compare these routes with the network diagram before the change window. A next hop off every connected subnet, or a backend with no up route, drops new connections.",
        evidence=evidence[:24],
    )


def _vserver_in_use(vserver: dict) -> bool:
    if vserver.get("show_bound"):
        return True
    kind = vserver.get("kind")
    if kind == "lb":
        return bool(vserver.get("config_children")) or bool(vserver.get("targeted"))
    if kind == "cs":
        return bool(vserver.get("cs_policies")) or bool(vserver.get("cs_default"))
    if kind == "gslb":
        return vserver.get("gslb_children", 0) > 0
    if kind == "vpn":
        return bool(vserver.get("vpn_bound"))
    if kind == "auth":
        return bool(vserver.get("auth_bound"))
    if kind == "cr":
        return bool(vserver.get("config_children"))
    return False


def _platform_service(name: str) -> bool:
    lowered = name.lower()
    return lowered.startswith(("adm_", "mas_", "nsrms_")) or "metric_collector" in lowered


def _backends(data: dict) -> list[dict]:
    servers = {item["name"]: item.get("address", "") for item in data.get("servers") or []}
    found = []
    seen: set[str] = set()
    for service in data.get("services") or []:
        token = service.get("server") or ""
        address = _ip(token) or _ip(servers.get(token, ""))
        if address is None or address in seen:
            continue
        seen.add(address)
        found.append({"name": service["name"], "ip": address})
    return found


def _longest(address: ipaddress.IPv4Address | ipaddress.IPv6Address, routes: list[dict]):
    best = None
    for route in routes:
        network = route.get("net")
        if network is None or address not in network:
            continue
        if best is None or network.prefixlen > best["net"].prefixlen:
            best = route
    return best


def _network(network: str, netmask: str):
    try:
        return ipaddress.ip_network(f"{network}/{netmask}", strict=False)
    except ValueError:
        return None


def _ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _join(names: list[str], limit: int = 12) -> str:
    unique = list(dict.fromkeys(names))
    if len(unique) <= limit:
        return ", ".join(unique)
    return ", ".join(unique[:limit]) + f", and {len(unique) - limit} more"
