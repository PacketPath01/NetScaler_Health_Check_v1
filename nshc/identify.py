"""Attach a VIP name and a partial IP address to customer-facing findings.

The first two octets are hidden. The last two stay visible so a customer can
match a finding to the right virtual server without the full address.
"""

from __future__ import annotations

import re
from dataclasses import replace

from nshc.evaluate import Outcome
from nshc.parse import Appliance, IpDetail

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_NSIP_CHECKS = {f"nshc0000{number}" for number in range(30, 36)}
_PROFILE_CHECKS = {
    "nshc000048",
    "nshc000049",
    "nshc000050",
    "nshc000051",
    "nshc000054",
    "nshc000061",
    "nshc000068",
    "nshc000070",
}
_AREA_CHECKS = {"nshc000046", "nshc000074", "nshc000077", "nshc-adv-upgrade"}
_KIND = {"lb": "VIP", "cs": "VIP", "vpn": "Gateway", "auth": "AAA", "gslb": "GSLB", "cr": "CR"}


def mask_ip(address: str) -> str:
    parts = address.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return f"x.x.{parts[2]}.{parts[3]}"
    return address


def mask_ipv4(text: str) -> str:
    return _IPV4.sub(lambda match: mask_ip(match.group(0)), text or "")


def apply_identifiers(app: Appliance, outcomes: list[Outcome]) -> list[Outcome]:
    index = _Index(app)
    updated: list[Outcome] = []
    for item in outcomes:
        if item.status not in {"fail", "review"}:
            updated.append(item)
            continue
        where = index.where(item, item.evidence)
        evidence = [mask_ipv4(line) for line in item.evidence]
        if where:
            evidence = [where, *evidence]
        updated.append(replace(item, wording=mask_ipv4(item.wording), evidence=evidence))
    return updated


class _Index:
    def __init__(self, app: Appliance) -> None:
        self.app = app
        self.vservers = list((app.inventory or {}).get("vservers") or [])
        self.services = list((app.inventory or {}).get("services") or [])
        self.servers = {item["name"]: item.get("address", "") for item in (app.inventory or {}).get("servers") or []}
        self.by_name = {item["name"]: item for item in self.vservers}
        self.by_ip: dict[str, list[dict]] = {}
        for item in self.vservers:
            address = item.get("address") or ""
            if address:
                self.by_ip.setdefault(address, []).append(item)
        self.service_parents: dict[str, list[str]] = {}
        for item in self.vservers:
            for child in item.get("config_children") or []:
                self.service_parents.setdefault(child, []).append(item["name"])
        self.profile_parents: dict[str, list[str]] = {}
        for vserver, profile in app.ssl_vservers:
            self.profile_parents.setdefault(profile, []).append(vserver)

    def where(self, item: Outcome, evidence: list[str]) -> str:
        blob = " ".join(evidence)
        labels: list[str] = []
        labels.extend(self._named(blob))
        labels.extend(self._profiles(blob))
        if item.id in _NSIP_CHECKS:
            labels.extend(self._ip_labels(nsip=True))
        if item.id == "nshc000064":
            labels.extend(self._ip_labels(nsip=False, managed=True))
        if item.id == "nshc000059":
            labels.extend(self._typed("SNIP"))
        if item.id == "nshc000070":
            labels.extend(self._ciphers())
        if item.id in _AREA_CHECKS:
            labels.extend(self._area())
        unique = list(dict.fromkeys(label for label in labels if label))
        if not unique:
            return ""
        shown = unique[:8]
        extra = len(unique) - len(shown)
        text = "; ".join(shown)
        if extra:
            text += f"; and {extra} more"
        return "Where: " + text

    def _named(self, blob: str) -> list[str]:
        found: list[str] = []
        for item in self.vservers:
            if _has_token(blob, item["name"]):
                found.append(self._vs(item))
        for service in self.services:
            if not _has_token(blob, service["name"]):
                continue
            parents = self.service_parents.get(service["name"]) or []
            if parents:
                found.extend(self._vs(self.by_name[name]) for name in parents if name in self.by_name)
            else:
                found.append(self._service(service))
        for address in _IPV4.findall(blob):
            # Evidence is already masked, so match the original form as well.
            found.extend(self._vs(item) for item in self._vservers_for_masked(address))
        return found

    def _vservers_for_masked(self, masked_or_full: str) -> list[dict]:
        if masked_or_full in self.by_ip:
            return self.by_ip[masked_or_full]
        return [item for address, items in self.by_ip.items() if mask_ip(address) == masked_or_full for item in items]

    def _profiles(self, blob: str) -> list[str]:
        found: list[str] = []
        for profile, parents in self.profile_parents.items():
            if not _has_token(blob, profile):
                continue
            for name in parents:
                item = self.by_name.get(name)
                found.append(self._vs(item) if item else f"VIP {name}")
        return found

    def _ciphers(self) -> list[str]:
        found: list[str] = []
        for bind in self.app.cipher_binds:
            if not isinstance(bind, tuple) or len(bind) != 2:
                continue
            entity, cipher = bind
            if _recommended(cipher) and cipher.upper() != "DEFAULT":
                continue
            item = self.by_name.get(entity)
            if item:
                found.append(self._vs(item))
            elif entity:
                found.append(f"Cipher on {entity}")
        return found

    def _area(self) -> list[str]:
        return [self._vs(item) for item in self.vservers if item.get("kind") in {"lb", "cs", "vpn", "auth"}]

    def _ip_labels(self, nsip: bool, managed: bool = False) -> list[str]:
        found: list[str] = []
        for ip in self.app.ips:
            is_nsip = "netscaler" in ip.type.lower() or ip.type.upper() == "NSIP"
            if is_nsip != nsip:
                continue
            if managed and not _enabled(ip.management):
                continue
            found.extend(self._label_for_address(ip))
        return found

    def _typed(self, kind: str) -> list[str]:
        found: list[str] = []
        for ip in self.app.ips:
            if kind.upper() not in ip.type.upper():
                continue
            found.extend(self._label_for_address(ip))
        return found

    def _label_for_address(self, ip: IpDetail) -> list[str]:
        matches = self.by_ip.get(ip.address) or []
        if matches:
            return [self._vs(item) for item in matches]
        return [f"{ip.type or 'IP'} {mask_ip(ip.address)}"]

    def _vs(self, item: dict) -> str:
        kind = _KIND.get(item.get("kind", ""), "VIP")
        address = mask_ip(item.get("address") or "")
        port = item.get("port") or ""
        if address and port and port != "0":
            return f"{kind} {item['name']} ({address}:{port})"
        if address:
            return f"{kind} {item['name']} ({address})"
        return f"{kind} {item['name']}"

    def _service(self, service: dict) -> str:
        token = service.get("server") or ""
        address = token if _IPV4.fullmatch(token) else self.servers.get(token, "")
        if address and _IPV4.fullmatch(address):
            return f"Service {service['name']} ({mask_ip(address)})"
        return f"Service {service['name']}"


def _has_token(blob: str, name: str) -> bool:
    if not name:
        return False
    return re.search(rf"(?<!\S){re.escape(name)}(?!\S)", blob) is not None


def _enabled(value: str) -> bool:
    return (value or "").upper() in {"ENABLED", "ON", "YES", "SECUREONLY"}


def _recommended(name: str) -> bool:
    upper = name.upper().replace("TLSV", "TLS")
    return upper in {"HIGH", "TLS1.3", "TLS1.2"} or upper.startswith("TLS1.2-ECDHE") or upper.startswith("TLS1.3")
