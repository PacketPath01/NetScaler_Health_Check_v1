"""Mapped-IP and classic-policy findings.

A check is emitted only when the bundle shows the problem. Addresses and
expression text are not stored. Each finding says why it matters and cites
one Citrix document.
"""

from __future__ import annotations

from nshc.cleanup import Note
from nshc.parse import Appliance

_INAT_DOC = (
    "https://docs.netscaler.com/en-us/citrix-adc/current-release/networking/ip-addressing/"
    "configuring-network-address-translation/configuring-inbound-network-address-translation-in.html"
)
_CLASSIC_FAQ = (
    "https://docs.netscaler.com/en-us/citrix-adc/current-release/appexpert/policies-and-expressions/"
    "introduction-to-policies-and-exp/classic-policy-deprecation-faq.html"
)
_CLASSIC_UPGRADE = (
    "https://docs.netscaler.com/en-us/citrix-adc/current-release/upgrade-downgrade-citrix-adc-appliance/"
    "upgrade-considerations-classic-policies.html"
)
_MGMT_ON = {"ENABLED", "ON", "YES"}


def notes(app: Appliance) -> list[Note]:
    found = [_mapped_ip(app), _classic_removed(app), _classic_custom(app)]
    return [item for item in found if item is not None]


def _note(
    check_id: str,
    title: str,
    status: str,
    risk: str,
    wording: str,
    evidence: list[str],
    resources: list[str],
) -> Note:
    return Note(
        id=check_id,
        title=title,
        focus="Configuration",
        status=status,
        risk=risk,
        wording=wording,
        evidence=evidence,
        resources=resources,
    )


def _join(names: list[str], limit: int = 6) -> str:
    unique = list(dict.fromkeys(names))
    shown = unique[:limit]
    extra = len(unique) - len(shown)
    text = ", ".join(shown)
    if extra:
        text += f", and {extra} more"
    return text


def _mode(app: Appliance, acronym: str) -> bool | None:
    if acronym not in app.modes:
        return None
    return bool(app.modes[acronym])


def _is_mip(kind: str) -> bool:
    upper = kind.upper()
    if "SNIP" in upper:
        return False
    return upper in {"MIP", "MAPPED", "MAPPED IP"} or upper.endswith(" MIP")


def _is_snip(kind: str) -> bool:
    upper = kind.upper()
    return upper == "SNIP" or upper.endswith(" SNIP") or upper.startswith("SNIP")


def _mapped_ip(app: Appliance) -> Note | None:
    shown = [ip for ip in app.ips if _is_mip(ip.type)]
    if app.ips:
        count = len(shown)
        snip_count: int | None = sum(1 for ip in app.ips if _is_snip(ip.type))
        mgmt_values = [ip.management.strip() for ip in shown]
        mgmt_on = any(value.upper() in _MGMT_ON for value in mgmt_values)
        mgmt_known = mgmt_on or any(mgmt_values)
    else:
        count = app.config_mip_count
        snip_count = None
        mgmt_on = any(kind.upper() == "MIP" for kind in app.config_mgmt_non_nsip)
        mgmt_known = mgmt_on
    if count <= 0:
        return None

    usnip = _mode(app, "USNIP")
    usip = _mode(app, "USIP")
    depends_on_mip = (usnip is False and usip is not True) or (usnip is True and snip_count == 0)
    risk = "MEDIUM" if mgmt_on or depends_on_mip else "LOW"

    evidence: list[str] = []
    if snip_count is None:
        evidence.append(f"{count} mapped IP(s) in the saved configuration. show ns ip was not collected.")
    else:
        evidence.append(f"{count} mapped IP(s) and {snip_count} subnet IP(s).")
    if usnip is not None:
        evidence.append(f"USNIP is {'ON' if usnip else 'OFF'}.")
    if usip is not None:
        evidence.append(f"USIP is {'ON' if usip else 'OFF'}.")
    if mgmt_on:
        evidence.append("Management access is enabled on a mapped IP.")
    elif mgmt_known:
        evidence.append("Management access is not enabled on the mapped IP(s).")

    wording = [
        "A mapped IP (MIP) is still configured. A MIP is a legacy source address. "
        "When neither Use Subnet IP nor Use Source IP applies, and no net profile sets a source address, "
        "the appliance can use the MIP. Otherwise it can use the NSIP."
    ]
    if usnip is True and snip_count:
        wording.append("Use Subnet IP is on and a subnet IP exists, so server traffic uses the subnet IP. The mapped IP is only the fallback.")
    elif usnip is True and snip_count == 0:
        wording.append("Use Subnet IP is on, but no subnet IP was found, so server traffic can still use the mapped IP.")
    elif usnip is False and usip is True:
        wording.append(
            "Use Source IP is on and Use Subnet IP is off, so server traffic uses the client address when that mode applies. "
            "The mapped IP remains the fallback when Use Source IP does not apply."
        )
    elif usnip is False:
        wording.append("Use Subnet IP is off, so server traffic and monitors can use the mapped IP as the source address. Prefer a subnet IP with Use Subnet IP on.")
    if mgmt_on:
        wording.append("Management access is enabled on the mapped IP. Keep management on the NSIP.")
    wording.append("Remove the mapped IP after confirming nothing still depends on it.")
    return _note(
        "nshc-x-mip",
        "Mapped IP is still configured",
        "review",
        risk,
        " ".join(wording),
        evidence,
        [_INAT_DOC],
    )


def _classic_removed(app: Appliance) -> Note | None:
    removed = list((app.classic or {}).get("removed") or [])
    if not removed:
        return None
    return _note(
        "nshc-x-classic-removed",
        "Removed classic features are still configured",
        "fail",
        "MEDIUM",
        "Filter policies or patclass objects are still configured. Support for these classic features was removed in 13.1, "
        "and an upgrade can fail until they are removed or converted with nspepi.",
        [f"{len(removed)} removed classic object(s): {_join(removed)}."],
        [_CLASSIC_UPGRADE],
    )


def _classic_custom(app: Appliance) -> Note | None:
    data = app.classic or {}
    expressions = list(data.get("expressions") or [])
    policies = list(data.get("policies") or [])
    if not expressions and not policies:
        return None
    evidence: list[str] = []
    if expressions:
        evidence.append(f"{len(expressions)} custom classic expression(s): {_join(expressions)}.")
    if policies:
        evidence.append(f"{len(policies)} classic policy command(s): {_join(policies)}.")
    return _note(
        "nshc-x-classic",
        "Classic expressions or policies remain",
        "review",
        "MEDIUM",
        "Custom classic expressions or classic authentication policies are still configured. "
        "Classic policies were deprecated in 12.0 build 56.20. From 13.1, support is removed for some features, "
        "and nspepi does not convert authentication, authorization, VPN, syslog, or nslog classic policies. "
        "Convert the custom objects before the next upgrade. Built-in ns_ expressions are not counted.",
        evidence,
        [_CLASSIC_FAQ],
    )
