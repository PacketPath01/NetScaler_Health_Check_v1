"""Published NetScaler security bulletins.

Each row is a version and configuration check against the vendor bulletin.
The remediation is the fixed build named by Citrix. This module does not
describe how to attack an appliance.

Advisory data was checked against Citrix bulletin summaries on 2026-10-12.
Confirm the bulletin before an upgrade window; later builds supersede these floors.
"""

from __future__ import annotations

from dataclasses import dataclass

from nshc.parse import Appliance
from nshc.version import NSVersion, V

AS_OF = "2026-10-12"

# Latest customer-managed floors that close the bulletins below, including
# CVE-2026-107406 (CTX697191, 9 October 2026).
CURRENT = {
    (14, 1, False): V(14, 1, 73, 46),
    (13, 1, False): V(13, 1, 64, 29),
    (14, 1, True): V(14, 1, 73, 46, fips=True),
    (13, 1, True): V(13, 1, 37, 283, fips=True, ndcpp=True),
}


@dataclass
class Advisory:
    bulletin: str
    cves: list[str]
    title: str
    severity: str
    status: str
    summary: str
    fixed: str
    precondition: str


def recommended_build(version: NSVersion | None) -> str:
    if version is None:
        return "a current supported 14.1 build"
    if version.train not in {(13, 1), (14, 1)}:
        return CURRENT[(14, 1, False)].label + " (12.1 and 13.0 are end of life)"
    floor = CURRENT.get((version.major, version.minor, version.fips or version.ndcpp))
    if floor is None:
        return CURRENT[(14, 1, False)].label
    return floor.label + " or later"


def assess(app: Appliance) -> list[Advisory]:
    version = app.version
    if version is None:
        return [
            Advisory(
                "version",
                [],
                "Firmware build was not found",
                "HIGH",
                "affected",
                "The collector did not include a readable build number, so advisory matching could not run.",
                "Collect show ns version and compare it with current Citrix security bulletins.",
                "A readable NS version string",
            )
        ]
    rows = [
        _eol(version),
        _bleed(app, version),
        _cve_2023_3519(app, version),
        _cve_2025(app, version),
        _ctx696604(version),
        _ctx697096(version),
        _cve_2026_88779(app, version),
        _cve_2026_107406(app, version),
    ]
    return [row for row in rows if row is not None]


def _eol(version: NSVersion) -> Advisory:
    supported = version.train in {(13, 1), (14, 1)}
    return Advisory(
        "lifecycle",
        [],
        "Software support lifecycle",
        "HIGH" if not supported else "INFO",
        "affected" if not supported else "addressed",
        "NetScaler 12.1 and 13.0 are end of life and do not receive fixes for later bulletins."
        if not supported
        else f"{version.train[0]}.{version.train[1]} is a supported train. Stay on its current security build.",
        recommended_build(version),
        "Any deployment on an end-of-life train",
    )


def _gateway_or_aaa(app: Appliance) -> bool:
    return bool(
        app.vpn_vservers
        or app.auth_vservers
        or app.saml_sp
        or app.saml_idp
        or app.features.get("SSLVPN")
        or app.features.get("AAA")
    )


def _saml(app: Appliance) -> bool:
    return bool(app.saml_sp or app.saml_idp)


def _same_line(version: NSVersion, floor: NSVersion) -> bool:
    return version.train == floor.train and bool(version.fips or version.ndcpp) == bool(floor.fips or floor.ndcpp)


def _older(version: NSVersion, floor: NSVersion) -> bool:
    if not _same_line(version, floor):
        return False
    return (version.build, version.sub) < (floor.build, floor.sub)


def _floor_for(version: NSVersion, main_14: NSVersion, main_13: NSVersion, fips_14: NSVersion, fips_13: NSVersion) -> NSVersion | None:
    if version.train == (14, 1) and not version.fips:
        return main_14
    if version.train == (13, 1) and not version.fips and not version.ndcpp:
        return main_13
    if version.train == (14, 1) and version.fips:
        return fips_14
    if version.train == (13, 1) and (version.fips or version.ndcpp):
        return fips_13
    return None


def _status_for_floor(version: NSVersion, floor: NSVersion | None, precondition: bool) -> str:
    if version.train not in {(13, 1), (14, 1)}:
        return "affected" if precondition else "not_applicable"
    if floor is None:
        return "not_applicable"
    if not _older(version, floor):
        return "addressed"
    return "affected" if precondition else "not_applicable"


def _bleed(app: Appliance, version: NSVersion) -> Advisory:
    floor = _floor_for(
        version,
        V(14, 1, 8, 50),
        V(13, 1, 49, 15),
        V(13, 1, 37, 164, fips=True),
        V(13, 1, 37, 164, fips=True, ndcpp=True),
    )
    # 12.1-FIPS fixed at 12.1-55.300; the train is end of life, so it stays affected.
    precondition = _gateway_or_aaa(app)
    status = _status_for_floor(version, floor, precondition)
    if version.train not in {(13, 1), (14, 1)} and precondition:
        status = "affected"
    return Advisory(
        "CTX579459",
        ["CVE-2023-4966", "CVE-2023-4967"],
        "Session token disclosure on Gateway or AAA",
        "CRITICAL" if status == "affected" else "INFO",
        status,
        "Citrix rated CVE-2023-4966 as a sensitive-information disclosure on Gateway or AAA virtual servers. "
        "Fixed builds start at 14.1-8.50 and 13.1-49.15.",
        "14.1-8.50 / 13.1-49.15 or any later build, ideally the current floor",
        "Gateway (VPN, ICA Proxy, CVPN, RDP Proxy) or an AAA virtual server",
    )


def _cve_2023_3519(app: Appliance, version: NSVersion) -> Advisory:
    floor = _floor_for(version, V(14, 1, 8, 50), V(13, 1, 49, 13), V(13, 1, 37, 159, fips=True), V(13, 1, 37, 159, fips=True))
    precondition = _gateway_or_aaa(app)
    status = _status_for_floor(version, floor, precondition)
    if version.train not in {(13, 1), (14, 1)} and precondition:
        status = "affected"
    return Advisory(
        "CTX561482",
        ["CVE-2023-3519"],
        "Unauthenticated remote code execution on Gateway or AAA",
        "CRITICAL" if status == "affected" else "INFO",
        status,
        "Fixed for supported trains before the 14.1-8.50 / 13.1-49.13 line. End-of-life 12.1 and 13.0 builds were not given a current fix.",
        "A supported build at or after 13.1-49.13 or 14.1-8.50",
        "Appliance configured as a Gateway or AAA virtual server",
    )


def _cve_2025(app: Appliance, version: NSVersion) -> Advisory:
    floor = _floor_for(
        version,
        V(14, 1, 43, 56),
        V(13, 1, 58, 32),
        V(12, 1, 55, 328, fips=True),
        V(13, 1, 37, 235, fips=True, ndcpp=True),
    )
    precondition = _gateway_or_aaa(app) or bool(app.ips)
    status = _status_for_floor(version, floor, precondition)
    if version.train not in {(13, 1), (14, 1)}:
        status = "affected"
    return Advisory(
        "CTX693420",
        ["CVE-2025-5349", "CVE-2025-5777"],
        "Management access control and Gateway/AAA memory overread",
        "CRITICAL" if status == "affected" else "INFO",
        status,
        "CTX693420 covers CVE-2025-5349 on the management interface and CVE-2025-5777 on Gateway or AAA. "
        "Fixed builds are 14.1-43.56 and 13.1-58.32.",
        "14.1-43.56 / 13.1-58.32 or later",
        "NSIP, cluster IP, or GSLB site IP for CVE-2025-5349; Gateway or AAA for CVE-2025-5777",
    )


def _ctx696604(version: NSVersion) -> Advisory:
    floor = _floor_for(
        version,
        V(14, 1, 72, 61),
        V(13, 1, 63, 18),
        V(14, 1, 72, 61, fips=True),
        V(13, 1, 37, 272, fips=True, ndcpp=True),
    )
    status = _status_for_floor(version, floor, True)
    if version.train not in {(13, 1), (14, 1)}:
        status = "affected"
    return Advisory(
        "CTX696604",
        ["CVE-2026-8451", "CVE-2026-8452", "CVE-2026-8655", "CVE-2026-10816", "CVE-2026-10817", "CVE-2026-13474"],
        "June 2026 NetScaler security bulletin",
        "HIGH" if status == "affected" else "INFO",
        status,
        "Fixed builds in CTX696604 start at 14.1-72.61 and 13.1-63.18. Individual CVEs in that bulletin have their own configuration preconditions.",
        "14.1-72.61 / 13.1-63.18 or later",
        "See CTX696604 for each CVE. The version floor is the automated check.",
    )


def _ctx697096(version: NSVersion) -> Advisory:
    floor = _floor_for(
        version,
        V(14, 1, 73, 37),
        V(13, 1, 64, 23),
        V(14, 1, 73, 37, fips=True),
        V(13, 1, 37, 279, fips=True, ndcpp=True),
    )
    status = _status_for_floor(version, floor, True)
    if version.train not in {(13, 1), (14, 1)}:
        status = "affected"
    return Advisory(
        "CTX697096",
        ["CVE-2026-88771", "CVE-2026-88772", "CVE-2026-88778"],
        "September 2026 NetScaler security bulletin",
        "CRITICAL" if status == "affected" else "INFO",
        status,
        "Citrix reported exploitation of CVE-2026-88771 and CVE-2026-88772. "
        "The bulletin's fixed builds are 14.1-73.37 and 13.1-64.23 (13.1 customers should use the released 13.1-64.24 or later).",
        "14.1-73.37 / 13.1-64.24 or later",
        "Depends on the CVE. CVE-2026-88778 applies when TCP is enabled, which is a normal ADC deployment.",
    )


def _cve_2026_88779(app: Appliance, version: NSVersion) -> Advisory:
    floor = _floor_for(
        version,
        V(14, 1, 73, 41),
        V(13, 1, 64, 28),
        V(14, 1, 73, 41, fips=True),
        V(13, 1, 37, 282, fips=True, ndcpp=True),
    )
    precondition = _saml(app)
    status = _status_for_floor(version, floor, precondition)
    if version.train not in {(13, 1), (14, 1)} and precondition:
        status = "affected"
    return Advisory(
        "CTX697174",
        ["CVE-2026-88779"],
        "SAML memory overflow",
        "HIGH" if status == "affected" else "INFO",
        status,
        "CTX697174 describes a memory overflow that can deny service when the appliance is a SAML service provider or identity provider. "
        "CISA listed CVE-2026-88779 as exploited. The 14.1-73.37 fix for the September bulletin does not close this one.",
        "14.1-73.41 / 13.1-64.28, or the later CTX697191 build",
        "add authentication samlAction (SAML SP) or add authentication samlIdPProfile (SAML IdP)",
    )


def _between(version: NSVersion, low: NSVersion, high: NSVersion) -> bool:
    if not _same_line(version, low):
        return False
    current = (version.build, version.sub)
    return (low.build, low.sub) <= current <= (high.build, high.sub)


def _cve_2026_107406(app: Appliance, version: NSVersion) -> Advisory:
    """CTX697191. The vulnerable window depends on SAML role and the build band."""
    status = "not_applicable"
    sp, idp = bool(app.saml_sp), bool(app.saml_idp)
    if version.train == (14, 1) and not version.fips:
        if _between(version, V(14, 1, 73, 37), V(14, 1, 73, 41)):
            status = "affected" if idp else "not_applicable"
        elif _older(version, V(14, 1, 73, 37)):
            status = "affected" if (sp or idp) else "not_applicable"
        else:
            status = "addressed" if (sp or idp) else "not_applicable"
    elif version.train == (13, 1) and not version.fips and not version.ndcpp:
        if _between(version, V(13, 1, 64, 23), V(13, 1, 64, 28)):
            status = "affected" if idp else "not_applicable"
        elif _older(version, V(13, 1, 64, 23)):
            status = "affected" if (sp or idp) else "not_applicable"
        else:
            status = "addressed" if (sp or idp) else "not_applicable"
    elif version.train not in {(13, 1), (14, 1)} and (sp or idp):
        status = "affected"
    elif sp or idp:
        status = "addressed" if not _older(version, recommended_floor_version(version)) else "affected"
    return Advisory(
        "CTX697191",
        ["CVE-2026-107406"],
        "SAML memory overflow with a remote code execution impact",
        "CRITICAL" if status == "affected" else "INFO",
        status,
        "On 14.1-73.37 through 14.1-73.41, and on 13.1-64.23 through 13.1-64.28, CTX697191 applies when the appliance is a SAML identity provider. "
        "Older builds in those trains are in scope as either a SAML service provider or a SAML identity provider. "
        "The fixed builds are 14.1-73.46 and 13.1-64.29.",
        "14.1-73.46 / 13.1-64.29 or later",
        "SAML IdP on the 73.37-73.41 and 64.23-64.28 bands; SAML SP or IdP on older builds",
    )


def recommended_floor_version(version: NSVersion) -> NSVersion:
    return CURRENT.get((version.major, version.minor, bool(version.fips or version.ndcpp)), CURRENT[(14, 1, False)])
