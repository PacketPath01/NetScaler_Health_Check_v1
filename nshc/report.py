"""Build the JSON document and a self-contained HTML report."""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone

from nshc import __version__
from nshc.advisories import AS_OF
from nshc.evaluate import FAIL, NA, PASS, REVIEW, Outcome
from nshc.identify import mask_ip
from nshc.parse import Appliance
from nshc.redact import redact

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "PASS": 5}


def build_document(
    bundle_name: str,
    bundle_sha256: str,
    appliances: list[tuple[Appliance, list[Outcome]]],
    show_targets: bool = False,
) -> dict:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    nodes = []
    for app, outcomes in appliances:
        clean = [_public_outcome(item) for item in outcomes]
        counts = Counter(item.status for item in outcomes)
        risks = Counter(item.risk for item in outcomes if item.status == FAIL)
        nodes.append(
            {
                "source": app.source,
                "hostname": app.hostname,
                "platform": app.platform,
                "version": app.version.label if app.version else "",
                "license": app.license_type,
                "ha_nodes": app.ha_nodes,
                "nsip": [
                    mask_ip(ip.address) if show_targets else ip.address
                    for ip in app.ips
                    if "netscaler" in ip.type.lower()
                ],
                "counts": dict(counts),
                "fail_risks": dict(risks),
                "findings": clean,
            }
        )
    return {
        "tool": "netscaler-healthcheck",
        "version": __version__,
        "generated": generated,
        "advisory_data": AS_OF,
        "bundle": bundle_name,
        "bundle_sha256": bundle_sha256,
        "identifiers": "partial" if show_targets else "full",
        "appliances": nodes,
    }


def _public_outcome(item: Outcome) -> dict:
    return {
        "id": item.id,
        "title": item.title,
        "focus": item.focus,
        "status": item.status,
        "risk": item.risk,
        "kind": item.kind,
        "likelihood": item.likelihood,
        "impact": item.impact,
        "wording": redact(item.wording),
        "evidence": [redact(line) for line in item.evidence],
        "resources": item.resources,
    }


def render_html(document: dict) -> str:
    parts = [
        "<!DOCTYPE html>",
        "<html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>NetScaler health check — {html.escape(document['bundle'])}</title>",
        "<style>",
        _CSS,
        "</style></head><body>",
        "<header><p class='eyebrow'>NetScaler health check</p>",
        f"<h1>{html.escape(document['bundle'])}</h1>",
        f"<p class='meta'>Generated {html.escape(document['generated'])} · tool {html.escape(document['version'])} · "
        f"advisory data {html.escape(document['advisory_data'])}</p>",
        f"<p class='meta'>Bundle SHA-256 {html.escape(document['bundle_sha256'])}</p>",
        "<p class='note'>This report is configuration guidance. It does not change the appliance. "
        "Confirm every bulletin against Citrix before the upgrade window. "
        "Cleanup entries are proposals: confirm them with the application owner before removing a virtual server or service. "
        + (
            "VIP names are shown with the last two octets of each address so a finding can be matched to the right virtual server. "
            if document.get("identifiers") == "partial"
            else ""
        )
        + "Private keys and password material are not included.</p>",
        "</header>",
    ]
    for node in document["appliances"]:
        parts.append(_node_html(node))
    parts.append("</body></html>")
    return "\n".join(parts)


def _node_html(node: dict) -> str:
    counts = node["counts"]
    chips = " ".join(
        f"<span class='chip'>{html.escape(str(counts.get(status, 0)))} {status}</span>"
        for status in (FAIL, REVIEW, PASS, NA)
    )
    inventory = (
        "<table><tr><th>Hostname</th><th>Platform</th><th>Firmware</th><th>License</th><th>HA nodes</th><th>NSIP</th></tr>"
        f"<tr><td>{html.escape(node['hostname'] or '—')}</td><td>{html.escape(node['platform'])}</td>"
        f"<td>{html.escape(node['version'] or '—')}</td><td>{html.escape(node['license'] or '—')}</td>"
        f"<td>{html.escape(str(node['ha_nodes']))}</td><td>{html.escape(', '.join(node['nsip']) or '—')}</td></tr></table>"
    )
    findings = node["findings"]
    actionable = [item for item in findings if item["status"] in {FAIL, REVIEW}]
    actionable.sort(key=lambda item: (RISK_ORDER.get(item["risk"], 9), item["focus"], item["id"]))
    passed = [item for item in findings if item["status"] == PASS]
    body = [
        "<section>",
        f"<h2>{html.escape(node['hostname'] or node['source'])}</h2>",
        chips,
        inventory,
        "<h3>Findings to act on</h3>",
    ]
    if not actionable:
        body.append("<p>No failed or review items.</p>")
    current_focus = None
    for item in actionable:
        if item["focus"] != current_focus:
            current_focus = item["focus"]
            body.append(f"<h4>{html.escape(current_focus)}</h4>")
        body.append(_finding_html(item))
    body.append("<h3>Checks that passed</h3><ul class='passed'>")
    for item in passed:
        body.append(f"<li><code>{html.escape(item['id'])}</code> {html.escape(item['title'])}</li>")
    body.append("</ul></section>")
    return "\n".join(body)


def _finding_html(item: dict) -> str:
    resources = "".join(
        f"<li><a href='{html.escape(url)}'>{html.escape(url)}</a></li>" for url in item["resources"]
    )
    where = [line for line in item["evidence"] if line.startswith("Where: ")]
    details = [line for line in item["evidence"] if not line.startswith("Where: ")]
    where_html = "".join(f"<p class='where'>{html.escape(line)}</p>" for line in where)
    evidence = "".join(f"<li>{html.escape(line)}</li>" for line in details)
    score = ""
    if item["likelihood"] and item["impact"]:
        score = f"<span class='score'>L{item['likelihood']} / I{item['impact']}</span>"
    return (
        "<article class='finding'>"
        f"<div class='row'><span class='risk {html.escape(item['risk'].lower())}'>{html.escape(item['risk'])}</span>"
        f"<span class='status'>{html.escape(item['status'])}</span>"
        f"<code>{html.escape(item['id'])}</code>{score}</div>"
        f"<h5>{html.escape(item['title'])}</h5>"
        f"<p>{html.escape(item['wording'])}</p>"
        f"{where_html}"
        f"<ul>{evidence}</ul>"
        + (f"<ul class='links'>{resources}</ul>" if resources else "")
        + "</article>"
    )


_CSS = """
:root { color-scheme: light; --ink:#1c2430; --muted:#5c6b7a; --line:#d9e0e7; --paper:#f6f8fa; --high:#8c2f39; --med:#8a5a12; --low:#1f6b4a; --crit:#6d28d9; }
* { box-sizing: border-box; }
body { margin:0; font:16px/1.5 "Segoe UI", sans-serif; color:var(--ink); background:var(--paper); }
header, section { max-width:980px; margin:0 auto; padding:24px; }
header { background:#14324f; color:white; max-width:none; padding:40px 24px 32px; }
header h1, header p { max-width:980px; margin-left:auto; margin-right:auto; }
h1 { font-size:32px; margin:0 0 8px; }
h2 { margin-bottom:8px; }
h4 { margin:28px 0 8px; }
.eyebrow { letter-spacing:.08em; text-transform:uppercase; font-size:12px; margin:0; }
.meta, .note { color:#d5e2ee; }
section { background:white; margin-top:20px; border:1px solid var(--line); }
table { width:100%; border-collapse:collapse; margin:12px 0 20px; }
th, td { border-bottom:1px solid var(--line); text-align:left; padding:8px; vertical-align:top; }
th { font-size:13px; color:var(--muted); }
.chip { display:inline-block; margin:0 8px 8px 0; padding:4px 10px; border-radius:999px; background:#eef3f7; }
.finding { border-top:1px solid var(--line); padding:14px 0; }
.row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.risk, .status { font-size:12px; font-weight:700; letter-spacing:.04em; padding:2px 8px; border-radius:999px; }
.risk.critical, .risk.high { background:#fde8ea; color:var(--high); }
.risk.critical { color:var(--crit); background:#f3e8ff; }
.risk.medium { background:#fff4df; color:var(--med); }
.risk.low, .risk.info { background:#e7f6ee; color:var(--low); }
.status { background:#eef3f7; color:var(--muted); }
.score { color:var(--muted); font-size:13px; }
h5 { margin:6px 0; font-size:18px; }
.where { margin:8px 0; padding:8px 10px; background:#eef4f8; border-left:3px solid #14324f; font-weight:600; }
code { font-family:Consolas, monospace; font-size:13px; }
.passed { columns:2; }
.links a { color:#14324f; }
@media print { body { background:white; } header { background:white; color:black; } .meta,.note { color:#333; } }
"""
