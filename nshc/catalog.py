"""Load the professional-services check definitions.

The workbook is the source of the check id, scoring, and recommendation wording.
A JSON copy is shipped with the tool so a scan does not need Excel installed.
"""

from __future__ import annotations

import json
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path


def _data_dir() -> Path:
    """Directory that holds checks.json, including a PyInstaller build."""
    here = Path(__file__).resolve().parent / "data"
    if (here / "checks.json").is_file():
        return here
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        for candidate in (Path(meipass) / "nshc" / "data", Path(meipass) / "data"):
            if (candidate / "checks.json").is_file():
                return candidate
    return here


DATA_PATH = _data_dir() / "checks.json"
NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


@dataclass
class CheckDef:
    id: str
    platforms: list[str]
    focus: str
    title: str
    details: str
    resources: list[str]
    likelihood: int
    impact: int
    wording: str

    @property
    def risk(self) -> str:
        return risk_label(self.likelihood, self.impact)


def risk_label(likelihood: int, impact: int) -> str:
    table = {
        (1, 1): "LOW",
        (1, 2): "LOW",
        (1, 3): "MEDIUM",
        (2, 1): "LOW",
        (2, 2): "MEDIUM",
        (2, 3): "HIGH",
        (3, 1): "MEDIUM",
        (3, 2): "HIGH",
        (3, 3): "HIGH",
    }
    return table.get((likelihood, impact), "MEDIUM")


def load_catalog(path: Path | None = None) -> list[CheckDef]:
    source = path or DATA_PATH
    if source.suffix.lower() in {".xlsx", ".xlsm"}:
        return load_xlsx(source)
    payload = json.loads(source.read_text(encoding="utf-8"))
    return [_from_dict(item) for item in payload["checks"]]


def _from_dict(item: dict) -> CheckDef:
    return CheckDef(
        id=item["id"],
        platforms=list(item["platforms"]),
        focus=item["focus"],
        title=item["title"],
        details=item.get("details") or "",
        resources=list(item.get("resources") or []),
        likelihood=int(item["likelihood"]),
        impact=int(item["impact"]),
        wording=item.get("wording") or item["title"],
    )


def save_catalog(checks: list[CheckDef], path: Path | None = None) -> None:
    target = path or DATA_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {"checks": [asdict(item) for item in checks]}
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _urls(text: str) -> list[str]:
    return re.findall(r"https?://\S+", text or "")


def load_xlsx(path: Path) -> list[CheckDef]:
    rows = _xlsx_rows(path)
    if not rows:
        return []
    header = {name.strip(): col for col, name in rows[1].items()}
    checks: list[CheckDef] = []
    for index in sorted(row for row in rows if row > 1):
        cells = rows[index]
        issue = cells.get(header.get("Issue ID", "A"), "").strip()
        if not issue:
            continue
        likelihood = _int_cell(cells.get(header.get("Likelihood", "I"), "1"))
        impact = _int_cell(cells.get(header.get("Impact", "J"), "1"))
        platforms = [
            part.strip()
            for part in cells.get(header.get("Platform", "B"), "").replace(" ", "").split("/")
            if part.strip()
        ]
        resources_cell = cells.get(header.get("Recommendation Resources", "H"), "")
        checks.append(
            CheckDef(
                id=issue,
                platforms=platforms or ["VPX", "MPX", "SDX", "BLX"],
                focus=cells.get(header.get("Focus Area", "C"), "").strip() or "General",
                title=cells.get(header.get("Recommendation", "D"), "").strip() or issue,
                details=cells.get(header.get("Recommendation Details", "E"), "").strip(),
                resources=_urls(resources_cell),
                likelihood=likelihood,
                impact=impact,
                wording=cells.get(header.get("Key Findings Recommendation wording", "L"), "").strip(),
            )
        )
    return checks


def _int_cell(value: str) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 1


def _xlsx_rows(path: Path) -> dict[int, dict[str, str]]:
    with zipfile.ZipFile(path) as workbook:
        shared: list[str] = []
        if "xl/sharedStrings.xml" in workbook.namelist():
            root = ET.fromstring(workbook.read("xl/sharedStrings.xml"))
            for item in root.findall("m:si", NS):
                texts = [
                    node.text or ""
                    for node in item.iter("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t")
                ]
                shared.append("".join(texts))
        sheet = ET.fromstring(workbook.read("xl/worksheets/sheet1.xml"))
        rows: dict[int, dict[str, str]] = {}
        for cell in sheet.iter("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}c"):
            ref = cell.attrib.get("r")
            if not ref:
                continue
            match = re.match(r"([A-Z]+)(\d+)", ref)
            if not match:
                continue
            column, row_number = match.group(1), int(match.group(2))
            kind = cell.attrib.get("t")
            value_node = cell.find("m:v", NS)
            inline = cell.find("m:is", NS)
            value = ""
            if kind == "s" and value_node is not None and value_node.text:
                value = shared[int(value_node.text)]
            elif kind == "inlineStr" and inline is not None:
                value = "".join(
                    node.text or ""
                    for node in inline.iter("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t")
                )
            elif value_node is not None and value_node.text:
                value = value_node.text
            rows.setdefault(row_number, {})[column] = value
        return rows
