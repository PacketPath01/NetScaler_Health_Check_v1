"""Command line for encrypted NetScaler health-check reports."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import io
import json
import os
import sys
import zipfile
from pathlib import Path

from nshc import __version__
from nshc.bundle import load_input
from nshc.catalog import DATA_PATH, load_catalog, save_catalog, load_xlsx
from nshc.crypto import CryptoError, decrypt_bytes, encrypt_bytes, validate_passphrase
from nshc.evaluate import FAIL, evaluate
from nshc.identify import apply_identifiers
from nshc.parse import parse_node
from nshc.report import build_document, render_html

RISK_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="nshc",
        description="Health-check a NetScaler support bundle and write an encrypted advisory report.",
    )
    parser.add_argument("--version", action="version", version=f"nshc {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Read a support bundle and write an encrypted report")
    scan.add_argument("bundles", nargs="+", type=Path, help="collector .tgz, a directory, or ns.conf")
    scan.add_argument("--out", type=Path, required=True, help="Report path (.nshc unless --plaintext)")
    scan.add_argument("--definitions", type=Path, help="Workbook .xlsx or checks JSON. Defaults to the built-in catalog.")
    scan.add_argument("--plaintext", action="store_true", help="Write report.html and report.json without encryption")
    scan.add_argument("--show-targets", action="store_true", help="Show each finding's VIP name and the last two IP octets")
    scan.add_argument("--passphrase-env", default="NSHC_PASSPHRASE", help="Environment variable that holds the passphrase")

    decrypt = sub.add_parser("decrypt", help="Decrypt a report into HTML and JSON")
    decrypt.add_argument("report", type=Path)
    decrypt.add_argument("--out", type=Path, required=True, help="Directory for report.html and report.json")
    decrypt.add_argument("--passphrase-env", default="NSHC_PASSPHRASE")

    imported = sub.add_parser("import-checks", help="Refresh the built-in catalog from the definitions workbook")
    imported.add_argument("workbook", type=Path)
    imported.add_argument("--out", type=Path, default=DATA_PATH)

    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "decrypt":
            return _decrypt(args)
        if args.command == "import-checks":
            checks = load_xlsx(args.workbook)
            save_catalog(checks, args.out)
            print(f"Wrote {len(checks)} checks to {args.out}")
            return 0
    except (CryptoError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


def scan_bundles(
    bundles: list[Path],
    out: Path,
    *,
    passphrase: str = "",
    plaintext: bool = False,
    definitions: Path | None = None,
    show_targets: bool = False,
) -> dict:
    """Scan support bundles and write an encrypted report, or a plaintext folder."""
    if not plaintext:
        validate_passphrase(passphrase)
    _reject_report_on_bundle(bundles, out)
    checks = load_catalog(definitions)
    appliances = []
    hashes = []
    for bundle in bundles:
        if not bundle.exists():
            raise ValueError(f"Input not found: {bundle}")
        hashes.append(_sha256(bundle) if bundle.is_file() else "directory")
        for node in load_input(bundle):
            app = parse_node(node)
            outcomes = evaluate(app, checks)
            if show_targets:
                outcomes = apply_identifiers(app, outcomes)
            appliances.append((app, outcomes))
    if not appliances:
        raise ValueError("No appliance configuration was found.")
    document = build_document(
        ", ".join(path.name for path in bundles),
        hashes[0] if len(hashes) == 1 else ",".join(hashes),
        appliances,
        show_targets=show_targets,
    )
    html = render_html(document)
    payload = _zip(document, html)
    if plaintext:
        out.mkdir(parents=True, exist_ok=True)
        (out / "report.json").write_text(json.dumps(document, indent=2), encoding="utf-8")
        (out / "report.html").write_text(html, encoding="utf-8")
        _lock_down(out)
    else:
        blob = encrypt_bytes(payload, passphrase)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(blob)
        _lock_down(out)
    return document


def decrypt_report(report: Path, out: Path, passphrase: str) -> Path:
    """Decrypt a .nshc report into report.html and report.json."""
    if not report.is_file():
        raise ValueError(f"Report not found: {report}")
    payload = decrypt_bytes(report.read_bytes(), passphrase)
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for name in ("report.json", "report.html"):
            target = out / name
            target.write_bytes(archive.read(name))
            _lock_down(target)
    return out / "report.html"


def _reject_report_on_bundle(bundles: list[Path], out: Path) -> None:
    destination = out.resolve()
    for bundle in bundles:
        if not bundle.exists():
            continue
        source = bundle.resolve()
        inside = bundle.is_dir() and (destination == source or destination.is_relative_to(source))
        if source == destination or inside:
            raise ValueError("Choose a report path outside the support bundle.")


def _scan(args: argparse.Namespace) -> int:
    passphrase = "" if args.plaintext else _passphrase(args.passphrase_env, confirm=True)
    document = scan_bundles(
        list(args.bundles),
        args.out,
        passphrase=passphrase,
        plaintext=args.plaintext,
        definitions=args.definitions,
        show_targets=args.show_targets,
    )
    if args.plaintext:
        print("Wrote a plaintext report. It contains deployment details. Protect the directory and delete it when you are done.")
        print(args.out)
    else:
        print(f"Encrypted report: {args.out}")
        print(f"Decrypt it with: {_decrypt_command()}")
    _print_summary(document)
    return 0


def _decrypt_command() -> str:
    if getattr(sys, "frozen", False):
        return f'"{Path(sys.executable).name}" decrypt <report> --out <directory>'
    return "python -m nshc decrypt <report> --out <directory>"


def _decrypt(args: argparse.Namespace) -> int:
    passphrase = _passphrase(args.passphrase_env, confirm=False)
    html_path = decrypt_report(args.report, args.out, passphrase)
    print(f"Decrypted report in {html_path.parent}")
    print("The HTML and JSON are plaintext. Delete them when you are done.")
    return 0


def _zip(document: dict, html: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.json", json.dumps(document, indent=2))
        archive.writestr("report.html", html)
    return buffer.getvalue()


def _passphrase(env_name: str, confirm: bool) -> str:
    value = os.environ.get(env_name, "")
    if value:
        return value
    if not sys.stdin.isatty():
        raise CryptoError(f"Set {env_name} or run in a terminal to enter a passphrase.")
    first = getpass.getpass("Report passphrase: ")
    if confirm:
        second = getpass.getpass("Repeat passphrase: ")
        if first != second:
            raise CryptoError("Passphrases did not match.")
    return first


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _lock_down(path: Path) -> None:
    """Best-effort restriction to the current user. Never remove existing access."""
    if os.name != "nt":
        try:
            path.chmod(0o600 if path.is_file() else 0o700)
        except OSError:
            return
        return
    user = os.environ.get("USERNAME", "")
    if not user:
        return
    try:
        import subprocess

        subprocess.run(
            ["icacls", str(path), "/grant:r", f"{user}:(R,W)"],
            check=False,
            capture_output=True,
        )
    except OSError:
        return


def summary_text(document: dict) -> str:
    lines = [""]
    for node in document["appliances"]:
        lines.append(f"{node['hostname'] or node['source']}  {node['platform']}  {node['version']}")
        counts = node["counts"]
        lines.append(
            f"  fail {counts.get(FAIL, 0)}  review {counts.get('review', 0)}  "
            f"pass {counts.get('pass', 0)}  n/a {counts.get('na', 0)}"
        )
        actionable = [item for item in node["findings"] if item["status"] == FAIL]
        actionable.sort(key=lambda item: RISK_RANK.get(item["risk"], 9))
        for item in actionable[:12]:
            lines.append(f"  {item['risk']:<8} {item['id']:<18} {item['title']}")
            where = next((line for line in item.get("evidence") or [] if str(line).startswith("Where: ")), "")
            if where:
                lines.append(f"    {where}")
        remaining = len(actionable) - 12
        if remaining > 0:
            lines.append(f"  … {remaining} more failed checks are in the report")
        shown = {item["id"] for item in actionable[:12]}
        for item in node["findings"]:
            if item["id"] in {"nshc-x-unused", "nshc-x-route"} and item["status"] in {FAIL, "review"} and item["id"] not in shown:
                lines.append(f"  {item['risk']:<8} {item['id']:<18} {item['title']}")
                where = next((line for line in item.get("evidence") or [] if str(line).startswith("Where: ")), "")
                if where:
                    lines.append(f"    {where}")
    lines.append("")
    lines.append(f"Advisory data date: {document['advisory_data']}. Confirm bulletins before upgrading.")
    return "\n".join(lines)


def _print_summary(document: dict) -> None:
    print(summary_text(document))


if __name__ == "__main__":
    raise SystemExit(main())
