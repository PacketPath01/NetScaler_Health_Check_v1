"""Read a NetScaler techsupport collector without unpacking it to disk.

Only the configuration and show-command text needed for the health check is
loaded. Private-key members are recorded by name and are not read.
"""

from __future__ import annotations

import tarfile
from dataclasses import dataclass, field
from pathlib import Path

MAX_MEMBER_BYTES = 20 * 1024 * 1024
WANTED_SUFFIXES = (
    "nsconfig/ns.conf",
    "shell/showcmds.txt",
    "shell/statcmds.txt",
    "shell/df-akin.out",
    "shell/uptime.out",
    "shell/uname-a.out",
    "shell/ntpq-npcrv.out",
)
KEY_SUFFIXES = (".key", ".pfx", ".p12")


@dataclass
class CollectedNode:
    name: str
    files: dict[str, str] = field(default_factory=dict)
    skipped_keys: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def load_input(path: Path) -> list[CollectedNode]:
    if path.is_dir():
        return [_load_directory(path)]
    if path.suffix.lower() in {".conf"} or path.name == "ns.conf":
        text = path.read_text(encoding="utf-8", errors="replace")
        return [CollectedNode(name=path.stem, files={"nsconfig/ns.conf": text})]
    if path.suffix.lower() in {".tgz", ".gz", ".tar"} or path.name.endswith(".tar.gz"):
        return _load_tar(path)
    raise ValueError(f"Unsupported input: {path}")


def _load_directory(path: Path) -> CollectedNode:
    node = CollectedNode(name=path.name)
    for suffix in WANTED_SUFFIXES:
        candidate = path / suffix
        if candidate.is_file() and candidate.stat().st_size <= MAX_MEMBER_BYTES:
            node.files[suffix] = candidate.read_text(encoding="utf-8", errors="replace")
    if "nsconfig/ns.conf" not in node.files:
        found = list(path.rglob("ns.conf"))
        if found:
            node.files["nsconfig/ns.conf"] = found[0].read_text(encoding="utf-8", errors="replace")
    for candidate in path.rglob("*"):
        if candidate.is_file() and candidate.suffix.lower() in KEY_SUFFIXES:
            node.skipped_keys.append(candidate.name)
    return node


def _load_tar(path: Path) -> list[CollectedNode]:
    nodes: dict[str, CollectedNode] = {}
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            if not member.isfile():
                continue
            name = member.name.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                continue
            parts = name.split("/")
            root = parts[0] if len(parts) > 1 else ""
            relative = "/".join(parts[1:]) if root else name
            node = nodes.setdefault(root or path.stem, CollectedNode(name=root or path.stem))
            lowered = relative.lower()
            if lowered.endswith(KEY_SUFFIXES) or "/ssl/" in f"/{lowered}" and lowered.endswith(".key"):
                node.skipped_keys.append(parts[-1])
                continue
            if not any(lowered.endswith(suffix) for suffix in WANTED_SUFFIXES):
                continue
            if member.size > MAX_MEMBER_BYTES:
                node.notes.append(f"Skipped {relative} because it is larger than {MAX_MEMBER_BYTES} bytes.")
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            node.files[relative] = extracted.read().decode("utf-8", errors="replace")
    usable = [node for node in nodes.values() if "nsconfig/ns.conf" in node.files or "shell/showcmds.txt" in node.files]
    if not usable:
        raise ValueError("No ns.conf or showcmds.txt was found in the archive.")
    return usable
