"""NetScaler build numbers such as 14.1-73.37 and 13.1-37.282 FIPS."""

from __future__ import annotations

import re
from dataclasses import dataclass

_VERSION = re.compile(
    r"NS(\d+)\.(\d+)(?::)?\s*Build\s+(\d+)\.(\d+)",
    re.I,
)


@dataclass(frozen=True, order=True)
class NSVersion:
    major: int
    minor: int
    build: int
    sub: int
    fips: bool = False
    ndcpp: bool = False
    raw: str = ""

    @property
    def train(self) -> tuple[int, int]:
        return (self.major, self.minor)

    @property
    def label(self) -> str:
        suffix = ""
        if self.fips and self.ndcpp:
            suffix = " FIPS/NDcPP"
        elif self.fips:
            suffix = " FIPS"
        elif self.ndcpp:
            suffix = " NDcPP"
        return f"{self.major}.{self.minor}-{self.build}.{self.sub}{suffix}"

    def newer_or_equal(self, other: "NSVersion") -> bool:
        return (self.major, self.minor, self.build, self.sub) >= (
            other.major,
            other.minor,
            other.build,
            other.sub,
        )


def parse_version(text: str) -> NSVersion | None:
    match = _VERSION.search(text or "")
    if not match:
        return None
    window = text[max(0, match.start() - 40) : match.end() + 40]
    upper = window.upper()
    return NSVersion(
        major=int(match.group(1)),
        minor=int(match.group(2)),
        build=int(match.group(3)),
        sub=int(match.group(4)),
        fips="FIPS" in upper,
        ndcpp="NDCPP" in upper.replace("-", ""),
        raw=match.group(0),
    )


def V(major: int, minor: int, build: int, sub: int, fips: bool = False, ndcpp: bool = False) -> NSVersion:
    return NSVersion(major, minor, build, sub, fips, ndcpp, raw=f"{major}.{minor}-{build}.{sub}")
