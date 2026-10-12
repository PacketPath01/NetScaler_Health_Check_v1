"""Remove credential material from text that may be copied into a report."""

from __future__ import annotations

import re

_SECRET_FLAG = re.compile(
    r"(?i)(-encrypted|-password\S*|-passphrase|-community|-authpasswd|-privpasswd|"
    r"-radiuskey|-tacacssecret|-nssecret)\s+\S+"
)
_PEM = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.S,
)
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}")


def redact(text: str) -> str:
    if not text:
        return text
    cleaned = _PEM.sub("[private key removed]", text)
    cleaned = _SECRET_FLAG.sub(r"\1 [redacted]", cleaned)
    cleaned = _JWT.sub("[token removed]", cleaned)
    return cleaned
