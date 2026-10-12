"""Encrypt health-check reports at rest.

The container is JSON with a scrypt passphrase and an AES-256-GCM payload.
GCM authenticates the ciphertext, so a wrong passphrase or a modified file
fails closed. There is no recovery if the passphrase is lost.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = "NSHC1"
KDF_N = 2**15
KDF_R = 8
KDF_P = 1
MIN_PASSPHRASE = 12


class CryptoError(Exception):
    pass


def validate_passphrase(passphrase: str) -> None:
    if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE:
        raise CryptoError(
            f"Passphrase must be at least {MIN_PASSPHRASE} characters."
        )
    if passphrase.strip() != passphrase or not passphrase.strip():
        raise CryptoError("Passphrase must not be empty or wrapped in whitespace.")


def _derive(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=32,
        maxmem=128 * 1024 * 1024,
    )


def encrypt_bytes(plaintext: bytes, passphrase: str) -> bytes:
    validate_passphrase(passphrase)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive(passphrase, salt, KDF_N, KDF_R, KDF_P)
    try:
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, MAGIC.encode("ascii"))
    finally:
        key = b"\x00" * 32
    envelope: dict[str, Any] = {
        "magic": MAGIC,
        "kdf": "scrypt",
        "n": KDF_N,
        "r": KDF_R,
        "p": KDF_P,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return (MAGIC + "\n").encode("ascii") + json.dumps(envelope, indent=2).encode("utf-8")


def decrypt_bytes(blob: bytes, passphrase: str) -> bytes:
    validate_passphrase(passphrase)
    raw = blob
    if raw.startswith((MAGIC + "\n").encode("ascii")):
        raw = raw.split(b"\n", 1)[1]
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CryptoError("File is not an NSHC encrypted report.") from exc
    if envelope.get("magic") != MAGIC or envelope.get("kdf") != "scrypt":
        raise CryptoError("Unsupported report container.")
    try:
        salt = base64.b64decode(envelope["salt"])
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        n = int(envelope["n"])
        r = int(envelope["r"])
        p = int(envelope["p"])
    except (KeyError, ValueError, TypeError) as exc:
        raise CryptoError("Encrypted report is incomplete.") from exc
    if n > 2**20 or r > 64 or p > 16:
        raise CryptoError("Refusing unreasonable KDF parameters.")
    try:
        key = _derive(passphrase, salt, n, r, p)
    except ValueError as exc:
        raise CryptoError("Refusing this report's key-derivation parameters.") from exc
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, MAGIC.encode("ascii"))
    except Exception as exc:
        raise CryptoError("Could not decrypt the report. The passphrase is wrong or the file was modified.") from exc
    finally:
        key = b"\x00" * 32
