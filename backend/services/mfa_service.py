"""TOTP-based multi-factor authentication helpers."""

from __future__ import annotations

import pyotp

from config import Config


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(*, secret: str, label: str) -> str:
    issuer = str(getattr(Config, "TOTP_ISSUER", "ReconEngine"))
    return pyotp.TOTP(secret).provisioning_uri(name=label, issuer_name=issuer)


def verify_totp(*, secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    normalized = str(code).strip().replace(" ", "")
    if not normalized.isdigit():
        return False
    return pyotp.TOTP(secret).verify(normalized, valid_window=1)
