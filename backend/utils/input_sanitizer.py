"""Input sanitation and lightweight threat signal helpers."""

from __future__ import annotations

import re
from typing import Iterable

import bleach


_SUSPICIOUS_PATTERNS = (
    re.compile(r"<\s*script", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"or\s+1\s*=\s*1", re.IGNORECASE),
    re.compile(r"drop\s+table", re.IGNORECASE),
    re.compile(r"sleep\s*\(", re.IGNORECASE),
)


def sanitize_text(value: str | None, *, max_len: int = 512) -> str:
    if value is None:
        return ""
    cleaned = bleach.clean(str(value), tags=[], attributes={}, protocols=[], strip=True)
    cleaned = cleaned.replace("\x00", "").strip()
    if max_len > 0:
        return cleaned[:max_len]
    return cleaned


def sanitize_email(value: str | None, *, max_len: int = 254) -> str:
    return sanitize_text(value, max_len=max_len).lower()


def sanitize_identity(value: str | None, *, max_len: int = 150) -> str:
    return sanitize_text(value, max_len=max_len)


def sanitize_reason(value: str | None, *, max_len: int = 600) -> str:
    return sanitize_text(value, max_len=max_len)


def is_suspicious_input(value: str | None) -> bool:
    if not value:
        return False
    candidate = str(value)
    return any(pattern.search(candidate) for pattern in _SUSPICIOUS_PATTERNS)


def mask_identity(value: str | None) -> str:
    text = sanitize_identity(value)
    if not text:
        return ""
    if "@" in text:
        local, _, domain = text.partition("@")
        if len(local) <= 2:
            masked = f"{local[:1]}***@{domain}"
        else:
            masked = f"{local[:1]}***{local[-1]}@{domain}"
        return masked
    if len(text) <= 2:
        return text[:1] + "***"
    return f"{text[:1]}***{text[-1]}"


def sanitize_list(values: Iterable[str] | None, *, max_len: int = 256) -> list[str]:
    if not values:
        return []
    cleaned: list[str] = []
    for item in values:
        text = sanitize_text(item, max_len=max_len)
        if text:
            cleaned.append(text)
    return cleaned
