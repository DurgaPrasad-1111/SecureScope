"""One-time admin bootstrap helpers for /setup."""

from __future__ import annotations

import ipaddress
import secrets

from flask import current_app

from extensions import db
from models import User
from security import get_client_ip


LOCALHOSTS = {"127.0.0.1", "::1"}


def _any_user_exists() -> bool:
    return db.session.query(User.id).first() is not None


def setup_state() -> dict[str, object]:
    if _any_user_exists():
        return {"allowed": False, "reason": "Setup already completed", "token_required": False}

    app_env = str(current_app.config.get("APP_ENV", "")).lower()
    setup_token = str(current_app.config.get("SETUP_TOKEN", "") or "").strip()
    token_required = bool(setup_token)

    if app_env == "production" and not setup_token:
        return {"allowed": False, "reason": "Setup token not configured", "token_required": False}

    return {"allowed": True, "reason": "", "token_required": token_required}


def verify_setup_token(presented: str | None) -> bool:
    configured = str(current_app.config.get("SETUP_TOKEN", "") or "").strip()
    if not configured:
        return False
    return bool(presented) and secrets.compare_digest(configured, str(presented))


def is_local_request() -> bool:
    ip_str = get_client_ip()
    if ip_str in LOCALHOSTS:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return bool(ip_obj.is_private or ip_obj.is_loopback)
