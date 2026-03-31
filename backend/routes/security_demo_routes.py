"""Security demonstration endpoints (safe by design)."""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from decorators import login_required, role_required
from extensions import db
from models import User
from services.audit_service import log_action
from utils.input_sanitizer import is_suspicious_input, sanitize_text


bp = Blueprint("security_demo", __name__, url_prefix="/security-demo")


@bp.get("/sql-injection")
@login_required
def demo_sql_injection():
    raw_user_id = request.args.get("user_id") or ""
    sanitized = sanitize_text(raw_user_id, max_len=24)

    if is_suspicious_input(raw_user_id):
        log_action(
            action="security.suspicious_input",
            resource="demo.sql_injection",
            user_id=g.current_user.id,
            details={"target": "user_id"},
        )

    try:
        user_id = int(sanitized)
    except ValueError:
        return jsonify(
            {
                "message": "Parameter validation blocked the request",
                "input": sanitized,
                "blocked": True,
            }
        ), 422

    # ORM parameterization prevents SQL injection by treating user input as data.
    user_row = db.session.get(User, user_id)
    return jsonify(
        {
            "message": "Parameterized ORM query executed safely",
            "blocked": False,
            "found": bool(user_row),
            "user": {"id": user_row.id, "username": sanitize_text(user_row.username)} if user_row else None,
        }
    )


@bp.get("/xss")
@login_required
def demo_xss():
    raw = request.args.get("input") or ""
    sanitized = sanitize_text(raw, max_len=300)
    blocked = raw.strip() != sanitized.strip()
    return jsonify(
        {
            "message": "Output sanitized to prevent XSS",
            "input": sanitize_text(raw, max_len=300),
            "sanitized": sanitized,
            "blocked": blocked,
        }
    )


@bp.get("/admin-only")
@login_required
@role_required("admin")
def demo_admin_only():
    return jsonify({"message": "Access granted. RBAC enforcement is working."})
