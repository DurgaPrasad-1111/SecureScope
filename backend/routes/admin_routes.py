"""Admin-only routes for user management."""

from __future__ import annotations

import re

from flask import Blueprint, current_app, g, jsonify, redirect, render_template, request, url_for
from sqlalchemy import func, or_
from sqlalchemy.exc import SQLAlchemyError

from decorators import login_required, permission_required, role_required
from extensions import db
from models import AuditLog, Role, User
from services.audit_service import log_action
from services.auth_service import hash_password, validate_username
from services.rbac_service import seed_rbac_data
from services.setup_service import is_local_request, setup_state, verify_setup_token
from utils.input_sanitizer import is_suspicious_input, mask_identity, sanitize_email, sanitize_identity, sanitize_text


bp = Blueprint("admin", __name__, url_prefix="/admin")
setup_bp = Blueprint("setup", __name__, url_prefix="/setup")


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _parse_roles(raw_roles) -> list[str]:
    if isinstance(raw_roles, list):
        names = [sanitize_text(item).lower() for item in raw_roles if sanitize_text(item)]
    elif isinstance(raw_roles, str):
        names = [sanitize_text(item).lower() for item in raw_roles.split(",") if sanitize_text(item)]
    else:
        names = []

    return sorted(set(names or ["basic"]))


def _is_json_request() -> bool:
    if request.is_json:
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept.lower()


def _error_response(message: str, status: int = 400, **extra):
    payload = {"error": message}
    payload.update(extra)
    if _is_json_request():
        return jsonify(payload), status
    roles = Role.query.order_by(Role.name.asc()).all()
    return render_template("create_user.html", roles=roles, error=message), status


def _setup_guard() -> tuple[bool, str, bool]:
    state = setup_state()
    allowed = bool(state.get("allowed"))
    token_required = bool(state.get("token_required"))
    reason = str(state.get("reason") or "")

    if not allowed:
        return False, reason or "Setup is not available", token_required

    # No token configured: only allow non-production localhost access.
    app_env = str(current_app.config.get("APP_ENV", "")).lower()
    if app_env == "production":
        return False, "Setup token required in production", token_required
    if not is_local_request():
        return False, "Setup allowed only from localhost", token_required

    return True, "", token_required


@setup_bp.get("")
def setup_admin_page():
    ok, reason, token_required = _setup_guard()
    return render_template(
        "setup_admin.html",
        error=reason if not ok else None,
        token_required=token_required,
        setup_allowed=ok,
    )


@setup_bp.post("")
def setup_admin_create():
    payload = request.get_json(silent=True) if request.is_json else request.form
    presented_token = payload.get("setup_token") if isinstance(payload, dict) else None
    ok, reason, token_required = _setup_guard()
    if not ok:
        if request.is_json:
            return jsonify({"error": reason}), 403
        return render_template(
            "setup_admin.html",
            error=reason,
            token_required=token_required,
            setup_allowed=False,
        ), 403

    if token_required and not verify_setup_token(presented_token):
        message = "Invalid setup token"
        if request.is_json:
            return jsonify({"error": message}), 403
        return render_template(
            "setup_admin.html",
            error=message,
            token_required=token_required,
            setup_allowed=True,
        ), 403

    try:
        username = validate_username(sanitize_identity(payload.get("username", "")))
    except ValueError as exc:
        if request.is_json:
            return jsonify({"error": str(exc)}), 400
        return render_template("setup_admin.html", error=str(exc), token_required=token_required, setup_allowed=True), 400

    email_raw = payload.get("email") or ""
    email = sanitize_email(email_raw)
    password = str(payload.get("password") or "")
    confirm = str(payload.get("confirm_password") or payload.get("confirm") or "")

    if is_suspicious_input(email_raw):
        log_action(
            action="security.suspicious_input",
            resource="setup",
            user_id=None,
            details={"target": mask_identity(email_raw)},
        )

    if not _EMAIL_RE.match(email):
        message = "Invalid email address"
        if request.is_json:
            return jsonify({"error": message}), 400
        return render_template("setup_admin.html", error=message, token_required=token_required, setup_allowed=True), 400

    if not password or password != confirm:
        message = "Passwords do not match"
        if request.is_json:
            return jsonify({"error": message}), 400
        return render_template("setup_admin.html", error=message, token_required=token_required, setup_allowed=True), 400

    existing = User.query.filter(
        or_(func.lower(User.username) == username.lower(), func.lower(User.email) == email.lower())
    ).first()
    if existing is not None:
        message = "Username or email already exists"
        if request.is_json:
            return jsonify({"error": message}), 409
        return render_template("setup_admin.html", error=message, token_required=token_required, setup_allowed=True), 409

    try:
        seed_rbac_data()
        admin_role = Role.query.filter_by(name="admin").first()
        if admin_role is None:
            raise ValueError("Admin role missing. Seed RBAC first.")

        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            is_active=True,
        )
        user.roles = [admin_role]

        db.session.add(user)
        db.session.commit()

        log_action(
            action="setup.admin.created",
            resource="setup",
            user_id=None,
            details={"username": user.username, "email": user.email},
        )

        if request.is_json:
            return jsonify({"message": "Admin created", "user": user.to_dict()}), 201
        return redirect(url_for("auth.login_page", setup="1"))

    except ValueError as exc:
        if request.is_json:
            return jsonify({"error": str(exc)}), 400
        return render_template("setup_admin.html", error=str(exc), token_required=token_required, setup_allowed=True), 400

    except SQLAlchemyError:
        db.session.rollback()
        message = "Database error while creating admin user"
        if request.is_json:
            return jsonify({"error": message}), 500
        return render_template("setup_admin.html", error=message, token_required=token_required, setup_allowed=True), 500


@bp.get("/users/new")
@login_required
@role_required("admin")
@permission_required("user:create")
def create_user_page():
    roles = Role.query.order_by(Role.name.asc()).all()
    return render_template("create_user.html", roles=roles)


@bp.post("/users")
@login_required
@role_required("admin")
@permission_required("user:create")
def create_user():
    payload = request.get_json(silent=True) if request.is_json else request.form

    try:
        username = validate_username(sanitize_identity(payload.get("username", "")))
    except ValueError as exc:
        return _error_response(str(exc), 400)

    email_raw = payload.get("email") or ""
    email = sanitize_email(email_raw)
    password = str(payload.get("password") or "")
    if is_suspicious_input(email_raw):
        log_action(
            action="security.suspicious_input",
            resource="admin.user.create",
            user_id=g.current_user.id,
            details={"target": mask_identity(email_raw)},
        )

    if request.is_json:
        role_names = _parse_roles(payload.get("roles"))
    else:
        role_names = _parse_roles(request.form.getlist("roles"))

    if not _EMAIL_RE.match(email):
        return _error_response("Invalid email address", 400)

    existing = User.query.filter(
        or_(func.lower(User.username) == username.lower(), func.lower(User.email) == email.lower())
    ).first()
    if existing is not None:
        return _error_response("Username or email already exists", 409)

    roles = Role.query.filter(Role.name.in_(role_names)).all()
    found = {role.name for role in roles}
    missing_roles = sorted(set(role_names) - found)
    if missing_roles:
        return _error_response("Unknown roles", 400, missing_roles=missing_roles)

    try:
        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            is_active=True,
        )
        user.roles = roles

        db.session.add(user)
        db.session.commit()

        log_action(
            action="admin.user.created",
            resource="users",
            user_id=g.current_user.id,
            details={"created_user_id": user.id, "username": user.username, "roles": role_names},
        )

        if _is_json_request():
            return jsonify({"message": "User created", "user": user.to_dict()}), 201

        return render_template("create_user.html", roles=Role.query.order_by(Role.name.asc()).all(), success=True), 201

    except ValueError as exc:
        return _error_response(str(exc), 400)

    except SQLAlchemyError:
        db.session.rollback()
        return _error_response("Database error while creating user", 500)


@bp.get("/users")
@login_required
@role_required("admin")
@permission_required("user:read")
def list_users():
    users = User.query.order_by(User.created_at.desc()).limit(500).all()
    return jsonify({"users": [user.to_dict() for user in users]})


@bp.get("/audit-logs")
@login_required
@role_required("admin")
@permission_required("audit:read")
def list_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(500).all()
    return jsonify({"audit_logs": [log.to_dict() for log in logs]})
