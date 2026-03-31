"""Authentication routes (session-based, no JWT)."""

from __future__ import annotations

import re

from flask import Blueprint, current_app, g, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy import func, or_
from sqlalchemy.exc import SQLAlchemyError

from config import Config
from decorators import login_required
from extensions import db
from models import Role, User
from security import get_csrf_token
from services.audit_service import log_action
from services.auth_service import authenticate_user, clear_session, establish_session, hash_password, validate_username
from services.mfa_service import verify_totp
from services.rbac_service import seed_rbac_data
from services.setup_service import setup_state
from utils.input_sanitizer import is_suspicious_input, mask_identity, sanitize_email, sanitize_identity, sanitize_text


bp = Blueprint("auth", __name__, url_prefix="/auth")
public_bp = Blueprint("auth_public", __name__)


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _is_json_request() -> bool:
    if request.is_json:
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept.lower()


def _login_page_impl():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("frontend_app"))
    state = setup_state()
    setup_available = bool(state.get("allowed"))
    token_required = bool(state.get("token_required"))
    setup_success = request.args.get("setup") == "1"
    signup_success = request.args.get("signup") == "1"
    return render_template(
        "login.html",
        setup_available=setup_available,
        setup_token_required=token_required,
        setup_success=setup_success,
        allow_signup=_signup_enabled(),
        signup_success=signup_success,
    )


def _signup_enabled() -> bool:
    return bool(current_app.config.get("ALLOW_SIGNUP", False))


def _signup_page_impl():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("frontend_app"))
    if not _signup_enabled():
        return render_template("signup.html", error="Signups are disabled", signup_allowed=False)
    signup_success = request.args.get("signup") == "1"
    return render_template("signup.html", error=None, signup_allowed=True, signup_success=signup_success)


def _login_impl():
    payload = request.get_json(silent=True) if request.is_json else request.form
    identity_raw = payload.get("username") or payload.get("email") or payload.get("identity") or ""
    identity = sanitize_identity(identity_raw)
    password = str(payload.get("password") or "")
    otp_code = sanitize_text(payload.get("otp") or payload.get("totp") or payload.get("mfa_code") or "", max_len=12)

    if is_suspicious_input(identity_raw):
        log_action(
            action="security.suspicious_input",
            resource="auth.login",
            user_id=None,
            details={"target": mask_identity(identity_raw)},
        )

    if not identity or not password:
        if _is_json_request():
            return jsonify({"error": "Username/email and password are required"}), 400
        return render_template("login.html", error="Username/email and password are required"), 400

    user = authenticate_user(identity=identity, password=password)
    if user is None:
        log_action(
            action="auth.login.failed",
            resource="auth",
            user_id=None,
            details={"target": mask_identity(identity)},
        )
        if _is_json_request():
            return jsonify({"error": "Invalid credentials"}), 401
        return render_template("login.html", error="Invalid credentials"), 401

    mfa_enabled = False
    mfa_secret = None
    if Config.ENABLE_TOTP:
        try:
            if user.mfa is not None and user.mfa.enabled:
                mfa_enabled = True
                mfa_secret = user.mfa.totp_secret
        except Exception:
            mfa_enabled = False

    if mfa_enabled:
        if not otp_code:
            log_action(
                action="auth.mfa.required",
                resource="auth",
                user_id=user.id,
                details={"target": mask_identity(identity)},
            )
            if _is_json_request():
                return jsonify({"error": "Two-factor code required"}), 401
            return render_template("login.html", error="Two-factor code required"), 401

        if not verify_totp(secret=mfa_secret or "", code=otp_code):
            log_action(
                action="auth.mfa.failed",
                resource="auth",
                user_id=user.id,
                details={"target": mask_identity(identity)},
            )
            if _is_json_request():
                return jsonify({"error": "Invalid two-factor code"}), 401
            return render_template("login.html", error="Invalid two-factor code"), 401

    establish_session(user)
    csrf_token = get_csrf_token(current_app)

    log_action(
        action="auth.login.success",
        resource="auth",
        user_id=user.id,
        details={"target": mask_identity(identity), "roles": sorted(user.role_names)},
    )

    if _is_json_request():
        return jsonify({"message": "Login successful", "user": user.to_dict(), "csrf_token": csrf_token})

    return redirect(url_for("frontend_app"))


def _logout_impl():
    user = g.current_user
    clear_session()
    log_action(action="auth.logout", resource="auth", user_id=user.id, details={})

    if _is_json_request():
        return jsonify({"message": "Logged out"})

    return redirect(url_for("auth.login_page"))


def _signup_impl():
    if not _signup_enabled():
        if _is_json_request():
            return jsonify({"error": "Signups are disabled"}), 403
        return render_template("signup.html", error="Signups are disabled", signup_allowed=False), 403

    payload = request.get_json(silent=True) if request.is_json else request.form

    try:
        username = validate_username(sanitize_identity(payload.get("username", "")))
    except ValueError as exc:
        if _is_json_request():
            return jsonify({"error": str(exc)}), 400
        return render_template("signup.html", error=str(exc), signup_allowed=True), 400

    email_raw = payload.get("email") or ""
    email = sanitize_email(email_raw)
    password = str(payload.get("password") or "")
    confirm = payload.get("confirm_password") or payload.get("confirm") or ""

    if is_suspicious_input(email_raw):
        log_action(
            action="security.suspicious_input",
            resource="auth.signup",
            user_id=None,
            details={"target": mask_identity(email_raw)},
        )

    if not _EMAIL_RE.match(email):
        message = "Invalid email address"
        if _is_json_request():
            return jsonify({"error": message}), 400
        return render_template("signup.html", error=message, signup_allowed=True), 400

    if not password or password != confirm:
        message = "Passwords do not match"
        if _is_json_request():
            return jsonify({"error": message}), 400
        return render_template("signup.html", error=message, signup_allowed=True), 400

    existing = User.query.filter(
        or_(func.lower(User.username) == username.lower(), func.lower(User.email) == email.lower())
    ).first()
    if existing is not None:
        message = "Username or email already exists"
        if _is_json_request():
            return jsonify({"error": message}), 409
        return render_template("signup.html", error=message, signup_allowed=True), 409

    try:
        seed_rbac_data()
        basic_role = Role.query.filter_by(name="basic").first()
        if basic_role is None:
            raise ValueError("Basic role not found. Run seed-rbac.")

        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            is_active=True,
        )
        # New users start with NO roles, requiring them to request access
        user.roles = []
        db.session.add(user)
        db.session.commit()

        log_action(
            action="auth.signup",
            resource="auth",
            user_id=user.id,
            details={"username": user.username, "roles": ["basic"]},
        )

        if _is_json_request():
            return jsonify({"message": "Signup successful", "user": user.to_dict()}), 201
        return redirect(url_for("auth.login_page", signup="1"))

    except ValueError as exc:
        if _is_json_request():
            return jsonify({"error": str(exc)}), 400
        return render_template("signup.html", error=str(exc), signup_allowed=True), 400

    except SQLAlchemyError:
        db.session.rollback()
        message = "Database error while creating user"
        if _is_json_request():
            return jsonify({"error": message}), 500
        return render_template("signup.html", error=message, signup_allowed=True), 500


@bp.get("/csrf")
def csrf_token():
    return jsonify({"csrf_token": get_csrf_token(current_app)})


@public_bp.get("/csrf")
def csrf_token_legacy():
    return jsonify({"csrf_token": get_csrf_token(current_app)})


@bp.get("/login")
def login_page():
    return _login_page_impl()


@public_bp.get("/login")
def login_page_legacy():
    return _login_page_impl()


@bp.post("/login")
def login():
    return _login_impl()


@public_bp.post("/login")
def login_legacy():
    return _login_impl()


@bp.get("/signup")
def signup_page():
    return _signup_page_impl()


@public_bp.get("/signup")
def signup_page_legacy():
    return _signup_page_impl()


@bp.post("/signup")
def signup():
    return _signup_impl()


@public_bp.post("/signup")
def signup_legacy():
    return _signup_impl()


@bp.post("/logout")
@login_required
def logout():
    return _logout_impl()


@public_bp.post("/logout")
@login_required
def logout_legacy():
    return _logout_impl()


@bp.get("/me")
@login_required
def me():
    return jsonify(
        {
            "user": g.current_user.to_dict(),
            "session_user_id": session.get("user_id"),
            "csrf_token": get_csrf_token(current_app),
        }
    )


@public_bp.get("/me")
@login_required
def me_legacy():
    return me()
