from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timezone

from extensions import db
from models import AdminAccessRequest, User, Role
from decorators import login_required, role_required
from services.audit_service import log_action
from utils.input_sanitizer import is_suspicious_input, sanitize_reason

bp = Blueprint("access", __name__, url_prefix="/api/access-requests")

@bp.post("")
@login_required
def request_access():
    user = g.current_user
    payload = request.get_json(silent=True) or {}
    reason_raw = payload.get("reason") or ""
    reason = sanitize_reason(reason_raw)

    if is_suspicious_input(reason_raw):
        log_action(
            action="security.suspicious_input",
            resource="access_request",
            user_id=user.id,
            details={"target": "reason"},
        )
    
    existing = AdminAccessRequest.query.filter_by(user_id=user.id, status="pending").first()
    if existing:
        return jsonify({"error": "You already have a pending access request."}), 400
        
    req = AdminAccessRequest(user_id=user.id, reason=reason)
    db.session.add(req)
    try:
        db.session.commit()
        log_action("access.requested", "access_request", user.id, {"reason": reason})
        return jsonify({"message": "Access request submitted successfully.", "request": req.to_dict()}), 201
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({"error": "Failed to submit request"}), 500

@bp.get("")
@login_required
def list_requests():
    user = g.current_user
    if user.has_role("admin"):
        reqs = AdminAccessRequest.query.order_by(AdminAccessRequest.created_at.desc()).all()
    else:
        reqs = AdminAccessRequest.query.filter_by(user_id=user.id).order_by(AdminAccessRequest.created_at.desc()).all()
    return jsonify({"requests": [r.to_dict() for r in reqs]})


@bp.patch("/<int:req_id>")
@login_required
@role_required("admin")
def review_request(req_id):
    payload = request.get_json(silent=True) or {}
    status = payload.get("status")
    decision_raw = payload.get("decision_reason") or ""
    decision_reason = sanitize_reason(decision_raw)
    
    if status not in ["approved", "denied"]:
        return jsonify({"error": "Invalid status"}), 400
        
    req = AdminAccessRequest.query.get_or_404(req_id)
    if req.status != "pending":
        return jsonify({"error": "Request already reviewed"}), 400
        
    req.status = status
    req.reviewed_by = g.current_user.id
    req.reviewed_at = datetime.now(timezone.utc)
    req.decision_reason = decision_reason
    
    if status == "approved":
        basic_role = Role.query.filter_by(name="basic").first()
        if basic_role and basic_role not in req.requester.roles:
            req.requester.roles.append(basic_role)
            
    try:
        db.session.commit()
        log_action("access.reviewed", "access_request", g.current_user.id, {"request_id": req.id, "status": status})
        return jsonify({"message": f"Request {status}", "request": req.to_dict()})
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({"error": "Failed to update request"}), 500
