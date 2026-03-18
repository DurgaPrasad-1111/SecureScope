import json
from app.models import AuditLog


def write_audit_log(db, user_id: int | None, action: str, resource: str, metadata: dict | None = None):
    item = AuditLog(user_id=user_id, action=action, resource=resource, log_metadata=json.dumps(metadata or {}))
    db.add(item)
    db.commit()
