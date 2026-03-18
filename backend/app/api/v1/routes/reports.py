import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.rbac import ensure_role
from app.deps import get_current_user, security
from app.models import Report, Scan

router = APIRouter()


@router.get('/')
def list_reports(credentials=Depends(security), db: Session = Depends(get_db)):
    user = get_current_user(credentials, db)
    ensure_role(user.role.name, 'Viewer')

    query = db.query(Report, Scan).join(Scan, Report.scan_id == Scan.id)
    if user.role.name != 'Admin':
        query = query.filter(Scan.requested_by == user.id)

    rows = query.order_by(Report.created_at.desc()).all()

    # Create user-specific sequential report IDs (1..N) per owner.
    owner_counters: dict[int, int] = {}
    payload = []
    for report, scan in rows:
        owner_counters[scan.requested_by] = owner_counters.get(scan.requested_by, 0) + 1
        payload.append({
            'id': report.id,
            'user_report_id': owner_counters[scan.requested_by],
            'scan_id': report.scan_id,
            'file_path': report.file_path,
            'created_at': report.created_at,
            'domain': scan.domain,
            'scanned_at': scan.created_at,
            'risk_score': scan.risk_score,
            'owner_user_id': scan.requested_by,
        })
    return payload


@router.get('/{report_id}/download')
def download_report(report_id: int, credentials=Depends(security), db: Session = Depends(get_db)):
    user = get_current_user(credentials, db)
    ensure_role(user.role.name, 'Viewer')

    row = db.query(Report, Scan).join(Scan, Report.scan_id == Scan.id).filter(Report.id == report_id).first()
    if not row:
        raise HTTPException(status_code=404, detail='Report not found')

    report, scan = row
    if user.role.name != 'Admin' and scan.requested_by != user.id:
        raise HTTPException(status_code=403, detail='Access denied for this report')

    if not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail='Report file missing on server')

    return FileResponse(
        path=report.file_path,
        filename=f'securescope_report_{report.scan_id}.pdf',
        media_type='application/pdf',
    )
