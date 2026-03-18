import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.rbac import ensure_role
from app.deps import get_current_user, security
from app.models import User, Scan
from app.schemas.user import UserOut, UserProfileOut
from app.services.crypto_service import crypto_service

router = APIRouter()


def _parse_profile_blob(encrypted_value: str | None) -> dict:
    if not encrypted_value:
        return {
            'full_name': '',
            'organization': '',
            'purpose': '',
            'job_title': '',
            'phone': '',
        }
    try:
        raw = crypto_service.decrypt(encrypted_value)
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return {
                'full_name': obj.get('full_name', ''),
                'organization': obj.get('organization', ''),
                'purpose': obj.get('purpose', ''),
                'job_title': obj.get('job_title', ''),
                'phone': obj.get('phone', ''),
            }
    except Exception:
        pass

    return {
        'full_name': encrypted_value,
        'organization': '',
        'purpose': '',
        'job_title': '',
        'phone': '',
    }


@router.get('/me', response_model=UserOut)
def me(credentials=Depends(security), db: Session = Depends(get_db)):
    user = get_current_user(credentials, db)
    return UserOut(id=user.id, email=user.email, role=user.role.name)


@router.get('/me/details', response_model=UserProfileOut)
def my_details(credentials=Depends(security), db: Session = Depends(get_db)):
    user = get_current_user(credentials, db)
    profile = _parse_profile_blob(user.encrypted_full_name)
    return UserProfileOut(
        id=user.id,
        email=user.email,
        role=user.role.name,
        full_name=profile['full_name'],
        organization=profile['organization'],
        purpose=profile['purpose'],
        job_title=profile['job_title'],
        phone=profile['phone'],
    )


@router.get('/me/stats')
def my_stats(credentials=Depends(security), db: Session = Depends(get_db)):
    user = get_current_user(credentials, db)
    scans_performed = db.query(Scan).filter(Scan.requested_by == user.id).count()
    return {'scans_performed': scans_performed}


@router.get('/{user_id}/details', response_model=UserProfileOut)
def user_details(user_id: int, credentials=Depends(security), db: Session = Depends(get_db)):
    user = get_current_user(credentials, db)
    ensure_role(user.role.name, 'Admin')

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail='User not found')

    profile = _parse_profile_blob(target.encrypted_full_name)
    return UserProfileOut(
        id=target.id,
        email=target.email,
        role=target.role.name,
        full_name=profile['full_name'],
        organization=profile['organization'],
        purpose=profile['purpose'],
        job_title=profile['job_title'],
        phone=profile['phone'],
    )


@router.get('/', response_model=list[UserOut])
def list_users(credentials=Depends(security), db: Session = Depends(get_db)):
    user = get_current_user(credentials, db)
    ensure_role(user.role.name, 'Admin')
    users = db.query(User).all()
    return [UserOut(id=u.id, email=u.email, role=u.role.name) for u in users]
