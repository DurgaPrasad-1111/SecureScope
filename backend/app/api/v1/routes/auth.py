from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.auth import LoginRequest, RefreshRequest, TokenResponse
from app.schemas.user import UserCreate, UserOut
from app.services.auth_service import auth_service
from app.middleware.rate_limit import limiter

router = APIRouter()


@router.post('/register', response_model=UserOut)
@limiter.limit('10/minute')
def register(request: Request, payload: UserCreate, db: Session = Depends(get_db)):
    user = auth_service.register(
        db,
        payload.email,
        payload.full_name,
        payload.password,
        payload.role,
        payload.organization,
        payload.purpose,
        payload.job_title,
        payload.phone,
    )
    return UserOut(id=user.id, email=user.email, role=user.role.name)


@router.post('/login', response_model=TokenResponse)
@limiter.limit('20/minute')
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)):
    data = auth_service.login(db, payload.email, payload.password)
    return TokenResponse(**data)


@router.post('/refresh', response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)):
    data = auth_service.refresh(db, payload.refresh_token)
    return TokenResponse(**data)


@router.post('/logout')
def logout(payload: RefreshRequest, db: Session = Depends(get_db)):
    auth_service.logout(db, payload.refresh_token)
    return {'detail': 'Logged out'}
