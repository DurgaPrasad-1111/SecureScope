from fastapi import APIRouter
from app.api.v1.routes import auth, scans, reports, users

router = APIRouter()
router.include_router(auth.router, prefix='/auth', tags=['auth'])
router.include_router(users.router, prefix='/users', tags=['users'])
router.include_router(scans.router, prefix='/scans', tags=['scans'])
router.include_router(reports.router, prefix='/reports', tags=['reports'])
