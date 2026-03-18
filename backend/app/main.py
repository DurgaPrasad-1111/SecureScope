import json
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi import _rate_limit_exceeded_handler
from app.api.v1.api import router as api_router
from app.core.config import settings
from app.core.database import Base, engine
from app.core.exceptions import AppError, app_error_handler, generic_error_handler
from app.core.logging import configure_logging
from app.core.security import hash_password
from app.middleware.rate_limit import limiter
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.models import Role, User
from app.services.crypto_service import crypto_service

configure_logging()

app = FastAPI(title=settings.app_name, debug=settings.debug)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(AppError, app_error_handler)
app.add_exception_handler(Exception, generic_error_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[x.strip() for x in settings.cors_origins.split(',')],
    allow_credentials=False,
    allow_methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allow_headers=['Authorization', 'Content-Type', 'X-CSRF-Token'],
)

app.include_router(api_router, prefix='/api/v1')


@app.get('/health')
def health_check():
    return {'status': 'ok'}


@app.on_event('startup')
def startup():
    Base.metadata.create_all(bind=engine)
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        for role_name in ['Admin', 'Security Analyst', 'Developer', 'Viewer']:
            if not db.query(Role).filter(Role.name == role_name).first():
                db.add(Role(name=role_name, description=f'{role_name} role'))
        db.commit()

        if settings.initial_admin_email and settings.initial_admin_password:
            existing = db.query(User).filter(User.email == settings.initial_admin_email).first()
            if not existing:
                admin_role = db.query(Role).filter(Role.name == 'Admin').first()
                profile = {
                    'full_name': settings.initial_admin_name,
                    'organization': 'SecureScope',
                    'purpose': 'Administrative platform management',
                    'job_title': 'Platform Administrator',
                    'phone': 'N/A',
                }
                db.add(User(
                    email=settings.initial_admin_email,
                    encrypted_full_name=crypto_service.encrypt(json.dumps(profile)),
                    password_hash=hash_password(settings.initial_admin_password),
                    role_id=admin_role.id,
                    is_active=True,
                ))
                db.commit()
    finally:
        db.close()
