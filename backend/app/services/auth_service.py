import json
import secrets
from datetime import datetime, timezone
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.core.security import create_token, decode_token, hash_password, verify_password
from app.models import Role, TokenBlacklist, User
from app.services.audit_service import write_audit_log
from app.services.crypto_service import crypto_service
from app.core.config import settings


class AuthService:
    def register(
        self,
        db: Session,
        email: str,
        full_name: str,
        password: str,
        role_name: str,
        organization: str,
        purpose: str,
        job_title: str,
        phone: str,
    ) -> User:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            raise HTTPException(status_code=400, detail='Email already in use')

        if role_name == 'Admin':
            raise HTTPException(status_code=403, detail='Admin registration is restricted')

        role = db.query(Role).filter(Role.name == role_name).first()
        if not role:
            raise HTTPException(status_code=400, detail='Invalid role')

        profile = {
            'full_name': full_name,
            'organization': organization,
            'purpose': purpose,
            'job_title': job_title,
            'phone': phone,
        }

        user = User(
            email=email,
            encrypted_full_name=crypto_service.encrypt(json.dumps(profile)),
            password_hash=hash_password(password),
            role_id=role.id,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        write_audit_log(db, user.id, 'user_register', 'users', {'email': email, 'role': role_name})
        return user

    def login(self, db: Session, email: str, password: str):
        user = db.query(User).filter(User.email == email, User.is_active.is_(True)).first()
        if not user or not verify_password(password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid credentials')

        role_name = user.role.name
        csrf = secrets.token_urlsafe(24)
        access = create_token(str(user.id), role_name, 'access', settings.access_token_exp_minutes, csrf=csrf)
        refresh = create_token(str(user.id), role_name, 'refresh', settings.refresh_token_exp_minutes)
        write_audit_log(db, user.id, 'user_login', 'auth', {'email': email})
        return {'access_token': access, 'refresh_token': refresh, 'csrf_token': csrf}

    def refresh(self, db: Session, refresh_token: str):
        claims = decode_token(refresh_token)
        if claims.get('type') != 'refresh':
            raise HTTPException(status_code=401, detail='Invalid refresh token')

        blacklisted = db.query(TokenBlacklist).filter(TokenBlacklist.jti == claims.get('jti')).first()
        if blacklisted:
            raise HTTPException(status_code=401, detail='Refresh token revoked')

        user = db.query(User).filter(User.id == int(claims['sub']), User.is_active.is_(True)).first()
        if not user:
            raise HTTPException(status_code=401, detail='User not found')

        csrf = secrets.token_urlsafe(24)
        access = create_token(str(user.id), user.role.name, 'access', settings.access_token_exp_minutes, csrf=csrf)
        new_refresh = create_token(str(user.id), user.role.name, 'refresh', settings.refresh_token_exp_minutes)
        return {'access_token': access, 'refresh_token': new_refresh, 'csrf_token': csrf}

    def logout(self, db: Session, refresh_token: str):
        claims = decode_token(refresh_token)
        expires = datetime.fromtimestamp(claims['exp'], tz=timezone.utc)
        db.add(TokenBlacklist(jti=claims.get('jti'), expires_at=expires))
        db.commit()


auth_service = AuthService()
