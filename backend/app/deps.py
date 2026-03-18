from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session
from app.core.security import decode_token
from app.models import TokenBlacklist, User

security = HTTPBearer(auto_error=False)


def get_current_user(credentials: HTTPAuthorizationCredentials, db: Session) -> User:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Missing authentication token')
    try:
        payload = decode_token(credentials.credentials)
        if payload.get('type') != 'access':
            raise HTTPException(status_code=401, detail='Invalid access token')

        blacklisted = db.query(TokenBlacklist).filter(TokenBlacklist.jti == payload.get('jti')).first()
        if blacklisted:
            raise HTTPException(status_code=401, detail='Token revoked')

        user = db.query(User).filter(User.id == int(payload['sub']), User.is_active.is_(True)).first()
        if not user:
            raise HTTPException(status_code=401, detail='User not found')
        user._claims = payload
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail='Invalid token')
