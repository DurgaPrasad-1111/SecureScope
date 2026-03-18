from fastapi import HTTPException, Request, status


def enforce_csrf(request: Request, claims: dict) -> None:
    if request.method in {'GET', 'HEAD', 'OPTIONS'}:
        return
    header_token = request.headers.get('X-CSRF-Token')
    expected = claims.get('csrf')
    if not expected or header_token != expected:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='CSRF token mismatch')
