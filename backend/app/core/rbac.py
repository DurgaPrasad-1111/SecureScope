from fastapi import HTTPException, status

ROLE_ORDER = {
    'Viewer': 1,
    'Developer': 2,
    'Security Analyst': 3,
    'Admin': 4,
}


def ensure_role(user_role: str, min_role: str) -> None:
    if ROLE_ORDER.get(user_role, 0) < ROLE_ORDER.get(min_role, 99):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Insufficient privileges')
