
class TokenError(Exception):
    """Raised when a JWT cannot be decoded or has the wrong type."""


def unauthorized(detail: str = "Could not validate credentials") -> Exception:
    from fastapi import HTTPException

    return HTTPException(
        status_code=401,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )
