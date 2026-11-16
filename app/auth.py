"""Login tokens (JWT). The token only says WHO signed in. The role is always read from the database."""
import os
import time

import jwt
from dotenv import load_dotenv

load_dotenv()  # reads JWT_SECRET from the .env file

ALGORITHM = "HS256"
TOKEN_HOURS = 8
PLACEHOLDERS = {"", "type_any_long_random_text_here", "changeme", "secret"}


def _secret():
    secret = os.getenv("JWT_SECRET", "")
    if len(secret) < 32 or secret in PLACEHOLDERS:
        raise RuntimeError(
            "JWT_SECRET in your .env file is missing, too short, or still the placeholder. "
            "Create a strong one by running:\n"
            '    python -c "import secrets; print(secrets.token_urlsafe(48))"\n'
            "and paste the result after JWT_SECRET= in .env (no quotes, no spaces)."
        )
    return secret


def require_secret():
    _secret()


def create_token(employee_id):
    now = int(time.time())
    payload = {"sub": employee_id, "iat": now, "exp": now + TOKEN_HOURS * 3600}
    return jwt.encode(payload, _secret(), algorithm=ALGORITHM)


def decode_token(token):
    """Return the employee ID, or None if the token is forged, expired or malformed."""
    try:
        payload = jwt.decode(
            token, _secret(), algorithms=[ALGORITHM], options={"require": ["exp", "sub"]}
        )
    except jwt.PyJWTError:
        return None
    sub = payload.get("sub")
    return sub if isinstance(sub, str) else None
