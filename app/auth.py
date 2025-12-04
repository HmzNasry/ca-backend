import uuid
from datetime import datetime
from fastapi import HTTPException
from jose import jwt
from passlib.context import CryptContext
from .models.auth_models import Login, Token, SignUp, SignIn, AccountInfo, UpdateAccount
from .db import SessionLocal
from .db_models import AccountUser

SECRET_KEY = "41bbd87b957b7261457a5cb438974dd9f9131cc1f9a1099afb314cbd843ee642"
ALGORITHM = "HS256"
# SUPER_PASS is used for /mkadmin and /rmadmin admin commands (not for login)
SUPER_PASS = "71060481"

def _apply_dev_claim(payload: dict, force_dev: bool = False) -> dict:
    if not force_dev:
        return payload
    updated = dict(payload)
    updated["role"] = "dev"
    updated["dev_claim"] = True
    return updated

# Legacy server-password login (kept temporarily for backward compatibility)
ADMIN_USER = "HAZ"
ADMIN_PASS = "INBDgXLqXC6GPikU8P/+ichtP"
SERVER_PASSWORD = "securepass32x1"

# Simple database-backed account store
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _format_iso(dt: datetime | None) -> str | None:
    if not dt:
        return None
    try:
        return dt.replace(tzinfo=None).isoformat() + "Z"
    except Exception:
        return None


def _account_to_info_obj(acc: AccountUser) -> AccountInfo:
    return AccountInfo(
        username=acc.username or "",
        display_name=acc.display_name or (acc.username or ""),
        created_at=_format_iso(acc.created_at),
        last_seen_ip=acc.last_seen_ip,
    )


def _get_account_by_key(db, username_key: str) -> AccountUser | None:
    if not username_key:
        return None
    return db.query(AccountUser).filter(AccountUser.username_key == username_key).one_or_none()


def list_account_usernames() -> list[str]:
    """Return a sorted list of all account usernames from the auth DB.
    Uses case preserved 'username' values as stored.
    """
    try:
        with SessionLocal() as db:
            rows = db.query(AccountUser.username).all()
            users = [row[0] for row in rows if isinstance(row[0], str) and row[0].strip()]
        return sorted(list({*users}))
    except Exception:
        return []


def reset_auth():
    """Reset the account database to an empty state."""
    try:
        with SessionLocal() as db:
            db.query(AccountUser).delete()
            db.commit()
    except Exception:
        pass


def _normalize_username(u: str) -> str:
    return (u or "").strip()


def _key_username(u: str) -> str:
    # Case-insensitive uniqueness
    return _normalize_username(u).lower()


def hash_password(password: str) -> str:
    return pwd_ctx.hash((password or "").strip())


def verify_password(password: str, hashed: str) -> bool:
    try:
        return pwd_ctx.verify((password or "").strip(), hashed or "")
    except Exception:
        return False


def signup_user(data: SignUp, force_dev: bool = False) -> Token:
    username_raw = _normalize_username(data.username)
    display_raw = (data.display_name or "").strip()
    password_raw = (data.password or "").strip()
    if not username_raw:
        raise HTTPException(status_code=400, detail="username required")
    # Display name is optional and can be any length (including empty)
    if not password_raw or len(password_raw) < 4:
        raise HTTPException(status_code=400, detail="password too short")
    key = _key_username(username_raw)
    with SessionLocal() as db:
        existing = _get_account_by_key(db, key)
        if existing:
            raise HTTPException(status_code=409, detail="username exists")
        account = AccountUser(
            id=uuid.uuid4().hex,
            username=username_raw,
            username_key=key,
            display_name=display_raw,
            pass_hash=hash_password(password_raw),
            created_at=datetime.utcnow(),
            last_seen_ip=None,
        )
        db.add(account)
        db.commit()
    # sub = display name used in chat UI (fallback to username if blank); acct = account username used for auth ops
    sub = display_raw if display_raw != "" else username_raw
    payload = {"sub": sub, "acct": username_raw, "role": "user"}
    tok = jwt.encode(_apply_dev_claim(payload, force_dev), SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": tok, "token_type": "bearer"}


def signin_user(data: SignIn, force_dev: bool = False) -> Token:
    username_raw = _normalize_username(data.username)
    password_raw = (data.password or "").strip()
    if not username_raw or not password_raw:
        raise HTTPException(status_code=400, detail="missing credentials")
    key = _key_username(username_raw)
    with SessionLocal() as db:
        rec = _get_account_by_key(db, key)
        pass_hash = rec.pass_hash if rec else ""
    if not rec or not verify_password(password_raw, pass_hash):
        raise HTTPException(status_code=401, detail="invalid credentials")
    display = rec.display_name or rec.username or username_raw
    acct_user = rec.username or username_raw
    payload = {"sub": display, "acct": acct_user, "role": "user"}
    tok = jwt.encode(_apply_dev_claim(payload, force_dev), SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": tok, "token_type": "bearer"}


def set_last_seen_ip(username: str, ip: str | None):
    try:
        if not username:
            return
        key = _key_username(username)
        if not key or not ip:
            return
        with SessionLocal() as db:
            rec = _get_account_by_key(db, key)
            if not rec:
                return
            rec.last_seen_ip = ip
            db.commit()
    except Exception:
        pass


def is_account_available(name: str) -> bool:
    key = _key_username(name or "")
    if not key:
        return False
    with SessionLocal() as db:
        existing = _get_account_by_key(db, key)
        return existing is None


def is_display_available(display_name: str, current_acct: str | None = None) -> bool:
    # Display names are allowed to collide and can be any length; always available
    return True


def get_account_from_token(token: str) -> AccountInfo:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        acct = _key_username(payload.get("acct") or payload.get("sub") or "")
        if not acct:
            raise HTTPException(status_code=401, detail="invalid token")
        with SessionLocal() as db:
            rec = _get_account_by_key(db, acct)
        if not rec:
            # Fallback for legacy/guest tokens: return token-derived info instead of failing
            sub = (payload.get("sub") or "")
            return {
                "username": payload.get("acct") or sub or "",
                "display_name": sub or (payload.get("acct") or ""),
                "created_at": None,
                "last_seen_ip": None,
            }
        return _account_to_info_obj(rec)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")


def update_account_from_token(token: str, upd: UpdateAccount) -> Token:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        acct_key = _key_username(payload.get("acct") or payload.get("sub") or "")
        if not acct_key:
            raise HTTPException(status_code=401, detail="invalid token")
        with SessionLocal() as db:
            rec = _get_account_by_key(db, acct_key)
            if not rec:
                new_password = (upd.password or "").strip() if upd.password is not None else ""
                if not new_password or len(new_password) < 4:
                    raise HTTPException(status_code=400, detail="password required to create account")
                want_username = _normalize_username(upd.username) if upd.username is not None else (payload.get("acct") or payload.get("sub") or "")
                new_key = _key_username(want_username)
                if not new_key:
                    raise HTTPException(status_code=400, detail="username required")
                if _get_account_by_key(db, new_key):
                    raise HTTPException(status_code=409, detail="username exists")
                display = (upd.display_name or "").strip() if upd.display_name is not None else (payload.get("sub") or want_username)
                rec = AccountUser(
                    id=uuid.uuid4().hex,
                    username=want_username,
                    username_key=new_key,
                    display_name=display,
                    pass_hash=hash_password(new_password),
                    created_at=datetime.utcnow(),
                    last_seen_ip=None,
                )
                db.add(rec)
                acct_key = new_key
            new_username = _normalize_username(upd.username) if upd.username is not None else None
            new_display = (upd.display_name or "").strip() if upd.display_name is not None else None
            new_password = (upd.password or "").strip() if upd.password is not None else None

            if new_username is not None and new_username != (rec.username or ""):
                new_key = _key_username(new_username)
                if not new_key:
                    raise HTTPException(status_code=400, detail="username required")
                existing = _get_account_by_key(db, new_key)
                if existing and existing.id != rec.id:
                    raise HTTPException(status_code=409, detail="username exists")
                rec.username = new_username
                rec.username_key = new_key
                acct_key = new_key

            if new_display is not None and new_display != rec.display_name:
                rec.display_name = new_display

            if new_password is not None:
                if new_password and len(new_password) < 4:
                    raise HTTPException(status_code=400, detail="password too short")
                if new_password:
                    rec.pass_hash = hash_password(new_password)

            db.commit()

            display = rec.display_name if rec.display_name is not None else rec.username
            acct_user = rec.username
        new_payload = {"sub": display, "acct": acct_user, "role": payload.get("role", "user")}
        if payload.get("dev_claim"):
            new_payload["dev_claim"] = True
        tok = jwt.encode(new_payload, SECRET_KEY, algorithm=ALGORITHM)
        return {"access_token": tok, "token_type": "bearer"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="invalid request")


# --- Admin helpers (DEV-only via HTTP layer checks) ---
def _get_account_by_username(username: str) -> AccountUser | None:
    key = _key_username(username)
    if not key:
        return None
    with SessionLocal() as db:
        return _get_account_by_key(db, key)


def get_account_for_admin(username: str) -> AccountInfo:
    rec = _get_account_by_username(username)
    if not rec:
        # Return fallback for non-registered users
        return {
            "username": username,
            "display_name": username,
            "created_at": None,
            "last_seen_ip": None,
        }
    return _account_to_info_obj(rec)


def update_account_for_admin(target_username: str, upd: UpdateAccount) -> AccountInfo:
    with SessionLocal() as db:
        tgt_key = _key_username(target_username)
        rec = _get_account_by_key(db, tgt_key)
        if not rec:
            new_password = (upd.password or "").strip() if upd.password is not None else ""
            if not new_password or len(new_password) < 4:
                raise HTTPException(status_code=400, detail="password required to create account")
            new_username = _normalize_username(upd.username) if upd.username is not None else target_username
            if not new_username:
                raise HTTPException(status_code=400, detail="username required")
            new_key = _key_username(new_username)
            if _get_account_by_key(db, new_key):
                raise HTTPException(status_code=409, detail="username exists")
            display = (upd.display_name or "").strip() if upd.display_name is not None else new_username
            rec = AccountUser(
                id=uuid.uuid4().hex,
                username=new_username,
                username_key=new_key,
                display_name=display,
                pass_hash=hash_password(new_password),
                created_at=datetime.utcnow(),
                last_seen_ip=None,
            )
            db.add(rec)
        else:
            new_username = _normalize_username(upd.username) if upd.username is not None else None
            new_display = (upd.display_name or "").strip() if upd.display_name is not None else None
            new_password = (upd.password or "").strip() if upd.password is not None else None
            if new_username is not None and new_username != rec.username:
                new_key = _key_username(new_username)
                if not new_key:
                    raise HTTPException(status_code=400, detail="username required")
                existing = _get_account_by_key(db, new_key)
                if existing and existing.id != rec.id:
                    raise HTTPException(status_code=409, detail="username exists")
                rec.username = new_username
                rec.username_key = new_key
            if new_display is not None and new_display != rec.display_name:
                rec.display_name = new_display
            if new_password is not None:
                if new_password and len(new_password) < 4:
                    raise HTTPException(status_code=400, detail="password too short")
                if new_password:
                    rec.pass_hash = hash_password(new_password)
        db.commit()
        return _account_to_info_obj(rec)


def delete_account_for_admin(username: str) -> dict:
    """Delete an account record by username. Returns {deleted: bool, last_seen_ip: str|None}."""
    key = _key_username(username)
    if not key:
        return {"deleted": False, "last_seen_ip": None}
    with SessionLocal() as db:
        rec = _get_account_by_key(db, key)
        if not rec:
            return {"deleted": False, "last_seen_ip": None}
        last_ip = rec.last_seen_ip
        db.delete(rec)
        db.commit()
        return {"deleted": True, "last_seen_ip": last_ip}


def delete_account_from_token(token: str) -> dict:
    """Delete the account associated with the provided bearer token.
    Returns {deleted: bool, username: str|None, last_seen_ip: str|None}.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")
    acct = _key_username(payload.get("acct") or payload.get("sub") or "")
    if not acct:
        raise HTTPException(status_code=401, detail="invalid token")
    with SessionLocal() as db:
        rec = _get_account_by_key(db, acct)
        if not rec:
            return {"deleted": False, "username": None, "last_seen_ip": None}
        username = rec.username
        last_ip = rec.last_seen_ip
        db.delete(rec)
        db.commit()
        return {"deleted": True, "username": username, "last_seen_ip": last_ip}


def login_user(data: Login, force_dev: bool = False):
    """Legacy login via server password. Retained for backward compatibility."""
    username = (data.username or "").strip()
    server_password = (data.server_password or "").strip()

    # If the provided password matches ADMIN_PASS, grant admin regardless of username (legacy)
    if server_password == ADMIN_PASS:
        payload = {"sub": username, "role": "admin"}
        tok = jwt.encode(_apply_dev_claim(payload, force_dev), SECRET_KEY, algorithm=ALGORITHM)
        return {"access_token": tok, "token_type": "bearer"}

    # Otherwise require the regular server password and grant user role (legacy)
    if server_password != SERVER_PASSWORD:
        raise HTTPException(status_code=401)

    payload = {"sub": username, "role": "user"}
    tok = jwt.encode(_apply_dev_claim(payload, force_dev), SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": tok, "token_type": "bearer"}
