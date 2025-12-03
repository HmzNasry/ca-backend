import json
import os
import uuid
from datetime import datetime
from fastapi import HTTPException
from jose import jwt
from passlib.context import CryptContext
from .models.auth_models import Login, Token, SignUp, SignIn, AccountInfo, UpdateAccount

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

# Simple file-backed account store
AUTH_USERS_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "auth_users.json"))
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _load_auth_db():
    try:
        if os.path.exists(AUTH_USERS_FILE):
            with open(AUTH_USERS_FILE, "r") as f:
                data = json.load(f) or {}
            if isinstance(data, dict):
                return {"users": dict(data.get("users", {}))}
    except Exception:
        pass
    return {"users": {}}


def _save_auth_db(db: dict):
    try:
        with open(AUTH_USERS_FILE, "w") as f:
            json.dump(db, f, indent=2)
    except Exception:
        pass


def list_account_usernames() -> list[str]:
    """Return a sorted list of all account usernames from the auth DB.
    Uses case preserved 'username' values as stored.
    """
    try:
        db = _load_auth_db()
        users = []
        for rec in (db.get("users", {}) or {}).values():
            u = (rec or {}).get("username")
            if isinstance(u, str) and u.strip():
                users.append(u)
        # de-dup and sort
        return sorted(list({*users}))
    except Exception:
        return []


def reset_auth():
    """Reset the account database (auth_users.json) to an empty state."""
    try:
        _save_auth_db({"users": {}})
    except Exception:
        pass


def _now_iso():
    try:
        return datetime.utcnow().isoformat() + "Z"
    except Exception:
        return ""


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
    db = _load_auth_db()
    if key in db["users"]:
        raise HTTPException(status_code=409, detail="username exists")
    account_id = uuid.uuid4().hex
    db["users"][key] = {
        "id": account_id,
        "username": username_raw,  # preserve case
        "display_name": display_raw,
        "pass_hash": hash_password(password_raw),
        "created_at": _now_iso(),
        "last_seen_ip": None,
    }
    _save_auth_db(db)
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
    db = _load_auth_db()
    rec = db["users"].get(key)
    if not rec or not verify_password(password_raw, rec.get("pass_hash", "")):
        raise HTTPException(status_code=401, detail="invalid credentials")
    display = rec.get("display_name") or rec.get("username") or username_raw
    acct_user = rec.get("username") or username_raw
    payload = {"sub": display, "acct": acct_user, "role": "user"}
    tok = jwt.encode(_apply_dev_claim(payload, force_dev), SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": tok, "token_type": "bearer"}


def set_last_seen_ip(username: str, ip: str | None):
    try:
        if not username:
            return
        key = _key_username(username)
        db = _load_auth_db()
        if key not in db["users"]:
            return
        if ip:
            db["users"][key]["last_seen_ip"] = ip
            _save_auth_db(db)
    except Exception:
        pass


def is_account_available(name: str) -> bool:
    key = _key_username(name or "")
    if not key:
        return False
    db = _load_auth_db()
    return key not in db["users"]


def is_display_available(display_name: str, current_acct: str | None = None) -> bool:
    # Display names are allowed to collide and can be any length; always available
    return True


def get_account_from_token(token: str) -> AccountInfo:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        acct = _key_username(payload.get("acct") or payload.get("sub") or "")
        if not acct:
            raise HTTPException(status_code=401, detail="invalid token")
        db = _load_auth_db()
        rec = db["users"].get(acct)
        if not rec:
            # Fallback for legacy/guest tokens: return token-derived info instead of failing
            sub = (payload.get("sub") or "")
            return {
                "username": payload.get("acct") or sub or "",
                "display_name": sub or (payload.get("acct") or ""),
                "created_at": None,
                "last_seen_ip": None,
            }
        return {
            "username": rec.get("username") or "",
            "display_name": rec.get("display_name") or (rec.get("username") or ""),
            "created_at": rec.get("created_at"),
            "last_seen_ip": rec.get("last_seen_ip"),
        }
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
        db = _load_auth_db()
        rec = db["users"].get(acct_key)
        if not rec:
            # Allow creating a new account record from token via update
            # Require a new password to establish credentials
            new_password = (upd.password or "").strip() if upd.password is not None else ""
            if not new_password or len(new_password) < 4:
                raise HTTPException(status_code=400, detail="password required to create account")
            # Determine target username and display
            want_username = _normalize_username(upd.username) if upd.username is not None else (payload.get("acct") or payload.get("sub") or "")
            new_key = _key_username(want_username)
            if not new_key:
                raise HTTPException(status_code=400, detail="username required")
            if new_key in db["users"]:
                raise HTTPException(status_code=409, detail="username exists")
            display = (upd.display_name or "").strip() if upd.display_name is not None else (payload.get("sub") or want_username)
            rec = {
                "id": uuid.uuid4().hex,
                "username": want_username,
                "display_name": display,
                "pass_hash": hash_password(new_password),
                "created_at": _now_iso(),
                "last_seen_ip": None,
            }
            db["users"][new_key] = rec
            acct_key = new_key

        # Normalize inputs
        new_username = _normalize_username(upd.username) if upd.username is not None else None
        new_display = (upd.display_name or "").strip() if upd.display_name is not None else None
        new_password = (upd.password or "").strip() if upd.password is not None else None

        # Username change
        if new_username is not None and new_username != rec.get("username"):
            new_key = _key_username(new_username)
            if not new_key:
                raise HTTPException(status_code=400, detail="username required")
            if new_key in db["users"] and new_key != acct_key:
                raise HTTPException(status_code=409, detail="username exists")
            # Move record key
            db["users"][new_key] = rec
            db["users"].pop(acct_key, None)
            rec["username"] = new_username
            acct_key = new_key

        # Display name change (optional, can be any length including empty, collisions allowed)
        if new_display is not None and new_display != rec.get("display_name"):
            rec["display_name"] = new_display

        # Password change
        if new_password is not None:
            if new_password and len(new_password) < 4:
                raise HTTPException(status_code=400, detail="password too short")
            rec["pass_hash"] = hash_password(new_password) if new_password else rec.get("pass_hash")

        _save_auth_db(db)

        # Issue fresh token reflecting latest display/account username
        display = rec.get("display_name") if rec.get("display_name") is not None else rec.get("username")
        acct_user = rec.get("username")
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
def _get_account_by_username(username: str) -> dict | None:
    key = _key_username(username)
    if not key:
        return None
    db = _load_auth_db()
    return db["users"].get(key)


def get_account_for_admin(username: str) -> AccountInfo:
    db = _load_auth_db()
    key = _key_username(username)
    rec = db["users"].get(key)
    if not rec:
        # Return fallback for non-registered users
        return {
            "username": username,
            "display_name": username,
            "created_at": None,
            "last_seen_ip": None,
        }
    return {
        "username": rec.get("username") or username,
        "display_name": rec.get("display_name") or (rec.get("username") or username),
        "created_at": rec.get("created_at"),
        "last_seen_ip": rec.get("last_seen_ip"),
    }


def update_account_for_admin(target_username: str, upd: UpdateAccount) -> AccountInfo:
    db = _load_auth_db()
    tgt_key = _key_username(target_username)
    rec = db["users"].get(tgt_key)
    # If missing, allow creating one if password provided
    if not rec:
        new_password = (upd.password or "").strip() if upd.password is not None else ""
        if not new_password or len(new_password) < 4:
            raise HTTPException(status_code=400, detail="password required to create account")
        new_username = _normalize_username(upd.username) if upd.username is not None else target_username
        if not new_username:
            raise HTTPException(status_code=400, detail="username required")
        new_key = _key_username(new_username)
        if new_key in db["users"]:
            raise HTTPException(status_code=409, detail="username exists")
        display = (upd.display_name or "").strip() if upd.display_name is not None else new_username
        rec = {
            "id": uuid.uuid4().hex,
            "username": new_username,
            "display_name": display,
            "pass_hash": hash_password(new_password),
            "created_at": _now_iso(),
            "last_seen_ip": None,
        }
        db["users"][new_key] = rec
    else:
        # Update existing
        new_username = _normalize_username(upd.username) if upd.username is not None else None
        new_display = (upd.display_name or "").strip() if upd.display_name is not None else None
        new_password = (upd.password or "").strip() if upd.password is not None else None
        # Handle username change
        if new_username is not None and new_username != rec.get("username"):
            new_key = _key_username(new_username)
            if not new_key:
                raise HTTPException(status_code=400, detail="username required")
            if new_key in db["users"] and new_key != tgt_key:
                raise HTTPException(status_code=409, detail="username exists")
            db["users"][new_key] = rec
            db["users"].pop(tgt_key, None)
            rec["username"] = new_username
            tgt_key = new_key
        if new_display is not None and new_display != rec.get("display_name"):
            rec["display_name"] = new_display
        if new_password is not None:
            if new_password and len(new_password) < 4:
                raise HTTPException(status_code=400, detail="password too short")
            rec["pass_hash"] = hash_password(new_password) if new_password else rec.get("pass_hash")
        db["users"][tgt_key] = rec
    _save_auth_db(db)
    return {
        "username": rec.get("username") or target_username,
        "display_name": rec.get("display_name") or (rec.get("username") or target_username),
        "created_at": rec.get("created_at"),
        "last_seen_ip": rec.get("last_seen_ip"),
    }


def delete_account_for_admin(username: str) -> dict:
    """Delete an account record by username. Returns {deleted: bool, last_seen_ip: str|None}."""
    db = _load_auth_db()
    key = _key_username(username)
    rec = db["users"].pop(key, None)
    _save_auth_db(db)
    return {"deleted": bool(rec), "last_seen_ip": (rec or {}).get("last_seen_ip") if rec else None}


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
    db = _load_auth_db()
    rec = db["users"].pop(acct, None)
    _save_auth_db(db)
    return {"deleted": bool(rec), "username": (rec or {}).get("username") if rec else None, "last_seen_ip": (rec or {}).get("last_seen_ip") if rec else None}


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
