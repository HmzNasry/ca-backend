from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Tuple, Type

from app.db import init_db, SessionLocal
from app.db_models import (
    AccountUser,
    AdminAllowIP,
    AdminAllowUser,
    AdminBlacklistIP,
    AdminBlacklistUser,
    BannedIP,
    BannedUser,
    UserRegistry,
)


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app"


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        clean = ts.rstrip("Z")
        return datetime.fromisoformat(clean)
    except Exception:
        return None


def _normalize_username(u: str | None) -> str:
    return (u or "").strip()


def _key_username(u: str | None) -> str:
    return _normalize_username(u).lower()


def migrate_accounts(db_session, path: Path) -> int:
    data = _load_json(path)
    users = data.get("users", {}) if isinstance(data.get("users"), dict) else {}
    added = 0
    for key, rec in users.items():
        if not isinstance(rec, dict):
            continue
        username = _normalize_username(rec.get("username"))
        username_key = _key_username(username or key)
        if not username_key:
            continue
        if db_session.query(AccountUser).filter(AccountUser.username_key == username_key).first():
            continue
        created = _parse_iso(rec.get("created_at")) or datetime.utcnow()
        account_id = rec.get("id") or uuid.uuid4().hex
        display = rec.get("display_name")
        db_session.add(
            AccountUser(
                id=account_id,
                username=username,
                username_key=username_key,
                display_name=display if display is not None else username,
                pass_hash=rec.get("pass_hash") or "",
                created_at=created,
                last_seen_ip=rec.get("last_seen_ip"),
            )
        )
        added += 1
    if added:
        db_session.commit()
    return added


def migrate_registry(db_session, path: Path) -> int:
    data = _load_json(path)
    entries = data.get("users", {}) if isinstance(data.get("users"), dict) else {}
    added = 0
    for uid, meta in entries.items():
        if not uid or db_session.get(UserRegistry, uid):
            continue
        if not isinstance(meta, dict):
            continue
        username = _normalize_username(meta.get("username"))
        ips = meta.get("ips") if isinstance(meta.get("ips"), list) else []
        tag = meta.get("tag") if isinstance(meta.get("tag"), dict) else {}
        db_session.add(
            UserRegistry(
                id=uid,
                username=username or None,
                ips=[ip for ip in ips if isinstance(ip, str) and ip.strip()],
                tag_text=tag.get("text"),
                tag_color=tag.get("color"),
                tag_locked=bool(meta.get("tag_locked")),
            )
        )
        added += 1
    if added:
        db_session.commit()
    return added


def _migrate_flag_list(
    db_session,
    data: Dict[str, Any],
    user_model: Type,
    ip_model: Type,
) -> Tuple[int, int]:
    users = data.get("users", []) if isinstance(data.get("users"), list) else []
    ips = data.get("ips", []) if isinstance(data.get("ips"), list) else []
    user_ips = data.get("user_ips", {}) if isinstance(data.get("user_ips"), dict) else {}
    user_added = 0
    ip_added = 0
    for username in users:
        uname = _normalize_username(username)
        if not uname:
            continue
        if db_session.query(user_model).filter(user_model.username == uname).first():
            continue
        db_session.add(
            user_model(
                username=uname,
                last_ip=user_ips.get(username),
            )
        )
        user_added += 1
    for ip in ips:
        if not isinstance(ip, str) or not ip.strip():
            continue
        clean = ip.strip()
        if db_session.query(ip_model).filter(ip_model.ip == clean).first():
            continue
        db_session.add(ip_model(ip=clean))
        ip_added += 1
    if user_added or ip_added:
        db_session.commit()
    return (user_added, ip_added)


def migrate_flags(db_session, base_dir: Path) -> Dict[str, Tuple[int, int]]:
    results: Dict[str, Tuple[int, int]] = {}
    results["banned"] = _migrate_flag_list(
        db_session,
        _load_json(base_dir / "banned.json"),
        BannedUser,
        BannedIP,
    )
    results["admins"] = _migrate_flag_list(
        db_session,
        _load_json(base_dir / "admins.json"),
        AdminAllowUser,
        AdminAllowIP,
    )
    results["admin_blacklist"] = _migrate_flag_list(
        db_session,
        _load_json(base_dir / "admin_blacklist.json"),
        AdminBlacklistUser,
        AdminBlacklistIP,
    )
    return results


def main():
    parser = argparse.ArgumentParser(description="Import legacy JSON data into the SQL database.")
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=APP_DIR,
        help="Directory that contains the legacy JSON files (default: %(default)s)",
    )
    args = parser.parse_args()
    base_dir: Path = args.base_dir

    init_db()
    with SessionLocal() as session:
        accounts_added = migrate_accounts(session, base_dir / "auth_users.json")
        registry_added = migrate_registry(session, base_dir / "users.json")
        flag_results = migrate_flags(session, base_dir)

    print(f"Imported {accounts_added} account(s) from auth_users.json")
    print(f"Imported {registry_added} user registry entries from users.json")
    for label, (users, ips) in flag_results.items():
        print(f"Imported {users} {label} user(s) and {ips} IP(s)")


if __name__ == "__main__":
    main()
