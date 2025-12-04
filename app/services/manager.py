from datetime import datetime, timedelta
import json, uuid
from typing import Dict, List
from fastapi import WebSocket
from ..db import SessionLocal
from ..db_models import (
    AdminAllowIP,
    AdminAllowUser,
    AdminBlacklistIP,
    AdminBlacklistUser,
    BannedIP,
    BannedUser,
    UserRegistry,
)

HISTORY = 500

# Server-side limits
MAX_GC_NAME_LEN = 20

def _clamp_with_ellipsis(text: str | None, max_len: int) -> str:
    """Clamp text to max_len, appending a single-character ellipsis if truncated.
    Ensures the resulting string length is at most max_len.
    """
    s = (text or "").strip()
    if not s:
        return s
    if len(s) <= max_len:
        return s
    if max_len <= 1:
        return "…"[:max_len]
    return s[: max_len - 1] + "…"

class ConnMgr:
    def add_user_to_gc(self, gid: str, user: str):
        gc = self.gcs.get(gid)
        if not gc:
            return
        gc.setdefault("members", set()).add(user)

    def remove_user_from_gc(self, gid: str, user: str):
        gc = self.gcs.get(gid)
        if not gc:
            return
        gc.setdefault("members", set()).discard(user)
    def __init__(self):
        self.active: Dict[str, WebSocket] = {}
        self.user_ips: Dict[str, str] = {}  # map username -> last seen IP (in-memory)
        self.history: List[dict] = []  # main chat history
        self.dm_histories: Dict[str, List[dict]] = {}  # key: dm_id(userA,userB) -> history list
        # moderation/admin & roles
        self.roles: Dict[str, str] = {}  # username -> role (e.g., 'admin' or 'user')
        self.promoted_admins: set[str] = set()  # runtime-granted admins
        self.demoted_admins: set[str] = set()   # runtime-demoted built-in admins (persists in-memory until mkadmin)
        # Track demoted admin identities by last-seen IPs to prevent quick re-admin via rename
        self.demoted_admin_ips: set[str] = set()
        # tagging
        self.tags: Dict[str, dict] = {}  # username -> { text: str, color: str }
        self.tag_rejects: set[str] = set()
        # tag locks: when a user is locked, only DEV can change/remove/set their tag
        self.tag_locks: set[str] = set()
        # mutes
        self.mutes: Dict[str, datetime] = {}
        self.mute_all = False
        # per-DM mutes: key = (receiver, sender)
        self.dm_mutes: Dict[tuple[str, str], datetime] = {}
        # bans
        self.banned_users: set[str] = set()
        self.banned_ips: set[str] = set()
        self._load_bans()
        # admins persistence
        self.persistent_admin_users: set[str] = set()
        self.persistent_admin_ips: set[str] = set()
        self._load_admins()
        # blacklisted (demoted) admins persistence
        self.admin_blacklist_users: set[str] = set()
        self.admin_blacklist_ips: set[str] = set()
        self._load_admin_blacklist()
        # group chats (GCs) runtime store: id -> {name, creator, members:set[str], history:list[dict]}
        self.gcs = {}
        # User activity: username -> bool (True=active/on tab, False=inactive)
        self.user_activity: Dict[str, bool] = {}
        # No DB: start with empty history and groups
        # persistent user identity mapping
        self._users = {"users": {}, "ip_to_uid": {}}
        self._username_to_uid = {}
        self._load_users()
        # Preload persisted tags into runtime map if present
        try:
            _normalized_any = False
            for uid, meta in (self._users.get("users", {}) or {}).items():
                if not isinstance(meta, dict):
                    continue
                uname = (meta.get("username") or "").strip()
                tag = meta.get("tag")
                if uname and isinstance(tag, dict) and tag.get("text"):
                    # Normalize: ensure color present
                    color = tag.get("color") or "white"
                    text_val = str(tag.get("text"))
                    # If a legacy DEV+tag combined string slipped into text (e.g., "DEV) (mytag"), strip the DEV part
                    try:
                        if str(tag.get("special") or "").lower() == "dev" and ") (" in text_val:
                            text_val = text_val.split(") (", 1)[1]
                            # persist normalization back into in-memory users store
                            tag["text"] = text_val
                            meta["tag"] = tag
                            _normalized_any = True
                    except Exception:
                        pass
                    t_obj = {"text": text_val, "color": str(color)}
                    # Preserve special if present
                    if isinstance(tag.get("special"), str):
                        t_obj["special"] = tag.get("special")
                    self.tags[uname] = t_obj
                # Persisted tag lock state
                if uname and bool(meta.get("tag_locked")):
                    self.tag_locks.add(uname)
        except Exception:
            pass
        else:
            try:
                if _normalized_any:
                    self._save_users()
            except Exception:
                pass

    # --- DM helpers ---
    def dm_id(self, a: str, b: str) -> str:
        return "::".join(sorted([a, b]))

    def get_dm_history(self, a: str, b: str) -> List[dict]:
        tid = self.dm_id(a, b)
        return list(self.dm_histories.get(tid, []))

    def _append_dm(self, a: str, b: str, obj: dict):
        tid = self.dm_id(a, b)
        hist = self.dm_histories.setdefault(tid, [])
        hist.append(obj)
        if len(hist) > HISTORY:
            self.dm_histories[tid] = hist[-HISTORY:]
        # No DB: do nothing

    def update_dm_text(self, a: str, b: str, msg_id: str, text: str) -> bool:
        """Update text of a DM message in-place in the canonical stored history."""
        tid = self.dm_id(a, b)
        arr = self.dm_histories.get(tid)
        if not arr:
            return False
        for m in arr:
            if m.get("id") == msg_id:
                m["text"] = text
                m["edited"] = True
                # No DB: do nothing
                return True
        return False

    def update_main_text(self, msg_id: str, text: str) -> bool:
        """Update text of a Main message in-place."""
        for m in self.history:
            if m.get("id") == msg_id:
                m["text"] = text
                m["edited"] = True
                return True
        return False

    async def _broadcast_dm(self, a: str, b: str, obj: dict):
        # Store canonical copy
        base = dict(obj)
        base.setdefault("thread", "dm")
        base.pop("peer", None)
        self._append_dm(a, b, base)
        # Send personalized payloads with peer=other
        for user, other in ((a, b), (b, a)):
            ws = self.active.get(user)
            if not ws:
                continue
            # If this is a message/media from 'sender', and 'user' has muted 'sender' in DM, skip delivery
            if base.get("type") in ("message", "media"):
                sender = base.get("sender")
                if sender and self.is_dm_muted(user, sender):
                    continue
            payload = dict(base)
            payload["peer"] = other
            try:
                await ws.send_text(json.dumps(payload))
            except:
                pass

    async def _broadcast_dm_update(self, a: str, b: str, obj: dict):
        # Do not persist; just send update to both with proper peer field
        base = dict(obj)
        base.setdefault("thread", "dm")
        base.pop("peer", None)
        for user, other in ((a, b), (b, a)):
            ws = self.active.get(user)
            if not ws:
                continue
            payload = dict(base)
            payload["peer"] = other
            try:
                await ws.send_text(json.dumps(payload))
            except:
                pass

    # New: delete helpers
    def delete_main_message(self, msg_id: str) -> bool:
        idx = next((i for i, m in enumerate(self.history) if m.get("id") == msg_id), None)
        if idx is None:
            return False
        self.history.pop(idx)
        return True

    def delete_dm_message(self, a: str, b: str, msg_id: str, requester: str | None = None, allow_any: bool = False) -> bool:
        tid = self.dm_id(a, b)
        arr = self.dm_histories.get(tid)
        if not arr:
            return False
        idx = next((i for i, m in enumerate(arr) if m.get("id") == msg_id), None)
        if idx is None:
            return False
        if not allow_any and requester and arr[idx].get("sender") != requester:
            return False
        arr.pop(idx)
        # No DB: do nothing
        return True

    def clear_dm_history(self, a: str, b: str):
        tid = self.dm_id(a, b)
        self.dm_histories[tid] = []
        # No DB: do nothing

    # --- GC helpers ---
    def create_gc(self, name: str, creator: str, members: List[str]) -> str:
        """Create a group chat and return its id. Members should not include the creator; we'll add automatically."""
        gid = f"gc-{int(datetime.utcnow().timestamp()*1000)}-{uuid.uuid4().hex[:6]}"
        mems = set(members or [])
        mems.add(creator)
        self.gcs[gid] = {
            "id": gid,
            # Enforce max GC name length server-side
            "name": _clamp_with_ellipsis(name or "Group Chat", MAX_GC_NAME_LEN),
            "creator": creator,
            "members": mems,
            "history": [],
        }
        # No DB: do nothing
        return gid

    def user_in_gc(self, gid: str, user: str) -> bool:
        gc = self.gcs.get(gid)
        if not gc:
            return False
        return user in gc.get("members", set())

    def get_gc_history(self, gid: str) -> List[dict]:
        gc = self.gcs.get(gid)
        if not gc:
            return []
        arr = gc.get("history", [])
        return list(arr)

    def clear_gc_history(self, gid: str):
        if gid in self.gcs:
            self.gcs[gid]["history"] = []
        # No DB: do nothing

    def update_gc_text(self, gid: str, msg_id: str, text: str) -> bool:
        gc = self.gcs.get(gid)
        if not gc:
            return False
        arr = gc.get("history", [])
        for m in arr:
            if m.get("id") == msg_id:
                m["text"] = text
                m["edited"] = True
                return True
        return False

    def delete_gc_message(self, gid: str, msg_id: str, requester: str | None = None, allow_creator: bool = True) -> bool:
        gc = self.gcs.get(gid)
        if not gc:
            return False
        arr = gc.get("history", [])
        idx = next((i for i, m in enumerate(arr) if m.get("id") == msg_id), None)
        if idx is None:
            return False
        if requester and not allow_creator:
            if arr[idx].get("sender") != requester:
                return False
        if requester and allow_creator:
            if arr[idx].get("sender") != requester and requester != gc.get("creator"):
                return False
        arr.pop(idx)
        # No DB: do nothing
        return True

    async def _broadcast_gc(self, gid: str, obj: dict):
        gc = self.gcs.get(gid)
        if not gc:
            return
        base = dict(obj)
        base.setdefault("thread", "gc")
        base["gcid"] = gid
        # Persist like main/dm: include message/media/polls and also system messages for GC
        if base.get("type") in ("message", "media", "poll", "system") and (base.get("sender") != "SYSTEM" or base.get("type") == "system"):
            gc["history"].append(base)
            if len(gc["history"]) > HISTORY:
                gc["history"] = gc["history"][-HISTORY:]
        data = json.dumps(base)
        gc = self.gcs.get(gid)
        if not gc:
            return
        base = dict(obj)
        base.setdefault("thread", "gc")
        base["gcid"] = gid
        data = json.dumps(base)
        for user in list(gc.get("members", set())):
            ws = self.active.get(user)
            if not ws:
                continue
            try:
                await ws.send_text(data)
            except:
                pass

    async def _broadcast_gc_update(self, gid: str, obj: dict):
        """Broadcast a GC update (typing, clear, delete, settings, etc.) without persisting.
        Ensures gcid and thread fields are set and sends to all current members.
        """
        gc = self.gcs.get(gid)
        if not gc:
            return
        base = dict(obj)
        base.setdefault("thread", "gc")
        base["gcid"] = gid
        data = json.dumps(base)
        for user in list(gc.get("members", set())):
            ws = self.active.get(user)
            if not ws:
                continue
            try:
                await ws.send_text(data)
            except:
                pass

    def get_user_gcs(self, user: str) -> List[dict]:
        out: List[dict] = []
        for gid, gc in self.gcs.items():
            if user in gc.get("members", set()):
                out.append({
                    "id": gid,
                    "name": gc.get("name"),
                    "creator": gc.get("creator"),
                    "members": list(gc.get("members", set())),
                })
        return out

    def update_gc(self, gid: str, name: str | None = None, members: List[str] | None = None):
        gc = self.gcs.get(gid)
        if not gc:
            return
        if name is not None:
            # Enforce max GC name length server-side
            gc["name"] = _clamp_with_ellipsis(name, MAX_GC_NAME_LEN)
        if members is not None:
            # Always include creator in members
            mset = set(members)
            creator = gc.get("creator")
            if creator:
                mset.add(creator)
            gc["members"] = mset
        # No DB: do nothing

    # ---- reactions helpers ----
    def _toggle_reaction_map(self, react_map: dict | None, emoji: str, username: str) -> dict:
        """Toggle username in reactions map for an emoji. Returns updated map of {emoji: [users...]}"""
        if react_map is None or not isinstance(react_map, dict):
            react_map = {}
        users = set(react_map.get(emoji, []))
        if username in users:
            users.remove(username)
        else:
            users.add(username)
        react_map[emoji] = sorted(list(users))
        # prune empties
        for k in list(react_map.keys()):
            if not react_map[k]:
                react_map.pop(k, None)
        return react_map

    def toggle_main_reaction(self, msg_id: str, emoji: str, username: str) -> dict | None:
        for m in self.history:
            if m.get("id") == msg_id:
                m["reactions"] = self._toggle_reaction_map(m.get("reactions"), emoji, username)
                return m.get("reactions")
        return None

    def toggle_dm_reaction(self, a: str, b: str, msg_id: str, emoji: str, username: str) -> dict | None:
        tid = self.dm_id(a, b)
        arr = self.dm_histories.get(tid) or []
        for m in arr:
            if m.get("id") == msg_id:
                m["reactions"] = self._toggle_reaction_map(m.get("reactions"), emoji, username)
                return m.get("reactions")
        return None

    def toggle_gc_reaction(self, gid: str, msg_id: str, emoji: str, username: str) -> dict | None:
        gc = self.gcs.get(gid) or {}
        arr = gc.get("history", [])
        for m in arr:
            if m.get("id") == msg_id:
                m["reactions"] = self._toggle_reaction_map(m.get("reactions"), emoji, username)
                return m.get("reactions")
        return None

    # ---- targeted send helper ----
    async def send_to_user(self, username: str, payload: dict):
        ws = self.active.get(username)
        if not ws:
            return
        try:
            await ws.send_text(json.dumps(payload))
        except Exception:
            pass
    def exit_gc(self, gid: str, user: str):
        gc = self.gcs.get(gid)
        if not gc:
            return
        mems: set = gc.get("members", set())
        if user in mems:
            mems.remove(user)
        # Transfer creator if necessary
        if gc.get("creator") == user:
            # Pick the next in remaining members (arbitrary)
            new_creator = next(iter(mems), None)
            gc["creator"] = new_creator
        # If no members left, delete GC entirely
        if not mems:
            self.gcs.pop(gid, None)

    # --- presence (join/leave) ---
    async def _presence(self, user: str, action: str):
        # action: "join" | "leave"; not stored in history
        await self._broadcast({"type": "presence", "user": user, "action": action})

    # --- persistence ---
    def _load_bans(self):
        try:
            with SessionLocal() as db:
                user_rows = db.query(BannedUser).all()
                self.banned_users = {row.username for row in user_rows}
                for row in user_rows:
                    if row.username and row.last_ip:
                        self.user_ips[row.username] = row.last_ip
                self.banned_ips = {row.ip for row in db.query(BannedIP).all()}
        except Exception as e:
            print("Failed to load ban list:", e)

    def _save_bans(self):
        try:
            with SessionLocal() as db:
                existing_users = {row.username: row for row in db.query(BannedUser).all()}
                for username in list(self.banned_users):
                    last_ip = self.user_ips.get(username)
                    row = existing_users.pop(username, None)
                    if row:
                        row.last_ip = last_ip
                    else:
                        db.add(BannedUser(username=username, last_ip=last_ip))
                for stale in existing_users.values():
                    db.delete(stale)

                existing_ips = {row.ip: row for row in db.query(BannedIP).all()}
                for ip in list(self.banned_ips):
                    if ip in existing_ips:
                        existing_ips.pop(ip, None)
                    else:
                        db.add(BannedIP(ip=ip))
                for stale in existing_ips.values():
                    db.delete(stale)
                db.commit()
        except Exception as e:
            print("Failed to save ban list:", e)

    # --- persistent admins (allow list) ---
    def _load_admins(self):
        try:
            with SessionLocal() as db:
                user_rows = db.query(AdminAllowUser).all()
                self.persistent_admin_users = {row.username for row in user_rows}
                for row in user_rows:
                    if row.username and row.last_ip:
                        self.user_ips.setdefault(row.username, row.last_ip)
                self.persistent_admin_ips = {row.ip for row in db.query(AdminAllowIP).all()}
        except Exception as e:
            print("Failed to load admins:", e)

    def _save_admins(self):
        try:
            with SessionLocal() as db:
                existing_users = {row.username: row for row in db.query(AdminAllowUser).all()}
                for username in list(self.persistent_admin_users):
                    last_ip = self.user_ips.get(username)
                    row = existing_users.pop(username, None)
                    if row:
                        row.last_ip = last_ip
                    else:
                        db.add(AdminAllowUser(username=username, last_ip=last_ip))
                for stale in existing_users.values():
                    db.delete(stale)

                existing_ips = {row.ip: row for row in db.query(AdminAllowIP).all()}
                for ip in list(self.persistent_admin_ips):
                    if ip in existing_ips:
                        existing_ips.pop(ip, None)
                    else:
                        db.add(AdminAllowIP(ip=ip))
                for stale in existing_ips.values():
                    db.delete(stale)
                db.commit()
        except Exception as e:
            print("Failed to save admins:", e)

    # --- persistent admin blacklist ---
    def _load_admin_blacklist(self):
        try:
            with SessionLocal() as db:
                user_rows = db.query(AdminBlacklistUser).all()
                self.admin_blacklist_users = {row.username for row in user_rows}
                for row in user_rows:
                    if row.username and row.last_ip:
                        self.user_ips.setdefault(row.username, row.last_ip)
                self.admin_blacklist_ips = {row.ip for row in db.query(AdminBlacklistIP).all()}
        except Exception as e:
            print("Failed to load admin blacklist:", e)

    def _save_admin_blacklist(self):
        try:
            with SessionLocal() as db:
                existing_users = {row.username: row for row in db.query(AdminBlacklistUser).all()}
                for username in list(self.admin_blacklist_users):
                    last_ip = self.user_ips.get(username)
                    row = existing_users.pop(username, None)
                    if row:
                        row.last_ip = last_ip
                    else:
                        db.add(AdminBlacklistUser(username=username, last_ip=last_ip))
                for stale in existing_users.values():
                    db.delete(stale)

                existing_ips = {row.ip: row for row in db.query(AdminBlacklistIP).all()}
                for ip in list(self.admin_blacklist_ips):
                    if ip in existing_ips:
                        existing_ips.pop(ip, None)
                    else:
                        db.add(AdminBlacklistIP(ip=ip))
                for stale in existing_ips.values():
                    db.delete(stale)
                db.commit()
        except Exception as e:
            print("Failed to save admin blacklist:", e)

    # --- user registry persistence ---
    def _load_users(self):
        try:
            self._users = {"users": {}, "ip_to_uid": {}}
            self._username_to_uid = {}
            with SessionLocal() as db:
                rows = db.query(UserRegistry).all()
                for row in rows:
                    meta = {
                        "username": row.username,
                        "ips": list(row.ips or []),
                    }
                    if row.tag_text:
                        meta["tag"] = {"text": row.tag_text, "color": row.tag_color or "white"}
                    if row.tag_locked:
                        meta["tag_locked"] = True
                    self._users.setdefault("users", {})[row.id] = meta
                    if row.username:
                        self._username_to_uid[row.username] = row.id
                    for ip in meta.get("ips", []):
                        if ip:
                            self._users.setdefault("ip_to_uid", {})[ip] = row.id
        except Exception as e:
            print("Failed to load user registry:", e)

    def _save_users(self):
        try:
            with SessionLocal() as db:
                stored = self._users.get("users", {}) or {}
                existing = {row.id: row for row in db.query(UserRegistry).all()}
                for uid, meta in stored.items():
                    username = (meta or {}).get("username")
                    ips = list((meta or {}).get("ips") or [])
                    tag = meta.get("tag") if isinstance(meta.get("tag"), dict) else None
                    tag_text = (tag or {}).get("text")
                    tag_color = (tag or {}).get("color")
                    tag_locked = bool(meta.get("tag_locked"))
                    row = existing.pop(uid, None)
                    if row:
                        row.username = username
                        row.ips = ips
                        row.tag_text = tag_text
                        row.tag_color = tag_color
                        row.tag_locked = tag_locked
                    else:
                        db.add(UserRegistry(
                            id=uid,
                            username=username,
                            ips=ips,
                            tag_text=tag_text,
                            tag_color=tag_color,
                            tag_locked=tag_locked,
                        ))
                for stale in existing.values():
                    db.delete(stale)
                db.commit()
        except Exception as e:
            print("Failed to save user registry:", e)

    # --- persisted tag helpers ---
    def _ensure_uid_for_username(self, username: str) -> str:
        uname = (username or "").strip()
        if not uname:
            return ""
        uid = self._get_uid_for_username(uname)
        if uid:
            return uid
        # Create a record without binding to an IP
        uid = uuid.uuid4().hex
        self._users.setdefault("users", {})[uid] = {"username": uname, "ips": []}
        self._username_to_uid[uname] = uid
        self._save_users()
        return uid

    def set_user_tag(self, username: str, tag: dict | None):
        """Update runtime tag map and persist tag into the registry for this username."""
        uname = (username or "").strip()
        if not uname:
            return
        # Update runtime tags map
        if tag is None:
            self.tags.pop(uname, None)
        else:
            # normalize structure
            t_obj = {"text": str(tag.get("text", "")), "color": str(tag.get("color", "white"))}
            if tag.get("special"):
                t_obj["special"] = tag.get("special")
            self.tags[uname] = t_obj
        # Persist in the registry storage
        uid = self._ensure_uid_for_username(uname)
        if not uid:
            return
        meta = self._users.setdefault("users", {}).setdefault(uid, {"username": uname, "ips": []})
        if tag is None:
            if "tag" in meta:
                meta.pop("tag", None)
        else:
            # Persist only the personal tag; never persist DEV/ADMIN status markers
            runtime_tag = self.tags.get(uname) or {}
            special = str((runtime_tag.get("special") or "")).lower()
            text_val = str(runtime_tag.get("text") or "")
            color_val = str(runtime_tag.get("color") or "white")
            if special == "dev" and text_val.strip().upper() == "DEV":
                # Base DEV badge only — do not persist anything
                meta.pop("tag", None)
            else:
                # Persist without the special flag so only the personal tag is saved
                meta["tag"] = {"text": text_val, "color": color_val}
        self._save_users()

    def clear_user_tag(self, username: str):
        self.set_user_tag(username, None)

    # --- tag lock persistence ---
    def set_tag_lock(self, username: str, locked: bool):
        uname = (username or "").strip()
        if not uname:
            return
        if locked:
            self.tag_locks.add(uname)
        else:
            self.tag_locks.discard(uname)
        uid = self._ensure_uid_for_username(uname)
        if not uid:
            return
        meta = self._users.setdefault("users", {}).setdefault(uid, {"username": uname, "ips": []})
        if locked:
            meta["tag_locked"] = True
        else:
            if "tag_locked" in meta:
                meta.pop("tag_locked", None)
        self._save_users()

    # --- registry reset ---
    def reset_users_registry(self):
        self._users = {"users": {}, "ip_to_uid": {}}
        self._username_to_uid = {}
        self._save_users()

    # Public helpers for managing the user registry
    def list_user_registry(self) -> List[str]:
        try:
            names = []
            for uid, meta in (self._users.get("users", {}) or {}).items():
                uname = (meta or {}).get("username")
                if isinstance(uname, str) and uname:
                    names.append(uname)
            # unique + sort
            return sorted(list({*names}))
        except Exception:
            return []

    def remove_user_identity(self, username: str) -> bool:
        """Remove a username and its uid/ip associations from the registry.
        Returns True if removed, False if not found or failed.
        """
        try:
            uid = self._username_to_uid.get(username)
            if not uid:
                return False
            user_entry = (self._users.get("users", {}) or {}).get(uid)
            ips = []
            if isinstance(user_entry, dict):
                ips = list(user_entry.get("ips", []) or [])
            # Remove ip->uid mappings
            ip_map = self._users.setdefault("ip_to_uid", {})
            for ip in ips:
                try:
                    if ip in ip_map:
                        ip_map.pop(ip, None)
                except Exception:
                    pass
            # Remove user entry and username index
            self._users.setdefault("users", {}).pop(uid, None)
            self._username_to_uid.pop(username, None)
            self._save_users()
            return True
        except Exception:
            return False

    def _get_or_create_uid_for_ip(self, ip: str | None) -> str:
        if not ip:
            # Generate a stable ephemeral uid for None IP
            uid = self._users.get("ip_to_uid", {}).get("__none__")
            if not uid:
                uid = uuid.uuid4().hex
                self._users.setdefault("users", {})[uid] = {"username": None, "ips": []}
                self._users.setdefault("ip_to_uid", {})["__none__"] = uid
                self._save_users()
            return uid
        uid = self._users.get("ip_to_uid", {}).get(ip)
        if uid:
            return uid
        uid = uuid.uuid4().hex
        self._users.setdefault("users", {})[uid] = {"username": None, "ips": [ip]}
        self._users.setdefault("ip_to_uid", {})[ip] = uid
        self._save_users()
        return uid

    def _associate_ip(self, uid: str, ip: str | None):
        if ip is None:
            return
        self._users.setdefault("users", {}).setdefault(uid, {"username": None, "ips": []})
        meta = self._users["users"][uid]
        ips = meta.get("ips") or []
        if ip not in ips:
            ips.append(ip)
            meta["ips"] = ips
        self._users.setdefault("ip_to_uid", {})[ip] = uid
        self._save_users()

    def _get_uid_for_username(self, username: str | None) -> str | None:
        if not username:
            return None
        return self._username_to_uid.get(username)

    def _bind_username(self, uid: str, username: str) -> bool:
        # Reserve username for this uid if not reserved by others
        other = self._get_uid_for_username(username)
        if other and other != uid:
            return False
        # Update mapping
        self._users.setdefault("users", {}).setdefault(uid, {"username": None, "ips": []})
        self._users["users"][uid]["username"] = username
        # rebuild index
        # First remove any old username mapping for this uid
        to_delete = [u for u, _uid in self._username_to_uid.items() if _uid == uid and u != username]
        for u in to_delete:
            self._username_to_uid.pop(u, None)
        self._username_to_uid[username] = uid
        self._save_users()
        return True

    def ensure_user_identity(self, ip: str | None, username: str) -> tuple[bool, str | None, str | None]:
        """Record last-seen IP and maintain a lightweight username registry.
        Always ensure a registry entry exists for this username and refresh IP mapping.
        """
        try:
            uname = (username or "").strip()
            if not uname:
                return (False, None, "invalid username")
            # Get existing uid for this username or create a new one
            uid = self._get_uid_for_username(uname)
            if not uid:
                uid = uuid.uuid4().hex
                self._users.setdefault("users", {})[uid] = {"username": uname, "ips": []}
            # Associate/refresh IP for audit trail only
            if ip:
                self._users.setdefault("users", {}).setdefault(uid, {"username": uname, "ips": []})
                meta = self._users["users"][uid]
                ips = meta.get("ips") or []
                if ip not in ips:
                    ips.append(ip)
                    meta["ips"] = ips
                self._users.setdefault("ip_to_uid", {})[ip] = uid
            # Rebuild username index and save
            self._username_to_uid[uname] = uid
            self._save_users()
            return (True, uid, None)
        except Exception:
            return (True, None, None)

    def add_persistent_admin(self, user: str, ip: str | None = None):
        if user:
            self.persistent_admin_users.add(user)
        if ip:
            self.persistent_admin_ips.add(ip)
            self.user_ips[user] = ip
        self._save_admins()

    def remove_persistent_admin(self, user: str):
        if user in self.persistent_admin_users:
            self.persistent_admin_users.discard(user)
        # Do not remove IPs immediately to preserve audit trail; optional: purge stale IPs separately
        self._save_admins()

    def add_admin_blacklist(self, user: str, ip: str | None = None):
        if user:
            self.admin_blacklist_users.add(user)
        if ip:
            self.admin_blacklist_ips.add(ip)
            self.user_ips[user] = ip
        self._save_admin_blacklist()

    def remove_admin_blacklist(self, user: str):
        if user in self.admin_blacklist_users:
            self.admin_blacklist_users.discard(user)
        self._save_admin_blacklist()

    # --- connection logic ---
    async def connect(self, ws: WebSocket, user: str, role: str = "user"):
        self.active[user] = ws
        # Determine client IP up-front
        ip = None
        try:
            ip = ws.client.host
        except Exception:
            ip = None
        # Determine role with persistence and blacklist rules
        incoming_role = (role or "user")
        final_role = incoming_role
        try:
            # Blacklist check first: if blacklisted by user or IP, downgrade to user regardless
            if (user in self.admin_blacklist_users) or (ip and ip in self.admin_blacklist_ips):
                final_role = "user"
            else:
                # If they are in persistent admins (by user or IP), upgrade to admin
                if (user in self.persistent_admin_users) or (ip and ip in self.persistent_admin_ips):
                    final_role = "admin"
                # If they logged in with admin pass and are not blacklisted, persist them as admin
                elif incoming_role == "admin":
                    self.add_persistent_admin(user, ip)
                    final_role = "admin"
        except Exception:
            final_role = incoming_role
        # set/refresh role for this session (after enforcement)
        self.roles[user] = final_role
        # record latest IP for the user (in-memory); persist only for banned users
        try:
            if ip:
                self.user_ips[user] = ip
        except Exception:
            pass
        # Mark user as active on connect
        self.user_activity[user] = True
        await ws.send_text(json.dumps({"type": "history", "items": self.history}))
        # Presence event (no SYSTEM message)
        await self._presence(user, "join")
        await self._user_list()

    async def disconnect(self, user: str):
        if user in self.active:
            self.active.pop(user)
            # Mark user as inactive on disconnect
            self.user_activity[user] = False
            # Presence event (no SYSTEM message)
            await self._presence(user, "leave")
            # Clean up session-scoped demotions/promotions/tags for this user if desired
            # Note: we do not remove tags by default; keep until session end or explicit clear
            await self._user_list()

    def _effective_admins(self) -> List[str]:
        admins: List[str] = []
        for u in self.active.keys():
            base_admin = (self.roles.get(u) == "admin") and (u not in self.demoted_admins)
            promoted = u in self.promoted_admins
            if base_admin or promoted:
                admins.append(u)
        return admins

    async def _user_list(self):
        payload = {
            "type": "user_list",
            "users": list(self.active.keys()),
            "admins": self._effective_admins(),
            "tags": self.tags,
            "user_activity": self.user_activity,
            "tag_locks": list(self.tag_locks),
        }
        await self._broadcast(payload)

    async def send_gc_list(self, users: List[str] | None = None):
        targets = users or list(self.active.keys())
        for u in targets:
            ws = self.active.get(u)
            if not ws:
                continue
            try:
                payload = {"type": "gc_list", "gcs": self.get_user_gcs(u)}
                await ws.send_text(json.dumps(payload))
            except Exception:
                pass

    async def _system(self, text: str, store: bool = True):
        # Capitalize first letter of system messages
        try:
            s_raw = (text or "").strip()
            s = (s_raw[:1].upper() + s_raw[1:]) if s_raw else s_raw
        except Exception:
            s = text
        msg = {
            "id": f"system-{int(datetime.utcnow().timestamp()*1000)}",
            "sender": "SYSTEM",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "system",
            "text": s,
        }
        if store:
            self.history.append(msg)
            if len(self.history) > HISTORY:
                self.history = self.history[-HISTORY:]
        await self._broadcast(msg)

    async def _broadcast(self, obj: dict):
        # Persist only real user messages/media in main; do NOT store system or presence here
        if obj.get("type") in ("message", "media", "poll") and obj.get("sender") and obj.get("sender") != "SYSTEM":
            # Treat missing thread as main for backward-compat
            if obj.get("thread") in (None, "main"):
                self.history.append(obj)
                if len(self.history) > HISTORY:
                    self.history = self.history[-HISTORY:]
        data = json.dumps(obj)
        for ws in list(self.active.values()):
            try:
                await ws.send_text(data)
            except:
                pass

    # ---- helpers for ban/unban ----
    def ban_user(self, username: str, ip: str | None = None):
        self.banned_users.add(username)
        ip_to_add = ip or self.user_ips.get(username)
        if ip_to_add:
            self.banned_ips.add(ip_to_add)
            self.user_ips[username] = ip_to_add
        self._save_bans()

    def unban_user(self, username: str):
        if username in self.banned_users:
            self.banned_users.remove(username)
        # remove IP if known in mapping
        ip = self.user_ips.get(username)
        if ip and ip in self.banned_ips:
            self.banned_ips.remove(ip)
        # also remove stored mapping entry so it doesn't linger
        self.user_ips.pop(username, None)
        self._save_bans()

    # ---- mute helpers ----
    def mute_user(self, username: str, minutes: int):
        try:
            mins = max(int(minutes), 0)
        except Exception:
            mins = 0
        until = datetime.utcnow() + timedelta(minutes=mins)
        self.mutes[username] = until

    def unmute_user(self, username: str):
        self.mutes.pop(username, None)

    def is_muted(self, username: str) -> bool:
        until = self.mutes.get(username)
        if not until:
            return False
        if datetime.utcnow() >= until:
            # expired
            self.mutes.pop(username, None)
            return False
        return True

    def remaining_mute_seconds(self, username: str) -> int:
        until = self.mutes.get(username)
        if not until:
            return 0
        delta = (until - datetime.utcnow()).total_seconds()
        return max(int(delta), 0)

    # ---- per-DM mute helpers (receiver mutes sender) ----
    def mute_dm(self, receiver: str, sender: str, minutes: int):
        try:
            mins = max(int(minutes), 0)
        except Exception:
            mins = 0
        until = datetime.utcnow() + timedelta(minutes=mins)
        self.dm_mutes[(receiver, sender)] = until

    def unmute_dm(self, receiver: str, sender: str):
        self.dm_mutes.pop((receiver, sender), None)

    def is_dm_muted(self, receiver: str, sender: str) -> bool:
        until = self.dm_mutes.get((receiver, sender))
        if not until:
            return False
        if datetime.utcnow() >= until:
            self.dm_mutes.pop((receiver, sender), None)
            return False
        return True

    def remaining_dm_mute_seconds(self, receiver: str, sender: str) -> int:
        until = self.dm_mutes.get((receiver, sender))
        if not until:
            return 0
        delta = (until - datetime.utcnow()).total_seconds()
        return max(int(delta), 0)
