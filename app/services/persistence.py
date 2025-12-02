from __future__ import annotations
from datetime import datetime
from typing import Iterable, List, Optional

from ..db import SessionLocal
from ..db_models import Message, GroupChat, GroupMember


def _parse_ts(ts: Optional[str]) -> datetime:
    if not ts:
        return datetime.utcnow()
    try:
        # Strip trailing Z if present
        t = ts.rstrip("Z")
        return datetime.fromisoformat(t)
    except Exception:
        return datetime.utcnow()


def save_message(thread: str, scope: Optional[str], obj: dict) -> None:
    with SessionLocal() as db:
        m = Message(
            id=str(obj.get("id")),
            thread=thread,
            scope=scope,
            sender=str(obj.get("sender")) if obj.get("sender") is not None else None,
            type=str(obj.get("type")),
            text=str(obj.get("text")) if obj.get("text") is not None else None,
            url=str(obj.get("url")) if obj.get("url") is not None else None,
            mime=str(obj.get("mime")) if obj.get("mime") is not None else None,
            timestamp=_parse_ts(obj.get("timestamp")),
        )
        # Upsert on id to be safe
        existing = db.get(Message, m.id)
        if existing:
            existing.thread = m.thread
            existing.scope = m.scope
            existing.sender = m.sender
            existing.type = m.type
            existing.text = m.text
            existing.url = m.url
            existing.mime = m.mime
            existing.timestamp = m.timestamp
        else:
            db.add(m)
        db.commit()


def update_message_text(thread: str, scope: Optional[str], msg_id: str, text: str) -> None:
    with SessionLocal() as db:
        m = db.get(Message, msg_id)
        if m and m.thread == thread and (m.scope or None) == (scope or None):
            m.text = text
            db.commit()


def delete_message(thread: str, scope: Optional[str], msg_id: str) -> None:
    with SessionLocal() as db:
        m = db.get(Message, msg_id)
        if m and m.thread == thread and (m.scope or None) == (scope or None):
            db.delete(m)
            db.commit()


def clear_history(thread: str, scope: Optional[str]) -> None:
    with SessionLocal() as db:
        q = db.query(Message).filter(Message.thread == thread)
        if scope is None:
            q = q.filter(Message.scope.is_(None))
        else:
            q = q.filter(Message.scope == scope)
        q.delete(synchronize_session=False)
        db.commit()


def load_recent(thread: str, scope: Optional[str], limit: int) -> List[dict]:
    with SessionLocal() as db:
        q = db.query(Message).filter(Message.thread == thread)
        if scope is None:
            q = q.filter(Message.scope.is_(None))
        else:
            q = q.filter(Message.scope == scope)
        rows = q.order_by(Message.timestamp.desc()).limit(limit).all()
        out = []
        for r in reversed(rows):  # reverse to chronological
            d = {
                "id": r.id,
                "sender": r.sender,
                "timestamp": (r.timestamp.isoformat() + "Z"),
                "type": r.type,
                "thread": thread,
            }
            if r.text is not None:
                d["text"] = r.text
            if r.url is not None:
                d["url"] = r.url
            if r.mime is not None:
                d["mime"] = r.mime
            out.append(d)
        return out


# ---- Group chat persistence ----

def get_all_groups() -> List[dict]:
    with SessionLocal() as db:
        groups = {gc.id: {"id": gc.id, "name": gc.name, "creator": gc.creator, "members": []} for gc in db.query(GroupChat).all()}
        if not groups:
            return []
        mrows = db.query(GroupMember).all()
        for m in mrows:
            if m.gcid in groups:
                groups[m.gcid]["members"].append(m.user)
        return list(groups.values())


def create_group(gid: str, name: str, creator: str, members: Iterable[str]) -> None:
    with SessionLocal() as db:
        gc = db.get(GroupChat, gid)
        if not gc:
            gc = GroupChat(id=gid, name=name, creator=creator)
            db.add(gc)
            db.flush()
        else:
            gc.name = name
            gc.creator = creator
        # reset members
        db.query(GroupMember).filter(GroupMember.gcid == gid).delete(synchronize_session=False)
        for u in set(members):
            db.add(GroupMember(gcid=gid, user=u))
        db.commit()


def update_group(gid: str, name: Optional[str], members: Optional[Iterable[str]]) -> None:
    with SessionLocal() as db:
        gc = db.get(GroupChat, gid)
        if not gc:
            return
        if name is not None:
            gc.name = name
        if members is not None:
            db.query(GroupMember).filter(GroupMember.gcid == gid).delete(synchronize_session=False)
            for u in set(members):
                db.add(GroupMember(gcid=gid, user=u))
        db.commit()


def delete_group(gid: str) -> None:
    with SessionLocal() as db:
        db.query(GroupMember).filter(GroupMember.gcid == gid).delete(synchronize_session=False)
        gc = db.get(GroupChat, gid)
        if gc:
            db.delete(gc)
        # also clear messages of this gc
        db.query(Message).where(Message.thread == 'gc', Message.scope == gid).delete(synchronize_session=False)
        db.commit()
