import json, os, re, shutil, asyncio
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect, status
from jose import jwt, JWTError
from .manager import ConnMgr
from .upload import UPLOAD_DIR
from .auth import SECRET_KEY, ALGORITHM
from .ollama_client import stream_ollama, TEXT_MODEL
import logging

logger = logging.getLogger(__name__)

# New: import auth module so we can mutate SERVER_PASSWORD at runtime
from . import auth as auth_mod

manager = ConnMgr()
manager.HISTORY = 100 if hasattr(manager, 'HISTORY') else None

# --- AI controls/state ---
ai_enabled = True
ai_tasks = {}  # ai_id -> {"task": asyncio.Task, "owner": str}

# Safe-name helper to mirror upload.py folder naming
_SAFE_RE = re.compile(r"[^a-zA-Z0-9_.-]+")

def _safe_name(s: str) -> str:
    return _SAFE_RE.sub("_", s or "")

# Resolve a username to the exact online casing; fallback to the original if not found
def _canonical_user(name: str) -> str:
    try:
        n = (name or "").strip()
        if not n:
            return name
        low = n.lower()
        for u in list(manager.active.keys()):
            if u.lower() == low:
                return u
        return name
    except Exception:
        return name

# Check if a user is an effective admin (built-in or promoted)
def _is_effective_admin(user: str) -> bool:
    try:
        # Treat DEV (localhost) as superior admin for moderation protections
        tag = manager.tags.get(user) or {}
        is_dev = isinstance(tag, dict) and tag.get("special") == "dev"
        return is_dev or (manager.roles.get(user) == "admin") or (user in manager.promoted_admins)
    except Exception:
        return False

def _is_dev(user: str) -> bool:
    try:
        tag = manager.tags.get(user) or {}
        return isinstance(tag, dict) and tag.get("special") == "dev"
    except Exception:
        return False

# Map color flags to canonical color strings for the UI
COLOR_FLAGS = {
    '-r': 'red', '-red': 'red',
    '-g': 'green', '-green': 'green',
    '-b': 'blue', '-blue': 'blue',
    '-p': 'pink', '-pink': 'pink',
    '-y': 'yellow', '-yellow': 'yellow',
    '-w': 'white', '-white': 'white',
    '-c': 'cyan', '-cyan': 'cyan',
    # Additional colors
    '-purple': 'purple',
    '-violet': 'violet',
    '-indigo': 'indigo',
    '-teal': 'teal',
    '-lime': 'lime',
    '-amber': 'amber',
    '-emerald': 'emerald',
    '-fuchsia': 'fuchsia',
    '-sky': 'sky',
    '-gray': 'gray',
}

async def _cancel_all_ai():
    for ai_id, meta in list(ai_tasks.items()):
        task: asyncio.Task = meta.get("task")
        if task and not task.done():
            task.cancel()
        ai_tasks.pop(ai_id, None)


async def _cancel_ai_for_user(target: str):
    for ai_id, meta in list(ai_tasks.items()):
        if meta.get("owner") == target:
            task: asyncio.Task = meta.get("task")
            if task and not task.done():
                task.cancel()
            ai_tasks.pop(ai_id, None)


async def _run_ai(ai_id: str, owner: str, prompt: str, image_url: str | None = None):
    full_text = ""
    history = list(manager.history)  # same history, so /clear wipes it
    try:
        async for chunk in stream_ollama(prompt, image_url=image_url, history=history, invoker=owner):
            full_text += chunk
            try:
                await manager._broadcast({"type": "update", "id": ai_id, "text": full_text})
            except Exception:
                pass
    except asyncio.CancelledError:
        try:
            # Resolve spinner with a stopped marker
            await manager._broadcast({"type": "update", "id": ai_id, "text": "[STOPPED]"})
            await manager._system(f"AI generation by {owner} was stopped", store=True)
        except Exception:
            pass
        raise
    finally:
        try:
            # If no output was ever produced, push a placeholder so spinner ends
            if not full_text.strip():
                try:
                    await manager._broadcast({"type": "update", "id": ai_id, "text": "[NO RESPONSE]"})
                except Exception:
                    pass
            # Persist final text into history
            for msg in manager.history:
                if msg.get("id") == ai_id:
                    msg["text"] = full_text if full_text.strip() else "[NO RESPONSE]"
                    break
        except Exception:
            pass
        ai_tasks.pop(ai_id, None)


from .sockets.ws import ws_handler

__all__ = ["ws_handler"]

