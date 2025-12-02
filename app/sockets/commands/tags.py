import re, json
from ..helpers import canonical_user, is_dev, is_effective_admin, COLOR_FLAGS
from ...services.manager import ConnMgr

async def _alert(ws, code: str, text: str):
    await ws.send_text(json.dumps({"type": "alert", "code": code, "text": text}))


def _is_dev_user(manager: ConnMgr, user: str) -> bool:
    return is_dev(manager, user)

MAX_TAG_LABEL_LEN = 60

def _clamp_label(text: str) -> tuple[str, bool]:
    """Clamp tag label to MAX_TAG_LABEL_LEN, appending ellipsis if truncated.
    Returns (label, trimmed_bool)."""
    s = (text or "").strip()
    if len(s) <= MAX_TAG_LABEL_LEN:
        return (s, False)
    if MAX_TAG_LABEL_LEN <= 1:
        return ("…"[:MAX_TAG_LABEL_LEN], True)
    return (s[: MAX_TAG_LABEL_LEN - 1] + "…", True)

async def handle_tag_commands(manager: ConnMgr, ws, sub: str, role: str, txt: str) -> bool:
    # Helpers: validate and parse color flags (named or hex) with default 'white'
    def _normalize_hex(h: str) -> str | None:
        if not isinstance(h, str):
            return None
        s = h.strip()
        if not s.startswith('#'):
            return None
        s = s[1:]
        if re.fullmatch(r'[0-9a-fA-F]{3}', s):
            r, g, b = s[0], s[1], s[2]
            return f"#{r}{r}{g}{g}{b}{b}".lower()
        if re.fullmatch(r'[0-9a-fA-F]{4}', s):
            r, g, b, a = s[0], s[1], s[2], s[3]
            return f"#{r}{r}{g}{g}{b}{b}{a}{a}".lower()
        if re.fullmatch(r'[0-9a-fA-F]{6}', s):
            return f"#{s.lower()}"
        if re.fullmatch(r'[0-9a-fA-F]{8}', s):
            return f"#{s.lower()}"
        return None

    def _parse_color(flag: str | None) -> str:
        if not flag:
            return 'white'
        f = flag.strip()
        if not f:
            return 'white'
        lf = f.lower()
        # accept -#HEX or plain #HEX
        if lf.startswith('-#'):
            norm = _normalize_hex(f[1:])
            return norm or 'white'
        if lf.startswith('#'):
            norm = _normalize_hex(f)
            return norm or 'white'
        # named color flag
        if lf in {'-rainbow', '-rainbwo', '-rnbw'}:
            return 'rainbow'
        return COLOR_FLAGS.get(lf, 'white')

    # /tag myself "tag" [color]
    m = re.match(r'^\s*/tag\s+myself\s+"([^"]+)"(?:\s+(\S+))?\s*$', txt, re.I)
    if m:
        raw_tag_text = m.group(1)
        tag_text, trimmed = _clamp_label(raw_tag_text)
        color_flag = (m.group(2) or '').strip() or None
        color = _parse_color(color_flag)
        if tag_text.strip().lower() in {"dev", "admin"}:
            await _alert(ws, "INFO", "That tag is reserved")
            return True
        # Enforce rainbow only if DEV
        if color == 'rainbow' and not _is_dev_user(manager, sub):
            await _alert(ws, "INFO", "Only DEV can set rainbow tag")
            return True
        # Respect tag lock on self unless DEV
        if sub in manager.tag_locks and not _is_dev_user(manager, sub):
            await _alert(ws, "INFO", "Your tag is locked (DEV only)")
            return True
        # If self is DEV, preserve DEV rainbow and append the personal tag
        if _is_dev_user(manager, sub):
            # DEV: store only the user's personal tag text; mark special but keep chosen color
            manager.set_user_tag(sub, {"text": tag_text, "color": color, "special": "dev"})
        else:
            manager.set_user_tag(sub, {"text": tag_text, "color": color})
        await manager._user_list()
        # Report trimming if applied
        to_report_trim = trimmed
        if to_report_trim:
            await _alert(ws, "INFO", f"Tag trimmed to {MAX_TAG_LABEL_LEN} chars")
        await manager._system(f"{sub} was tagged {tag_text}", store=True)
        return True

    # /tag "username" "tag" [color] (admin/promoted/dev only for tagging others)
    m = re.match(r'^\s*/tag\s+"([^"]+)"\s+"([^"]+)"(?:\s+(\S+))?\s*$', txt, re.I)
    if m:
        is_admin = is_effective_admin(manager, sub)
        target_label = (m.group(1) or '').strip()
        raw_tag_text = m.group(2)
        tag_text, trimmed = _clamp_label(raw_tag_text)
        color_flag = (m.group(3) or '').strip() or None
        if not is_admin and target_label.lower() != "myself":
            await _alert(ws, "INFO", 'You can only tag yourself. Use: /tag "myself" "tag" [color or -#HEXCODE]')
            return True
        # Resolve target; support quoted "myself"
        if target_label.lower() == "myself":
            target = sub
        else:
            target = canonical_user(manager, target_label)
            # Require target to be online when tagging others
            if target not in manager.active:
                await _alert(ws, "INFO", f"{target_label} is not online")
                return True
        # Disallow tagging DEV users unless self
        if _is_dev_user(manager, target) and target.lower() != sub.lower():
            await _alert(ws, "INFO", "Cannot tag DEV users")
            return True
        # Respect tag locks: only DEV can change a locked user's tag
        if (target in manager.tag_locks) and not _is_dev_user(manager, sub):
            await _alert(ws, "INFO", "User's tag is locked (DEV only)")
            return True
        # Respect tag rejects: only DEV can override another user's opt-out
        if (target in manager.tag_rejects) and (target.lower() != sub.lower()) and not _is_dev_user(manager, sub):
            await _alert(ws, "INFO", "User rejects being tagged by others")
            return True
        color = _parse_color(color_flag)
        if tag_text.strip().lower() in {"dev", "admin"}:
            await _alert(ws, "INFO", "That tag is reserved")
            return True
        # Enforce rainbow only if DEV
        if color == 'rainbow' and not _is_dev_user(manager, sub):
            await _alert(ws, "INFO", "Only DEV can assign rainbow tag")
            return True
        if _is_dev_user(manager, target):
            # DEV target: store only user's personal tag text; mark special but keep chosen color
            manager.set_user_tag(target, {"text": tag_text, "color": color, "special": "dev"})
        else:
            manager.set_user_tag(target, {"text": tag_text, "color": color})
        await manager._user_list()
        to_report_trim = trimmed
        if to_report_trim:
            await _alert(ws, "INFO", f"Tag trimmed to {MAX_TAG_LABEL_LEN} chars")
        await manager._system(f"{target} was tagged {tag_text}", store=True)
        return True

    # /rmtag "username" (admin/dev) or /rmtag (self)
    m = re.match(r'^\s*/rmtag\s+"([^"]+)"\s*$', txt, re.I)
    if m:
        is_admin = is_effective_admin(manager, sub)
        target_label = m.group(1)
        target = canonical_user(manager, target_label)
        # Permission: only self unless admin/dev
        if target.lower() != sub.lower() and not is_admin:
            await _alert(ws, "INFO", "You can only remove your own tag")
            return True
        if (target in manager.tag_locks) and not _is_dev_user(manager, sub):
            await _alert(ws, "INFO", "User's tag is locked (DEV only)")
            return True
        # Admin cannot touch other admins; DEV can modify anyone
        if target.lower() != sub.lower():
            if not _is_dev_user(manager, sub):
                # Non-DEV admin: disallow if target is admin
                try:
                    if is_effective_admin(manager, target):
                        await _alert(ws, "INFO", "Cannot modify another admin's tag")
                        return True
                except Exception:
                    pass
            # Never allow modifying DEV user by non-DEV
            if _is_dev_user(manager, target) and not _is_dev_user(manager, sub):
                await _alert(ws, "INFO", "Cannot modify DEV user's tag")
                return True
        if target in manager.tags:
            if _is_dev_user(manager, target):
                # Revert to base DEV tag
                manager.set_user_tag(target, {"text": "DEV", "color": "rainbow", "special": "dev"})
                await manager._system(f"{target} removed their tag", store=True)
            else:
                manager.clear_user_tag(target)
                await manager._system(f"{target} tag cleared", store=True)
            await manager._user_list()
        else:
            await _alert(ws, "INFO", "User has no tag")
        return True

    if re.match(r'^\s*/rmtag\s*$', txt, re.I):
        # Enforce lock on self unless DEV
        if (sub in manager.tag_locks) and not _is_dev_user(manager, sub):
            await _alert(ws, "INFO", "Your tag is locked (DEV only)")
            return True
        if sub in manager.tags:
            if _is_dev_user(manager, sub):
                # Revert to base DEV tag
                manager.set_user_tag(sub, {"text": "DEV", "color": "rainbow", "special": "dev"})
                await manager._user_list()
                await manager._system(f"{sub} removed their tag", store=True)
            else:
                manager.clear_user_tag(sub)
                await manager._user_list()
                await manager._system(f"{sub} removed their tag", store=True)
        else:
            await _alert(ws, "INFO", "You have no tag")
        return True

    # /rjtag and /acptag
    if re.match(r'^\s*/rjtag\s*$', txt, re.I):
        manager.tag_rejects.add(sub)
        await manager._user_list()
        await manager._system(f"{sub} rejects being tagged by others", store=True)
        return True

    if re.match(r'^\s*/ac(?:p)?tag\s*$', txt, re.I):
        manager.tag_rejects.discard(sub)
        await manager._user_list()
        await manager._system(f"{sub} accepts being tagged by others", store=True)
        return True

    if re.match(r'^\s*/tag', txt, re.I):
        await _alert(ws, "INFO", 'Usage: /tag "myself" "tag" [color or -#HEXCODE] or /tag "username" "tag" [color or -#HEXCODE]')
        return True

    return False
