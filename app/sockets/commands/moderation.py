import re, json
from ..helpers import canonical_user, is_dev, is_effective_admin
from ...services.manager import ConnMgr

async def _alert(ws, code: str, text: str):
    await ws.send_text(json.dumps({"type": "alert", "code": code, "text": text}))


async def handle_moderation_commands(manager: ConnMgr, ws, sub: str, role: str, txt: str) -> bool:
    """Handle /mute, /unmute, /locktag, /unlocktag. Return True if handled."""
    is_adminish = is_effective_admin(manager, sub)

    # /mute "user" <minutes>; admin or dev
    m = re.match(r'^\s*/mute\s+"([^"]+)"\s+(\d+)\s*$', txt, re.I)
    if m and is_adminish:
        if manager.mute_all and not is_dev(manager, sub):
            await _alert(ws, "INFO", "Muting is disabled by DEV.")
            return True
        target_raw = m.group(1)
        target = canonical_user(manager, target_raw)
        minutes = int(m.group(2))
        if is_effective_admin(manager, target) and not is_dev(manager, sub):
            await _alert(ws, "INFO", "cannot moderate admins")
            return True
        manager.mute_user(target, minutes)
        await manager._system(f"{target} was muted for {minutes} minute(s)", store=True)
        if target in manager.active:
            try:
                await manager.active[target].send_text(json.dumps({
                    "type": "alert",
                    "code": "MUTED",
                    "text": "You are muted",
                    "seconds": manager.remaining_mute_seconds(target)
                }))
            except: pass
        return True

    # /unmute "user"; admin or dev
    m = re.match(r'^\s*/unmute\s+"([^"]+)"\s*$', txt, re.I)
    if m and is_adminish:
        if manager.mute_all and not is_dev(manager, sub):
            await _alert(ws, "INFO", "Unmuting is disabled by DEV.")
            return True
        target_raw = m.group(1)
        target = canonical_user(manager, target_raw)
        manager.unmute_user(target)
        await manager._system(f"{target} was unmuted", store=True)
        return True

    # /unmute (no args) -> prompt list of currently muted users (admin/dev only)
    if re.match(r'^\s*/unmute\s*$', txt, re.I) and is_adminish:
        try:
            muted = []
            # collect users with active mutes
            for u in list((manager.mutes or {}).keys()):
                if manager.is_muted(u):
                    muted.append(u)
            muted.sort()
        except Exception:
            muted = []
        if not muted:
            await _alert(ws, "INFO", "Nobody is muted")
            return True
        await ws.send_text(json.dumps({"type": "unmute_prompt", "muted": muted}))
        return True

    # /locktag "user" (DEV only)
    m = re.match(r'^\s*/locktag\s+"([^"]+)"\s*$', txt, re.I)
    if m:
        if not is_dev(manager, sub):
            await _alert(ws, "INFO", "only DEV can lock tags")
            return True
        target_raw = m.group(1)
        target = canonical_user(manager, target_raw)
        manager.set_tag_lock(target, True)
        await manager._user_list()
        await manager._system(f"{target}'s tag was locked", store=True)
        return True

    # /unlocktag "user" (DEV only)
    m = re.match(r'^\s*/unlocktag\s+"([^"]+)"\s*$', txt, re.I)
    if m:
        if not is_dev(manager, sub):
            await _alert(ws, "INFO", "only DEV can unlock tags")
            return True
        target_raw = m.group(1)
        target = canonical_user(manager, target_raw)
        manager.set_tag_lock(target, False)
        await manager._user_list()
        await manager._system(f"{target}'s tag was unlocked", store=True)
        return True

    return False