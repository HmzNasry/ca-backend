import re, json
from ..helpers import canonical_user, is_dev, is_effective_admin
from ...services.manager import ConnMgr
from ... import auth as auth_mod
from ...upload import UPLOAD_DIR
import os, shutil

# Admin and DEV command handlers

# Utility: send alert modal
async def _alert(ws, code: str, text: str):
    await ws.send_text(json.dumps({"type": "alert", "code": code, "text": text}))


async def handle_admin_commands(manager: ConnMgr, ws, sub: str, role: str, txt: str) -> bool:
    """Return True if the command was handled."""
    # Superpass bypass for mkadmin/rmadmin: allow any user with valid SUPER_PASS
    # This comes BEFORE the effective admin gate so non-admins can elevate/demote with the superpass.
    m = re.match(r'^\s*/mkadmin\s+"([^\"]+)"\s+(\S+)\s*$', txt, re.I)
    if m:
        target = canonical_user(manager, m.group(1))
        sup = m.group(2)
        if sup != getattr(auth_mod, 'SUPER_PASS', ''):
            await _alert(ws, "INFO", "invalid superpass")
            return True
        if (manager.tags.get(target, {}).get("text", "").upper() == "WEIRDO"):
            await _alert(ws, "INFO", "Cannot make weirdos admins!")
            return True
        manager.promoted_admins.add(target)
        try:
            ws_t = manager.active.get(target)
            ip_t = None
            if ws_t and getattr(ws_t, 'client', None):
                ip_t = getattr(ws_t.client, 'host', None)
            if not ip_t:
                ip_t = manager.user_ips.get(target)
            manager.add_persistent_admin(target, ip_t)
            manager.remove_admin_blacklist(target)
        except Exception:
            pass
        await manager._system(f"{target} was granted admin", store=True)
        await manager._user_list()
        return True
    m = re.match(r'^\s*/rmadmin\s+"([^\"]+)"\s+(\S+)\s*$', txt, re.I)
    if m:
        target = canonical_user(manager, m.group(1))
        sup = m.group(2)
        if sup != getattr(auth_mod, 'SUPER_PASS', ''):
            await _alert(ws, "INFO", "invalid superpass")
            return True
        is_builtin = manager.roles.get(target) == "admin"
        is_promoted = target in manager.promoted_admins
        if not (is_builtin or is_promoted):
            await _alert(ws, "INFO", "user is not an admin")
            return True
        manager.promoted_admins.discard(target)
        manager.demoted_admins.add(target)
        try:
            ws_t = manager.active.get(target)
            ip_t = None
            if ws_t and getattr(ws_t, 'client', None):
                ip_t = getattr(ws_t.client, 'host', None)
            if not ip_t:
                ip_t = manager.user_ips.get(target)
            if ip_t:
                manager.demoted_admin_ips.add(ip_t)
            manager.remove_persistent_admin(target)
            manager.add_admin_blacklist(target, ip_t)
        except Exception:
            pass
        await manager._system(f"{target} was demoted from admin", store=True)
        await manager._user_list()
        return True

    # All other admin commands require effective admin / DEV
    if not is_effective_admin(manager, sub):
        return False

    # /pass "newpass"
    m = re.match(r'^\s*/pass\s+"([^"]+)"\s*$', txt, re.I)
    if m:
        auth_mod.SERVER_PASSWORD = m.group(1)
        await manager._system("server message changed", store=True)
        return True

    # (Removed duplicate mkadmin/rmadmin blocks; superpass handling occurs above.)

    # /kick "username"
    m = re.match(r'^\s*/kick\s+"([^"]+)"\s*$', txt, re.I)
    if m:
        target = canonical_user(manager, m.group(1))
        if is_effective_admin(manager, target) and not is_dev(manager, sub):
            await _alert(ws, "INFO", "cannot moderate admins")
            return True
        if target in manager.active:
            await manager._system(f"{target} was kicked by admin", store=True)
            try:
                await manager.active[target].send_text(json.dumps({"type": "alert", "code": "KICKED", "text": "You were kicked by admin"}))
            except: pass
            await manager.active[target].close()
            manager.active.pop(target, None)
            await manager._user_list()
        else:
            await _alert(ws, "INFO", f"{target} is not online")
        return True

    # /kickA  (DEV only) kick EVERYONE except the issuer
    if re.match(r'^\s*/kickA\s*$', txt, re.I):
        if not is_dev(manager, sub):
            await _alert(ws, "INFO", "only DEV can use /kickA")
            return True
        to_kick = [u for u in list(manager.active.keys()) if u != sub]
        for u in to_kick:
            ws_target = manager.active.get(u)
            if not ws_target:
                continue
            try:
                await ws_target.send_text(json.dumps({"type": "alert", "code": "KICKED", "text": "You were kicked from chat"}))
            except:
                pass
            try:
                await ws_target.close()
            except:
                pass
            manager.active.pop(u, None)
        await manager._user_list()
        await manager._system("admin kicked everyone", store=True)
        return True

    # /purgeadmin (demote every admin / promoted admin except DEV users)
    if re.match(r'^\s*/purgeadmin\s*$', txt, re.I):
        # Remove all promoted admins except DEV
        manager.promoted_admins = {u for u in manager.promoted_admins if is_dev(manager, u)}
        # Demote built-in admins (roles==admin) unless DEV
        for u, r in list(manager.roles.items()):
            if r == 'admin' and not is_dev(manager, u):
                manager.demoted_admins.add(u)
                # Track by IP as well for persistence across sessions
                try:
                    ws_u = manager.active.get(u)
                    ip_u = None
                    if ws_u and getattr(ws_u, 'client', None):
                        ip_u = getattr(ws_u.client, 'host', None)
                    if not ip_u:
                        ip_u = manager.user_ips.get(u)
                    if ip_u:
                        manager.demoted_admin_ips.add(ip_u)
                except Exception:
                    pass
        # Remove ADMIN tags (but preserve DEV tag for actual devs)
        for u, tag in list(manager.tags.items()):
            if is_dev(manager, u):
                continue
            try:
                t = (tag or {}).get('text', '')
                if isinstance(t, str) and t.strip().upper() == 'ADMIN':
                    manager.clear_user_tag(u)
            except Exception:
                pass
        await manager._user_list()
        await manager._system("all admins purged", store=True)
        return True

    # /reset "superpass" (DEV only): clear history, users registry, admins, admin blacklist, bans, uploads
    m = re.match(r'^\s*/reset\s+"([^\"]+)"\s*$', txt, re.I)
    if m:
        if not is_dev(manager, sub):
            await _alert(ws, "INFO", "only DEV can reset server state")
            return True
        sup = m.group(1)
        if sup != getattr(auth_mod, 'SUPER_PASS', ''):
            await _alert(ws, "INFO", "invalid superpass")
            return True
        # 1) Clear histories and runtime state
        manager.history = []
        manager.dm_histories = {}
        manager.gcs = {}
        manager.tags = {}
        manager.tag_rejects = set()
        manager.tag_locks = set()
        manager.mutes = {}
        manager.mute_all = False
        manager.user_activity = {}
        manager.roles = {}
        manager.promoted_admins = set()
        manager.demoted_admins = set()
        manager.demoted_admin_ips = set()
        manager.user_ips = {}
        # 1a) Clear accounts/auth DB
        try:
            auth_mod.reset_auth()
        except Exception:
            pass
        # 2) Clear persistent lists/files via managers
        manager.banned_users = set()
        manager.banned_ips = set()
        manager._save_bans()
        manager.persistent_admin_users = set()
        manager.persistent_admin_ips = set()
        manager._admin_user_ips = {}
        manager._save_admins()
        manager.admin_blacklist_users = set()
        manager.admin_blacklist_ips = set()
        manager._admin_blacklist_user_ips = {}
        manager._save_admin_blacklist()
        # 3) Clear user registry (database-backed)
        manager.reset_users_registry()
        # 4) Remove uploads (dm, gc, main contents)
        try:
            dm_dir = os.path.join(UPLOAD_DIR, "dm")
            gc_dir = os.path.join(UPLOAD_DIR, "gc")
            main_dir = os.path.join(UPLOAD_DIR, "main")
            for d in (dm_dir, gc_dir, main_dir):
                if os.path.isdir(d):
                    shutil.rmtree(d)
            os.makedirs(dm_dir, exist_ok=True)
            os.makedirs(gc_dir, exist_ok=True)
            os.makedirs(main_dir, exist_ok=True)
        except Exception:
            pass
        # Notify all connected clients with a modal and then force sign-out on dismiss
        try:
            payload = json.dumps({"type": "alert", "code": "RESET", "text": "Server state has been reset"})
            for u, ws_target in list(manager.active.items()):
                try:
                    await ws_target.send_text(payload)
                except Exception:
                    pass
        except Exception:
            pass
        await manager._user_list()
        await manager._system("server state reset by DEV", store=True)
        return True

    # /reset (no args) -> prompt superpass on the client
    if re.match(r'^\s*/reset\s*$', txt, re.I):
        if not is_dev(manager, sub):
            await _alert(ws, "INFO", "only DEV can reset server state")
            return True
        try:
            await ws.send_text(json.dumps({"type": "reset_prompt"}))
        except Exception:
            pass
        return True

    # /muteA <minutes>  (DEV only) mute everyone for N minutes (excluding issuing DEV)
    m = re.match(r'^\s*/muteA\s+(\d+)\s*$', txt, re.I)
    if m:
        if not is_dev(manager, sub):
            await _alert(ws, "INFO", "only DEV can use /muteA")
            return True
        manager.mute_all = True
        minutes = int(m.group(1))
        for u in list(manager.active.keys()):
            if u == sub and is_dev(manager, u):
                continue  # skip muting the issuing DEV
            manager.mute_user(u, minutes)
            # If a user is currently connected and is the one issuing, optionally show their own mute modal (consistency)
            ws_target = manager.active.get(u)
            if ws_target:
                try:
                    await ws_target.send_text(json.dumps({
                        "type": "alert",
                        "code": "MUTED",
                        "text": "You are muted",
                        "seconds": manager.remaining_mute_seconds(u)
                    }))
                except:
                    pass
        await manager._system(f"everyone muted for {minutes} minute(s)", store=False)
        return True

    # /unmuteA  (DEV only) unmute everyone immediately
    if re.match(r'^\s*/unmuteA\s*$', txt, re.I):
        if not is_dev(manager, sub):
            await _alert(ws, "INFO", "only DEV can use /unmuteA")
            return True
        manager.mute_all = False
        for u in list(manager.mutes.keys()):
            manager.unmute_user(u)
        await manager._system("all mutes lifted by admin", store=True)
        return True

    # /psa "message" (DEV only) modal for everyone, not persisted
    m = re.match(r'^\s*/psa\s+"([^"]+)"\s*$', txt, re.I)
    if m:
        if not is_dev(manager, sub):
            await _alert(ws, "INFO", "only DEV can use /psa")
            return True
        psa_text = m.group(1)[:400]
        payload = json.dumps({"type": "alert", "code": "PSA", "text": psa_text})
        for u, ws_target in list(manager.active.items()):
            try:
                await ws_target.send_text(payload)
            except:
                pass
        return True

    # /users (DEV only) -> prompt list from account database
    if re.match(r'^\s*/users\s*$', txt, re.I):
        if not is_dev(manager, sub):
            await _alert(ws, "INFO", "only DEV can use /users")
            return True
        try:
            reg_users = auth_mod.list_account_usernames()
        except Exception:
            reg_users = []
        await ws.send_text(json.dumps({"type": "users_prompt", "users": reg_users}))
        return True

    # /rmuser "username" (DEV only) -> remove from persistent user registry and kick if online
    m = re.match(r'^\s*/rmuser\s+"([^"]+)"\s*$', txt, re.I)
    if m:
        if not is_dev(manager, sub):
            await _alert(ws, "INFO", "only DEV can use /rmuser")
            return True
        target = m.group(1)
        # If the user is currently online, notify and disconnect them first
        if target in manager.active:
            try:
                ws_target = manager.active.get(target)
                if ws_target:
                    try:
                        await ws_target.send_text(json.dumps({"type": "alert", "code": "ACCOUNT_DELETED", "text": "Your account was deleted"}))
                    except Exception:
                        pass
                    try:
                        await ws_target.close()
                    except Exception:
                        pass
                manager.active.pop(target, None)
                await manager._user_list()
            except Exception:
                pass
        ok = manager.remove_user_identity(target)
        if ok:
            await manager._system(f"removed {target} from users registry", store=True)
        else:
            await _alert(ws, "INFO", f"{target} not found in users registry")
        return True

    # /ban "username"
    m = re.match(r'^\s*/ban\s+"([^"]+)"\s*$', txt, re.I)
    if m:
        target = canonical_user(manager, m.group(1))
        if is_effective_admin(manager, target) and not is_dev(manager, sub):
            await _alert(ws, "INFO", "cannot moderate admins")
            return True
        if target in manager.active:
            ws_target = manager.active[target]
            ip_target = ws_target.client.host
            manager.ban_user(target, ip_target)
            await manager._system(f"{target} was banned by admin", store=True)
            try:
                await ws_target.send_text(json.dumps({"type": "alert", "code": "BANNED", "text": "You were banned from chat"}))
            except: pass
            await ws_target.close()
            manager.active.pop(target, None)
            await manager._user_list()
        else:
            manager.ban_user(target)
            await manager._system(f"{target} (offline) was banned by admin", store=True)
        return True

    # /unban (no args) -> prompt banned list
    if re.match(r'^\s*/unban\s*$', txt, re.I):
        try:
            banned = sorted(list(manager.banned_users))
        except Exception:
            banned = []
        if not banned:
            await _alert(ws, "INFO", "Nobody is banned")
            return True
        await ws.send_text(json.dumps({"type": "unban_prompt", "banned": banned}))
        return True

    # /unban "username"
    m = re.match(r'^\s*/unban\s+"([^"]+)"\s*$', txt, re.I)
    if m:
        target = canonical_user(manager, m.group(1))
        existed = target in manager.banned_users
        if existed:
            manager.unban_user(target)
            await manager._system(f"{target} was unbanned by admin", store=True)
        else:
            await _alert(ws, "NOT_BANNED", f"{target} is not banned")
        return True

    return False
