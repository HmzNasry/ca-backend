from fastapi import FastAPI, WebSocket, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from .auth import (
    login_user, Login, Token,
    signup_user, signin_user, SignUp, SignIn, is_account_available,
    get_account_from_token, update_account_from_token, AccountInfo, UpdateAccount,
    get_account_for_admin, update_account_for_admin, delete_account_for_admin, delete_account_from_token
)
from jose import jwt
from .auth import SECRET_KEY, ALGORITHM
from .upload import router as upload_router, UPLOAD_DIR
from .dev_override import combined_request_has_secret
from .db import init_db
from .websocket_handlers import ws_handler
import os
from .logging_setup import setup_logging

# Initialize logging as early as possible
try:
    setup_logging()
except Exception:
    pass

app = FastAPI()
init_db()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/files", StaticFiles(directory=UPLOAD_DIR), name="files")
app.include_router(upload_router)

@app.get("/health")
async def health_check():
    return {"ok": True}

# Cleanup uploads on server start: remove DM/GC folders and clear main files
try:
    import shutil
    @app.on_event("startup")
    async def _cleanup_uploads_on_start():
        try:
            dm_dir = os.path.join(UPLOAD_DIR, "dm")
            gc_dir = os.path.join(UPLOAD_DIR, "gc")
            main_dir = os.path.join(UPLOAD_DIR, "main")
            # Remove dm and gc folders entirely
            for d in (dm_dir, gc_dir):
                if os.path.isdir(d):
                    try:
                        shutil.rmtree(d)
                    except Exception:
                        pass
            # Recreate empty dm and gc directories
            try:
                os.makedirs(dm_dir, exist_ok=True)
                os.makedirs(gc_dir, exist_ok=True)
            except Exception:
                pass
            # Clear files inside main directory (but keep the folder)
            if os.path.isdir(main_dir):
                try:
                    for name in os.listdir(main_dir):
                        p = os.path.join(main_dir, name)
                        try:
                            if os.path.isfile(p) or os.path.islink(p):
                                os.remove(p)
                            elif os.path.isdir(p):
                                shutil.rmtree(p)
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            # Never crash server due to cleanup
            pass
except Exception:
    pass

@app.post("/login", response_model=Token)
async def login(data: Login, request: Request):
    is_dev = combined_request_has_secret(request.headers, request.cookies)
    return login_user(data, force_dev=is_dev)


@app.post("/signup", response_model=Token)
async def signup(data: SignUp, request: Request):
    is_dev = combined_request_has_secret(request.headers, request.cookies)
    return signup_user(data, force_dev=is_dev)


@app.post("/signin", response_model=Token)
async def signin(data: SignIn, request: Request):
    is_dev = combined_request_has_secret(request.headers, request.cookies)
    return signin_user(data, force_dev=is_dev)

# New: username availability check (case-insensitive), uses the WebSocket manager state
try:
    from .sockets.ws import manager as ws_manager  # active connections live here
    from .sockets.helpers import is_dev as _is_dev
    @app.get("/user-available")
    async def user_available(name: str):
        low = (name or "").strip().lower()
        taken = any((u or "").lower() == low for u in ws_manager.active.keys())
        return {"available": (not taken)}

    @app.get("/account-available")
    async def account_available(name: str):
        try:
            return {"available": bool(is_account_available(name))}
        except Exception:
            # Fail-open for UX; frontend will still handle sign-up failures
            return {"available": True}

    @app.get("/account", response_model=AccountInfo)
    async def get_account(authorization: str | None = Header(None)):
        # Expect Authorization: Bearer <token>
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing token")
        token = authorization.split(" ", 1)[1].strip()
        return get_account_from_token(token)

    @app.post("/account/update", response_model=Token)
    async def update_account(data: UpdateAccount, authorization: str | None = Header(None)):
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing token")
        token = authorization.split(" ", 1)[1].strip()
        return update_account_from_token(token, data)

    # Admin/DEV endpoints to manage any account (requester must be DEV online)
    @app.get("/admin/account", response_model=AccountInfo)
    async def admin_get_account(username: str, authorization: str | None = Header(None)):
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing token")
        # Verify requester is DEV (must be connected)
        try:
            payload = jwt.decode(authorization.split(" ", 1)[1].strip(), SECRET_KEY, algorithms=[ALGORITHM])
            requester = payload.get("sub")
            if not requester or requester not in ws_manager.active or not _is_dev(ws_manager, requester):
                raise HTTPException(status_code=403, detail="forbidden")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=401, detail="invalid token")
        return get_account_for_admin(username)

    @app.post("/admin/account/update", response_model=AccountInfo)
    async def admin_update_account(username: str, data: UpdateAccount, authorization: str | None = Header(None)):
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing token")
        # Verify requester is DEV (must be connected)
        try:
            payload = jwt.decode(authorization.split(" ", 1)[1].strip(), SECRET_KEY, algorithms=[ALGORITHM])
            requester = payload.get("sub")
            if not requester or requester not in ws_manager.active or not _is_dev(ws_manager, requester):
                raise HTTPException(status_code=403, detail="forbidden")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=401, detail="invalid token")
        return update_account_for_admin(username, data)

    @app.post("/admin/account/delete")
    async def admin_delete_account(username: str, authorization: str | None = Header(None)):
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing token")
        # Verify requester is DEV (must be connected)
        try:
            payload = jwt.decode(authorization.split(" ", 1)[1].strip(), SECRET_KEY, algorithms=[ALGORITHM])
            requester = payload.get("sub")
            if not requester or requester not in ws_manager.active or not _is_dev(ws_manager, requester):
                raise HTTPException(status_code=403, detail="forbidden")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=401, detail="invalid token")

        # Capture potential last IP before delete for best-effort disconnect
        result = delete_account_for_admin(username)
        # Also remove identity from users.json registry so the name is fully freed
        try:
            ws_manager.remove_user_identity(username)
        except Exception:
            pass
        # Best-effort: notify and disconnect any session that matches username or last seen IP
        try:
            # Direct match by display name (if same as username)
            if username in ws_manager.active:
                try:
                    ws_target = ws_manager.active.get(username)
                    if ws_target:
                        try:
                            await ws_target.send_text('{"type":"alert","code":"ACCOUNT_DELETED","text":"Your account was deleted"}')
                        except Exception:
                            pass
                        try:
                            await ws_target.close()
                        except Exception:
                            pass
                    ws_manager.active.pop(username, None)
                except Exception:
                    pass
                try:
                    await ws_manager._user_list()
                except Exception:
                    pass

            # Match by IP if available
            ip = result.get("last_seen_ip") if isinstance(result, dict) else None
            if ip:
                try:
                    to_close = [u for u, w in ws_manager.active.items() if getattr(w, 'client', None) and getattr(w.client, 'host', None) == ip]
                except Exception:
                    to_close = []
                for u in to_close:
                    try:
                        ws_target = ws_manager.active.get(u)
                        if ws_target:
                            try:
                                await ws_target.send_text('{"type":"alert","code":"ACCOUNT_DELETED","text":"Your account was deleted"}')
                            except Exception:
                                pass
                            try:
                                await ws_target.close()
                            except Exception:
                                pass
                        ws_manager.active.pop(u, None)
                    except Exception:
                        pass
                if to_close:
                    try:
                        await ws_manager._user_list()
                    except Exception:
                        pass
        except Exception:
            # Never fail delete due to disconnect issues
            pass

        if not (isinstance(result, dict) and result.get("deleted")):
            raise HTTPException(status_code=404, detail="not found")
        # Persist a system message about deletion
        try:
            await ws_manager._system(f"{username} account deleted by admin", store=True)
        except Exception:
            pass
        return {"ok": True}
except Exception:
    # Fallback if import fails; treat as available to avoid blocking logins
    @app.get("/user-available")
    async def user_available(name: str):
        return {"available": True}

    @app.get("/account-available")
    async def account_available(name: str):
        return {"available": True}

@app.websocket("/ws/{token}")
async def websocket_endpoint(ws: WebSocket, token: str):
    await ws_handler(ws, token)

# Self account deletion endpoint (must be defined before SPA mount to avoid 405s)
try:
    from .sockets.ws import manager as ws_manager  # reuse manager instance
    @app.post("/account/delete")
    async def self_delete_account(authorization: str | None = Header(None)):
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing token")
        token = authorization.split(" ", 1)[1].strip()
        # Determine requester username for disconnect and message wording
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            requester = payload.get("sub") or payload.get("acct")
        except Exception:
            requester = None
        result = delete_account_from_token(token)
        if not (isinstance(result, dict) and result.get("deleted")):
            raise HTTPException(status_code=404, detail="not found")
        # Remove identity from users.json registry as well to fully free the name
        try:
            if requester:
                ws_manager.remove_user_identity(requester)
        except Exception:
            pass
        # Notify and disconnect any live session for this requester
        try:
            if requester and requester in ws_manager.active:
                ws_target = ws_manager.active.get(requester)
                if ws_target:
                    try:
                        await ws_target.send_text('{"type":"alert","code":"ACCOUNT_DELETED","text":"Your account was deleted"}')
                    except Exception:
                        pass
                    try:
                        await ws_target.close()
                    except Exception:
                        pass
                ws_manager.active.pop(requester, None)
                try:
                    await ws_manager._user_list()
                except Exception:
                    pass
        except Exception:
            pass
        # Persist a system message about self-deletion
        try:
            who = requester or (result.get("username") if isinstance(result, dict) else None) or "A user"
            await ws_manager._system(f"{who} deleted their account", store=True)
        except Exception:
            pass
        return {"ok": True}
except Exception:
    pass

# Serve frontend SPA (built files) at root so GET / works locally and via Cloudflare
try:
    import os
    from fastapi.staticfiles import StaticFiles
    FRONTEND_DIR = os.environ.get("CA_FRONTEND_DIR") or os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist"))
    if os.path.isdir(FRONTEND_DIR):
        app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="spa")
except Exception:
    pass
