#!/usr/bin/env python3
# Flood tester without a browser: logs in via HTTP, opens WS, sends a message, closes.
# Usage (fish):
#   python food.py --base-url http://127.0.0.1:8000/ --count 100 --password securepass32x1 --message hello
# Requires: pip install aiohttp

import asyncio
import argparse
import json
from typing import Optional
from urllib.parse import urlparse

import aiohttp


def build_urls(base_url: str, token: Optional[str] = None) -> tuple[str, Optional[str]]:
    """Return (http_base, ws_url) given a base URL and optional token."""
    b = (base_url or "").strip()
    if not b:
        raise ValueError("base-url is required")
    if not b.endswith("/"):
        b += "/"
    http_base = b.rstrip("/")
    u = urlparse(http_base)
    scheme = u.scheme.lower()
    host = u.netloc
    path = u.path.rstrip("/")
    if token:
        ws_scheme = "wss" if scheme == "https" else "ws"
        ws_url = f"{ws_scheme}://{host}{path}/ws/{token}"
    else:
        ws_url = None
    return http_base, ws_url


async def login(session: aiohttp.ClientSession, base_url: str, username: str, server_password: str) -> Optional[str]:
    http_base, _ = build_urls(base_url)
    url = f"{http_base}/login"
    try:
        async with session.post(url, json={"username": username, "server_password": server_password}) as r:
            if r.status != 200:
                txt = await r.text()
                print(f"[fail] {username}: login {r.status} {txt[:120]}")
                return None
            data = await r.json()
            return data.get("access_token")
    except Exception as e:
        print(f"[fail] {username}: login error {e}")
        return None


async def send_ws(session: aiohttp.ClientSession, base_url: str, token: str, message: str) -> bool:
    _, ws_url = build_urls(base_url, token)
    if not ws_url:
        return False
    try:
        async with session.ws_connect(ws_url, heartbeat=20) as ws:
            # Send a regular chat message to Main thread
            await ws.send_str(json.dumps({"text": message}))
            # Wait a short moment to read any server response (optional)
            try:
                for _ in range(3):
                    msg = await ws.receive(timeout=0.5)
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        # Detect duplicate login rejection
                        try:
                            d = json.loads(msg.data)
                            if d.get("type") == "alert" and str(d.get("code")) == "DUPLICATE":
                                print("[info] duplicate session rejected by server")
                                return False
                        except Exception:
                            pass
                    elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                        break
            except Exception:
                pass
            return True
    except Exception as e:
        print(f"[fail] ws error: {e}")
        return False


async def worker(i: int, base_url: str, password: str, message: str, sem: asyncio.Semaphore):
    username = f"YUH {i}"
    async with sem:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tok = await login(session, base_url, username, password)
            if not tok:
                return
            ok = await send_ws(session, base_url, tok, message)
            if ok:
                print(f"[ok]  {username}")
            else:
                print(f"[skip] {username}")


async def amain():
    ap = argparse.ArgumentParser(description="ChatApp flood tester (HTTP + WS)")
    ap.add_argument("--base-url", default="http://127.0.0.1:8000/", help="Base URL, e.g. http://127.0.0.1:8000/")
    ap.add_argument("--password", required=True, help="Server password to use")
    ap.add_argument("--message", default="hello", help="Message to send")
    ap.add_argument("--count", type=int, default=100, help="Number of users (Test 1..N)")
    ap.add_argument("--start", type=int, default=1, help="Start index (default 1)")
    ap.add_argument("--concurrency", type=int, default=20, help="Parallel workers")
    args = ap.parse_args()

    sem = asyncio.Semaphore(max(1, args.concurrency))
    tasks = [asyncio.create_task(worker(i, args.base_url, args.password, args.message, sem))
             for i in range(args.start, args.start + args.count)]
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        print("\nInterrupted")
