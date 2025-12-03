import os
from http.cookies import SimpleCookie
from typing import Mapping

DEV_COOKIE_NAME = os.environ.get("CA_DEV_COOKIE_NAME", "ca_dev_pass")
DEV_COOKIE_SECRET = os.environ.get("CA_DEV_COOKIE_SECRET", "71060481")


def _matches(secret: str | None) -> bool:
    if not secret:
        return False
    return secret.strip() == DEV_COOKIE_SECRET


def cookie_jar_has_secret(cookies: Mapping[str, str | None] | None) -> bool:
    try:
        if not cookies:
            return False
        value = cookies.get(DEV_COOKIE_NAME)
        return _matches(value)
    except Exception:
        return False


def header_has_secret(headers: Mapping[str, str | None] | None) -> bool:
    try:
        if not headers:
            return False
        value = headers.get("x-dev-secret")
        if _matches(value):
            return True
        # Some frameworks/title-case headers; try fallback
        value = headers.get("X-Dev-Secret")
        return _matches(value)
    except Exception:
        return False


def combined_request_has_secret(headers, cookies) -> bool:
    return cookie_jar_has_secret(cookies) or header_has_secret(headers)


def raw_cookie_header_has_secret(raw_cookie: str | None) -> bool:
    if not raw_cookie:
        return False
    try:
        jar = SimpleCookie()
        jar.load(raw_cookie)
        morsel = jar.get(DEV_COOKIE_NAME)
        if not morsel:
            return False
        return _matches(morsel.value)
    except Exception:
        return False

