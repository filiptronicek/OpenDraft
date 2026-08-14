"""Smoke test for backend auth JWT verification.

Run from project root:
    venv/bin/python test-script/test_backend_auth.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

# Ensure backend/ is importable
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

# Configure the shared secret BEFORE importing app modules.
os.environ["COLLAB_JWT_SECRET"] = "test-secret-0123456789"
os.environ["COLLAB_JWT_ISSUER"] = "opendraft-collab"
os.environ["COLLAB_JWT_AUDIENCE"] = "opendraft-backend"
# Point at a non-existent DB so auth_service falls back to payload-only.
os.environ["COLLAB_DB_PATH"] = ""

import jwt  # noqa: E402
import httpx  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.security import HTTPAuthorizationCredentials  # noqa: E402
from starlette.requests import Request  # noqa: E402

import app.dependencies as auth_dependencies  # noqa: E402
import app.api.auth as auth_api  # noqa: E402
import app.services.auth_service as auth_service  # noqa: E402

from app.services.auth_service import (  # noqa: E402
    auth_user_from_payload,
    verify_access_token,
)


def _make_token(payload: dict) -> str:
    return jwt.encode(
        {
            "iss": "opendraft-collab",
            "aud": "opendraft-backend",
            **payload,
        },
        "test-secret-0123456789",
        algorithm="HS256",
    )


def test_valid_token():
    token = _make_token({
        "sub": "user-1",
        "email": "alice@example.com",
        "name": "Alice Writer",
        "email_verified": True,
        "type": "access",
        "exp": int(time.time()) + 60,
    })
    payload = verify_access_token(token)
    assert payload is not None, "valid token should verify"
    assert payload["sub"] == "user-1"
    user = auth_user_from_payload(payload)
    assert user.id == "user-1"
    assert user.email == "alice@example.com"
    assert user.display_name == "Alice Writer"
    assert user.email_verified is True
    print("  ok: valid token")


def test_expired_token():
    token = _make_token({
        "sub": "user-1",
        "email": "alice@example.com",
        "type": "access",
        "exp": int(time.time()) - 10,
    })
    assert verify_access_token(token) is None, "expired token should reject"
    print("  ok: expired token rejected")


def test_wrong_secret():
    token = jwt.encode(
        {
            "iss": "opendraft-collab",
            "aud": "opendraft-backend",
            "sub": "u",
            "email": "e",
            "type": "access",
            "exp": int(time.time()) + 60,
        },
        "wrong-secret",
        algorithm="HS256",
    )
    assert verify_access_token(token) is None, "wrong-secret token should reject"
    print("  ok: wrong-secret token rejected")


def test_wrong_type():
    token = _make_token({
        "sub": "u",
        "email": "e",
        "type": "refresh",  # only 'access' is accepted
        "exp": int(time.time()) + 60,
    })
    assert verify_access_token(token) is None, "refresh-typed token should reject"
    print("  ok: non-access token rejected")


def test_missing_fields():
    token = _make_token({
        "type": "access",
        "exp": int(time.time()) + 60,
    })
    assert verify_access_token(token) is None, "token missing sub/email should reject"
    print("  ok: malformed token rejected")


def test_wrong_issuer():
    token = _make_token({
        "iss": "another-service",
        "sub": "u",
        "email": "e",
        "type": "access",
        "exp": int(time.time()) + 60,
    })
    assert verify_access_token(token) is None, "wrong-issuer token should reject"
    print("  ok: wrong-issuer token rejected")


def test_wrong_audience():
    token = _make_token({
        "aud": "another-service",
        "sub": "u",
        "email": "e",
        "type": "access",
        "exp": int(time.time()) + 60,
    })
    assert verify_access_token(token) is None, "wrong-audience token should reject"
    print("  ok: wrong-audience token rejected")


def test_missing_issuer_or_audience():
    base_payload = {
        "sub": "u",
        "email": "e",
        "type": "access",
        "exp": int(time.time()) + 60,
    }
    for claim in ("iss", "aud"):
        payload = {
            "iss": "opendraft-collab",
            "aud": "opendraft-backend",
            **base_payload,
        }
        del payload[claim]
        token = jwt.encode(payload, "test-secret-0123456789", algorithm="HS256")
        assert verify_access_token(token) is None, f"token missing {claim} should reject"
    print("  ok: tokens missing issuer/audience rejected")


def test_unsigned_token():
    token = jwt.encode(
        {
            "iss": "opendraft-collab",
            "aud": "opendraft-backend",
            "sub": "u",
            "email": "e",
            "type": "access",
            "exp": int(time.time()) + 60,
        },
        key="",
        algorithm="none",
    )
    assert verify_access_token(token) is None, "unsigned token should reject"
    print("  ok: unsigned token rejected")


def test_payload_fallback_is_conservative():
    payload = {
        "sub": "user-1",
        "email": "alice@example.com",
        "name": "",
        "email_verified": "true",
    }
    user = auth_user_from_payload(payload)
    assert user.display_name == "alice@example.com"
    assert user.email_verified is False
    print("  ok: malformed fallback claims handled conservatively")


def _valid_credentials() -> HTTPAuthorizationCredentials:
    token = _make_token({
        "sub": "user-fallback",
        "email": "fallback@example.com",
        "name": "Fallback Writer",
        "email_verified": True,
        "type": "access",
        "exp": int(time.time()) + 60,
    })
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_unset_db_uses_signed_claim_fallback():
    original_dependency_path = auth_dependencies.COLLAB_DB_PATH
    original_service_path = auth_service.COLLAB_DB_PATH
    try:
        auth_dependencies.COLLAB_DB_PATH = ""
        auth_service.COLLAB_DB_PATH = ""
        user = auth_dependencies._extract_user(_valid_credentials())
        assert user is not None, "split deployment should trust verified signed claims"
        assert user.id == "user-fallback"
        assert user.display_name == "Fallback Writer"
        assert user.email_verified is True
    finally:
        auth_dependencies.COLLAB_DB_PATH = original_dependency_path
        auth_service.COLLAB_DB_PATH = original_service_path
    print("  ok: unset DB uses signed-claim fallback")


def test_configured_missing_db_fails_closed():
    original_dependency_path = auth_dependencies.COLLAB_DB_PATH
    original_service_path = auth_service.COLLAB_DB_PATH
    try:
        missing = "/tmp/opendraft-auth-test/does-not-exist.sqlite3"
        auth_dependencies.COLLAB_DB_PATH = missing
        auth_service.COLLAB_DB_PATH = missing
        assert auth_dependencies._extract_user(_valid_credentials()) is None
    finally:
        auth_dependencies.COLLAB_DB_PATH = original_dependency_path
        auth_service.COLLAB_DB_PATH = original_service_path
    print("  ok: configured missing DB fails closed")


def test_configured_unreadable_db_fails_closed():
    original_dependency_path = auth_dependencies.COLLAB_DB_PATH
    original_service_path = auth_service.COLLAB_DB_PATH
    try:
        with tempfile.NamedTemporaryFile() as invalid_db:
            invalid_db.write(b"not a sqlite database")
            invalid_db.flush()
            auth_dependencies.COLLAB_DB_PATH = invalid_db.name
            auth_service.COLLAB_DB_PATH = invalid_db.name
            assert auth_dependencies._extract_user(_valid_credentials()) is None
    finally:
        auth_dependencies.COLLAB_DB_PATH = original_dependency_path
        auth_service.COLLAB_DB_PATH = original_service_path
    print("  ok: configured unreadable DB fails closed")


def test_auth_proxy_forwards_browser_device_context():
    assert "user-agent" in auth_api._FORWARD_REQUEST_HEADERS
    assert "x-device-id" in auth_api._FORWARD_REQUEST_HEADERS
    print("  ok: auth proxy forwards browser device context")


def _make_request(
    *,
    method: str = "GET",
    query: bytes = b"",
    headers: list[tuple[bytes, bytes]] | None = None,
    body: bytes = b"",
) -> Request:
    delivered = False

    async def receive():
        nonlocal delivered
        if delivered:
            return {"type": "http.disconnect"}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "https",
            "path": "/api/auth/oidc/callback",
            "raw_path": b"/api/auth/oidc/callback",
            "query_string": query,
            "root_path": "",
            "headers": headers or [],
            "client": ("203.0.113.17", 43210),
            "server": ("scripts.example.test", 443),
        },
        receive,
    )


def _run_proxy_with_response(
    request: Request,
    upstream: httpx.Response,
    path: str = "oidc/callback",
):
    captured = {}

    class FakeAsyncClient:
        def __init__(self, **kwargs):
            captured["client_kwargs"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def request(self, method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return upstream

    original_client = auth_api.httpx.AsyncClient
    auth_api.httpx.AsyncClient = FakeAsyncClient
    try:
        response = asyncio.run(auth_api._proxy(request, request.method, path))
    finally:
        auth_api.httpx.AsyncClient = original_client
    return response, captured


def test_oidc_proxy_preserves_query_cookie_redirect_and_set_cookie_headers():
    query = b"code=a%2Fb&state=x+y&scope=openid&scope=email"
    request = _make_request(
        query=query,
        headers=[
            (b"cookie", b"opendraft_oidc_state=state-cookie"),
            (b"user-agent", b"OpenDraft proxy test"),
            (b"x-not-forwarded", b"internal-value"),
        ],
    )
    cookies = [
        "opendraft_oidc_state=; Path=/api/auth/oidc; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
        "opendraft_oidc_flow=next; Path=/api/auth/oidc; HttpOnly; Secure; SameSite=Lax",
    ]
    upstream = httpx.Response(
        302,
        headers=[
            ("location", "https://scripts.example.test/auth/callback?handoff=one-time"),
            ("set-cookie", cookies[0]),
            ("set-cookie", cookies[1]),
            ("connection", "keep-alive"),
            ("content-type", "text/plain"),
        ],
        content=b"redirecting",
    )

    response, captured = _run_proxy_with_response(request, upstream)

    assert captured["method"] == "GET"
    assert captured["url"].query == query
    assert captured["headers"]["cookie"] == "opendraft_oidc_state=state-cookie"
    assert captured["headers"]["user-agent"] == "OpenDraft proxy test"
    assert captured["headers"]["x-forwarded-for"] == "203.0.113.17"
    assert "x-not-forwarded" not in captured["headers"]
    assert captured["follow_redirects"] is False
    assert response.status_code == 302
    assert response.headers["location"] == (
        "https://scripts.example.test/auth/callback?handoff=one-time"
    )
    assert response.headers.getlist("set-cookie") == cookies
    assert "connection" not in response.headers
    assert response.body == b"redirecting"
    print("  ok: OIDC proxy preserves query, cookies, and redirect response")


def test_auth_proxy_rejects_non_web_redirects():
    for location in (
        "javascript:alert(document.domain)",
        "data:text/html,unsafe",
        "//attacker.example/redirect",
        "////attacker.example/redirect",
        "\\\\attacker.example\\redirect",
        "/\\attacker.example/redirect",
        "https://user:password@safe.example/redirect",
        "https://safe.example/\nunsafe",
    ):
        request = _make_request()
        upstream = httpx.Response(302, headers={"location": location})
        try:
            _run_proxy_with_response(request, upstream)
        except HTTPException as exc:
            assert exc.status_code == 502
        else:
            raise AssertionError(f"unsafe redirect was forwarded: {location!r}")
    print("  ok: auth proxy rejects non-web redirects")


def test_oidc_link_start_forwards_authenticated_browser_context():
    body = b'{"returnTo":"/settings"}'
    request = _make_request(
        method="POST",
        headers=[
            (b"authorization", b"Bearer opendraft-access-token"),
            (b"content-type", b"application/json"),
            (b"cookie", b"existing_session=context"),
            (b"user-agent", b"OpenDraft link test"),
            (b"x-device-id", b"browser-device-1"),
        ],
        body=body,
    )
    state_cookie = (
        "opendraft_oidc_state=link-state; Path=/api/auth/oidc; "
        "HttpOnly; Secure; SameSite=Lax"
    )
    upstream = httpx.Response(
        200,
        headers=[("content-type", "application/json"), ("set-cookie", state_cookie)],
        content=b'{"authorizationUrl":"https://auth.example/authorize"}',
    )

    response, captured = _run_proxy_with_response(
        request,
        upstream,
        "oidc/link/start",
    )

    assert captured["method"] == "POST"
    assert str(captured["url"]).endswith("/auth/oidc/link/start")
    assert captured["content"] == body
    assert captured["headers"]["authorization"] == "Bearer opendraft-access-token"
    assert captured["headers"]["content-type"] == "application/json"
    assert captured["headers"]["cookie"] == "existing_session=context"
    assert captured["headers"]["user-agent"] == "OpenDraft link test"
    assert captured["headers"]["x-device-id"] == "browser-device-1"
    assert response.status_code == 200
    assert response.headers.getlist("set-cookie") == [state_cookie]
    print("  ok: OIDC account linking preserves auth and browser context")


def test_oidc_routes_proxy_only_fixed_identity_paths():
    calls = []
    sentinel = object()

    async def fake_proxy(request, method, path):
        calls.append((request, method, path))
        return sentinel

    original_proxy = auth_api._proxy
    auth_api._proxy = fake_proxy
    requests = [object(), object(), object(), object()]
    user = auth_service.AuthUser(
        id="user-1",
        email="alice@example.com",
        display_name="Alice",
        email_verified=True,
    )
    try:
        assert asyncio.run(auth_api.oidc_start(requests[0])) is sentinel
        assert asyncio.run(auth_api.oidc_callback(requests[1])) is sentinel
        assert asyncio.run(auth_api.oidc_exchange(requests[2])) is sentinel
        assert asyncio.run(auth_api.oidc_link_start(requests[3], user)) is sentinel
    finally:
        auth_api._proxy = original_proxy

    assert calls == [
        (requests[0], "GET", "oidc/start"),
        (requests[1], "GET", "oidc/callback"),
        (requests[2], "POST", "oidc/exchange"),
        (requests[3], "POST", "oidc/link/start"),
    ]
    print("  ok: OIDC routes proxy only fixed identity-service paths")


def test_me_proxies_authoritative_user_state():
    calls = []
    sentinel = object()

    async def fake_proxy(request, method, path):
        calls.append((request, method, path))
        return sentinel

    original_proxy = auth_api._proxy
    auth_api._proxy = fake_proxy
    try:
        result = asyncio.run(auth_api.me(object(), auth_service.AuthUser(
            id="user-1",
            email="alice@example.com",
            display_name="Alice",
            email_verified=True,
        )))
    finally:
        auth_api._proxy = original_proxy
    assert result is sentinel
    assert calls == [(calls[0][0], "GET", "me")]
    print("  ok: /me proxies authoritative identity-provider state")

if __name__ == "__main__":
    print("Running backend auth JWT tests…")
    test_valid_token()
    test_expired_token()
    test_wrong_secret()
    test_wrong_type()
    test_missing_fields()
    test_wrong_issuer()
    test_wrong_audience()
    test_missing_issuer_or_audience()
    test_unsigned_token()
    test_payload_fallback_is_conservative()
    test_unset_db_uses_signed_claim_fallback()
    test_configured_missing_db_fails_closed()
    test_configured_unreadable_db_fails_closed()
    test_me_proxies_authoritative_user_state()
    test_auth_proxy_forwards_browser_device_context()
    test_oidc_proxy_preserves_query_cookie_redirect_and_set_cookie_headers()
    test_auth_proxy_rejects_non_web_redirects()
    test_oidc_link_start_forwards_authenticated_browser_context()
    test_oidc_routes_proxy_only_fixed_identity_paths()
    print("All tests passed.")
