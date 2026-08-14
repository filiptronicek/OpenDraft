"""Auth routes — thin proxy to the collab server (identity provider).

The collab server owns user registration, OTP email verification, password
login, refresh tokens, and Google OAuth. Backend proxies writes to it and
proxies current-user state back to the identity provider.

Rationale: a single host (backend) serves the frontend; the frontend doesn't
need to know about the collab server URL for auth. The /api/auth/me route uses
the same authoritative user record as login and settings, including 2FA
state.
"""

from __future__ import annotations

import logging
import shutil

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.config import COLLAB_SERVER_URL, PROJECTS_DIR_BASE, _safe_user_id
from app.dependencies import require_user
from app.services.auth_service import AuthUser

logger = logging.getLogger(__name__)

router = APIRouter()

# Preserve authentication, content negotiation, and browser device context.
# The collab server uses x-device-id for the current-device flag and User-Agent
# for new-device records and security notices.
_FORWARD_REQUEST_HEADERS = {
    "authorization", "content-type", "accept", "accept-language", "x-device-id", "user-agent",
}

# Headers to forward back from collab to the client (skip hop-by-hop).
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-encoding",
    "content-length",
}


async def _proxy(
    request: Request,
    method: str,
    path: str,
) -> Response:
    url = f"{COLLAB_SERVER_URL}/auth/{path}"
    forward_headers = {
        k: v for k, v in request.headers.items() if k.lower() in _FORWARD_REQUEST_HEADERS
    }
    # Preserve client IP for the collab audit log.
    if request.client and request.client.host:
        forward_headers["x-forwarded-for"] = request.client.host

    body = await request.body()

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            upstream = await client.request(
                method,
                url,
                content=body if body else None,
                headers=forward_headers,
            )
    except httpx.TimeoutException:
        logger.warning("Collab server timeout on %s %s", method, url)
        raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail="Auth server timeout")
    except httpx.RequestError as exc:
        logger.error("Collab server unreachable at %s: %s", url, exc)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Auth server unavailable")

    resp_headers = {
        k: v for k, v in upstream.headers.items() if k.lower() not in _HOP_BY_HOP
    }
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=resp_headers,
        media_type=upstream.headers.get("content-type"),
    )


@router.post("/register")
async def register(request: Request) -> Response:
    return await _proxy(request, "POST", "register")


@router.post("/login")
async def login(request: Request) -> Response:
    return await _proxy(request, "POST", "login")


@router.post("/verify-email")
async def verify_email(request: Request) -> Response:
    return await _proxy(request, "POST", "verify-email")


@router.post("/verify-email-link")
async def verify_email_link(request: Request) -> Response:
    """Unauthenticated magic-link verification: {email, code} → tokens."""
    return await _proxy(request, "POST", "verify-email-link")


@router.post("/resend-verification")
async def resend_verification(request: Request) -> Response:
    return await _proxy(request, "POST", "resend-verification")


@router.post("/refresh")
async def refresh(request: Request) -> Response:
    return await _proxy(request, "POST", "refresh")


@router.post("/logout")
async def logout(request: Request) -> Response:
    return await _proxy(request, "POST", "logout")


@router.post("/google")
async def google_login(request: Request) -> Response:
    return await _proxy(request, "POST", "google")


@router.get("/config")
async def config_route(request: Request) -> Response:
    return await _proxy(request, "GET", "config")


@router.get("/me")
async def me(
    request: Request,
    _user: AuthUser = Depends(require_user),
) -> Response:
    """Return the identity provider authoritative current user state."""
    return await _proxy(request, "GET", "me")


@router.post("/verify-device")
async def verify_device(request: Request) -> Response:
    """Confirm a new-device 2FA challenge with the emailed 6-digit code."""
    return await _proxy(request, "POST", "verify-device")


@router.post("/resend-device-challenge")
async def resend_device_challenge(request: Request) -> Response:
    """Re-issue a fresh new-device 2FA code for an existing pending challenge."""
    return await _proxy(request, "POST", "resend-device-challenge")


@router.post("/change-password")
async def change_password(request: Request) -> Response:
    return await _proxy(request, "POST", "change-password")


@router.post("/forgot-password")
async def forgot_password(request: Request) -> Response:
    """Request a password-reset email. Always returns a generic message so
    callers can't enumerate registered email addresses."""
    return await _proxy(request, "POST", "forgot-password")


@router.post("/reset-password")
async def reset_password(request: Request) -> Response:
    """Consume a reset token + set the new password."""
    return await _proxy(request, "POST", "reset-password")


@router.post("/two-factor")
async def toggle_two_factor(request: Request) -> Response:
    return await _proxy(request, "POST", "two-factor")


@router.get("/devices")
async def list_devices(request: Request) -> Response:
    return await _proxy(request, "GET", "devices")


@router.delete("/devices/{device_id}")
async def revoke_device(device_id: str, request: Request) -> Response:
    # device_id is opaque from the backend's perspective; the collab server
    # validates ownership against the bearer token.
    return await _proxy(request, "DELETE", f"devices/{device_id}")


def _wipe_user_projects(user_id: str) -> None:
    """Remove every screenplay/project owned by user_id from the on-disk store.

    This is the local Python backend's portion of account deletion — the
    collab server tears down the auth record, and this function tears down
    the per-user projects directory under <PROJECTS_DIR_BASE>/users/<id>/.
    Best-effort: failures are logged but do not block deletion.
    """
    try:
        safe_id = _safe_user_id(user_id)
        user_dir = PROJECTS_DIR_BASE / "users" / safe_id
        if user_dir.exists():
            shutil.rmtree(user_dir)
            logger.info("Wiped user projects directory: %s", user_dir)
    except Exception as exc:  # noqa: BLE001 — never block account deletion on cleanup
        logger.warning("Failed to wipe user projects for %s: %s", user_id, exc)


@router.delete("/account")
async def delete_account(
    request: Request,
    user: AuthUser = Depends(require_user),
) -> Response:
    """Permanently delete the authenticated user's account.

    Apple App Store Guideline 5.1.1(v) requires apps that support account
    creation to also offer account deletion. We:

      1. Delegate auth-side deletion to the collab server (proxied below).
         It validates the password / typed confirmation, removes the user,
         their refresh tokens, devices, and email verifications, and records
         an audit event.
      2. On success, also wipe this user's locally-stored cloud projects so
         no screenplay data lingers in the per-user data directory.

    The frontend is expected to first prompt the user to download any cloud
    screenplays — once we return 200 there is no recovery path.
    """
    response = await _proxy(request, "DELETE", "account")
    if 200 <= response.status_code < 300:
        _wipe_user_projects(user.id)
    return response
