"""Fetch Open Graph / HTML metadata for a URL to generate link previews."""

import asyncio
import html
import http.client
import ipaddress
import logging
import re
import socket
import time
from urllib.parse import quote, urljoin, urlparse, urlunparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.dependencies import require_verified_user

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_verified_user)])

_TIMEOUT = 5  # seconds
_MAX_BYTES = 256_000  # only read first ~256 KB of the page
_MAX_REDIRECTS = 3
_MAX_URL_LENGTH = 4096
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_HTML_CONTENT_TYPES = ("text/html", "application/xhtml")
_UA = "Mozilla/5.0 (compatible; OpenDraft/1.0; +https://opendraft.dev)"


def _validate_url(url: str) -> tuple[str, str]:
    """Resolve a public HTTP(S) target and return an IP-pinned URL + hostname."""
    if not url or len(url) > _MAX_URL_LENGTH:
        raise HTTPException(status_code=400, detail="Invalid URL")

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://",
        )
    if parsed.username is not None or parsed.password is not None:
        raise HTTPException(status_code=400, detail="URL credentials are not allowed")

    try:
        parsed_port = parsed.port
        if parsed_port == 0:
            raise ValueError("Port must be between 1 and 65535")
        port = parsed_port or (443 if parsed.scheme == "https" else 80)
        original_host = parsed.hostname.encode("idna").decode("ascii")
        addr_infos = socket.getaddrinfo(
            original_host,
            port,
            type=socket.SOCK_STREAM,
        )
    except (socket.gaierror, UnicodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Could not resolve hostname") from exc
    if not addr_infos:
        raise HTTPException(status_code=400, detail="Could not resolve hostname")

    resolved_ips = []
    for _family, _type, _proto, _canonname, sockaddr in addr_infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail="Hostname resolved to an invalid address",
            ) from exc
        if ip.is_multicast or not ip.is_global:
            raise HTTPException(
                status_code=400,
                detail="URL points to a restricted address",
            )
        resolved_ips.append(ip)

    # Pin one validated answer for the TCP connection. Every answer must be
    # global so DNS round-robin cannot smuggle a private fallback.
    selected_ip = resolved_ips[0]
    netloc = f"[{selected_ip}]" if selected_ip.version == 6 else str(selected_ip)
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    safe_url = urlunparse(
        (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, "")
    )
    return safe_url, original_host


def _request_target(safe_url: str) -> str:
    parsed = urlparse(safe_url)
    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    if parsed.params:
        path += ";" + quote(parsed.params, safe="%:@!$&'()*+,;=-._~")
    if parsed.query:
        path += "?" + quote(parsed.query, safe="=&?/:;+,%@!$'()*-._~")
    return path


def _host_header(hostname: str, port: int, scheme: str) -> str:
    try:
        is_ipv6 = isinstance(ipaddress.ip_address(hostname), ipaddress.IPv6Address)
    except ValueError:
        is_ipv6 = False
    host = f"[{hostname}]" if is_ipv6 else hostname
    default_port = 443 if scheme == "https" else 80
    return f"{host}:{port}" if port != default_port else host


def _open_once(
    safe_url: str,
    original_host: str,
    timeout: float,
) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse]:
    """Open one IP-pinned hop while retaining original TLS SNI verification."""
    parsed = urlparse(safe_url)
    resolved_ip = parsed.hostname
    if resolved_ip is None:
        raise ValueError("Pinned URL has no address")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    connection_class = (
        http.client.HTTPSConnection
        if parsed.scheme == "https"
        else http.client.HTTPConnection
    )
    connection = connection_class(original_host, port=port, timeout=timeout)

    def _pinned_create_connection(_address, connect_timeout, source_address):
        return socket.create_connection(
            (resolved_ip, port),
            connect_timeout,
            source_address,
        )

    # self.host remains the original hostname for TLS SNI/certificate checks;
    # only the underlying socket destination is replaced with the validated IP.
    connection._create_connection = _pinned_create_connection  # type: ignore[attr-defined]  # noqa: SLF001
    headers = {
        "User-Agent": _UA,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Encoding": "identity",
        "Host": _host_header(original_host, port, parsed.scheme),
    }
    try:
        connection.request("GET", _request_target(safe_url), headers=headers)
        return connection, connection.getresponse()
    except Exception:
        connection.close()
        raise


def _fetch_page(url: str) -> tuple[bytes, str, str]:
    """Fetch bounded HTML while validating and pinning every redirect hop."""
    deadline = time.monotonic() + _TIMEOUT
    current_url = url
    seen: set[str] = set()

    for redirect_count in range(_MAX_REDIRECTS + 1):
        if current_url in seen:
            raise HTTPException(status_code=502, detail="Redirect loop detected")
        seen.add(current_url)

        safe_url, original_host = _validate_url(current_url)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise HTTPException(status_code=502, detail="Link preview request timed out")

        connection = None
        response = None
        try:
            connection, response = _open_once(safe_url, original_host, remaining)
            if response.status in _REDIRECT_STATUSES:
                location = response.headers.get("Location")
                if not location or redirect_count >= _MAX_REDIRECTS:
                    raise HTTPException(
                        status_code=502,
                        detail="Too many or invalid redirects",
                    )
                current_url = urljoin(current_url, location.strip())
                continue
            if response.status >= 400:
                raise HTTPException(
                    status_code=502,
                    detail="Could not fetch the requested URL",
                )

            content_type = response.headers.get("Content-Type", "")
            if not any(kind in content_type.lower() for kind in _HTML_CONTENT_TYPES):
                raise HTTPException(status_code=422, detail="URL is not an HTML page")
            raw = response.read(_MAX_BYTES + 1)
            if len(raw) > _MAX_BYTES:
                raise HTTPException(status_code=413, detail="HTML page is too large")
            return raw, content_type, current_url
        except HTTPException:
            raise
        except (
            http.client.HTTPException,
            OSError,
            TimeoutError,
            UnicodeError,
            ValueError,
        ) as exc:
            logger.warning("Link preview fetch failed: %s", exc)
            raise HTTPException(
                status_code=502,
                detail="Could not fetch the requested URL",
            ) from exc
        finally:
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()

    raise HTTPException(status_code=502, detail="Too many redirects")


class LinkPreviewRequest(BaseModel):
    url: str


class LinkPreviewResponse(BaseModel):
    url: str
    title: str
    description: str
    image: str
    site_name: str


def _meta(body: str, prop: str) -> str:
    """Extract a meta tag value by property or name."""
    # property="og:..."
    m = re.search(
        rf'<meta[^>]+(?:property|name)\s*=\s*["\']?{re.escape(prop)}["\']?[^>]+content\s*=\s*["\']([^"\']*)["\']',
        body,
        re.IGNORECASE,
    )
    if m:
        return html.unescape(m.group(1)).strip()
    # content comes before property (reversed order)
    m = re.search(
        rf'<meta[^>]+content\s*=\s*["\']([^"\']*)["\'][^>]+(?:property|name)\s*=\s*["\']?{re.escape(prop)}["\']?',
        body,
        re.IGNORECASE,
    )
    if m:
        return html.unescape(m.group(1)).strip()
    return ""


def _title(body: str) -> str:
    m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
    return html.unescape(m.group(1)).strip() if m else ""


def _build_preview(url: str) -> LinkPreviewResponse:
    raw, content_type, final_url = _fetch_page(url)

    charset = "utf-8"
    lowered_content_type = content_type.lower()
    if "charset=" in lowered_content_type:
        charset = lowered_content_type.split("charset=")[-1].split(";")[0].strip()
    try:
        page = raw.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        page = raw.decode("utf-8", errors="replace")

    og_title = _meta(page, "og:title") or _title(page)
    og_desc = _meta(page, "og:description") or _meta(page, "description")
    og_site = _meta(page, "og:site_name")

    return LinkPreviewResponse(
        url=final_url,
        title=og_title[:300],
        description=og_desc[:500],
        image="",
        site_name=og_site[:100],
    )


@router.post("/preview", response_model=LinkPreviewResponse)
async def fetch_link_preview(body: LinkPreviewRequest):
    """Build a preview without running DNS, sockets, or parsing on the event loop."""
    url = body.url.strip()
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_build_preview, url),
            timeout=_TIMEOUT + 1,
        )
    except TimeoutError as exc:
        raise HTTPException(
            status_code=502,
            detail="Link preview request timed out",
        ) from exc
