"""Focused security tests for the link-preview fetcher."""

from __future__ import annotations

import asyncio
import socket
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.api import link_preview  # noqa: E402


def address_info(ip):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sockaddr = (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


def expect_http_status(status, function, *args):
    try:
        function(*args)
    except HTTPException as exc:
        assert exc.status_code == status, exc
        return
    raise AssertionError(f"expected HTTP {status}")


def test_global_address_policy():
    original = link_preview.socket.getaddrinfo
    try:
        link_preview.socket.getaddrinfo = lambda *_args, **_kwargs: [
            address_info("8.8.8.8")
        ]
        safe_url, hostname = link_preview._validate_url(
            "https://example.test/path?q=1"
        )
        assert safe_url == "https://8.8.8.8/path?q=1"
        assert hostname == "example.test"

        for answers in (
            [address_info("127.0.0.1")],
            [address_info("100.64.0.1")],
            [address_info("224.0.0.1")],
            [address_info("ff02::1")],
            [address_info("8.8.8.8"), address_info("192.168.1.2")],
        ):
            link_preview.socket.getaddrinfo = (
                lambda *_args, _answers=answers, **_kwargs: _answers
            )
            expect_http_status(
                400,
                link_preview._validate_url,
                "https://example.test/",
            )
        expect_http_status(
            400,
            link_preview._validate_url,
            "https://user:pass@example.test/",
        )
    finally:
        link_preview.socket.getaddrinfo = original
    print("  ok: only all-global DNS answers are accepted")


class FakeConnection:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = headers or {}
        self.body = body
        self.closed = False
        self.requested = None

    def read(self, size):
        self.requested = size
        return self.body

    def close(self):
        self.closed = True


def test_redirect_revalidation_and_body_limit():
    original_dns = link_preview.socket.getaddrinfo
    original_open = link_preview._open_once
    calls = []

    def fake_dns(host, *_args, **_kwargs):
        ip = "127.0.0.1" if host == "private.test" else "8.8.8.8"
        return [address_info(ip)]

    def redirect_once(safe_url, original_host, timeout):
        calls.append((safe_url, original_host, timeout))
        return FakeConnection(), FakeResponse(
            status=302,
            headers={"Location": "http://private.test/admin"},
        )

    try:
        link_preview.socket.getaddrinfo = fake_dns
        link_preview._open_once = redirect_once
        expect_http_status(
            400,
            link_preview._fetch_page,
            "https://public.test/start",
        )
        assert len(calls) == 1

        oversized = FakeResponse(
            headers={"Content-Type": "text/html"},
            body=b"x" * (link_preview._MAX_BYTES + 1),
        )
        link_preview._open_once = (
            lambda *_args: (FakeConnection(), oversized)
        )
        expect_http_status(
            413,
            link_preview._fetch_page,
            "https://public.test/large",
        )
        assert oversized.requested == link_preview._MAX_BYTES + 1
    finally:
        link_preview.socket.getaddrinfo = original_dns
        link_preview._open_once = original_open
    print("  ok: redirects are revalidated and response bodies are bounded")


def test_https_uses_original_sni_and_pinned_ip():
    original_https = link_preview.http.client.HTTPSConnection
    original_create = link_preview.socket.create_connection
    captured = {}

    class FakeHTTPSConnection:
        def __init__(self, host, port, timeout):
            captured["constructor"] = (host, port, timeout)
            self._create_connection = None
            self.closed = False

        def request(self, method, target, headers):
            captured["request"] = (method, target, headers)
            self._create_connection(("ignored", 443), 2.5, None)

        def getresponse(self):
            return FakeResponse(headers={"Content-Type": "text/html"})

        def close(self):
            self.closed = True

    def fake_create_connection(address, timeout, source_address):
        captured["socket"] = (address, timeout, source_address)
        return object()

    try:
        link_preview.http.client.HTTPSConnection = FakeHTTPSConnection
        link_preview.socket.create_connection = fake_create_connection
        connection, response = link_preview._open_once(
            "https://8.8.8.8/path?q=1",
            "example.test",
            2.5,
        )
        assert captured["constructor"] == ("example.test", 443, 2.5)
        assert captured["socket"][0] == ("8.8.8.8", 443)
        assert captured["request"][1] == "/path?q=1"
        assert captured["request"][2]["Host"] == "example.test"
        response.close()
        connection.close()
    finally:
        link_preview.http.client.HTTPSConnection = original_https
        link_preview.socket.create_connection = original_create
    print("  ok: HTTPS retains original host/SNI while TCP uses the pinned IP")


def test_verified_auth_and_thread_offload():
    app = FastAPI()
    app.include_router(link_preview.router, prefix="/link")
    response = TestClient(app).post(
        "/link/preview",
        json={"url": "https://example.test"},
    )
    assert response.status_code == 401, response.text

    original_builder = link_preview._build_preview
    caller_thread = threading.get_ident()
    worker_threads = []

    def fake_builder(url):
        worker_threads.append(threading.get_ident())
        return link_preview.LinkPreviewResponse(
            url=url,
            title="Title",
            description="",
            image="",
            site_name="",
        )

    try:
        link_preview._build_preview = fake_builder
        result = asyncio.run(
            link_preview.fetch_link_preview(
                link_preview.LinkPreviewRequest(url="https://example.test")
            )
        )
        assert result.title == "Title"
        assert worker_threads and worker_threads[0] != caller_thread
    finally:
        link_preview._build_preview = original_builder
    print("  ok: route requires verified auth and blocking work runs off-loop")


def test_preview_uses_validated_final_url_and_drops_remote_images():
    original_fetch = link_preview._fetch_page
    page = b"""<html><head>
        <meta property="og:title" content="Redirected">
        <meta property="og:image" content="https://tracking.test/pixel.png">
        </head></html>"""

    try:
        link_preview._fetch_page = lambda _url: (
            page,
            "text/html; charset=utf-8",
            "https://final.example.test/article",
        )
        preview = link_preview._build_preview("https://start.example.test/")
        assert preview.url == "https://final.example.test/article"
        assert preview.title == "Redirected"
        assert preview.image == ""
    finally:
        link_preview._fetch_page = original_fetch
    print("  ok: previews use the validated final URL and omit remote images")


if __name__ == "__main__":
    print("Running link-preview security tests…")
    test_global_address_policy()
    test_redirect_revalidation_and_body_limit()
    test_https_uses_original_sni_and_pinned_ip()
    test_preview_uses_validated_final_url_and_drops_remote_images()
    test_verified_auth_and_thread_offload()
    print("All tests passed.")
