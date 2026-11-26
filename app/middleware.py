"""Bound resource use and serve the dashboard under a same-origin CSP."""

import asyncio
import time
from collections import OrderedDict, deque
from urllib.parse import urlsplit

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse

MAX_JSON_BYTES = 128 * 1024
MAX_CLIENTS = 4096
SCAN_POSTS = {
    "/api/v1/scan", "/api/v1/email-scan", "/api/v1/html-scan", "/api/v1/bulk-scan",
    "/email-scan", "/bulk-scan", "/cli", "/api/v1/hash-lookup",
}
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'self'; object-src 'none'"
)


class WorkbenchMiddleware:
    def __init__(self, app):
        self.app = app
        self.buckets: OrderedDict[str, deque] = OrderedDict()

    def permit(self, client: str, cost: int) -> bool:
        now = time.monotonic()
        bucket = self.buckets.pop(client, deque())
        while bucket and now - bucket[0] >= 60:
            bucket.popleft()
        self.buckets[client] = bucket
        if len(self.buckets) > MAX_CLIENTS:
            self.buckets.popitem(last=False)
        if len(bucket) + cost > 30:
            return False
        bucket.extend([now] * cost)
        return True

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_secured(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Content-Security-Policy"] = CSP
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
                if scope["scheme"] == "https":
                    headers["Strict-Transport-Security"] = "max-age=31536000"
                if scope["path"].startswith("/api/") or scope["path"] in SCAN_POSTS:
                    headers["Cache-Control"] = "no-store"
            await send(message)

        async def deny(status, detail, headers=None):
            await JSONResponse({"detail": detail}, status_code=status, headers=headers)(scope, receive, send_secured)

        path = scope["path"].rstrip("/") or "/"
        method = scope["method"]
        is_scan = path in SCAN_POSTS and (method == "POST" or path == "/cli" and method == "GET")
        if not is_scan:
            await self.app(scope, receive, send_secured)
            return

        key = scope["client"][0] if scope.get("client") else "unknown"
        if not self.permit(key, 8 if "bulk-scan" in path else 1):
            await deny(429, "Scan limit reached. Try again in one minute.", {"Retry-After": "60"})
            return
        if method != "POST":
            await self.app(scope, receive, send_secured)
            return

        headers = Headers(scope=scope)
        origin = headers.get("origin")
        if headers.get("sec-fetch-site") == "cross-site":
            await deny(403, "Cross-site scan requests are disabled.")
            return
        if origin:
            try:
                parts = urlsplit(origin)
                same_host = parts.netloc.lower() == headers.get("host", "").lower()
                if not same_host or parts.scheme not in {"https", "http"}:
                    raise ValueError()
            except ValueError:
                await deny(403, "Cross-site scan requests are disabled.")
                return
        if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            await deny(415, "Send application/json.")
            return
        if headers.get("content-encoding", "identity").lower() != "identity":
            await deny(415, "Compressed request bodies are disabled.")
            return
        length = headers.get("content-length")
        if length is not None and (not length.isascii() or not length.isdecimal() or len(length) > 10):
            await deny(400, "Invalid Content-Length.")
            return
        if length is not None and int(length) > MAX_JSON_BYTES:
            await deny(413, "Request body exceeds 128 KiB.")
            return

        body = bytearray()
        try:
            async with asyncio.timeout(5):
                while True:
                    event = await receive()
                    if event["type"] == "http.disconnect":
                        return
                    chunk = event.get("body", b"")
                    if len(body) + len(chunk) > MAX_JSON_BYTES:
                        await deny(413, "Request body exceeds 128 KiB.")
                        return
                    body.extend(chunk)
                    if not event.get("more_body"):
                        break
        except TimeoutError:
            await deny(408, "Request body took too long.")
            return

        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send_secured)
