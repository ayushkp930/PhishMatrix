"""Bounded, verified HTTPS transport for threat-intelligence providers."""

import asyncio
import json

import httpx

MAX_PROVIDER_BYTES = 512 * 1024


async def request_body(client: httpx.AsyncClient, method: str, endpoint: str, **kwargs) -> tuple[int, bytes]:
    if not endpoint.startswith("https://"):
        raise ValueError("Provider connections require HTTPS.")
    headers = {"Accept": "application/json", "Accept-Encoding": "identity", **kwargs.pop("headers", {})}
    async with asyncio.timeout(4.0):
        async with client.stream(method, endpoint, headers=headers, follow_redirects=False, **kwargs) as response:
            if not response.is_success:
                return response.status_code, b""
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                raise ValueError("Unexpected provider response encoding.")
            body = bytearray()
            async for part in response.aiter_bytes(16384):
                body.extend(part)
                if len(body) > MAX_PROVIDER_BYTES:
                    raise ValueError("Provider response exceeds size limit.")
    return response.status_code, bytes(body)


async def request_json(client: httpx.AsyncClient, method: str, endpoint: str, *, expected=dict, **kwargs):
    status, body = await request_body(client, method, endpoint, **kwargs)
    if not 200 <= status < 300:
        return status, expected()
    try:
        data = json.loads(body)
    except RecursionError:
        raise ValueError("Provider JSON nesting exceeds the parser limit.") from None
    if not isinstance(data, expected):
        raise ValueError("Unexpected provider response type.")
    return status, data


def failure(status: int) -> str:
    return {401: "Auth rejected", 403: "Access denied", 429: "Rate limited"}.get(status, "Unavailable")


def provider(status: str, *, scope: str, **data) -> dict:
    return {"status": status, "scope": scope, **data}

async def bounded_lookup(operation, fallback, *, seconds=5):
    """Isolate optional enrichment failures. Cancellation from the caller still propagates."""
    try:
        async with asyncio.timeout(seconds):
            return await operation
    except Exception:
        # Exception messages from HTTP clients can contain credential-bearing URLs.
        return fallback
