"""A mitmproxy addon that writes what an app sends, one JSON object per line.

    mitmdump -s mitm_log_addon.py            (the log goes to $MITM_LOG, default decrypted.jsonl)

For every completed exchange: when, the method and the full URL (the query string is often the
point: a search term, a location), the request headers' NAMES, the values of a few harmless ones,
and the start of the body if it is text. `Authorization`, `Cookie` and similar values are never
written, only that they were present. A client that did not accept the proxy's certificate is
logged as a `tls_failed` event, which is how certificate pinning shows up: an app that pins
refuses the CA and the proxy sees a handshake that never completes.

No mitmproxy import: the hooks only use attributes of the objects mitmproxy hands them, which
keeps this testable without it.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

MAX_BODY_CHARS = 2048
SAFE_HEADER_VALUES = frozenset(
    {"host", "user-agent", "content-type", "content-length", "accept", "accept-language"}
)
SECRET_HEADERS = frozenset(
    {"authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token"}
)
TEXTUAL = ("text/", "application/json", "application/x-www-form-urlencoded", "application/xml")


def describe_request(flow: Any) -> dict[str, Any]:
    request = flow.request
    headers = list(request.headers.items())
    content_type = (request.headers.get("content-type") or "").lower()
    body: str | None = None
    raw = request.content or b""
    if raw and content_type.startswith(TEXTUAL):
        body = raw[: MAX_BODY_CHARS * 4].decode("utf-8", "replace")[:MAX_BODY_CHARS]
    record: dict[str, Any] = {
        "event": "request",
        "ts": getattr(request, "timestamp_start", None) or time.time(),
        "method": request.method,
        "url": request.pretty_url,
        "header_names": sorted({name.lower() for name, _ in headers}),
        "headers": {
            name.lower(): value for name, value in headers if name.lower() in SAFE_HEADER_VALUES
        },
        "secret_headers_present": sorted(
            {name.lower() for name, _ in headers if name.lower() in SECRET_HEADERS}
        ),
        "body_bytes": len(raw),
    }
    if body is not None:
        record["body"] = body
    response = getattr(flow, "response", None)
    if response is not None:
        record["status"] = response.status_code
    return record


def describe_tls_failure(data: Any) -> dict[str, Any]:
    context = getattr(data, "context", None)
    conn = getattr(data, "conn", None) or getattr(context, "client", None)
    return {
        "event": "tls_failed",
        "ts": time.time(),
        "sni": getattr(conn, "sni", None),
        "error": str(getattr(conn, "error", None) or getattr(data, "error", None) or "unknown"),
    }


class Logger:
    def __init__(self, path: str | None = None) -> None:
        self.path = path or os.environ.get("MITM_LOG", "decrypted.jsonl")

    def _write(self, record: dict[str, Any]) -> None:
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def response(self, flow: Any) -> None:
        self._write(describe_request(flow))

    def tls_failed_client(self, data: Any) -> None:
        self._write(describe_tls_failure(data))


addons = [Logger()]
