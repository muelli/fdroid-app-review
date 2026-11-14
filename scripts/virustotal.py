"""VirusTotal results for an APK, for the reviewer guide's "All or most vendors on VirusTotal
or similar scanning services indicate the app is benign".

Needs a VirusTotal API key (a free account has one), read from the environment, never from
an argument (an argument shows in `ps`). The key is sent only to the API base URL. A lookup
by hash comes first and uploads nothing; uploading the file is a separate, explicit step.
No key-free route exists: the transfer service's `/virustotal` route and MetaDefender both
failed or refused without one when tried.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

KEY_ENV_VAR = "VT_API_KEY"
API_BASE = "https://www.virustotal.com/api/v3"
# The API's own limit for a plain upload; larger files go to a special upload URL it hands out.
MAX_UPLOAD_BYTES = 32 * 1024 * 1024
# Our own ceiling for those: the file is read into memory to build the request.
MAX_BIG_UPLOAD_BYTES = 200 * 1024 * 1024
# A free key allows 4 requests a minute.
POLL_SECONDS = 16.0
MAX_WAIT_SECONDS = 300.0


class VirusTotalError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class VtResult:
    sha256: str
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    analysed_at: str | None  # ISO date of the analysis
    uploaded_by_us: bool = False

    @property
    def engines(self) -> int:
        return self.malicious + self.suspicious + self.harmless + self.undetected

    @property
    def url(self) -> str:
        return gui_url(self.sha256)

    @property
    def flagged(self) -> int:
        return self.malicious + self.suspicious


def gui_url(sha256: str) -> str:
    return f"https://www.virustotal.com/gui/file/{sha256}"


def api_key() -> str | None:
    return os.environ.get(KEY_ENV_VAR, "").strip() or None


def _check_base(base: str) -> None:
    parts = urlsplit(base)
    loopback = parts.hostname in ("127.0.0.1", "localhost")
    if parts.scheme == "https" or (parts.scheme == "http" and loopback):
        return
    raise VirusTotalError("the VirusTotal base URL must be https (http only on loopback)")


def _check_upload_url(url: str, base: str) -> None:
    """The one-off URL for a big file: https on a virustotal.com host, or, when the base itself is
    a loopback test server, the same loopback host.
    """
    _check_base(url)
    host, base_host = urlsplit(url).hostname or "", urlsplit(base).hostname or ""
    if host == base_host and host in ("127.0.0.1", "localhost"):
        return
    if urlsplit(url).scheme != "https" or not (
        host == "virustotal.com" or host.endswith(".virustotal.com")
    ):
        raise VirusTotalError(f"VirusTotal gave an upload URL on an unexpected host ({host})")


def _request(
    url: str, key: str, *, data: bytes | None = None, content_type: str | None = None
) -> Any:
    headers = {
        "x-apikey": key,
        "accept": "application/json",
        "User-Agent": "fdroid-review-session",
    }
    if content_type:
        headers["content-type"] = content_type
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise
        if exc.code in (401, 403):
            raise VirusTotalError(
                f"VirusTotal refused the key (HTTP {exc.code}): check {KEY_ENV_VAR}"
            ) from exc
        if exc.code == 429:
            raise VirusTotalError(
                "VirusTotal rate limit reached (a free key allows 4 a minute)"
            ) from exc
        raise VirusTotalError(f"VirusTotal answered HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise VirusTotalError(f"could not reach VirusTotal: {type(exc).__name__}") from exc


def _result(sha256: str, attributes: dict[str, Any], *, uploaded: bool = False) -> VtResult:
    stats = attributes.get("last_analysis_stats") or attributes.get("stats") or {}
    date = attributes.get("last_analysis_date") or attributes.get("date")
    analysed = (
        datetime.fromtimestamp(int(date), UTC).date().isoformat() if isinstance(date, int) else None
    )
    return VtResult(
        sha256=sha256,
        malicious=int(stats.get("malicious", 0)),
        suspicious=int(stats.get("suspicious", 0)),
        harmless=int(stats.get("harmless", 0)),
        undetected=int(stats.get("undetected", 0)),
        analysed_at=analysed,
        uploaded_by_us=uploaded,
    )


def lookup(sha256: str, key: str, *, base: str = API_BASE) -> VtResult | None:
    """The existing report for this hash, or None if VirusTotal has never seen the file."""
    _check_base(base)
    try:
        body = _request(f"{base}/files/{sha256}", key)
    except urllib.error.HTTPError:
        return None
    attributes = (body.get("data") or {}).get("attributes") or {}
    if not attributes.get("last_analysis_stats"):
        return None
    return _result(sha256, attributes)


def _multipart(path: Path) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    return head + path.read_bytes() + f"\r\n--{boundary}--\r\n".encode(), (
        f"multipart/form-data; boundary={boundary}"
    )


def upload_and_wait(
    path: Path,
    sha256: str,
    key: str,
    *,
    base: str = API_BASE,
    sleep: Callable[[float], None] = time.sleep,
    poll_seconds: float = POLL_SECONDS,
    max_wait: float = MAX_WAIT_SECONDS,
) -> VtResult:
    _check_base(base)
    size = path.stat().st_size
    if size > MAX_BIG_UPLOAD_BYTES:
        raise VirusTotalError(
            f"the file is {size // (1024 * 1024)} MB; this tool uploads at most "
            f"{MAX_BIG_UPLOAD_BYTES // (1024 * 1024)} MB"
        )
    payload, content_type = _multipart(path)
    target = f"{base}/files"
    if size > MAX_UPLOAD_BYTES:
        # Over 32 MB the API hands out a one-off upload URL; it is checked like the base URL
        # before the file goes there.
        target = (_request(f"{base}/files/upload_url", key).get("data")) or ""
        if not isinstance(target, str):
            raise VirusTotalError("VirusTotal did not return an upload URL")
        _check_upload_url(target, base)
    body = _request(target, key, data=payload, content_type=content_type)
    analysis_id = (body.get("data") or {}).get("id")
    plain_id = analysis_id.replace("-", "").replace("=", "") if isinstance(analysis_id, str) else ""
    if not plain_id.isalnum():
        raise VirusTotalError("VirusTotal did not return an analysis id")
    waited = 0.0
    while True:
        try:
            report = _request(f"{base}/analyses/{analysis_id}", key)
        except urllib.error.HTTPError:
            # Seen live: straight after an upload the analysis can answer 404 for a while. Not
            # ready yet, like "queued"; anything else became a VirusTotalError in _request.
            report = {}
        attributes = (report.get("data") or {}).get("attributes") or {}
        if attributes.get("status") == "completed":
            return _result(sha256, attributes, uploaded=True)
        if waited >= max_wait:
            raise VirusTotalError(
                "the VirusTotal analysis did not finish in time; open the link later"
            )
        sleep(poll_seconds)
        waited += poll_seconds


def check(
    path: Path,
    sha256: str,
    key: str,
    *,
    allow_upload: bool,
    base: str = API_BASE,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[VtResult | None, str]:
    """(result, note). Never raises: an unreachable or refusing service is a note."""
    try:
        existing = lookup(sha256, key, base=base)
        if existing is not None:
            return existing, "ok"
        if not allow_upload:
            return None, (
                "unknown to VirusTotal (not uploaded; pass --virustotal-upload to upload it)"
            )
        result = upload_and_wait(path, sha256, key, base=base, sleep=sleep)
        return result, "ok (uploaded by this run)"
    except VirusTotalError as exc:
        return None, f"could not check: {exc}"
    except urllib.error.HTTPError as exc:
        return None, f"could not check: VirusTotal answered HTTP {exc.code}"
