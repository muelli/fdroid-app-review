"""Opt-in upload of the tool's own screenshots to a temporary file service, so the review
checklist can link them. The default service is transfer.adminforge.de, a transfer.sh clone:
`PUT <base>/<name>` with a `Max-Days` header answers with the file's URL as plain text and a
delete URL in the `x-url-delete` header.

Only PNGs this tool took (and, with --upload-video, its own screen recording as an MP4) are
sent, checked by their magic bytes and size, over https
(plain http only on loopback, for tests). Nothing is uploaded unless the caller asks. Anyone
with the link can view the file until it expires, and the delete URL can remove it early, so
the delete URL is kept in a local file and never put in the checklist.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import device_capture as dc

DEFAULT_BASE = "https://transfer.adminforge.de"
DEFAULT_DAYS = 30
MAX_DAYS = 365
# A recording of a minute or two at the default bit rate is tens of MB. The service's own limit
# is not known to me; a refusal from it is reported as a failed upload.
MAX_VIDEO_BYTES = 100 * 1024 * 1024
VIDEO_TIMEOUT = 600
_CLEAN_URL_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9._~%/-]+$")


class UploadError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Uploaded:
    name: str
    url: str
    delete_url: str | None


def _check_base(base: str) -> None:
    parts = urlsplit(base)
    loopback = parts.hostname in ("127.0.0.1", "localhost")
    if not (parts.scheme == "https" or (parts.scheme == "http" and loopback)) or not parts.hostname:
        raise UploadError("the upload URL must be https (http only on loopback)")


def _clean_url(text: str, base: str) -> str:
    """The service's answer must be exactly one URL on the service's own host: it ends up in
    a Markdown comment, so anything else (a second line, a different host) is refused.
    """
    url = text.strip()
    if not _CLEAN_URL_RE.match(url) or urlsplit(url).hostname != urlsplit(base).hostname:
        raise UploadError("the service did not answer with a plain link on its own host")
    return url


def upload_png(path: Path, base: str, days: int) -> Uploaded:
    _check_base(base)
    if not 1 <= days <= MAX_DAYS:
        raise UploadError(f"--upload-days must be between 1 and {MAX_DAYS}")
    data = path.read_bytes()
    if not dc.valid_png(data):
        raise UploadError(f"{path.name} is not a PNG screenshot of this tool; not uploaded")
    request = urllib.request.Request(  # noqa: S310
        f"{base.rstrip('/')}/{path.name}",
        data=data,
        method="PUT",
        headers={
            "Max-Days": str(days),
            "Content-Type": "image/png",
            "User-Agent": "fdroid-review-session",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            body = response.read(2048).decode("utf-8", errors="replace")
            delete = response.headers.get("x-url-delete")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise UploadError(f"upload failed: {type(exc).__name__}") from exc
    url = _clean_url(body, base)
    try:
        delete_url = _clean_url(delete, base) if delete else None
    except UploadError:
        delete_url = None
    return Uploaded(path.name, url, delete_url)


def upload_all(paths: list[Path], base: str, days: int) -> tuple[list[Uploaded], list[str]]:
    """Every file is tried; a failure is a message, not an exception."""
    done: list[Uploaded] = []
    problems: list[str] = []
    for path in paths:
        try:
            done.append(upload_png(path, base, days))
        except (UploadError, OSError) as exc:
            problems.append(f"{path.name}: {exc}")
    return done, problems


def valid_mp4(path: Path) -> bool:
    """An MP4 starts with a box whose type, at bytes 4 to 8, is `ftyp`."""
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            head = handle.read(12)
    except OSError:
        return False
    return 0 < size <= MAX_VIDEO_BYTES and head[4:8] == b"ftyp"


def upload_mp4(path: Path, base: str, days: int) -> Uploaded:
    """The screen recording, streamed rather than read into memory."""
    _check_base(base)
    if not 1 <= days <= MAX_DAYS:
        raise UploadError(f"--upload-days must be between 1 and {MAX_DAYS}")
    if not valid_mp4(path):
        raise UploadError(
            f"{path.name} is not an MP4 of at most {MAX_VIDEO_BYTES // (1024 * 1024)} MB; "
            "not uploaded"
        )
    size = path.stat().st_size
    try:
        with path.open("rb") as handle:
            request = urllib.request.Request(  # noqa: S310
                f"{base.rstrip('/')}/{path.name}",
                data=handle,
                method="PUT",
                headers={
                    "Max-Days": str(days),
                    "Content-Type": "video/mp4",
                    "Content-Length": str(size),
                    "User-Agent": "fdroid-review-session",
                },
            )
            with urllib.request.urlopen(request, timeout=VIDEO_TIMEOUT) as response:  # noqa: S310
                body = response.read(2048).decode("utf-8", errors="replace")
                delete = response.headers.get("x-url-delete")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise UploadError(f"upload failed: {type(exc).__name__}") from exc
    url = _clean_url(body, base)
    try:
        delete_url = _clean_url(delete, base) if delete else None
    except UploadError:
        delete_url = None
    return Uploaded(path.name, url, delete_url)
