from __future__ import annotations

import json
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import virustotal as vt  # noqa: E402

SHA = "f" * 64
KEY = "test-key-0000000000000000"
STATS = {"malicious": 0, "suspicious": 1, "undetected": 60, "harmless": 12, "timeout": 2}


class Fake(BaseHTTPRequestHandler):
    state: dict[str, Any] = {}

    def log_message(self, *a: Any) -> None:
        return None

    def _send(self, code: int, body: dict[str, Any] | None = None) -> None:
        raw = json.dumps(body or {}).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _auth(self) -> bool:
        self.state.setdefault("keys", []).append(self.headers.get("x-apikey"))
        if self.headers.get("x-apikey") != KEY:
            self._send(401, {"error": {"code": "WrongCredentialsError"}})
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        if not self._auth():
            return
        self.state.setdefault("paths", []).append(self.path)
        if self.path == f"/files/{SHA}":
            if self.state.get("known"):
                attributes = {"last_analysis_stats": STATS, "last_analysis_date": 1793000000}
                self._send(200, {"data": {"attributes": attributes}})
            else:
                self._send(404, {"error": {"code": "NotFoundError"}})
        elif self.path == "/analyses/abc123":
            polls = self.state["polls"] = self.state.get("polls", 0) + 1
            if polls <= self.state.get("analysis_not_visible_polls", 0):
                self._send(404, {"error": {"code": "NotFoundError"}})
                return
            status = "completed" if polls >= 3 else "queued"
            attributes = {"status": status, "stats": STATS, "date": 1793000100}
            self._send(200, {"data": {"attributes": attributes}})
        elif self.path == "/files/upload_url":
            where = self.state.get("upload_url") or f"http://{self.headers['Host']}/big-upload"
            self._send(200, {"data": where})
        elif self.path == "/rate":
            self._send(429)
        else:
            self._send(500)

    def do_POST(self) -> None:  # noqa: N802
        if not self._auth():
            return
        length = int(self.headers.get("content-length", 0))
        self.state["posted_to"] = self.path
        self.state["upload"] = self.rfile.read(length)
        self.state["upload_type"] = self.headers.get("content-type")
        self._send(200, {"data": {"id": "abc123", "type": "analysis"}})


@pytest.fixture
def server() -> Iterator[tuple[str, dict[str, Any]]]:
    Fake.state = {}
    httpd = HTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}", Fake.state
    httpd.shutdown()


def test_a_known_file_is_looked_up_by_hash_and_nothing_is_uploaded(
    server: tuple[str, dict[str, Any]], tmp_path: Path
) -> None:
    base, state = server
    state["known"] = True
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"x")
    result, note = vt.check(apk, SHA, KEY, allow_upload=True, base=base)
    assert note == "ok" and result is not None
    counts = (result.malicious, result.suspicious, result.harmless, result.undetected)
    assert counts == (0, 1, 12, 60)
    assert result.engines == 73 and result.flagged == 1 and result.analysed_at == "2026-10-26"
    assert result.url == f"https://www.virustotal.com/gui/file/{SHA}"
    assert "upload" not in state and set(state["keys"]) == {KEY}


def test_an_unknown_file_is_not_uploaded_unless_allowed(
    server: tuple[str, dict[str, Any]], tmp_path: Path
) -> None:
    base, state = server
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"x")
    result, note = vt.check(apk, SHA, KEY, allow_upload=False, base=base)
    assert result is None and "not uploaded" in note and "--virustotal-upload" in note
    assert "upload" not in state


def test_an_allowed_upload_is_sent_then_polled_at_the_free_tier_pace(
    server: tuple[str, dict[str, Any]], tmp_path: Path
) -> None:
    base, state = server
    apk = tmp_path / "dozeoff.apk"
    apk.write_bytes(b"APKDATA")
    naps: list[float] = []
    result, note = vt.check(apk, SHA, KEY, allow_upload=True, base=base, sleep=naps.append)
    assert note == "ok (uploaded by this run)"
    assert result is not None and result.uploaded_by_us
    assert result.flagged == 1 and result.analysed_at == "2026-10-26"
    assert b'filename="dozeoff.apk"' in state["upload"] and b"APKDATA" in state["upload"]
    assert state["upload_type"].startswith("multipart/form-data; boundary=")
    assert naps == [vt.POLL_SECONDS, vt.POLL_SECONDS]  # queued, queued, completed


def test_a_wrong_key_is_a_note_not_a_crash_and_is_not_echoed(
    server: tuple[str, dict[str, Any]], tmp_path: Path
) -> None:
    base, _ = server
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"x")
    result, note = vt.check(apk, SHA, "the-wrong-key", allow_upload=True, base=base)
    assert result is None and "refused the key" in note and "VT_API_KEY" in note
    assert "the-wrong-key" not in note


def test_a_file_over_the_plain_limit_goes_to_the_one_off_upload_url(
    server: tuple[str, dict[str, Any]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base, state = server
    monkeypatch.setattr(vt, "MAX_UPLOAD_BYTES", 3)
    apk = tmp_path / "big.apk"
    apk.write_bytes(b"12345")
    result, note = vt.check(apk, SHA, KEY, allow_upload=True, base=base, sleep=lambda s: None)
    assert note == "ok (uploaded by this run)" and result is not None
    assert state["posted_to"] == "/big-upload" and b"12345" in state["upload"]
    assert "/files/upload_url" in state["paths"]


def test_a_small_file_still_uses_the_plain_upload(
    server: tuple[str, dict[str, Any]], tmp_path: Path
) -> None:
    base, state = server
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"x")
    vt.check(apk, SHA, KEY, allow_upload=True, base=base, sleep=lambda s: None)
    assert state["posted_to"] == "/files" and "/files/upload_url" not in state["paths"]


def test_an_upload_url_on_another_host_is_refused_and_nothing_is_sent(
    server: tuple[str, dict[str, Any]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base, state = server
    monkeypatch.setattr(vt, "MAX_UPLOAD_BYTES", 3)
    state["upload_url"] = "https://evil.example/upload"
    apk = tmp_path / "big.apk"
    apk.write_bytes(b"12345")
    result, note = vt.check(apk, SHA, KEY, allow_upload=True, base=base)
    assert result is None and "unexpected host" in note and "upload" not in state


def test_a_file_over_our_own_ceiling_is_refused_without_asking_for_a_url(
    server: tuple[str, dict[str, Any]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base, state = server
    monkeypatch.setattr(vt, "MAX_UPLOAD_BYTES", 3)
    monkeypatch.setattr(vt, "MAX_BIG_UPLOAD_BYTES", 4)
    apk = tmp_path / "huge.apk"
    apk.write_bytes(b"12345")
    result, note = vt.check(apk, SHA, KEY, allow_upload=True, base=base)
    assert result is None and "at most" in note and "upload" not in state
    assert "/files/upload_url" not in state.get("paths", [])


def test_rate_limiting_and_unreachable_servers_are_notes(tmp_path: Path) -> None:
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"x")
    result, note = vt.check(apk, SHA, KEY, allow_upload=False, base="http://127.0.0.1:9")
    assert result is None and note.startswith("could not check: could not reach VirusTotal")


def test_a_polling_that_never_finishes_gives_up(
    server: tuple[str, dict[str, Any]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base, state = server
    def always_queued(self: Fake) -> None:
        if self._auth():
            self._send(200, {"data": {"attributes": {"status": "queued"}}})

    monkeypatch.setattr(Fake, "do_GET", always_queued)
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"x")
    result, note = vt.check(apk, SHA, KEY, allow_upload=True, base=base, sleep=lambda s: None)
    assert result is None and "did not finish in time" in note


def test_only_https_or_loopback_bases_are_accepted() -> None:
    with pytest.raises(vt.VirusTotalError):
        vt.lookup(SHA, KEY, base="http://evil.example/api")
    with pytest.raises(vt.VirusTotalError):
        vt.lookup(SHA, KEY, base="file:///etc/passwd")


def test_the_key_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert vt.api_key() is None
    monkeypatch.setenv("VT_API_KEY", "  abc  ")
    assert vt.api_key() == "abc"


def test_an_analysis_that_is_not_visible_yet_is_waited_for_not_a_crash(
    server: tuple[str, dict[str, Any]], tmp_path: Path
) -> None:
    """Seen live: right after an upload the analysis answered 404 for a while, and the
    HTTPError escaped check(), which promises never to raise.
    """
    base, state = server
    state["analysis_not_visible_polls"] = 2
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"x")
    naps: list[float] = []
    result, note = vt.check(apk, SHA, KEY, allow_upload=True, base=base, sleep=naps.append)
    assert result is not None and result.uploaded_by_us and note == "ok (uploaded by this run)"
    assert naps == [vt.POLL_SECONDS, vt.POLL_SECONDS]  # two 404s, then the third poll completes


def test_an_analysis_that_never_appears_is_a_note(
    server: tuple[str, dict[str, Any]], tmp_path: Path
) -> None:
    base, state = server
    state["analysis_not_visible_polls"] = 10_000
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"x")
    result, note = vt.check(apk, SHA, KEY, allow_upload=True, base=base, sleep=lambda s: None)
    assert result is None and "did not finish in time" in note

