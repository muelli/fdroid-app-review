from __future__ import annotations

import importlib.util
import io
import json
import sys
import urllib.error
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "fetch_review_queue.py"
_spec = importlib.util.spec_from_file_location("fetch_review_queue", SCRIPT)
assert _spec is not None and _spec.loader is not None
frq = importlib.util.module_from_spec(_spec)
sys.modules["fetch_review_queue"] = frq
_spec.loader.exec_module(frq)


def _http_429(retry_after: str | None) -> urllib.error.HTTPError:
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError("https://x", 429, "Too Many Requests", headers, io.BytesIO(b""))


class _Response:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _script_urlopen(
    monkeypatch: pytest.MonkeyPatch, outcomes: list[Any]
) -> tuple[list[float], list[int]]:
    sleeps: list[float] = []
    calls: list[int] = []

    def fake_open(*_: Any, **__: Any) -> _Response:
        calls.append(1)
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return _Response(outcome)

    monkeypatch.setattr(frq, "_open", fake_open)
    monkeypatch.setattr(frq, "_sleep", sleeps.append)
    return sleeps, calls


def test_short_rate_limit_is_waited_out_and_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps, calls = _script_urlopen(monkeypatch, [_http_429("7"), b"ok"])
    assert frq.http_get_bytes("https://x") == b"ok"
    assert sleeps == [7.0]
    assert len(calls) == 2


def test_long_rate_limit_gives_up_at_once_without_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps, calls = _script_urlopen(monkeypatch, [_http_429("3047"), b"never"])
    with pytest.raises(frq.RateLimited) as caught:
        frq.http_get_bytes("https://x")
    assert caught.value.retry_after == 3047.0
    assert sleeps == []
    assert len(calls) == 1
    assert "try again after about" in caught.value.describe()


def test_rate_limit_without_a_header_backs_off_then_gives_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps, calls = _script_urlopen(monkeypatch, [_http_429(None)] * 3)
    with pytest.raises(frq.RateLimited):
        frq.http_get_bytes("https://x")
    assert sleeps == [5.0, 10.0]
    assert len(calls) == 3


def test_other_http_errors_are_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    error = urllib.error.HTTPError("https://x", 404, "Not Found", Message(), io.BytesIO(b""))
    sleeps, calls = _script_urlopen(monkeypatch, [error])
    with pytest.raises(urllib.error.HTTPError):
        frq.http_get_bytes("https://x")
    assert sleeps == [] and len(calls) == 1


APK_URL = "https://gitlab.com/g/p/-/jobs/9/artifacts/raw/tmp/binaries/org.example_1.binary.apk"
PIPELINE = {"id": 5, "web_url": "https://gitlab.com/g/p/-/pipelines/5"}
BUILD_JOB = {"id": 9, "name": "fdroid build", "status": "success"}


def _patch_http(
    monkeypatch: pytest.MonkeyPatch, *, json_results: list[Any], log: Any = None
) -> None:
    results = list(json_results)

    def fake_json(_: str) -> Any:
        outcome = results.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def fake_text(_: str) -> str:
        if isinstance(log, Exception):
            raise log
        return str(log)

    monkeypatch.setattr(frq, "http_get_json", fake_json)
    monkeypatch.setattr(frq, "http_get", fake_text)


def test_found_apk_is_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_http(monkeypatch, json_results=[[PIPELINE], [BUILD_JOB]], log=f"see {APK_URL}")
    assert frq.resolve_apk_urls(1) == frq.ApkLookup([APK_URL], complete=True)


def test_nothing_found_after_clean_lookup_is_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_http(monkeypatch, json_results=[[]])
    assert frq.resolve_apk_urls(1) == frq.ApkLookup([], complete=True)


@pytest.mark.parametrize("where", ["pipelines", "jobs", "log"])
def test_a_failed_request_is_not_reported_as_nothing_found(
    monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    boom = urllib.error.URLError("boom")
    if where == "pipelines":
        _patch_http(monkeypatch, json_results=[boom])
    elif where == "jobs":
        _patch_http(monkeypatch, json_results=[[PIPELINE], boom])
    else:
        _patch_http(monkeypatch, json_results=[[PIPELINE], [BUILD_JOB]], log=boom)
    lookup = frq.resolve_apk_urls(1, stderr=io.StringIO())
    assert lookup.urls == [] and lookup.complete is False


def _mrs(count: int) -> list[dict[str, Any]]:
    return [
        {
            "iid": 100 + i,
            "title": f"New app: {i}",
            "web_url": f"https://gitlab.com/x/{i}",
            "source_branch": "b",
            "created_at": "2026-01-01T00:00:00Z",
            "source_project_id": i,
        }
        for i in range(count)
    ]


def _run_main(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, lookups: list[Any], *, limit: int, mrs: int
) -> tuple[list[dict[str, Any]], list[int], str]:
    calls: list[int] = []
    pending = list(lookups)

    def fake_resolve(project_id: int, *, stderr: Any = None) -> Any:
        calls.append(project_id)
        outcome = pending.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(frq, "fetch_all_open_review_mrs", lambda **_: _mrs(mrs))
    monkeypatch.setattr(frq, "resolve_apk_urls", fake_resolve)
    err = io.StringIO()
    code = frq.main(
        ["--limit", str(limit), "--output-dir", str(tmp_path)], stdout=io.StringIO(), stderr=err
    )
    assert code == 0
    return json.loads((tmp_path / "index.json").read_text()), calls, err.getvalue()


def test_rate_limit_stops_lookups_and_labels_every_unchecked_row(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entries, calls, err = _run_main(
        monkeypatch,
        tmp_path,
        [frq.ApkLookup([], complete=True), frq.RateLimited(3047.0)],
        limit=4,
        mrs=6,
    )
    statuses = [e["apk_status"] for e in entries]
    assert statuses[0] == "no build artifact found"
    assert all(s.startswith("not checked: GitLab is rate limiting") for s in statuses[1:4])
    assert statuses[4:] == ["not fetched this run"] * 2
    assert calls == [0, 1], "no lookups after the rate limit"
    assert "Incomplete" in err
    assert "no build artifact found" not in statuses[1:]


def test_incomplete_lookup_is_labelled_could_not_check(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entries, _, _ = _run_main(
        monkeypatch, tmp_path, [frq.ApkLookup([], complete=False)], limit=1, mrs=1
    )
    assert entries[0]["apk_status"].startswith("could not check")
