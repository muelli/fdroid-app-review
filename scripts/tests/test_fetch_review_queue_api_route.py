from __future__ import annotations

import io
import sys
import urllib.error
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import test_fetch_review_queue as base  # noqa: E402

frq = base.frq
WEB_APK = (
    "https://gitlab.com/Xeakaes/pc-hw-monitor/-/jobs/17212849734/artifacts/raw/"
    "tmp/binaries/com.Obscrum.pchwmonitor_8.binary.apk"
)
API_APK = (
    "https://gitlab.com/api/v4/projects/Xeakaes%2Fpc-hw-monitor/jobs/17212849734/artifacts/"
    "tmp/binaries/com.Obscrum.pchwmonitor_8.binary.apk"
)
PIPELINE = {"id": 5, "web_url": "https://gitlab.com/g/p/-/pipelines/5"}
BUILD_JOB = {"id": 9, "name": "fdroid build", "status": "success"}


@pytest.fixture(autouse=True)
def _no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)


def test_the_api_artifact_url_is_built_from_the_web_one() -> None:
    assert frq._api_artifact_url(WEB_APK) == API_APK
    assert frq._api_artifact_url("https://gitlab.com/g/p/-/jobs/9/raw") is None


def test_the_project_comes_from_the_link_not_from_the_fork() -> None:
    """Code Quality links point into fdroid/fdroiddata, log links into a contributor's fork."""
    signed = (
        "https://gitlab.com/fdroid/fdroiddata/-/jobs/17462492034/artifacts/raw/"
        "tmp/signed/com.covertwogames.dozeoff.foss_14.signed.apk"
    )
    assert frq._api_artifact_url(signed) == (
        "https://gitlab.com/api/v4/projects/fdroid%2Ffdroiddata/jobs/17462492034/artifacts/"
        "tmp/signed/com.covertwogames.dozeoff.foss_14.signed.apk"
    )


def test_a_signed_apk_link_is_found_in_a_job_log() -> None:
    log = "Signed APK: https://gitlab.com/CoverTwo/fdroiddata/-/jobs/1/artifacts/raw/tmp/signed/a_1.signed.apk"
    assert frq.extract_apk_urls(log) == [
        "https://gitlab.com/CoverTwo/fdroiddata/-/jobs/1/artifacts/raw/tmp/signed/a_1.signed.apk"
    ]


def _lookup(monkeypatch: pytest.MonkeyPatch, texts: dict[str, Any]) -> list[str]:
    asked: list[str] = []
    jsons = iter([[PIPELINE], [BUILD_JOB]])
    monkeypatch.setattr(frq, "http_get_json", lambda url: next(jsons))

    def fake_get(url: str) -> str:
        asked.append(url)
        outcome = texts[url]
        if isinstance(outcome, Exception):
            raise outcome
        return str(outcome)

    monkeypatch.setattr(frq, "http_get", fake_get)
    frq.resolve_apk_urls(7, stderr=io.StringIO())
    return asked


def test_without_a_token_the_log_comes_from_the_web(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _lookup(monkeypatch, {"https://gitlab.com/g/p/-/jobs/9/raw": f"x {WEB_APK}"})
    assert asked == ["https://gitlab.com/g/p/-/jobs/9/raw"]


def test_with_a_token_the_log_comes_from_the_api(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")
    trace = "https://gitlab.com/api/v4/projects/7/jobs/9/trace"
    assert _lookup(monkeypatch, {trace: f"x {WEB_APK}"}) == [trace]


def test_a_failing_api_log_falls_back_to_the_web(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")
    trace = "https://gitlab.com/api/v4/projects/7/jobs/9/trace"
    web = "https://gitlab.com/g/p/-/jobs/9/raw"
    asked = _lookup(monkeypatch, {trace: urllib.error.URLError("nope"), web: f"x {WEB_APK}"})
    assert asked == [trace, web]


def _download(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, outcomes: dict[str, Any]
) -> tuple[bool, list[str]]:
    asked: list[str] = []

    def fake_bytes(url: str) -> bytes:
        asked.append(url)
        outcome = outcomes[url]
        if isinstance(outcome, Exception):
            raise outcome
        return bytes(outcome)

    monkeypatch.setattr(frq, "http_get_bytes", fake_bytes)
    ok = frq.download_apk(WEB_APK, tmp_path / "a.apk")
    return ok, asked


def test_without_a_token_only_the_web_url_is_used(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ok, asked = _download(monkeypatch, tmp_path, {WEB_APK: b"apk"})
    assert ok and asked == [WEB_APK] and (tmp_path / "a.apk").read_bytes() == b"apk"


def test_with_a_token_the_api_artifact_is_tried_first(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")
    ok, asked = _download(monkeypatch, tmp_path, {API_APK: b"apk"})
    assert ok and asked == [API_APK]


@pytest.mark.parametrize(
    "api_failure", [urllib.error.URLError("gone"), frq.RateLimited(30.0, authenticated=True)]
)
def test_a_failed_api_download_falls_back_to_the_web_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, api_failure: Exception
) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")
    ok, asked = _download(monkeypatch, tmp_path, {API_APK: api_failure, WEB_APK: b"apk"})
    assert ok and asked == [API_APK, WEB_APK]


def test_both_routes_failing_is_a_failed_download(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")
    boom = urllib.error.URLError("x")
    ok, _ = _download(monkeypatch, tmp_path, {API_APK: boom, WEB_APK: boom})
    assert not ok and not (tmp_path / "a.apk").exists()


def test_a_rejected_token_during_a_download_stops_the_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")
    with pytest.raises(frq.AuthRejected):
        _download(monkeypatch, tmp_path, {API_APK: frq.AuthRejected("401")})
