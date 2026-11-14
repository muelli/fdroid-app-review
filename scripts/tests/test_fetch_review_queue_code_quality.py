from __future__ import annotations

import io
import json
import sys
import urllib.error
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import code_quality as cq  # noqa: E402
import test_fetch_review_queue as base  # noqa: E402

frq = base.frq
FIXTURES = Path(__file__).parent / "fixtures"
SIGNED_URL = (
    "https://gitlab.com/fdroid/fdroiddata/-/jobs/17462492034/artifacts/raw/"
    "tmp/signed/com.covertwogames.dozeoff.foss_14.signed.apk"
)


def _report(name: str = "code_quality_signed_apk.json") -> cq.CodeQuality:
    return cq.parse(json.loads((FIXTURES / name).read_text()))


# ---- polling -----------------------------------------------------------------------------


@pytest.fixture
def real(monkeypatch: pytest.MonkeyPatch) -> Any:
    """The fetcher module with the real fetch_code_quality (conftest stubs it by default)."""
    monkeypatch.setattr(frq, "fetch_code_quality", frq.real_fetch_code_quality)
    return frq


def test_polling_until_ready(real: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    asked: list[str] = []
    answers = iter(["", "  ", (FIXTURES / "code_quality_signed_apk.json").read_text()])
    monkeypatch.setattr(real, "http_get", lambda url: (asked.append(url), next(answers))[1])
    monkeypatch.setattr(real, "_sleep", sleeps.append)
    report = real.fetch_code_quality(46633)
    assert report is not None and report.apks[0].url == SIGNED_URL
    assert sleeps == [2.0, 3.0]
    assert asked[0] == (
        "https://gitlab.com/fdroid/fdroiddata/-/merge_requests/46633/codequality_reports.json"
    )


def test_a_report_that_never_becomes_ready_is_an_error_not_no_report(
    real: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(real, "http_get", lambda url: "")
    monkeypatch.setattr(real, "_sleep", lambda s: None)
    with pytest.raises(OSError, match="not ready"):
        real.fetch_code_quality(1)
    assert real.lookup_code_quality(1)[1].startswith("could not check")


def test_a_404_means_no_report(real: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def not_found(url: str) -> str:
        raise urllib.error.HTTPError(url, 404, "nf", Message(), io.BytesIO(b""))

    monkeypatch.setattr(real, "http_get", not_found)
    assert real.fetch_code_quality(1) is None
    assert real.lookup_code_quality(1) == (None, "no Code Quality report on this merge request")


def test_a_rate_limit_propagates(real: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def limited(url: str) -> str:
        raise real.RateLimited(3000.0)

    monkeypatch.setattr(real, "http_get", limited)
    with pytest.raises(real.RateLimited):
        real.lookup_code_quality(1)


# ---- in the main flow --------------------------------------------------------------------


def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    report: cq.CodeQuality | None,
    *,
    fallback_urls: list[str] | None = None,
    fallback_complete: bool = True,
    extra_args: list[str] | None = None,
) -> tuple[dict[str, Any], dict[str, list[Any]]]:
    calls: dict[str, list[Any]] = {"downloads": [], "fallback": []}
    mr = base._mrs(1)[0]
    mr.update(iid=46633, user_notes_count=0, author={"username": "a"})
    monkeypatch.setattr(frq, "fetch_all_open_review_mrs", lambda **_: [mr])
    monkeypatch.setattr(frq, "fetch_code_quality", lambda iid: report)

    def resolve(project_id: int, *, stderr: Any = None) -> Any:
        calls["fallback"].append(project_id)
        return frq.ApkLookup(fallback_urls or [], complete=fallback_complete)

    def download(url: str, dest: Path) -> bool:
        calls["downloads"].append(url)
        return True

    monkeypatch.setattr(frq, "resolve_apk_urls", resolve)
    monkeypatch.setattr(frq, "download_apk", download)
    code = frq.main(
        ["--limit", "1", "--output-dir", str(tmp_path), *(extra_args or [])],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert code == 0
    return json.loads((tmp_path / "index.json").read_text())[0], calls


def test_a_signed_apk_from_code_quality_is_downloaded_without_walking_the_pipeline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    row, calls = _run(monkeypatch, tmp_path, _report())
    assert calls["downloads"] == [SIGNED_URL] and calls["fallback"] == []
    assert row["apk_status"] == "1 file(s) fetched"
    assert row["code_quality_status"] == "ok"
    assert "android.permission.WAKE_LOCK" in row["code_quality"]["permissions"]


def test_without_a_report_the_job_log_route_is_used(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    link = "https://gitlab.com/g/p/-/jobs/1/artifacts/raw/tmp/signed/a.signed.apk"
    row, calls = _run(monkeypatch, tmp_path, None, fallback_urls=[link])
    assert len(calls["fallback"]) == 1 and len(calls["downloads"]) == 1
    assert row["code_quality"] is None and row["apk_status"] == "1 file(s) fetched"


def test_a_report_naming_no_apk_still_tries_the_log(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    no_apk = cq.parse({"new_errors": [{"description": "Permission android.permission.WAKE_LOCK"}]})
    row, calls = _run(monkeypatch, tmp_path, no_apk)
    assert len(calls["fallback"]) == 1
    assert row["apk_status"] == "no build artifact found"
    assert row["code_quality"]["permissions"] == ["android.permission.WAKE_LOCK"]


def test_an_incomplete_fallback_is_could_not_check_never_none_found(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    row, _ = _run(monkeypatch, tmp_path, None, fallback_complete=False)
    assert row["apk_status"].startswith("could not check")


def _with_abis(*texts: str) -> cq.CodeQuality:
    entries = [{"description": f"Signed APK: {SIGNED_URL}"}]
    entries += [{"description": f"APK ABI and size: {t}"} for t in texts]
    return cq.parse({"new_errors": entries})


def test_an_arm_only_merge_request_is_skipped_with_the_reason_and_nothing_is_downloaded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """!45651 builds armeabi-v7a and arm64-v8a APKs, one per build, and no x86."""
    row, calls = _run(monkeypatch, tmp_path, _with_abis("armeabi-v7a, 24M", "arm64-v8a, 25M"))
    assert calls["downloads"] == [] and calls["fallback"] == []
    assert row["apk_status"].startswith("skipped: ARM-only (arm64-v8a, armeabi-v7a), no x86 build")
    assert "--include-arm-only" in row["apk_status"]
    assert row["code_quality"]["permissions"] == []  # the rest of the row is still filled in


def test_the_flag_lets_an_arm_only_merge_request_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    row, calls = _run(
        monkeypatch, tmp_path, _with_abis("arm64-v8a, 25M"), extra_args=["--include-arm-only"]
    )
    assert calls["downloads"] == [SIGNED_URL] and row["apk_status"] == "1 file(s) fetched"


def test_x86_pure_java_and_unknown_abis_are_not_arm_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for number, texts in enumerate(
        [("x86_64, 70M",), ("No native lib, 3.8M",), ("arm64-v8a, 1M", "x86_64, 1M"), ()]
    ):
        sub = tmp_path / str(number)
        sub.mkdir()
        _, calls = _run(monkeypatch, sub, _with_abis(*texts))
        assert calls["downloads"] == [SIGNED_URL], texts
