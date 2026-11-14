from __future__ import annotations

import io
import json
import sys
import urllib.error
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import test_fetch_review_queue as base  # noqa: E402
import test_review_coverage as cov  # noqa: E402

frq = base.frq


def _mr(iid: int = 100, *, notes: int = 3, author: str = "the-author") -> dict[str, Any]:
    mr = base._mrs(1)[0]
    mr.update(iid=iid, user_notes_count=notes, author={"username": author})
    mr["web_url"] = cov.URL
    return mr


def test_no_notes_means_no_request_and_level_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_: str) -> Any:
        raise AssertionError("no request expected")

    monkeypatch.setattr(frq, "http_get_json", boom)
    coverage, status = frq.lookup_coverage(_mr(notes=0))
    assert status == "ok" and coverage is not None and coverage["level"] == "none"


def test_a_failed_request_is_could_not_check_never_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(_: str) -> Any:
        raise urllib.error.URLError("boom")

    monkeypatch.setattr(frq, "http_get_json", fail)
    coverage, status = frq.lookup_coverage(_mr())
    assert coverage is None and status.startswith("could not check")


def test_rate_limits_and_rejected_tokens_propagate(monkeypatch: pytest.MonkeyPatch) -> None:
    def limited(_: str) -> Any:
        raise frq.RateLimited(3000.0)

    monkeypatch.setattr(frq, "http_get_json", limited)
    with pytest.raises(frq.RateLimited):
        frq.lookup_coverage(_mr())


def test_a_long_thread_is_read_across_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = [
        [cov.note(i, "short", "08-01T00:00") for i in range(100)],
        [cov.note(1000, cov.DEVICE_REVIEW, "10-15T19:25", "r")],
    ]
    seen: list[str] = []

    def fake(url: str) -> Any:
        seen.append(url)
        return pages[len(seen) - 1]

    monkeypatch.setattr(frq, "http_get_json", fake)
    coverage, _ = frq.lookup_coverage(_mr(notes=101))
    assert coverage is not None and coverage["level"] == "device"
    assert len(seen) == 2 and "page=1" in seen[0] and "page=2" in seen[1]


def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    notes_by_iid: dict[int, list[dict[str, Any]]],
    *extra: str,
) -> tuple[list[dict[str, Any]], list[int], str]:
    mrs = [_mr(iid, notes=len(n)) for iid, n in notes_by_iid.items()]
    for i, mr in enumerate(mrs):
        mr["source_project_id"] = i
    looked_up: list[int] = []

    def resolve(project_id: int, *, stderr: Any = None) -> Any:
        looked_up.append(project_id)
        return frq.ApkLookup([], complete=True)

    monkeypatch.setattr(frq, "fetch_all_open_review_mrs", lambda **_: mrs)
    monkeypatch.setattr(frq, "resolve_apk_urls", resolve)
    monkeypatch.setattr(frq, "http_get_json", lambda url: notes_by_iid[int(url.split("/")[-2])])
    out = io.StringIO()
    code = frq.main(
        ["--limit", "5", "--output-dir", str(tmp_path), *extra], stdout=out, stderr=io.StringIO()
    )
    assert code == 0
    return json.loads((tmp_path / "index.json").read_text()), looked_up, out.getvalue()


def test_each_row_carries_its_coverage(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    rows, _, _ = _run(
        monkeypatch,
        tmp_path,
        {
            1: [],
            2: [cov.note(1, cov.STATIC_REVIEW, "10-06T14:38", "r")],
            3: [cov.note(1, cov.DEVICE_REVIEW, "10-15T19:25", "r")],
        },
    )
    assert [r["coverage"]["level"] for r in rows] == ["none", "static", "device"]
    assert all(r["coverage_status"] == "ok" for r in rows)
    html = (tmp_path / "index.html").read_text()
    assert "Existing reviews" in html and "least covered first" in html


def test_skip_covered_spends_no_apk_lookup_on_a_current_device_test(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rows, looked_up, _ = _run(
        monkeypatch,
        tmp_path,
        {
            1: [cov.note(1, cov.DEVICE_REVIEW, "10-15T19:25", "r")],
            2: [cov.note(1, cov.STATIC_REVIEW, "10-06T14:38", "r")],
            3: [
                cov.note(1, cov.DEVICE_REVIEW, "10-15T19:25", "r"),
                cov.note(2, cov.UPDATE_COMMIT, "10-20T08:00", system=True),
            ],
        },
        "--skip-covered",
    )
    assert looked_up == [1, 2], "only the static-reviewed and the stale one are looked up"
    assert rows[0]["apk_status"].startswith("skipped:")
    assert rows[1]["apk_status"] == "no build artifact found"


def test_without_the_flag_everything_is_still_looked_up(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _, looked_up, _ = _run(
        monkeypatch, tmp_path, {1: [cov.note(1, cov.DEVICE_REVIEW, "10-15T19:25", "r")]}
    )
    assert looked_up == [0]


def test_a_rate_limit_in_the_notes_call_labels_both_columns(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    mrs = [_mr(1), _mr(2)]
    monkeypatch.setattr(frq, "fetch_all_open_review_mrs", lambda **_: mrs)

    def limited(_: str) -> Any:
        raise frq.RateLimited(3000.0)

    monkeypatch.setattr(frq, "http_get_json", limited)
    monkeypatch.setattr(frq, "resolve_apk_urls", lambda *a, **k: pytest.fail("not reached"))
    frq.main(
        ["--limit", "2", "--output-dir", str(tmp_path)], stdout=io.StringIO(), stderr=io.StringIO()
    )
    rows = json.loads((tmp_path / "index.json").read_text())
    for row in rows:
        assert row["coverage"] is None
        assert row["coverage_status"].startswith("not checked:")
        assert row["apk_status"].startswith("not checked:")


def test_hostile_usernames_cannot_break_out_of_the_page(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evil = "</script><img src=x onerror=alert(1)>"
    _run(
        monkeypatch,
        tmp_path,
        {1: [cov.note(1, cov.DEVICE_REVIEW, "10-15T19:25", evil)]},
    )
    html = (tmp_path / "index.html").read_text()
    assert "</script><img" not in html
