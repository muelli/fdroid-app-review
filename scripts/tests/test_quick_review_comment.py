from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "quick_review.py"
if str(SCRIPT.parent) not in sys.path:  # as when run as a script; see test_quick_review_emulator
    sys.path.insert(0, str(SCRIPT.parent))
_spec = importlib.util.spec_from_file_location("quick_review", SCRIPT)
assert _spec is not None and _spec.loader is not None
quick_review = importlib.util.module_from_spec(_spec)
sys.modules["quick_review"] = quick_review
_spec.loader.exec_module(quick_review)


def _data(
    tmp_path: Path,
    *,
    names: list[str] | None,
    permissions: list[str] | None,
) -> quick_review.ReportData:
    network_log: Path | None = None
    if names is not None:
        network_log = tmp_path / "network_log.jsonl"
        network_log.write_text(
            "".join(json.dumps({"query_name": name}) + "\n" for name in names), encoding="utf-8"
        )
    now = datetime.now(UTC)
    return quick_review.ReportData(
        apk_path=tmp_path / "app.apk",
        package="org.example.app",
        serial="emulator-5554",
        duration=30,
        started_at=now,
        ended_at=now,
        screen_recording_path=None,
        network_log_path=network_log,
        pcap_path=None,
        permissions=permissions,
        logcat_path=None,
        permission_accesses=[],
        logcat_entries=[],
        app_pids=[],
        warnings=[],
        logcat_scope="app",
        logcat_text="",
    )


def _table_rows(comment: str) -> list[str]:
    return [line for line in comment.splitlines() if line.startswith("|")]


def test_uncaptured_network_is_not_reported_as_none_observed(tmp_path: Path) -> None:
    comment = quick_review.build_review_comment(
        _data(tmp_path, names=None, permissions=["android.permission.INTERNET"]), 1234
    )
    assert "!1234" in comment
    assert "not captured in this run" in comment
    assert "none observed" not in comment


def test_captured_but_silent_app_is_none_observed(tmp_path: Path) -> None:
    internet = ["android.permission.INTERNET"]
    comment = quick_review.build_review_comment(_data(tmp_path, names=[], permissions=internet), 1)
    assert "none observed" in comment
    assert "none possible" not in comment  # it can use the network, it just did not


def test_missing_aapt_is_not_reported_as_no_permissions(tmp_path: Path) -> None:
    comment = quick_review.build_review_comment(_data(tmp_path, names=[], permissions=None), 1)
    assert "not automatically extracted" in comment
    assert "none declared" not in comment


def test_checks_this_run_cannot_make_do_not_read_as_a_pass(tmp_path: Path) -> None:
    comment = quick_review.build_review_comment(_data(tmp_path, names=[], permissions=[]), 1)
    assert comment.count("not checked (quick review)") == 2


def test_hostile_names_cannot_add_columns_or_markdown(tmp_path: Path) -> None:
    hostile = ["a.example|extra", "x`](https://evil.example)[`", "line\nbreak.example"]
    clean = quick_review.build_review_comment(_data(tmp_path, names=[], permissions=[]), 1)
    comment = quick_review.build_review_comment(
        _data(tmp_path, names=hostile, permissions=["p|q"]), 1
    )
    assert len(_table_rows(comment)) == len(_table_rows(clean))
    for row in _table_rows(comment)[2:]:
        assert row.count("|") - row.count("\\|") == 3, row
    assert "\nbreak" not in comment


def test_long_lists_are_bounded(tmp_path: Path) -> None:
    names = [f"h{i}.example" for i in range(200)]
    internet = ["android.permission.INTERNET"]
    comment = quick_review.build_review_comment(
        _data(tmp_path, names=names, permissions=internet), 1
    )
    assert "h29.example" in comment
    assert "h30.example" not in comment
    assert "and 170 more" in comment
    assert "report.md" not in comment  # a posted comment cannot point at a local file


APP_LINE = "10-27 17:50:56.822 11423 11423 I MyApp   : scanning for a QR code"
OTHER_LINE = '10-27 17:50:56.879  2706 10283 I NearbyMediums: Wifi changed new SSID: "homenet"'
NOLOG_LINE = "a continuation line with no header"
LOGCAT_RAW = "\n".join([OTHER_LINE, APP_LINE, NOLOG_LINE]) + "\n"


def _entries() -> list[quick_review.LogcatEntry]:
    return quick_review.parse_logcat(LOGCAT_RAW, None, reference_year=2026)


def test_only_the_apps_own_log_lines_are_shared_by_default() -> None:
    kept = quick_review.select_shareable_logcat(_entries(), [11423], full=False)
    assert [e.pid for e in kept] == [11423]


def test_unidentified_app_shares_no_log_lines_rather_than_all_of_them() -> None:
    assert quick_review.select_shareable_logcat(_entries(), [], full=False) == []


def test_full_logcat_is_opt_in_and_keeps_everything() -> None:
    assert len(quick_review.select_shareable_logcat(_entries(), [11423], full=True)) == 3


def _data_with_log(tmp_path: Path, *, scope: str, pids: list[int]) -> quick_review.ReportData:
    import dataclasses

    raw = tmp_path / "logcat.txt"
    raw.write_text(LOGCAT_RAW, encoding="utf-8")
    entries = quick_review.select_shareable_logcat(_entries(), pids, full=scope == "full")
    text = LOGCAT_RAW if scope == "full" else "\n".join(e.raw for e in entries)
    return dataclasses.replace(
        _data(tmp_path, names=None, permissions=None),
        logcat_path=raw,
        logcat_entries=entries,
        app_pids=pids,
        logcat_scope=scope,
        logcat_text=text,
    )


def test_neither_report_contains_other_apps_log_lines_by_default(tmp_path: Path) -> None:
    data = _data_with_log(tmp_path, scope="app", pids=[11423])
    markdown = quick_review.build_report(data)
    html = quick_review.build_html_report(data)
    assert "scanning for a QR code" in markdown
    assert "homenet" not in markdown
    assert "homenet" not in html
    # The download link carries base64 text, which a plain search would miss.
    import base64
    import re

    blobs = re.findall(r"data:text/plain;charset=utf-8;base64,([A-Za-z0-9+/=]+)", html)
    assert blobs, "no logcat download link found; this check would be vacuous"
    for blob in blobs:
        decoded = base64.b64decode(blob).decode("utf-8", "replace")
        assert "scanning for a QR code" in decoded
        assert "homenet" not in decoded


def test_full_logcat_includes_everything_and_warns_about_it(tmp_path: Path) -> None:
    markdown = quick_review.build_report(_data_with_log(tmp_path, scope="full", pids=[11423]))
    assert "homenet" in markdown
    assert "Read it before sharing it" in markdown


def test_unidentified_app_says_so_instead_of_showing_an_empty_log(tmp_path: Path) -> None:
    markdown = quick_review.build_report(_data_with_log(tmp_path, scope="app", pids=[]))
    assert "could not be identified" in markdown
    assert "homenet" not in markdown
