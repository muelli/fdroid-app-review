"""What the proxy saw (summarise_decrypted), and how it reaches the report and the checklist."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from test_quick_review_comment import _data, quick_review


def _log(tmp_path: Path, *records: dict[str, object] | str) -> Path:
    path = tmp_path / "decrypted.jsonl"
    path.write_text(
        "".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in records),
        encoding="utf-8",
    )
    return path


def _request(url: str, method: str = "GET", status: int = 200) -> dict[str, object]:
    return {"event": "request", "method": method, "url": url, "status": status}


def test_hosts_are_counted_with_calls_and_parameter_names(tmp_path: Path) -> None:
    path = _log(
        tmp_path,
        _request("https://nominatim.openstreetmap.org/search?q=Berlin&format=json"),
        _request("https://nominatim.openstreetmap.org/search?q=Paris&format=json"),
        _request("https://flagcdn.com/w40/de.png"),
    )
    summary = quick_review.summarise_decrypted(path)
    assert summary["requests"] == 3 and summary["host_count"] == 2
    top = summary["hosts"][0]
    assert top["host"] == "nominatim.openstreetmap.org" and top["count"] == 2
    assert top["calls"] == ["GET /search"] and top["params"] == ["q", "format"]


def test_a_missing_log_is_zero_requests_not_an_error(tmp_path: Path) -> None:
    summary = quick_review.summarise_decrypted(tmp_path / "absent.jsonl")
    assert summary["requests"] == 0 and summary["refused"] == []


def test_bad_lines_are_skipped_and_refused_handshakes_listed(tmp_path: Path) -> None:
    path = _log(
        tmp_path,
        "not json {",
        "[1, 2]",
        _request("https://a.example/x"),
        {"event": "tls_failed", "sni": "pinned.example", "error": "x"},
        {"event": "tls_failed", "sni": "pinned.example", "error": "x"},
        {"event": "tls_failed"},
    )
    summary = quick_review.summarise_decrypted(path)
    assert summary["requests"] == 1
    assert {"sni": "pinned.example", "count": 2} in summary["refused"]
    assert {"sni": "unknown host", "count": 1} in summary["refused"]


def test_the_checklist_row_has_names_but_never_query_values(tmp_path: Path) -> None:
    path = _log(
        tmp_path, _request("https://api.example/lookup?token=SECRET123&city=Berlin", "POST")
    )
    data = dataclasses.replace(
        _data(tmp_path, names=None, permissions=None),
        decrypted=quick_review.summarise_decrypted(path),
    )
    comment = quick_review.build_review_comment(data, 1)
    assert "api.example" in comment and "token" in comment and "city" in comment
    assert "SECRET123" not in comment and "Berlin" not in comment
    assert "different binary" in comment


def test_the_local_report_has_the_full_requests_and_a_warning(tmp_path: Path) -> None:
    path = _log(tmp_path, _request("https://api.example/lookup?city=Berlin"))
    data = dataclasses.replace(
        _data(tmp_path, names=None, permissions=None),
        decrypted=quick_review.summarise_decrypted(path),
    )
    report = quick_review.build_report(data)
    assert "api.example/lookup?city=Berlin" in report
    assert "Read this before sharing" in report and "different binary" in report


def test_nothing_reaching_the_proxy_is_not_called_proof(tmp_path: Path) -> None:
    data = dataclasses.replace(
        _data(tmp_path, names=None, permissions=None),
        decrypted=quick_review.summarise_decrypted(tmp_path / "absent.jsonl"),
    )
    assert "not proof" in quick_review.build_report(data)
    assert "may ignore the system proxy" in quick_review.build_review_comment(data, 1)


def test_hostile_values_cannot_break_out_of_the_table_cell(tmp_path: Path) -> None:
    path = _log(tmp_path, _request("https://evil.example/a|b`c\n# heading?x|y=1"))
    data = dataclasses.replace(
        _data(tmp_path, names=None, permissions=None),
        decrypted=quick_review.summarise_decrypted(path),
    )
    comment = quick_review.build_review_comment(data, 1)
    row = next(line for line in comment.splitlines() if "Decrypted requests" in line)
    # the label and value cell only: the hostile pipe is escaped
    assert row.replace("\\|", "").count("|") == 3


def test_no_decrypted_data_adds_nothing(tmp_path: Path) -> None:
    data = _data(tmp_path, names=None, permissions=None)
    assert "Decrypted" not in quick_review.build_review_comment(data, 1)
    assert "through a proxy" not in quick_review.build_report(data)


# ---- checking the proxy's hosts against the app's own capture --------------------------------


def _attributed(
    tmp_path: Path, capture: list[str] | None, state: str, *records: dict[str, object]
) -> quick_review.ReportData:
    base = _data(tmp_path, names=capture, permissions=None)
    return dataclasses.replace(
        base,
        network_state=state,
        decrypted=quick_review.summarise_decrypted(_log(tmp_path, *records)),
    )


def test_a_host_in_the_apps_own_capture_is_marked_as_backed(tmp_path: Path) -> None:
    data = _attributed(
        tmp_path, ["API.Example"], "app-filtered", _request("https://api.example/x")
    )  # case does not matter
    assert "in the app's own capture" in quick_review.build_report(data)
    assert "[in the app's own capture]" in quick_review.build_review_comment(data, 1)


def test_an_https_host_missing_from_the_apps_capture_is_flagged(tmp_path: Path) -> None:
    data = _attributed(
        tmp_path,
        ["api.example"],
        "app-filtered",
        _request("https://api.example/x"),
        _request("https://clients.other.example/y"),
    )
    report = quick_review.build_report(data)
    assert "`clients.other.example` x1: NOT in the app's own capture" in report
    comment = quick_review.build_review_comment(data, 1)
    assert "[NOT in the app's own capture" in comment and "[in the app's own capture]" in comment


def test_plain_http_is_not_called_foreign_because_it_cannot_be_checked(tmp_path: Path) -> None:
    data = _attributed(
        tmp_path, ["api.example"], "app-filtered", _request("http://plain.example/x")
    )
    report = quick_review.build_report(data)
    assert "cannot be checked" in report and "NOT in the app's own capture" not in report


def test_a_refused_handshake_is_checked_too(tmp_path: Path) -> None:
    data = _attributed(
        tmp_path,
        ["pinned.example"],
        "app-filtered",
        {"event": "tls_failed", "sni": "pinned.example"},
        {"event": "tls_failed", "sni": "update.googleapis.com"},
    )
    report = quick_review.build_report(data)
    assert "`pinned.example` x1: in the app's own capture" in report
    assert "`update.googleapis.com` x1: NOT in the app's own capture" in report


def test_a_whole_emulator_capture_is_never_used_to_attribute(tmp_path: Path) -> None:
    """Its hosts include the system's, so a match would prove nothing."""
    for capture, state in ((["api.example"], "windowed"), (None, "")):
        data = _attributed(tmp_path, capture, state, _request("https://api.example/x"))
        report = quick_review.build_report(data)
        assert "none of them is attributed to the app" in report
        assert "[" not in next(
            line for line in quick_review.build_review_comment(data, 1).splitlines()
            if "Decrypted requests" in line
        )  # fmt: skip


def test_an_empty_app_capture_flags_every_https_host(tmp_path: Path) -> None:
    """The NischenLicht case: the proxy saw hosts, the app's own capture saw none."""
    data = _attributed(tmp_path, [], "app-filtered", _request("https://x.example/a"))
    assert "NOT in the app's own capture" in quick_review.build_report(data)


def test_refused_handshakes_alone_do_not_print_an_empty_host_list(tmp_path: Path) -> None:
    data = _attributed(tmp_path, [], "app-filtered", {"event": "tls_failed", "sni": "x.example"})
    report = quick_review.build_report(data)
    assert "Hosts, checked against" not in report and "`x.example` x1: NOT in" in report
