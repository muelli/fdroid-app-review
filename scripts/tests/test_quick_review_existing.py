from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import test_quick_review_crash as crash_helpers  # noqa: E402
import test_review_coverage as cov  # noqa: E402

qr = crash_helpers.qr


class _Limited(Exception):
    def describe(self) -> str:
        return "GitLab is rate limiting this token; try again after about 19:00 UTC"


class _Rejected(Exception):
    def describe(self) -> str:
        return "GitLab rejected GITLAB_TOKEN (HTTP 401): it may be expired"


def _stub_fetcher(monkeypatch: pytest.MonkeyPatch, result: Any) -> None:
    def fetch_coverage_for(iid: int) -> Any:
        if isinstance(result, Exception):
            raise result
        return result

    stub = types.SimpleNamespace(
        fetch_coverage_for=fetch_coverage_for, RateLimited=_Limited, AuthRejected=_Rejected
    )
    monkeypatch.setitem(sys.modules, "fetch_review_queue", stub)


def _argv(tmp_path: Path, *extra: str) -> list[str]:
    return [*crash_helpers._stub_toolchain(tmp_path, ""), *extra]


def test_existing_reviews_are_printed_first_and_kept_out_of_the_checklist(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    coverage = cov.summarise(cov.note(7, cov.DEVICE_REVIEW, "10-15T19:25", "sookoothaii1"))
    _stub_fetcher(monkeypatch, coverage)
    code, out, _ = crash_helpers._run(_argv(tmp_path, "--existing-reviews"))
    assert code == 0
    assert out.index("Already on !5:") < out.index("Installing")
    assert "sookoothaii1" in out and "claims read from free text" in out
    report = (tmp_path / "out" / "report.md").read_text()
    assert "## Existing reviews on this merge request" in report and "sookoothaii1" in report
    assert "Existing reviews" in (tmp_path / "out" / "report.html").read_text()
    comment = (tmp_path / "out" / "review_comment.md").read_text()
    assert "sookoothaii1" not in comment and "Existing reviews" not in comment


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (_Limited(), "rate limiting this token"),
        (_Rejected(), "rejected GITLAB_TOKEN"),
        (OSError("network down"), "network down"),
    ],
)
def test_failure_to_read_comments_warns_and_the_review_carries_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: Exception, expected: str
) -> None:
    _stub_fetcher(monkeypatch, failure)
    code, out, err = crash_helpers._run(_argv(tmp_path, "--existing-reviews"))
    assert code == 0
    assert "could not read !5's existing comments" in err and expected in err
    assert "Already on" not in out
    assert (tmp_path / "out" / "review_comment.md").exists()
    assert "Existing reviews" not in (tmp_path / "out" / "report.md").read_text()


def test_without_the_flag_nothing_is_fetched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def boom(iid: int) -> Any:
        raise AssertionError("must not be called")

    stub = types.SimpleNamespace(
        fetch_coverage_for=boom, RateLimited=_Limited, AuthRejected=_Rejected
    )
    monkeypatch.setitem(sys.modules, "fetch_review_queue", stub)
    code, out, _ = crash_helpers._run(_argv(tmp_path))
    assert code == 0 and "Already on" not in out


def test_the_flag_needs_a_merge_request_number() -> None:
    with pytest.raises(SystemExit):
        qr.parse_args(["--apk", "a.apk", "--existing-reviews"])


def test_state_round_trips_the_lines(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _stub_fetcher(monkeypatch, cov.summarise(cov.note(7, cov.DEVICE_REVIEW, "10-15T19:25", "r")))
    pcap = tmp_path / "s.pcap"
    crash_helpers.helpers._dns_pcap(pcap, [("x.example", 1.0)])
    crash_helpers._run(_argv(tmp_path, "--existing-reviews", "--external-pcap", str(pcap)))
    text = (tmp_path / "out" / "review_state.json").read_text()
    data, mr_iid = qr.load_state(text)
    assert data.existing_reviews and qr.dump_state(data, mr_iid) == text
