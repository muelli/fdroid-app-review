import json
from pathlib import Path

import pytest
from gitlab_glue.mock import MockGitLab, MockGitlabError

FIXTURES = Path(__file__).parent / "fixtures" / "merge_requests.json"


def test_get_merge_request(tmp_path: Path) -> None:
    gl = MockGitLab(fixtures_path=FIXTURES, outbox_dir=tmp_path / "outbox")
    mr = gl.get_merge_request(32058)
    assert mr.title == "Add LANflix"
    assert mr.package_name == "org.example.lanflix"
    assert "Needs Testing" in mr.labels


def test_get_merge_request_unknown_raises(tmp_path: Path) -> None:
    gl = MockGitLab(fixtures_path=FIXTURES, outbox_dir=tmp_path / "outbox")
    with pytest.raises(MockGitlabError):
        gl.get_merge_request(999999)


def test_list_review_request_mrs_sorted(tmp_path: Path) -> None:
    gl = MockGitLab(fixtures_path=FIXTURES, outbox_dir=tmp_path / "outbox")
    mrs = gl.list_review_request_mrs()
    assert [mr.iid for mr in mrs] == [25589, 32058]


def test_post_comment_writes_outbox(tmp_path: Path) -> None:
    outbox = tmp_path / "outbox"
    gl = MockGitLab(fixtures_path=FIXTURES, outbox_dir=outbox)
    gl.post_comment(32058, "Hello world")

    mr_dir = outbox / "32058"
    files = list(mr_dir.glob("*-comment.md"))
    assert len(files) == 1
    assert files[0].read_text() == "Hello world"

    log_lines = (outbox / "outbox.jsonl").read_text().splitlines()
    assert len(log_lines) == 1
    record = json.loads(log_lines[0])
    assert record["iid"] == 32058


def test_post_comment_unknown_mr_raises(tmp_path: Path) -> None:
    gl = MockGitLab(fixtures_path=FIXTURES, outbox_dir=tmp_path / "outbox")
    with pytest.raises(MockGitlabError):
        gl.post_comment(999999, "nope")
