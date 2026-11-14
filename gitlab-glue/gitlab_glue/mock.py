"""Fixture-driven GitLab adapter. Used everywhere by default.

Never contacts any network. Merge requests come from a JSON fixture file;
posted comments are written to an outbox directory instead of a real
project, so `make dev` and `make demo` can be inspected on disk afterwards.
"""

from __future__ import annotations

import itertools
import json
import time
from dataclasses import asdict
from pathlib import Path

from gitlab_glue.base import GitLabAdapter, MergeRequestInfo


class MockGitlabError(Exception):
    pass


class MockGitLab(GitLabAdapter):
    def __init__(self, fixtures_path: Path, outbox_dir: Path) -> None:
        self._fixtures_path = fixtures_path
        self._outbox_dir = outbox_dir
        self._outbox_dir.mkdir(parents=True, exist_ok=True)
        self._mrs: dict[int, MergeRequestInfo] = self._load_fixtures(fixtures_path)
        # Comment filenames are timestamp-based for readability in the
        # outbox, but two comments posted within the same second (e.g. the
        # evidence comment immediately followed by the review checklist)
        # would otherwise collide and silently overwrite each other.
        self._comment_seq = itertools.count()

    @staticmethod
    def _load_fixtures(fixtures_path: Path) -> dict[int, MergeRequestInfo]:
        raw = json.loads(fixtures_path.read_text(encoding="utf-8"))
        result: dict[int, MergeRequestInfo] = {}
        for entry in raw["merge_requests"]:
            mr = MergeRequestInfo(
                iid=entry["iid"],
                title=entry["title"],
                web_url=entry["web_url"],
                author_username=entry["author_username"],
                source_branch=entry["source_branch"],
                target_branch=entry.get("target_branch", "master"),
                created_at=entry["created_at"],
                labels=tuple(entry.get("labels", ())),
                pipeline_status=entry.get("pipeline_status", "unknown"),
                package_name=entry.get("package_name"),
            )
            result[mr.iid] = mr
        return result

    def get_merge_request(self, iid: int) -> MergeRequestInfo:
        try:
            return self._mrs[iid]
        except KeyError as exc:
            raise MockGitlabError(f"no fixture merge request with iid={iid}") from exc

    def list_review_request_mrs(self) -> list[MergeRequestInfo]:
        return sorted(self._mrs.values(), key=lambda mr: mr.iid)

    def post_comment(self, iid: int, body: str) -> None:
        if iid not in self._mrs:
            raise MockGitlabError(f"no fixture merge request with iid={iid}")
        mr_dir = self._outbox_dir / str(iid)
        mr_dir.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        seq = next(self._comment_seq)
        comment_path = mr_dir / f"{timestamp}-{seq:04d}-comment.md"
        comment_path.write_text(body, encoding="utf-8")

        log_path = self._outbox_dir / "outbox.jsonl"
        record = {
            "iid": iid,
            "posted_at": timestamp,
            "path": str(comment_path.relative_to(self._outbox_dir)),
        }
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

    def as_json(self) -> str:
        """Render the current MR list as JSON, for the dashboard queue feed."""
        return json.dumps(
            [asdict(mr) for mr in self.list_review_request_mrs()],
            indent=2,
        )
