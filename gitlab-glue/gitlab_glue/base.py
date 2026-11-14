"""GitLab adapter interface.

Every caller (the broker, the dashboard feed) programs against
`GitLabAdapter`. `MockGitLab` is the only implementation used by tests and
default config; `RealGitLab` requires explicit non-default configuration.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class MergeRequestInfo:
    """The subset of merge request metadata this system needs."""

    iid: int
    title: str
    web_url: str
    author_username: str
    source_branch: str
    target_branch: str
    created_at: str
    labels: tuple[str, ...] = field(default_factory=tuple)
    pipeline_status: str = "unknown"
    package_name: str | None = None


class GitLabAdapter(abc.ABC):
    """Read merge request state and post review evidence back to it."""

    @abc.abstractmethod
    def get_merge_request(self, iid: int) -> MergeRequestInfo:
        """Fetch a single merge request by internal id (iid)."""

    @abc.abstractmethod
    def list_review_request_mrs(self) -> list[MergeRequestInfo]:
        """List merge requests currently waiting for a human review session."""

    @abc.abstractmethod
    def post_comment(self, iid: int, body: str) -> None:
        """Post a Markdown comment (note) on the given merge request."""
