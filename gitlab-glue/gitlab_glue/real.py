"""Live GitLab adapter. Not used by any test, `make dev` or `make demo`.

Requires a `RealGitLabConfig` to be constructed explicitly with a base URL,
an OAuth token and a project path; nothing in this repository's default
configuration provides one. This is the only module in the whole system
that performs a real, write-capable GitLab API call.
"""

from __future__ import annotations

from dataclasses import dataclass

import gitlab

from gitlab_glue.base import GitLabAdapter, MergeRequestInfo


@dataclass(frozen=True, slots=True)
class RealGitLabConfig:
    base_url: str
    oauth_token: str
    project_path: str
    review_request_label: str = "Needs Testing"


class RealGitLab(GitLabAdapter):
    def __init__(self, config: RealGitLabConfig) -> None:
        self._config = config
        self._gl = gitlab.Gitlab(config.base_url, oauth_token=config.oauth_token)
        self._project = self._gl.projects.get(config.project_path)

    def _to_info(self, mr: object) -> MergeRequestInfo:
        pipelines = mr.pipelines.list(get_all=False)  # type: ignore[attr-defined]
        pipeline_status = pipelines[0].status if pipelines else "unknown"
        return MergeRequestInfo(
            iid=mr.iid,  # type: ignore[attr-defined]
            title=mr.title,  # type: ignore[attr-defined]
            web_url=mr.web_url,  # type: ignore[attr-defined]
            author_username=mr.author["username"],  # type: ignore[attr-defined]
            source_branch=mr.source_branch,  # type: ignore[attr-defined]
            target_branch=mr.target_branch,  # type: ignore[attr-defined]
            created_at=mr.created_at,  # type: ignore[attr-defined]
            labels=tuple(mr.labels),  # type: ignore[attr-defined]
            pipeline_status=pipeline_status,
        )

    def get_merge_request(self, iid: int) -> MergeRequestInfo:
        mr = self._project.mergerequests.get(iid)
        return self._to_info(mr)

    def list_review_request_mrs(self) -> list[MergeRequestInfo]:
        mrs = self._project.mergerequests.list(
            state="opened",
            labels=[self._config.review_request_label],
            get_all=True,
        )
        return [self._to_info(mr) for mr in mrs]

    def post_comment(self, iid: int, body: str) -> None:
        mr = self._project.mergerequests.get(iid)
        mr.notes.create({"body": body})
