"""Render the two Markdown outputs this system posts to a merge request.

Templates are plain Markdown files with `$placeholder` substitution
(`string.Template`), kept in `gitlab_glue/templates/` so a deployment can
swap wording without touching Python.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from string import Template


def _load(name: str) -> Template:
    text = resources.files("gitlab_glue.templates").joinpath(name).read_text(encoding="utf-8")
    return Template(text)


@dataclass(frozen=True, slots=True)
class EvidenceCommentContext:
    mr_iid: int
    reviewer_username: str
    session_id: str
    started_at: str
    ended_at: str
    duration_minutes: int
    screen_recording_ref: str
    network_summary: str
    evidence_bundle_url: str
    logcat_excerpt: str


def render_evidence_comment(ctx: EvidenceCommentContext) -> str:
    template = _load("evidence_comment.md.tmpl")
    return template.substitute(
        mr_iid=ctx.mr_iid,
        reviewer_username=ctx.reviewer_username,
        session_id=ctx.session_id,
        started_at=ctx.started_at,
        ended_at=ctx.ended_at,
        duration_minutes=ctx.duration_minutes,
        screen_recording_ref=ctx.screen_recording_ref,
        network_summary=ctx.network_summary,
        evidence_bundle_url=ctx.evidence_bundle_url,
        logcat_excerpt=ctx.logcat_excerpt,
    )


@dataclass(frozen=True, slots=True)
class ReviewTemplateContext:
    mr_iid: int
    build_status: str
    version_tag_match: str
    permissions: tuple[str, ...] = ()
    network_endpoints: tuple[str, ...] = ()
    # Findings a tool already has, listed above the reviewer's own space for concerns.
    auto_concerns: tuple[str, ...] = ()
    # More (label, value) rows for the evidence table, e.g. a file hash or the languages.
    extra_rows: tuple[tuple[str, str], ...] = ()
    # One line, for a human to settle: "Good for inclusion", "More testing needed" or
    # "Unfit for inclusion". The tool never decides it.
    verdict: str = "_(good for inclusion / more testing needed / unfit for inclusion)_"

    @property
    def permission_list(self) -> str:
        return ", ".join(self.permissions) if self.permissions else "not automatically extracted"

    @property
    def network_endpoints_observed(self) -> str:
        return ", ".join(self.network_endpoints) if self.network_endpoints else "none observed"


def render_review_template(ctx: ReviewTemplateContext) -> str:
    template = _load("review_template.md.tmpl")
    return template.substitute(
        mr_iid=ctx.mr_iid,
        build_status=ctx.build_status,
        version_tag_match=ctx.version_tag_match,
        permission_list=ctx.permission_list,
        verdict=ctx.verdict,
        extra_rows="".join(f"| {label} | {value} |\n" for label, value in ctx.extra_rows),
        network_endpoints_observed=ctx.network_endpoints_observed,
        concerns_placeholder="\n".join(
            [*(f"- {concern}" for concern in ctx.auto_concerns), "", "_(fill in)_"]
        ).lstrip("\n")
        if ctx.auto_concerns
        else "_(fill in)_",
        free_text_placeholder="_(fill in)_",
    )
