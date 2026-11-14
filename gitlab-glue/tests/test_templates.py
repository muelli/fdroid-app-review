from pathlib import Path

from gitlab_glue.rendering import (
    EvidenceCommentContext,
    ReviewTemplateContext,
    render_evidence_comment,
    render_review_template,
)

GOLDEN = Path(__file__).parent / "golden"


def test_evidence_comment_matches_golden() -> None:
    ctx = EvidenceCommentContext(
        mr_iid=32058,
        reviewer_username="alice",
        session_id="sess-abc123",
        started_at="2026-09-17T10:00:00Z",
        ended_at="2026-09-17T10:22:00Z",
        duration_minutes=22,
        screen_recording_ref="https://broker.example/evidence/sess-abc123/screen_recording.mp4",
        network_summary="3 distinct hosts contacted; see network log",
        evidence_bundle_url="https://broker.example/evidence/sess-abc123/bundle.zip",
        logcat_excerpt=(
            "I/FakeRuntime: session sess-abc123 started\nI/FakeRuntime: session torn down"
        ),
    )
    rendered = render_evidence_comment(ctx)
    expected = (GOLDEN / "evidence_comment.md").read_text()
    assert rendered == expected


def test_review_template_matches_golden() -> None:
    ctx = ReviewTemplateContext(
        mr_iid=32058,
        build_status="success",
        version_tag_match="yes (1.2.3 == v1.2.3)",
        permissions=("INTERNET", "ACCESS_NETWORK_STATE"),
        network_endpoints=("f-droid.org:443",),
    )
    rendered = render_review_template(ctx)
    expected = (GOLDEN / "review_template.md").read_text()
    assert rendered == expected


def test_review_template_defaults_to_none_observed() -> None:
    ctx = ReviewTemplateContext(mr_iid=1, build_status="failed", version_tag_match="unknown")
    rendered = render_review_template(ctx)
    assert "none observed" in rendered


def test_review_template_contains_the_official_tester_table_verbatim() -> None:
    """F-Droid's own tester template (the wiki's "Reviewing new apps"), unedited, so a
    review posted with it looks like every other reviewer's.
    """
    official = (GOLDEN / "official_tester_table.html").read_text().strip()
    ctx = ReviewTemplateContext(mr_iid=1, build_status="x", version_tag_match="y")
    rendered = render_review_template(ctx)
    assert official in rendered
    # 3 + 3 + 2 + 7 + 1 + 1 boxes, all left for the reviewer: the tool ticks nothing.
    assert rendered.count("- [ ] ") == official.count("- [ ] ") == 17
    assert "- [x]" not in rendered.lower()


def test_extra_rows_land_in_the_evidence_table() -> None:
    ctx = ReviewTemplateContext(
        mr_iid=1,
        build_status="x",
        version_tag_match="y",
        extra_rows=(("APK SHA-256", "`abc`"), ("Languages", "en, de")),
    )
    rendered = render_review_template(ctx)
    assert "| APK SHA-256 | `abc` |\n| Languages | en, de |\n" in rendered
    evidence, _, checklist = rendered.partition("### Reviewer checklist")
    assert "APK SHA-256" in evidence and "APK SHA-256" not in checklist


def test_the_verdict_is_a_placeholder_unless_a_human_sets_it() -> None:
    base = {"mr_iid": 1, "build_status": "x", "version_tag_match": "y"}
    plain = render_review_template(ReviewTemplateContext(**base))
    assert plain.splitlines()[2] == (
        "**Verdict:** _(good for inclusion / more testing needed / unfit for inclusion)_"
    )
    chosen = render_review_template(ReviewTemplateContext(**base, verdict="Good for inclusion"))
    assert chosen.splitlines()[2] == "**Verdict:** Good for inclusion"
