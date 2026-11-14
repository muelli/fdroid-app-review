from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import code_quality as cq  # noqa: E402
import mr_evidence as ev  # noqa: E402

# The real recipe of the DozeOff merge request, as read from the API.
RECIPE = """Categories:
  - System
License: Apache-2.0
AuthorName: Cover Two Games

RepoType: git
Repo: https://github.com/covertwogames/dozeoff.git

Builds:
  - versionName: 2.0.3
    versionCode: 13
    commit: 75f98e92e0c0aaaaaaaaaaaaaaaaaaaaaaaaaaaa
    subdir: app
    gradle:
      - yes
  - versionName: 2.0.4
    versionCode: 14
    commit: e2e0a263c538f1ad3f2881116f2aa316c56d34ff
    subdir: app
    gradle:
      - yes

AutoUpdateMode: Version
"""
PIN = "e2e0a263c538f1ad3f2881116f2aa316c56d34ff"
REPO = "https://github.com/covertwogames/dozeoff.git"


def test_the_recipe_gives_repo_the_last_pinned_commit_and_categories() -> None:
    repo, commit, categories = ev.parse_recipe(RECIPE)
    assert repo == REPO and commit == PIN and categories == ["System"]
    assert ev.parse_recipe("") == (None, None, [])


def test_permalink_shapes_per_host_and_none_for_an_unknown_one() -> None:
    gh = "https://github.com/o/r.git"
    assert ev.permalink(gh, "abc") == "https://github.com/o/r/commit/abc"
    assert ev.permalink(gh, "abc", "a/b.txt") == "https://github.com/o/r/blob/abc/a/b.txt"
    assert (
        ev.permalink("https://gitlab.com/o/r", "abc", "x") == "https://gitlab.com/o/r/-/blob/abc/x"
    )
    assert ev.permalink("https://codeberg.org/o/r", "abc", "x") == (
        "https://codeberg.org/o/r/src/commit/abc/x"
    )
    assert ev.permalink("https://git.example.org/o/r", "abc") is None
    assert ev.permalink("not a url", "abc") is None


def _run(stdout: str, returncode: int = 0) -> Any:
    return lambda *a, **k: SimpleNamespace(stdout=stdout, returncode=returncode)


def test_an_annotated_tag_is_found_through_its_peeled_commit() -> None:
    out = (
        "1111111111111111111111111111111111111111\trefs/tags/v2.0.3\n"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/tags/v2.0.4\n"
        f"{PIN}\trefs/tags/v2.0.4^{{}}\n"
    )
    assert ev.tag_for_commit(REPO, PIN, _run(out)) == "v2.0.4"


def test_a_lightweight_tag_and_a_missing_tag() -> None:
    assert ev.tag_for_commit(REPO, PIN, _run(f"{PIN}\trefs/tags/v9\n")) == "v9"
    assert ev.tag_for_commit(REPO, PIN, _run("1" * 40 + "\trefs/tags/other\n")) is None
    assert ev.tag_for_commit(REPO, PIN, _run("", returncode=128)) is None


def test_a_timeout_or_missing_git_is_no_tag_not_a_crash() -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise OSError("no git")

    assert ev.tag_for_commit(REPO, PIN, boom) is None


MR = {
    "web_url": "https://gitlab.com/fdroid/fdroiddata/-/merge_requests/46633",
    "sha": "a6bfadfd1e8903b07e57b6a5599c543a16a91c5e",
    "source_project_id": 85679133,
    "head_pipeline": {
        "web_url": "https://gitlab.com/fdroid/fdroiddata/-/pipelines/1",
        "status": "success",
    },
}
FASTLANE = "Fastlane/Triple-T in en-US: summary (s), name (n), description (d)"
APK_LINK = "https://gitlab.com/fdroid/fdroiddata/-/jobs/9/artifacts/raw/tmp/signed/a_1.signed.apk"
CHANGES = {"changes": [{"new_path": "metadata/com.covertwogames.dozeoff.foss.yml"}]}


def _collect(resolving: set[str] | None = None, **kw: Any) -> ev.MrEvidence:
    def get_json(url: str) -> Any:
        return CHANGES if url.endswith("/changes") else MR

    report = cq.parse(
        {
            "new_errors": [
                {"description": f"Signed APK: {APK_LINK}"},
                {"description": FASTLANE},
            ]
        }
    )
    return ev.collect(
        46633,
        get_json=get_json,
        get_text=lambda url: RECIPE,
        code_quality=report,
        resolves_fn=(lambda u: True) if resolving is None else (lambda u: u in resolving),
        tag_fn=lambda repo, commit: "v2.0.4",
        **kw,
    )


def test_everything_is_collected_when_everything_resolves() -> None:
    e = _collect()
    assert e.pipeline_status == "success" and e.pipeline_url.endswith("/pipelines/1")
    assert e.apk_kind == "Signed APK" and e.apk_url.endswith("a_1.signed.apk")
    assert e.metadata_url == (
        f"https://gitlab.com/fdroid/fdroiddata/-/blob/{MR['sha']}"
        "/metadata/com.covertwogames.dozeoff.foss.yml"
    )
    assert e.categories == ["System"] and e.pinned_commit == PIN
    assert e.commit_url == f"https://github.com/covertwogames/dozeoff/commit/{PIN}"
    assert e.tag == "v2.0.4"
    assert e.tag_url == "https://github.com/covertwogames/dozeoff/tree/v2.0.4"
    assert e.descriptions == {
        "en-US": (
            f"https://github.com/covertwogames/dozeoff/blob/{PIN}"
            "/fastlane/metadata/android/en-US/full_description.txt"
        )
    }


def test_a_link_that_does_not_resolve_is_left_out_not_shown() -> None:
    e = _collect(resolving=set())
    assert e.commit_url is None and e.tag_url is None and e.descriptions == {}
    assert e.tag == "v2.0.4" and e.pinned_commit == PIN  # facts survive; only unverified links drop


def test_funding_files_are_reported_only_when_they_exist() -> None:
    funding = f"https://github.com/covertwogames/dozeoff/blob/{PIN}/.github/FUNDING.yml"
    assert _collect(resolving={funding}).funding_files == [funding]
    assert _collect(resolving=set()).funding_files == []


def test_a_merge_request_without_a_pipeline_or_report_still_collects() -> None:
    def get_json(url: str) -> Any:
        if url.endswith("/changes"):
            return {"changes": []}
        return {"web_url": "https://x/mr/1", "sha": None}

    e = ev.collect(1, get_json=get_json, get_text=lambda u: "", code_quality=None)
    assert e.mr_url == "https://x/mr/1" and e.pipeline_url is None and e.apk_url is None


def test_tag_links_per_host_never_use_the_commit_form() -> None:
    assert ev.tag_link("https://github.com/o/r.git", "v1") == "https://github.com/o/r/tree/v1"
    assert ev.tag_link("https://gitlab.com/o/r", "v1") == "https://gitlab.com/o/r/-/tree/v1"
    assert ev.tag_link("https://codeberg.org/o/r", "v1") == "https://codeberg.org/o/r/src/tag/v1"
    assert ev.tag_link("https://git.example.org/o/r", "v1") is None


def test_the_link_is_to_the_apk_that_was_tested_when_a_merge_request_builds_several() -> None:
    """Seen on !45651: one build per ABI, 109021 (armeabi-v7a) listed before 109022 (arm64-v8a)."""
    first = (
        "https://gitlab.com/fdroid/fdroiddata/-/jobs/9/artifacts/raw/tmp/signed/a_109021.signed.apk"
    )
    second = (
        "https://gitlab.com/fdroid/fdroiddata/-/jobs/9/artifacts/raw/tmp/signed/a_109022.signed.apk"
    )
    report = cq.parse(
        {
            "new_errors": [
                {"description": f"Signed APK: {first}"},
                {"description": f"Signed APK: {second}"},
            ]
        }
    )

    def build(name: str | None) -> ev.MrEvidence:
        return ev.collect(
            46633,
            get_json=lambda url: CHANGES if url.endswith("/changes") else MR,
            get_text=lambda url: RECIPE,
            code_quality=report,
            resolves_fn=lambda u: True,
            tag_fn=lambda repo, commit: None,
            apk_name=name,
        )

    assert build("a_109022.signed.apk").apk_url == second
    assert build("a_109021.signed.apk").apk_url == first
    assert build("not-in-the-report.apk").apk_url == first  # falls back to the first, as before
    assert build(None).apk_url == first
