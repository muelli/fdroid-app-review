from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import review_coverage as rc  # noqa: E402

URL = "https://gitlab.com/fdroid/fdroiddata/-/merge_requests/43883"
FILLER = " Permissions map to the stated use and the build is reproducible. " * 6

# Shapes taken from the real merge request, shortened.
DEVICE_REVIEW = (
    "Community review — tested on device (Samsung SM-G998B, Android 15 / One UI 7).\n\n"
    "**On-device test**\n- Installs and launches to a clean setup screen.\n" + FILLER
)
STATIC_REVIEW = (
    "@linsui Static review (CI artifacts + upstream source); on-device items still need "
    "a tester.\n\n**Maintainer review**\n\nNo blocking findings:" + FILLER
)
EMULATOR_REVIEW = (
    "## Tester review — `site.warpnet.warpdroid` (0.7.475)\n\n"
    "Tested on an Android 15 (API 35) emulator over `adb`." + FILLER
)
NEW_COMMIT = (
    "added 1 commit\n\n<ul><li>123d193f - New App: Flywheel</li></ul>\n\n"
    "[Compare with previous version](/fdroid/fdroiddata/-/merge_requests/43883/diffs)"
)
MASTER_MERGE_AND_OWN = (
    "added 59 commits\n\n<ul><li>86ad0be5...68e9ae4d - 58 commits from branch "
    "<code>fdroid:master</code></li><li>4403b46d - New App: Flywheel</li></ul>"
)
REBASE = (
    "added 7594 commits\n\n<ul><li>d89cc90d...344600da - 7589 commits from branch "
    "<code>fdroid:master</code></li><li>4a86ba12 - New App: Flywheel</li></ul>"
)
UPDATE_COMMIT = "added 1 commit\n\n<ul><li>72a4d872 - Update Flywheel to 1.1.1</li></ul>"


def note(
    nid: int, body: str, when: str, author: str = "someone", system: bool = False
) -> dict[str, Any]:
    return {
        "id": nid,
        "body": body,
        "created_at": f"2026-{when}:00.000Z",
        "system": system,
        "author": {"username": author},
    }


def summarise(*notes: dict[str, Any]) -> rc.Coverage:
    return rc.summarise(list(notes), "the-author", URL)


def test_no_notes_is_level_none() -> None:
    cov = summarise()
    assert cov.level == "none" and cov.reviews == []
    assert rc.describe(cov) == ["No review-like comments yet."]


def test_a_device_claim_is_recognised_and_linked() -> None:
    cov = summarise(note(1, DEVICE_REVIEW, "10-15T19:25", "sookoothaii1"))
    assert cov.level == "device"
    assert cov.device_tests[0].url == f"{URL}#note_1"
    assert cov.device_tests[0].author == "sookoothaii1"


def test_an_emulator_test_counts_as_a_device_claim() -> None:
    assert summarise(note(1, EMULATOR_REVIEW, "09-21T10:00")).level == "device"


def test_still_needs_a_tester_is_a_static_review_not_a_device_test() -> None:
    cov = summarise(note(1, STATIC_REVIEW, "10-06T14:38"))
    assert cov.level == "static" and len(cov.reviews) == 1 and not cov.device_tests


def test_negated_mentions_do_not_count() -> None:
    for sentence in (
        "On-device testing was not possible here.",
        "I did not test it on a real device.",
        "Not tested on device yet.",
        "On-device checks: n/a.",
        "Needs a tester with a real device.",
    ):
        assert not rc.claims_device_test(sentence), sentence
    assert rc.claims_device_test("Tested on a Pixel 6a.")


def test_short_comments_and_the_authors_own_are_not_reviews() -> None:
    cov = summarise(
        note(1, "Please add the reason", "08-14T04:00", "maintainer"),
        note(2, DEVICE_REVIEW, "08-15T04:00", "the-author"),
        note(3, "A long comment without the keywords. " * 20, "08-16T04:00", "chatty"),
    )
    assert cov.level == "none"


def test_a_real_change_after_the_device_test_makes_it_stale() -> None:
    cov = summarise(
        note(1, NEW_COMMIT, "07-26T16:52", system=True),
        note(2, DEVICE_REVIEW, "10-15T19:25", "r"),
        note(3, UPDATE_COMMIT, "10-20T08:00", system=True),
    )
    assert cov.level == "device-stale" and cov.changed_since_last_device
    assert "changed after the latest on-device" in " ".join(rc.describe(cov))


def test_a_rebase_after_a_review_is_not_a_change() -> None:
    cov = summarise(
        note(1, MASTER_MERGE_AND_OWN, "07-26T16:46", system=True),
        note(2, DEVICE_REVIEW, "10-15T19:25", "r"),
        note(3, REBASE, "10-15T19:33", system=True),  # same subject, new hash
    )
    assert cov.level == "device" and not cov.changed_since_last_device


def test_a_change_before_the_review_does_not_make_it_stale() -> None:
    cov = summarise(
        note(1, UPDATE_COMMIT, "08-13T18:29", system=True),
        note(2, STATIC_REVIEW, "10-06T14:38", "r"),
    )
    assert cov.level == "static" and not cov.changed_since_last_review


def test_own_commit_subjects_leave_out_the_master_line() -> None:
    assert rc.own_commit_subjects(MASTER_MERGE_AND_OWN) == ["New App: Flywheel"]
    assert rc.own_commit_subjects("resolved all threads") == []


def test_the_latest_of_several_reviews_is_the_one_described() -> None:
    cov = summarise(
        note(1, DEVICE_REVIEW, "09-01T10:00", "early"),
        note(2, DEVICE_REVIEW, "10-01T10:00", "later"),
    )
    text = " ".join(rc.describe(cov))
    assert "later, 2026-10-01" in text and "early" not in text
    assert "claims read from free text" in text


# From the real merge request for PC HW Monitor, shortened. An earlier version of the keyword
# filter missed it ("reproducible" never matched), so the queue showed no on-device test.
ONDEVICE_NOTE = (
    "On-device test of 1.6.1 (versionCode 8).\n\n**Build & packaging (all 9 jobs green)**\n"
    "- Tag `v1.6.1` resolves to the full-hash recipe commit `4739729f`.\n"
    "- **Finding:** the recipe sets `AllowedAPKSigningKeys` but has no `Binaries` URL. The "
    "`reproducible-builds` label is on the MR, but RB isn't exercised yet.\n\n"
    "**On-device test (Samsung SM-G998B, Android 15 / One UI 7)**\n"
    "- `PcHwMonitor-v1.6.1.apk` installs and launches to a localized empty state. "
    "No crashes in logcat.\n" + "Further detail on the manifest permissions. " * 6
)


def test_the_pc_hw_monitor_note_is_a_device_review() -> None:
    cov = summarise(note(1, ONDEVICE_NOTE, "10-15T18:20", "sookoothaii1"))
    assert cov.level == "device" and cov.device_tests[0].author == "sookoothaii1"


def test_review_keywords_match_their_stems() -> None:
    for word in ("reviewed", "reviews", "reproducible", "reproducibility", "testing", "tested"):
        assert rc._REVIEW_RE.search(word), word


def test_a_long_device_claim_counts_even_without_a_review_keyword() -> None:
    body = "Ran it on a Pixel 6a and it opens to the home screen and stays up. " * 6
    assert summarise(note(1, body, "10-15T18:20", "r")).level == "device"


def test_a_long_unrelated_comment_still_does_not_count() -> None:
    chatter = "Please rebase on master and squash. " * 15
    assert summarise(note(1, chatter, "10-15T18:20")).level == "none"
