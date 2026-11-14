"""What an fdroiddata merge request's comments already say about its review.

Pure functions over the notes GitLab returns, no network: `fetch_review_queue.py`
fetches the notes and shows the result in the queue page, and `quick_review.py`
can print it before a volunteer spends time duplicating it.

Everything here is a heuristic over free text, so it reports facts (who wrote
what, when, with a link) and a coarse level, never a verdict. A reviewer's claim
of an on-device test is a claim: nothing here checks that it happened.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Shorter comments are discussion, not a review.
MIN_REVIEW_CHARS = 250

# Stems, not whole words: a first version required a word boundary after "reproducib" and so
# never matched "reproducible", which hid a real on-device test from the queue page.
_REVIEW_RE = re.compile(
    r"(?i)\b(review\w*|verdict|lgtm|looks good|blocked|ready to merge|approved"
    r"|reproducib\w*|test(ed|ing)?)\b"
)
_DEVICE_RE = re.compile(
    r"(?i)(tested on device|on[- ]device|on a (real )?(phone|device)"
    r"|on my (phone|device|pixel)|real device|\bpixel \d|samsung|galaxy [a-z]\d|emulator|\bAVD\b)"
)
# A segment that mentions a device only to say it was not tested ("on-device items still
# need a tester") must not count as a device test. Deliberately broad: wrongly counting a
# merge request as device-tested makes volunteers skip it, while wrongly not counting one
# only costs a volunteer some time.
_NEGATION_RE = re.compile(
    r"(?i)(\b(not|no|never|none|unable|without|cannot|untested|todo|n/a)\b|n't"
    r"|still need|needs? a tester|to be tested|out of scope|impossible)"
)
_SEGMENT_RE = re.compile(r"[\n.!?]+")
_LI_RE = re.compile(r"<li>(.*?)</li>", re.S)
_FROM_BRANCH_RE = re.compile(r"\d+ commits? from branch")

# Ordered from least to most covered; the queue page sorts by it.
LEVELS = ("none", "static", "device-stale", "device")


@dataclass(frozen=True, slots=True)
class ReviewNote:
    note_id: int
    author: str
    created_at: str
    device_test: bool
    url: str


@dataclass(frozen=True, slots=True)
class Coverage:
    level: str
    reviews: list[ReviewNote]
    changed_since_last_device: bool
    changed_since_last_review: bool
    notes_seen: int

    @property
    def device_tests(self) -> list[ReviewNote]:
        return [r for r in self.reviews if r.device_test]


def claims_device_test(body: str) -> bool:
    return any(
        _DEVICE_RE.search(segment) and not _NEGATION_RE.search(segment)
        for segment in _SEGMENT_RE.split(body)
    )


def own_commit_subjects(system_body: str) -> list[str]:
    """The subjects of the merge request's own commits in an "added N commits"
    system note, leaving out the "N commits from branch fdroid:master" line.
    """
    if not system_body.startswith("added"):
        return []
    subjects = []
    for item in _LI_RE.findall(system_body):
        if _FROM_BRANCH_RE.search(item):
            continue
        subjects.append(item.split(" - ", 1)[-1].strip())
    return subjects


def summarise(notes: list[dict[str, Any]], mr_author: str, web_url: str) -> Coverage:
    """`notes` as returned by GitLab's notes API, oldest first."""
    reviews: list[ReviewNote] = []
    change_times: list[str] = []
    # A rebase re-lists every one of the merge request's own commits, with new hashes
    # and the same subjects. Only a subject not seen before counts as a change, so a
    # rebase after a review does not make it look stale. (A force-push that keeps the
    # subjects but changes the content cannot be told apart this way.)
    seen_subjects: set[str] = set()
    for note in notes:
        created = str(note.get("created_at", ""))
        body = str(note.get("body") or "")
        if note.get("system"):
            subjects = own_commit_subjects(body)
            if any(subject not in seen_subjects for subject in subjects):
                change_times.append(created)
            seen_subjects.update(subjects)
            continue
        author = str((note.get("author") or {}).get("username", ""))
        if author == mr_author or len(body) < MIN_REVIEW_CHARS:
            continue
        device_test = claims_device_test(body)
        if not (device_test or _REVIEW_RE.search(body)):
            continue
        reviews.append(
            ReviewNote(
                note_id=int(note["id"]),
                author=author,
                created_at=created,
                device_test=device_test,
                url=f"{web_url}#note_{int(note['id'])}",
            )
        )

    device = [r for r in reviews if r.device_test]
    last_device = max((r.created_at for r in device), default=None)
    last_review = max((r.created_at for r in reviews), default=None)
    changed_since_device = last_device is not None and any(t > last_device for t in change_times)
    changed_since_review = last_review is not None and any(t > last_review for t in change_times)

    if not reviews:
        level = "none"
    elif not device:
        level = "static"
    elif changed_since_device:
        level = "device-stale"
    else:
        level = "device"
    return Coverage(
        level=level,
        reviews=reviews,
        changed_since_last_device=changed_since_device,
        changed_since_last_review=changed_since_review,
        notes_seen=len(notes),
    )


def describe(coverage: Coverage) -> list[str]:
    """Short plain-text lines for a terminal or a report."""
    if coverage.level == "none":
        return ["No review-like comments yet."]
    lines = [f"{len(coverage.reviews)} review-like comment(s); "
             f"{len(coverage.device_tests)} claim an on-device or emulator test."]
    for label, notes in (("latest on-device test claim", coverage.device_tests),
                         ("latest review-like comment", coverage.reviews)):
        if notes:
            latest = max(notes, key=lambda r: r.created_at)
            lines.append(f"{label}: {latest.author}, {latest.created_at[:10]}: {latest.url}")
    if coverage.level == "device-stale":
        lines.append("The merge request itself changed after the latest on-device test claim.")
    elif coverage.level == "static" and coverage.changed_since_last_review:
        lines.append("The merge request itself changed after the latest review.")
    lines.append("These are claims read from free text; nothing here verified them.")
    return lines
