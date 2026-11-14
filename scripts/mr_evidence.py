"""The links a review's claims can point at, so a reader can check them.

Given a merge request, this gathers: its head pipeline and the CI-built APK, the metadata
file at the head commit, the upstream commit the recipe pins and the release tag that
points at it, and the Fastlane description files at that commit (the description a tester
checks the app against). Every upstream link is fetched before it is included: a link that
does not resolve is left out rather than shown. Network code takes its HTTP functions as
arguments so it can be tested without the network.
"""

from __future__ import annotations

import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

GITLAB_MR_BASE = "https://gitlab.com/fdroid/fdroiddata/-/merge_requests"
POLICY = "https://f-droid.org/docs/Inclusion_Policy/"
POLICY_QUALITY = POLICY + "#quality-control"
POLICY_SECURITY_LEGAL = POLICY + "#security--legal-compliance"
POLICY_FREE_SOFTWARE = POLICY + "#free-software-requirement"
CATEGORIES_DOC = "https://f-droid.org/docs/Build_Metadata_Reference/#Categories"

_REPO_RE = re.compile(r"^Repo:\s*(\S+)\s*$", re.M)
_COMMIT_RE = re.compile(r"^\s*commit:\s*([0-9a-fA-F]{7,40})\s*$", re.M)
_CATEGORIES_RE = re.compile(r"^Categories:\s*\n((?:\s+-\s*.+\n?)+)", re.M)


@dataclass(frozen=True, slots=True)
class MrEvidence:
    mr_url: str
    head_sha: str | None = None
    pipeline_url: str | None = None
    pipeline_status: str | None = None
    apk_url: str | None = None
    apk_kind: str | None = None
    metadata_url: str | None = None
    categories: list[str] = field(default_factory=list)
    repo_url: str | None = None
    pinned_commit: str | None = None
    commit_url: str | None = None
    tag: str | None = None
    tag_url: str | None = None
    # locale -> permalink to the full description at the pinned commit (verified to resolve)
    descriptions: dict[str, str] = field(default_factory=dict)
    funding_files: list[str] = field(default_factory=list)


def parse_recipe(text: str) -> tuple[str | None, str | None, list[str]]:
    """(repo, the commit of the last build entry, categories) from a metadata file."""
    repo = _REPO_RE.search(text)
    commits = _COMMIT_RE.findall(text)
    categories: list[str] = []
    block = _CATEGORIES_RE.search(text)
    if block is not None:
        categories = [line.strip().lstrip("-").strip() for line in block.group(1).splitlines()]
    return (repo.group(1) if repo else None, commits[-1] if commits else None, categories)


def _split_repo(repo_url: str) -> tuple[str, str, str] | None:
    """(host, owner/name) from an https repo URL, minus a trailing .git."""
    match = re.match(r"^https://([\w.-]+)/([\w.-]+/[\w.-]+?)(?:\.git)?/?$", repo_url)
    if match is None:
        return None
    return "https", match.group(1), match.group(2)


def permalink(repo_url: str, commit: str, path: str | None = None) -> str | None:
    """A link to the commit, or to a file at that commit, on the hosts whose URL shape is
    known. None for any other host: no guess is better than a broken link.
    """
    split = _split_repo(repo_url)
    if split is None:
        return None
    _, host, name = split
    suffix = f"/{path}" if path else ""
    if host == "github.com":
        return f"https://github.com/{name}/{'blob' if path else 'commit'}/{commit}{suffix}"
    if host == "gitlab.com":
        return f"https://gitlab.com/{name}/-/{'blob' if path else 'commit'}/{commit}{suffix}"
    if host == "codeberg.org":
        return f"https://codeberg.org/{name}/{'src/commit' if path else 'commit'}/{commit}{suffix}"
    return None


def tag_link(repo_url: str, tag: str) -> str | None:
    """A link to the tagged tree. Not `/commit/<tag>`: that is a 404 on GitHub."""
    split = _split_repo(repo_url)
    if split is None:
        return None
    _, host, name = split
    if host == "github.com":
        return f"https://github.com/{name}/tree/{tag}"
    if host == "gitlab.com":
        return f"https://gitlab.com/{name}/-/tree/{tag}"
    if host == "codeberg.org":
        return f"https://codeberg.org/{name}/src/tag/{tag}"
    return None


def tag_for_commit(
    repo_url: str, commit: str, run: Callable[..., Any] = subprocess.run
) -> str | None:
    """The release tag that points at `commit`, via `git ls-remote` (any host, no API)."""
    try:
        result = run(
            ["git", "ls-remote", "--tags", repo_url],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin:/usr/local/bin"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    found = None
    for line in result.stdout.splitlines():
        sha, _, ref = line.partition("\t")
        if not ref.startswith("refs/tags/") or not sha.startswith(commit[:7]):
            continue
        # An annotated tag is listed twice: the tag object, then the commit it points at
        # as `name^{}`. Only the commit's line matches `commit`, and both name the tag.
        found = ref[len("refs/tags/") :].removesuffix("^{}")
    return found


def resolves(url: str, opener: Callable[..., Any] = urllib.request.urlopen) -> bool:
    request = urllib.request.Request(
        url, method="HEAD", headers={"User-Agent": "fdroid-review-session"}
    )
    try:
        with opener(request, timeout=20) as response:
            return int(response.status) == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def collect(
    iid: int,
    *,
    get_json: Callable[[str], Any],
    get_text: Callable[[str], str],
    code_quality: Any,
    resolves_fn: Callable[[str], bool] = resolves,
    tag_fn: Callable[[str, str], str | None] = tag_for_commit,
    apk_name: str | None = None,
) -> MrEvidence:
    """Everything is best-effort: whatever cannot be found or verified is simply absent.

    `apk_name` is the file name of the APK being tested: a merge request can build several (one
    per ABI, say), and the link must be to the one that was reviewed, not the first listed.
    """
    api = "https://gitlab.com/api/v4/projects/fdroid%2Ffdroiddata"
    mr = get_json(f"{api}/merge_requests/{iid}")
    pipeline = mr.get("head_pipeline") or {}
    evidence: dict[str, Any] = {
        "mr_url": mr.get("web_url") or f"{GITLAB_MR_BASE}/{iid}",
        "head_sha": mr.get("sha"),
        "pipeline_url": pipeline.get("web_url"),
        "pipeline_status": pipeline.get("status"),
    }
    if code_quality is not None and code_quality.apks:
        built = next(
            (a for a in code_quality.apks if apk_name and a.url.rsplit("/", 1)[-1] == apk_name),
            code_quality.apks[0],
        )
        evidence["apk_url"] = built.url
        evidence["apk_kind"] = built.kind

    changes = get_json(f"{api}/merge_requests/{iid}/changes")
    metadata_path = next(
        (
            c["new_path"]
            for c in changes.get("changes", [])
            if re.fullmatch(r"metadata/[\w.-]+\.yml", c.get("new_path", ""))
        ),
        None,
    )
    if metadata_path is not None and mr.get("sha"):
        evidence["metadata_url"] = (
            f"https://gitlab.com/fdroid/fdroiddata/-/blob/{mr['sha']}/{metadata_path}"
        )
        raw = get_text(
            f"https://gitlab.com/api/v4/projects/{mr['source_project_id']}/repository/files/"
            f"{urllib.parse.quote(metadata_path, safe='')}/raw?ref={mr['sha']}"
        )
        repo, commit, categories = parse_recipe(raw)
        evidence["categories"] = categories
        evidence["repo_url"] = repo
        if repo and commit:
            evidence["pinned_commit"] = commit
            commit_link = permalink(repo, commit)
            if commit_link and resolves_fn(commit_link):
                evidence["commit_url"] = commit_link
            tag = tag_fn(repo, commit)
            if tag:
                evidence["tag"] = tag
                link = tag_link(repo, tag)
                if link and resolves_fn(link):
                    evidence["tag_url"] = link
            locales = list(code_quality.fastlane) if code_quality is not None else ["en-US"]
            descriptions: dict[str, str] = {}
            for locale in locales or ["en-US"]:
                path = f"fastlane/metadata/android/{locale}/full_description.txt"
                link = permalink(repo, commit, path)
                if link and resolves_fn(link):
                    descriptions[locale] = link
            evidence["descriptions"] = descriptions
            funding = []
            for path in (".github/FUNDING.yml", "FUNDING.yml", "funding.json"):
                link = permalink(repo, commit, path)
                if link and resolves_fn(link):
                    funding.append(link)
            evidence["funding_files"] = funding
    return MrEvidence(**evidence)
