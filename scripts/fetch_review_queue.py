#!/usr/bin/env python3
"""Fetch the real, currently open F-Droid "review requested" merge request
queue from gitlab.com/fdroid/fdroiddata, download the built APK for the N
oldest (default 20 — there are 200+ open at any time, and downloading
every one of them on every run would mean hundreds of GitLab API calls
and potentially several GB of transfer), and render a single searchable
HTML page listing all of them.

Stateless by design, safe to run from cron: every run re-fetches the
whole queue from scratch and overwrites --output-dir. There is no
"what's new since last time" tracking and no persisted seen-set — if you
want that, diff two runs' index.json against each other.

Usage:
    uv run scripts/fetch_review_queue.py
    uv run scripts/fetch_review_queue.py --limit 50 --output-dir /var/www/review-queue

Everything here talks to gitlab.com's public API and public CI job logs
for this public project, and needs no credentials. Without any, about ten merge
requests' worth of lookups exhaust the limit GitLab applies per IP address.
Setting GITLAB_TOKEN in the environment (a personal access token that can read
pipelines: see the README) sends it with API requests, and only those, and lifts
that limit. Finding an
MR's built APK is best-effort: a missing pipeline, an expired build artifact, or a changed
report just mean that MR's row says so, never fail the run. The APK link, the permissions
and the Fastlane description come from the merge request's Code Quality report, which is
where F-Droid's reviewer guide says to look; the job's own log is the fallback.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NamedTuple, TextIO

sys.path.insert(0, str(Path(__file__).resolve().parent))
from code_quality import CodeQuality  # noqa: E402
from code_quality import parse as parse_code_quality  # noqa: E402
from review_coverage import Coverage, summarise  # noqa: E402

GITLAB_API = "https://gitlab.com/api/v4"
PROJECT = "fdroid%2Ffdroiddata"
PROJECT_PATH = "fdroid/fdroiddata"
USER_AGENT = "fdroid-review-session/fetch_review_queue.py"
REQUEST_TIMEOUT_SECONDS = 30

# The APK's own URL, wherever it appears in a job log: a fixed prefix
# ("Reproducible build APK: ...") has been seen, but nothing documents
# that this is the only wording fdroidserver ever uses, so this matches
# the URL shape itself (a GitLab job-artifact raw-file link to an APK under
# tmp/binaries/ for a reproducible build, or tmp/signed/ for a plain CI-signed one;
# a first version knew only the former and so could not see most apps) rather than
# the sentence around it. This is the fallback: the Code Quality report is the source.
_APK_URL_RE = re.compile(
    r"https://gitlab\.com/[\w./-]+/-/jobs/\d+/artifacts/raw/tmp/(?:binaries|signed)/[\w.+-]+\.apk"
)


class FetchError(Exception):
    pass


# GitLab answers an over-limit request with HTTP 429 and a Retry-After in
# seconds. Observed against gitlab.com: for unauthenticated traffic the limit
# is per IP and the wait can be most of an hour, so retrying is only worth it
# when the wait is short; otherwise give up at once and say when to come back,
# instead of sending the remaining requests into a wall.
MAX_RATE_LIMIT_RETRIES = 2
MAX_RETRY_WAIT_SECONDS = 60


class RateLimited(Exception):
    def __init__(self, retry_after: float | None, *, authenticated: bool = False) -> None:
        super().__init__("GitLab rate limit reached")
        self.retry_after = retry_after
        self.authenticated = authenticated

    def describe(self) -> str:
        if self.authenticated:
            who = "this token"
        elif os.environ.get(TOKEN_ENV_VAR, "").strip():
            who = (
                "this IP: the refused request carried no token, because job logs and "
                "artifacts are fetched without one"
            )
        else:
            who = "this IP (unauthenticated traffic)"
        if self.retry_after is None:
            return f"GitLab is rate limiting {who}; try again later"
        until = datetime.now(UTC) + timedelta(seconds=self.retry_after)
        return f"GitLab is rate limiting {who}; try again after about {until:%H:%M} UTC"


class AuthRejected(FetchError):
    """GitLab answered 401 to a request that carried the token."""

    def describe(self) -> str:
        return str(self)


# An optional GitLab token, read from the environment (never an argument, which
# would show up in `ps`). It lifts the per-IP limit that unauthenticated
# requests share, and it is sent to GitLab's API only: never to the job-log or
# artifact URLs, and never on to another host if the API redirects.
TOKEN_ENV_VAR = "GITLAB_TOKEN"
_TOKEN_HEADER = "PRIVATE-TOKEN"
# Endpoints the token was refused for lack of a permission; they go without it.
_DENIED_ENDPOINTS: set[str] = set()


def _endpoint_key(url: str) -> str:
    return re.sub(r"\d+", "N", urllib.parse.urlsplit(url).path)


def _is_api_url(url: str) -> bool:
    return url.startswith(GITLAB_API + "/")


def _token_for(url: str) -> str | None:
    if not _is_api_url(url) or _endpoint_key(url) in _DENIED_ENDPOINTS:
        return None
    return os.environ.get(TOKEN_ENV_VAR, "").strip() or None


class _StripTokenOnRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(  # type: ignore[no-untyped-def]
        self, req, fp, code, msg, headers, newurl
    ):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and not _is_api_url(newurl):
            new.headers.pop(_TOKEN_HEADER.capitalize(), None)
        return new


_OPENER = urllib.request.build_opener(_StripTokenOnRedirect)


def _open(request: urllib.request.Request, timeout: float) -> Any:
    return _OPENER.open(request, timeout=timeout)


def _permission_problem(exc: urllib.error.HTTPError) -> str | None:
    """GitLab's own words when a 403 is about the token's permissions rather than
    about the resource, else None.
    """
    try:
        body = json.loads(exc.read().decode("utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(body, dict) or not str(body.get("error", "")).startswith("insufficient"):
        return None
    detail = str(body.get("error_description") or body["error"])
    return re.sub(r"[\x00-\x1f\x7f]", " ", detail)[:300]


class ApkLookup(NamedTuple):
    urls: list[str]
    # False if any request failed along the way, so "found nothing" cannot be
    # told apart from "could not look".
    complete: bool


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def http_get(url: str) -> str:
    return http_get_bytes(url).decode("utf-8", errors="replace")


def http_get_json(url: str) -> Any:
    return json.loads(http_get(url))


def _retry_after_seconds(exc: urllib.error.HTTPError) -> float | None:
    raw = exc.headers.get("Retry-After") if exc.headers is not None else None
    if raw is None:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        return None  # the HTTP-date form: treated as unknown


def http_get_bytes(url: str) -> bytes:
    attempt = 0
    while True:
        token = _token_for(url)
        headers = {"User-Agent": USER_AGENT}
        if token is not None:
            headers[_TOKEN_HEADER] = token
        request = urllib.request.Request(url, headers=headers)
        try:
            with _open(request, REQUEST_TIMEOUT_SECONDS) as response:
                body: bytes = response.read()
            return body
        except urllib.error.HTTPError as exc:
            if token is not None and exc.code == 401:
                raise AuthRejected(
                    f"GitLab rejected {TOKEN_ENV_VAR} (HTTP 401): it may be expired or revoked"
                ) from exc
            if token is not None and exc.code == 403:
                problem = _permission_problem(exc)
                if problem is not None:
                    _DENIED_ENDPOINTS.add(_endpoint_key(url))
                    print(
                        f"  warning: {TOKEN_ENV_VAR} was refused for {_endpoint_key(url)}: "
                        f"{problem}\n  requests to it now go without the token",
                        file=sys.stderr,
                    )
                    continue
            if exc.code != 429:
                raise
            wait = _retry_after_seconds(exc)
            if wait is None:
                wait = 5.0 * (2**attempt)
            if wait > MAX_RETRY_WAIT_SECONDS or attempt >= MAX_RATE_LIMIT_RETRIES:
                raise RateLimited(
                    _retry_after_seconds(exc), authenticated=token is not None
                ) from exc
            print(f"  GitLab rate limit: waiting {wait:.0f}s before retrying", file=sys.stderr)
            _sleep(wait)
            attempt += 1


def fetch_all_open_review_mrs(*, stderr: TextIO = sys.stderr) -> list[dict[str, Any]]:
    """Every open `review-requested` MR, oldest first, across as many
    pages as it takes — there are reliably 200+ of these at any time, well
    past GitLab's 100-per-page default.
    """
    mrs: list[dict[str, Any]] = []
    page = 1
    while True:
        url = (
            f"{GITLAB_API}/projects/{PROJECT}/merge_requests"
            f"?state=opened&labels=review-requested&order_by=created_at&sort=asc"
            f"&per_page=100&page={page}"
        )
        try:
            batch = http_get_json(url)
        except RateLimited as exc:
            raise FetchError(f"could not list merge requests: {exc.describe()}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise FetchError(f"could not list merge requests (page {page}): {exc}") from exc
        if not batch:
            break
        mrs.extend(batch)
        print(f"  fetched page {page} ({len(batch)} MRs, {len(mrs)} total so far)", file=stderr)
        if len(batch) < 100:
            break
        page += 1
    return mrs


def job_raw_log_url(pipeline_web_url: str, job_id: int) -> str:
    """A pipeline's own `web_url` (e.g.
    `https://gitlab.com/some/fork/-/pipelines/123`) always shares its
    project base with any job in it; GitLab has no documented API for
    "give me this job's raw log" that doesn't need auth on a public
    project, but the same `-/jobs/<id>/raw` web path used throughout this
    project's own CI (see local-image/README.md's "Verified end to end"
    section) does.
    """
    base = pipeline_web_url.rsplit("/-/pipelines/", 1)[0]
    return f"{base}/-/jobs/{job_id}/raw"


def extract_apk_urls(job_log_text: str) -> list[str]:
    """Order-preserving de-duplication: a multi-ABI app's build job
    mentions each split APK's URL more than once across the log.
    """
    seen: dict[str, None] = {}
    for match in _APK_URL_RE.finditer(job_log_text):
        seen[match.group(0)] = None
    return list(seen)


_ARTIFACT_URL_RE = re.compile(
    r"^https://gitlab\.com/(?P<project>[\w./-]+?)/-/jobs/(?P<job>\d+)/artifacts/raw/"
    r"(?P<path>tmp/(?:binaries|signed)/[\w.+-]+\.apk)$"
)


def _has_token() -> bool:
    return bool(os.environ.get(TOKEN_ENV_VAR, "").strip())


def _api_artifact_url(web_url: str) -> str | None:
    """The API form of an artifact link. The project comes from the link itself: Code
    Quality links point into fdroid/fdroiddata, log links into the contributor's fork.
    """
    match = _ARTIFACT_URL_RE.match(web_url)
    if match is None:
        return None
    project = urllib.parse.quote(match.group("project"), safe="")
    job, path = match.group("job"), match.group("path")
    return f"{GITLAB_API}/projects/{project}/jobs/{job}/artifacts/{path}"


def _job_log(project_id: int, pipeline_web_url: str, job_id: int) -> str:
    """With a token, read the log through the API, where the token counts (job logs on
    the web are fetched without it, and draw on the per-IP budget that unauthenticated
    traffic shares); otherwise, or if that fails, the web URL.
    """
    if _has_token():
        try:
            return http_get(f"{GITLAB_API}/projects/{project_id}/jobs/{job_id}/trace")
        except OSError:
            pass
    return http_get(job_raw_log_url(pipeline_web_url, job_id))


def resolve_apk_urls(source_project_id: int, *, stderr: TextIO = sys.stderr) -> ApkLookup:
    """Best-effort. `complete` is False if any request failed, which makes an
    empty `urls` mean "could not tell", not "checked, found nothing" (a failed
    or not-yet-run build). Raises `RateLimited` rather than carrying on: every
    further request would be refused too.
    """
    complete = True
    try:
        pipelines = http_get_json(
            f"{GITLAB_API}/projects/{source_project_id}/pipelines?per_page=5&order_by=id&sort=desc"
        )
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"  warning: could not list pipelines for project {source_project_id}: {exc}",
            file=stderr,
        )
        return ApkLookup([], complete=False)

    for pipeline in pipelines:
        try:
            jobs = http_get_json(
                f"{GITLAB_API}/projects/{source_project_id}/pipelines/{pipeline['id']}/jobs"
                "?per_page=100"
            )
        except (OSError, json.JSONDecodeError):
            complete = False
            continue
        build_job = next((j for j in jobs if j.get("name") == "fdroid build"), None)
        if build_job is None or build_job.get("status") != "success":
            continue
        try:
            log_text = _job_log(source_project_id, pipeline["web_url"], build_job["id"])
        except OSError as exc:
            print(
                f"  warning: could not fetch the log of job {build_job['id']}: {exc}",
                file=stderr,
            )
            complete = False
            continue
        urls = extract_apk_urls(log_text)
        if urls:
            return ApkLookup(urls, complete=True)
    return ApkLookup([], complete=complete)


def download_apk(url: str, dest: Path) -> bool:
    """With a token, try the API's artifact route first (the token counts there; the
    web URL is fetched without it), then the web URL.
    """
    candidates = [url]
    if _has_token():
        api_url = _api_artifact_url(url)
        if api_url is not None:
            candidates.insert(0, api_url)
    for candidate in candidates:
        try:
            data = http_get_bytes(candidate)
        except (OSError, RateLimited):
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        return True
    return False


CODE_QUALITY_POLL_SECONDS = (2.0, 3.0, 4.0, 6.0)


def fetch_code_quality(iid: int) -> CodeQuality | None:
    """The merge request's Code Quality report, or None if GitLab has none (no pipeline
    yet). GitLab computes it on first request and answers 204 until it is ready, so this
    asks again after a short wait. Raises on a failed request; a rate limit propagates.
    """
    url = f"https://gitlab.com/{PROJECT_PATH}/-/merge_requests/{iid}/codequality_reports.json"
    for delay in (*CODE_QUALITY_POLL_SECONDS, None):
        try:
            raw = http_get(url)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise
        if raw.strip():
            report = json.loads(raw)
            return parse_code_quality(report) if isinstance(report, dict) else None
        if delay is None:
            raise OSError("the Code Quality report was not ready after several tries")
        _sleep(delay)
    raise AssertionError("unreachable")


def lookup_code_quality(iid: int) -> tuple[CodeQuality | None, str]:
    try:
        report = fetch_code_quality(iid)
    except (OSError, ValueError):
        return None, "could not check (a GitLab request failed); run again later"
    if report is None:
        return None, "no Code Quality report on this merge request"
    return report, "ok"


MAX_NOTE_PAGES = 3  # 100 notes a page; a longer thread is read from its first 300


def fetch_notes(iid: int) -> list[dict[str, Any]]:
    notes: list[dict[str, Any]] = []
    for page in range(1, MAX_NOTE_PAGES + 1):
        batch = http_get_json(
            f"{GITLAB_API}/projects/{PROJECT}/merge_requests/{iid}/notes"
            f"?per_page=100&sort=asc&order_by=created_at&page={page}"
        )
        notes.extend(batch)
        if len(batch) < 100:
            break
    return notes


def lookup_coverage(mr: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """The coverage as a plain dict, and a status. A failed request is "could not check",
    never an empty result; rate limits and a rejected token propagate to the caller.
    """
    author = str((mr.get("author") or {}).get("username", ""))
    try:
        notes = fetch_notes(mr["iid"]) if mr.get("user_notes_count", 0) else []
    except (OSError, ValueError):
        return None, "could not check (a GitLab request failed); run again later"
    return asdict(summarise(notes, author, mr["web_url"])), "ok"


def fetch_coverage_for(iid: int) -> Coverage:
    """For one merge request by number (quick_review.py's use). Raises on failure."""
    mr = http_get_json(f"{GITLAB_API}/projects/{PROJECT}/merge_requests/{iid}")
    author = str((mr.get("author") or {}).get("username", ""))
    return summarise(fetch_notes(iid), author, mr["web_url"])


@dataclass(frozen=True, slots=True)
class QueueEntry:
    iid: int
    title: str
    web_url: str
    source_branch: str
    created_at: str
    labels: list[str]
    apk_paths: list[str] = field(default_factory=list)
    # Or "no build artifact found" (looked, none there), "could not check ..." (a
    # request failed, so unknown), "not checked: ..." (rate limited), "N file(s) fetched".
    apk_status: str = "not fetched this run"
    # What the merge request's comments already say about review (review_coverage.py), or
    # None with a coverage_status saying why not: "could not check ...", "not checked: ...".
    coverage: dict[str, Any] | None = None
    coverage_status: str = "not fetched this run"
    # The merge request's Code Quality report, parsed (code_quality.py): permissions, the built
    # APK's link, signing key, ABIs, Fastlane locales. None with a status saying why not.
    code_quality: dict[str, Any] | None = None
    code_quality_status: str = "not fetched this run"


def build_index_html(entries: list[QueueEntry], *, limit: int) -> str:
    payload = [
        {
            "iid": e.iid,
            "title": e.title,
            "web_url": e.web_url,
            "source_branch": e.source_branch,
            "created_at": e.created_at,
            "labels": e.labels,
            "apk_paths": e.apk_paths,
            "apk_status": e.apk_status,
            "coverage": e.coverage,
            "coverage_status": e.coverage_status,
            "code_quality": e.code_quality,
            "code_quality_status": e.code_quality_status,
        }
        for e in entries
    ]
    # Same reasoning as quick_review.py's report.html: MR titles/branches
    # are contributor-supplied GitLab content, not something this script
    # controls, so the embedded JSON gets the same <script>-breakout-proof
    # escaping before it's trusted to sit inside a <script> block.
    payload_json = json.dumps(payload).replace("<", "\\u003c")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fdroiddata review queue</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 80rem; margin: 1.5rem auto;
          padding: 0 1rem; line-height: 1.5; }}
  input[type=search] {{ font: inherit; padding: 0.4rem 0.6rem; width: 100%;
                         max-width: 24rem; box-sizing: border-box; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; margin-top: 1rem; }}
  th, td {{ text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #eee;
            vertical-align: top; }}
  th {{ position: sticky; top: 0; background: #fff; }}
  tbody tr:hover {{ background: #f8f8f8; }}
  .row-count {{ color: #666; font-size: 0.85rem; margin-top: 0.5rem; }}
  .status-fetched {{ color: #2d6a4f; }}
  .status-missing {{ color: #666; }}
  code {{ background: #f4f4f4; padding: 0.1rem 0.3rem; border-radius: 0.2rem; }}
</style>
</head>
<body>
<h1>fdroiddata review queue</h1>
<p><small>All currently open <code>review-requested</code> merge requests on
<a href="https://gitlab.com/fdroid/fdroiddata/-/merge_requests/?sort=created_asc&amp;state=opened&amp;label_name%5B%5D=review-requested"
target="_blank" rel="noopener">fdroid/fdroiddata</a>, oldest first. APKs were
fetched for the {limit} oldest only (see <code>--limit</code>); the rest show
metadata only. Regenerated fresh on every run &mdash; no memory of previous
runs.</small></p>
<p><small>APKs and permissions come from each merge request's Code Quality report, as
F-Droid's reviewer guide describes. "Existing reviews" is read from each merge request's
comments (long, review-like ones, and whether they claim an on-device or emulator test).
Those are claims in free text: nothing here checks that a test happened, and a review of an
older version of the merge request is flagged only when its own commits changed since. Read
the linked comments before deciding.</small></p>
<input type="search" id="search" placeholder="search title, branch, MR number...">
<label>Show
  <select id="show">
    <option value="all">all</option>
    <option value="no-device">no current on-device test claimed</option>
    <option value="none">no review-like comments yet</option>
  </select>
</label>
<label>Sort
  <select id="sort">
    <option value="oldest">oldest first</option>
    <option value="least">least covered first</option>
  </select>
</label>
<div class="row-count" id="count"></div>
<table>
  <thead><tr><th>MR</th><th>Branch</th><th>Age</th>
    <th>Existing reviews</th><th>APK</th></tr></thead>
  <tbody id="body"></tbody>
</table>

<script type="application/json" id="queue-data">{payload_json}</script>
<script>
(function () {{
  "use strict";
  var entries = JSON.parse(document.getElementById("queue-data").textContent);

  function ageDays(createdAt) {{
    return Math.floor((Date.now() - new Date(createdAt).getTime()) / 86400000);
  }}

  var RANK = {{"none": 0, "static": 1, "device-stale": 2, "device": 3}};
  var NO_DEVICE = {{"none": true, "static": true, "device-stale": true}};

  function latest(notes) {{
    return notes.reduce(function (a, b) {{
      return !a || b.created_at > a.created_at ? b : a;
    }}, null);
  }}

  function coverageCell(e) {{
    var cell = document.createElement("td");
    var c = e.coverage;
    if (!c) {{
      var unknown = document.createElement("span");
      unknown.className = "status-missing";
      unknown.textContent = e.coverage_status;
      cell.appendChild(unknown);
      return cell;
    }}
    var label = {{
      "none": "no review-like comments yet",
      "static": c.reviews.length + " review(s), no on-device test claimed",
      "device-stale": "on-device test claimed, but the MR changed since",
      "device": "on-device test claimed"
    }}[c.level];
    var text = document.createElement("div");
    text.textContent = label;
    cell.appendChild(text);
    var devices = c.reviews.filter(function (r) {{ return r.device_test; }});
    var pick = latest(devices) || latest(c.reviews);
    if (pick) {{
      var link = document.createElement("a");
      link.href = pick.url;
      link.target = "_blank";
      link.rel = "noopener";
      link.textContent = pick.author + ", " + pick.created_at.slice(0, 10);
      var small = document.createElement("small");
      small.appendChild(link);
      cell.appendChild(small);
    }}
    return cell;
  }}

  function permissionsNote(e) {{
    var q = e.code_quality;
    if (!q || !q.permissions || q.permissions.length === 0) return null;
    var net = q.permissions.some(function (p) {{ return /\\.INTERNET$/.test(p); }});
    var note = document.createElement("div");
    note.className = "status-missing";
    note.textContent = q.permissions.length + " permission(s), " +
      (net ? "INTERNET: check its network traffic" : "no INTERNET");
    note.title = q.permissions.join("\n");
    return note;
  }}

  function render() {{
    var query = document.getElementById("search").value.trim().toLowerCase();
    var show = document.getElementById("show").value;
    var sort = document.getElementById("sort").value;
    var tbody = document.getElementById("body");
    tbody.innerHTML = "";
    var shown = 0;
    var rows = entries.slice();
    if (sort === "least") {{
      rows.sort(function (a, b) {{
        var ra = a.coverage ? RANK[a.coverage.level] : 1.5;
        var rb = b.coverage ? RANK[b.coverage.level] : 1.5;
        return ra - rb || a.created_at.localeCompare(b.created_at);
      }});
    }}
    rows.forEach(function (e) {{
      var haystack = (e.iid + " " + e.title + " " + e.source_branch).toLowerCase();
      if (query && haystack.indexOf(query) === -1) return;
      if (show === "no-device" && !(e.coverage && NO_DEVICE[e.coverage.level])) return;
      if (show === "none" && !(e.coverage && e.coverage.level === "none")) return;
      shown++;

      var tr = document.createElement("tr");

      var mrCell = document.createElement("td");
      var link = document.createElement("a");
      link.href = e.web_url;
      link.target = "_blank";
      link.rel = "noopener";
      link.textContent = "!" + e.iid + " " + e.title;
      mrCell.appendChild(link);
      tr.appendChild(mrCell);

      var branchCell = document.createElement("td");
      branchCell.textContent = e.source_branch;
      tr.appendChild(branchCell);

      var ageCell = document.createElement("td");
      ageCell.textContent = ageDays(e.created_at) + "d";
      tr.appendChild(ageCell);

      tr.appendChild(coverageCell(e));

      var apkCell = document.createElement("td");
      if (e.apk_paths.length > 0) {{
        e.apk_paths.forEach(function (path, i) {{
          if (i > 0) apkCell.appendChild(document.createElement("br"));
          var apkLink = document.createElement("a");
          apkLink.href = path;
          apkLink.textContent = path.split("/").pop();
          apkCell.appendChild(apkLink);
        }});
      }} else {{
        var status = document.createElement("span");
        status.className = "status-missing";
        status.textContent = e.apk_status;
        apkCell.appendChild(status);
      }}
      var perms = permissionsNote(e);
      if (perms) apkCell.appendChild(perms);
      tr.appendChild(apkCell);

      tbody.appendChild(tr);
    }});
    var countLabel = shown + " of " + entries.length + " merge request(s)";
    document.getElementById("count").textContent = countLabel;
  }}

  document.getElementById("search").addEventListener("input", render);
  document.getElementById("show").addEventListener("change", render);
  document.getElementById("sort").addEventListener("change", render);
  render();
}})();
</script>
</body>
</html>
"""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="fetch_review_queue.py")
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="how many of the oldest open MRs to actually download APKs for (default: 20)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("review-queue"),
        help="directory to write index.html and apks/ into (default: ./review-queue)",
    )
    parser.add_argument(
        "--include-arm-only",
        action="store_true",
        help=(
            "also download and list merge requests whose APKs carry native code for ARM only. "
            "By default they are skipped with a note: an app without an x86 build cannot run on "
            "an x86 device, which is a finding, and it cannot run on the project's emulators."
        ),
    )
    parser.add_argument(
        "--skip-covered",
        action="store_true",
        help=(
            "do not look up or download APKs for merge requests whose comments already claim "
            "an on-device test that is not out of date; saves requests and time. The page "
            "still lists them. These are claims read from free text, not verified."
        ),
    )
    return parser.parse_args(argv)


def _with_apks(
    entry: QueueEntry,
    mr: dict[str, Any],
    apk_dir: Path,
    stderr: TextIO,
    *,
    include_arm_only: bool = False,
) -> QueueEntry:
    """Code Quality first: it names the built APK whether or not the build is
    reproducible, and lists the permissions. The older way (the job's log) is the
    fallback for a merge request whose report is missing or names no APK.
    """
    report, report_status = lookup_code_quality(mr["iid"])
    entry = replace(
        entry,
        code_quality=asdict(report) if report is not None else None,
        code_quality_status=report_status,
    )
    if report is not None and report.arm_only and not include_arm_only:
        # An F-Droid app that ships native code for ARM only is a finding in itself: it cannot run
        # on any x86 device. Not downloaded and not taken into the review phase.
        return replace(
            entry,
            apk_status=(
                f"skipped: ARM-only ({', '.join(report.native_abis)}), no x86 build: a finding, "
                "not reviewed (--include-arm-only to review it anyway)"
            ),
        )
    urls = [apk.url for apk in report.apks] if report is not None else []
    complete = report is not None
    if not urls:
        lookup = resolve_apk_urls(mr["source_project_id"], stderr=stderr)
        urls, complete = lookup.urls, lookup.complete
    if not urls:
        status = (
            "no build artifact found"
            if complete
            else "could not check (a GitLab request failed); run again later"
        )
        return replace(entry, apk_status=status)
    fetched_paths = []
    for url in urls:
        filename = url.rsplit("/", 1)[-1]
        dest = apk_dir / str(mr["iid"]) / filename
        if download_apk(url, dest):
            fetched_paths.append(f"apks/{mr['iid']}/{filename}")
        else:
            print(f"  warning: could not download {url}", file=stderr)
    status = f"{len(fetched_paths)} file(s) fetched" if fetched_paths else "download failed"
    return replace(entry, apk_paths=fetched_paths, apk_status=status)


def main(argv: list[str], *, stdout: TextIO = sys.stdout, stderr: TextIO = sys.stderr) -> int:
    args = parse_args(argv)
    output_dir: Path = args.output_dir
    apk_dir = output_dir / "apks"

    if os.environ.get(TOKEN_ENV_VAR, "").strip():
        print(f"Using {TOKEN_ENV_VAR} for GitLab API requests.", file=stdout)
    print("Fetching open review-requested merge requests...", file=stdout)
    try:
        mrs = fetch_all_open_review_mrs(stderr=stderr)
    except FetchError as exc:
        print(f"error: {exc}", file=stderr)
        return 1
    print(f"{len(mrs)} open merge requests found.", file=stdout)

    entries: list[QueueEntry] = []
    rate_limit_note: str | None = None
    for index, mr in enumerate(mrs):
        entry = QueueEntry(
            iid=mr["iid"],
            title=mr["title"],
            web_url=mr["web_url"],
            source_branch=mr["source_branch"],
            created_at=mr["created_at"],
            labels=list(mr.get("labels", [])),
        )
        if index < args.limit and rate_limit_note is not None:
            entry = replace(entry, apk_status=rate_limit_note, coverage_status=rate_limit_note)
        elif index < args.limit:
            position = f"[{index + 1}/{min(args.limit, len(mrs))}]"
            print(f"{position} !{mr['iid']} {mr['title']}...", file=stdout)
            try:
                coverage, coverage_status = lookup_coverage(mr)
                entry = replace(entry, coverage=coverage, coverage_status=coverage_status)
                if args.skip_covered and coverage is not None and coverage["level"] == "device":
                    entry = replace(
                        entry,
                        apk_status="skipped: a current on-device test is already claimed "
                        "(--skip-covered)",
                    )
                else:
                    entry = _with_apks(
                        entry, mr, apk_dir, stderr, include_arm_only=args.include_arm_only
                    )
            except (RateLimited, AuthRejected) as exc:
                rate_limit_note = f"not checked: {exc.describe()}"
                print(
                    f"  warning: {rate_limit_note}; skipping the remaining lookups",
                    file=stderr,
                )
                unset = "not fetched this run"
                entry = replace(
                    entry,
                    apk_status=rate_limit_note if entry.apk_status == unset else entry.apk_status,
                    coverage_status=(
                        rate_limit_note if entry.coverage_status == unset else entry.coverage_status
                    ),
                )
        entries.append(entry)

    output_dir.mkdir(parents=True, exist_ok=True)
    index_path = output_dir / "index.html"
    index_path.write_text(build_index_html(entries, limit=args.limit), encoding="utf-8")
    data_path = output_dir / "index.json"
    data_path.write_text(json.dumps([asdict(e) for e in entries], indent=2), encoding="utf-8")

    print(f"\nDone. {index_path}", file=stdout)
    if rate_limit_note is not None:
        print(f"Incomplete: {rate_limit_note}", file=stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
