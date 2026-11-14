#!/usr/bin/env bash
# Review one APK on a GitHub-hosted runner with nothing but `gh`: start the `review` workflow in
# REPO (your fork of this repository), wait for it, download the result, and say how long it took.
#
#   ci-spike/gh-review.sh --repo you/fdroid-app-review --apk-url URL --package NAME \
#       [--mr-iid N] [--duration S] [--out DIR]
#
# Needs: gh, logged in (`gh auth login`, or GH_TOKEN in the environment) with permission to run
# workflows in REPO. Nothing is posted anywhere: review_comment.md is for you to read and paste.
# If REPO is public, the run's log and artifact are public too (for the artifact's retention).
set -euo pipefail

REPO="" APK_URL="" PACKAGE="" MR_IID="" DURATION="60" OUT="" WORKFLOW="review.yml"
usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo) REPO="$2"; shift 2 ;;
        --apk-url) APK_URL="$2"; shift 2 ;;
        --package) PACKAGE="$2"; shift 2 ;;
        --mr-iid) MR_IID="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --workflow) WORKFLOW="$2"; shift 2 ;;
        *) usage ;;
    esac
done
[[ -n "$REPO" && -n "$APK_URL" && -n "$PACKAGE" ]] || usage
OUT="${OUT:-gh-review-${PACKAGE}-$(date +%Y%m%d-%H%M%S)}"

gh auth status >/dev/null 2>&1 || { echo "error: gh is not logged in (gh auth login)" >&2; exit 1; }

t0=$(date +%s)
since="$(date -u -d '-10 seconds' +%Y-%m-%dT%H:%M:%SZ)"
fields=(-f "apk_url=$APK_URL" -f "package=$PACKAGE" -f "duration=$DURATION")
[[ -n "$MR_IID" ]] && fields+=(-f "mr_iid=$MR_IID")
gh workflow run "$WORKFLOW" -R "$REPO" "${fields[@]}"

# `gh workflow run` does not return the run it started: find the newest dispatch run of this
# workflow, by this user, created after the dispatch.
me="$(gh api user --jq .login)"
run_id=""
for _ in $(seq 1 30); do
    run_id="$(gh run list -R "$REPO" -w "$WORKFLOW" -e workflow_dispatch -u "$me" -L 5 \
        --json databaseId,createdAt --jq "map(select(.createdAt >= \"$since\")) | .[0].databaseId // empty")"
    [[ -n "$run_id" ]] && break
    sleep 2
done
[[ -n "$run_id" ]] || { echo "error: could not find the run that was started" >&2; exit 1; }
url="$(gh run view "$run_id" -R "$REPO" --json url --jq .url)"
echo "Run: $url"

status=0
gh run watch "$run_id" -R "$REPO" --interval 20 --exit-status >/dev/null || status=$?
gh run view "$run_id" -R "$REPO" --json conclusion,jobs \
    --jq '"conclusion: \(.conclusion)", (.jobs[] | "job \(.name): \(.startedAt) -> \(.completedAt)")'

mkdir -p "$OUT"
gh run download "$run_id" -R "$REPO" -D "$OUT" || echo "warning: no artifact to download" >&2
t1=$(date +%s)

echo "End to end: $((t1 - t0)) s (dispatch to downloaded)"
comment="$(find "$OUT" -name review_comment.md -print -quit)"
report="$(find "$OUT" -name report.md -print -quit)"
[[ -n "$report" ]] && echo "Report: $report"
[[ -n "$comment" ]] && echo "Checklist to read, fill in and paste: $comment"
exit "$status"
