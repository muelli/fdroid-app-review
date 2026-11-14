#!/usr/bin/env bash
# Builds, in DIR, the tree a GitHub repository needs to run the ci-spike workflows: the committed
# files the review path uses (git HEAD, so another agent's uncommitted edits are never included),
# plus ci-spike/ from the working tree, with its workflows copied to .github/workflows/.
# It only builds the directory and commits it there; pushing is left to the caller.
#
#   ci-spike/publish-snapshot.sh DIR
set -euo pipefail
dir="${1:?usage: $0 DIR}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ ! -e "$dir" ]] || { echo "error: $dir exists" >&2; exit 1; }
mkdir -p "$dir"
git -C "$root" archive HEAD scripts local-image/avd_fallback.sh gitlab-glue netpolicy LICENSE \
    | tar -x -C "$dir"
rsync -a --exclude __pycache__ --exclude .pytest_cache --exclude FINDINGS.md "$root/ci-spike" "$dir/"
mkdir -p "$dir/.github/workflows"
cp "$root"/ci-spike/workflows/*.yml "$dir/.github/workflows/"
cat > "$dir/README.md" <<EOF
Snapshot of fdroid-app-review ($(git -C "$root" rev-parse --short HEAD)) for running the emulator
review on GitHub Actions. See ci-spike/README.md.
EOF
git -C "$dir" init -q -b main
git -C "$dir" add -A
git -C "$dir" -c user.name="ci-spike" -c user.email="ci-spike@invalid" commit -q \
    -m "Snapshot of fdroid-app-review $(git -C "$root" rev-parse --short HEAD) with ci-spike"
git -C "$dir" log --oneline -1
