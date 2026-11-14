# ci-spike: the emulator review on GitHub Actions

A spike, not a finished feature. It tests whether a volunteer who only has `gh` can review an
`fdroiddata` APK on a GitHub-hosted runner. The results, with run links, are in `FINDINGS.md`.

| File | What it is |
| --- | --- |
| `workflows/review.yml` | Runs `local-image/avd_fallback.sh --review` as it is: an AOSP x86_64 emulator under `nsntrace`, then `quick_review.py`, then the network evidence. It uploads `quick-review/` as an artifact that is kept for 3 days. |
| `workflows/kvm-baseline.yml` | Checks for KVM and measures boot time with `reactivecircus/android-emulator-runner`. No app is installed. |
| `workflows/explore.yml` | Runs the `uiautomator` explorer and then `monkey` on each app in a JSON list, one job and one emulator per app. |
| `gh-review.sh` | The contributor's command. It starts `review.yml`, waits for it, downloads the artifact and prints the elapsed time. |
| `publish-snapshot.sh` | Builds the tree a GitHub repository needs to run these workflows (`git HEAD` plus `ci-spike/`, with the workflows copied into `.github/workflows/`). It does not push. |
| `explorer/explore.py` | The explorer prototype. It uses only the standard library. Every adb call can be replaced by a fake. |
| `explorer/run_one.sh` | Runs the explorer on a fresh install of one app, then `monkey` on a second fresh install. |
| `explorer/test_explore.py` | Offline tests: `uv run --with pytest python -m pytest ci-spike/explorer`. |

## Using it

GitHub only runs workflows from `.github/workflows/`. For now, put them there yourself:

```sh
ci-spike/publish-snapshot.sh /tmp/snap
```

Then push `/tmp/snap` to a repository you own. Once the workflows are in `.github/workflows/` of
the repository you fork, a fork is all you need. Then run:

```sh
ci-spike/gh-review.sh --repo YOU/REPO \
    --apk-url https://gitlab.com/.../artifacts/raw/tmp/binaries/app.apk \
    --package the.app.id --mr-iid 12345 --duration 60
```

The output is in `gh-review-<package>-<time>/quick-review/`. Read `report.md` first, then
`review_comment.md`, which you fill in and paste into the merge request yourself. Nothing is
posted for you.

The explorer runs on any emulator or phone that adb can reach:

```sh
python3 ci-spike/explorer/explore.py --package the.app.id --out /tmp/explore --steps 40 --monkey-events 400
```

The app must already be installed. `run_one.sh` installs it for you.

## Before you use a public repository

Anyone can read the job logs and the artifact of a public repository: the screen recording,
screenshots, logcat, the pcap and the report. The artifact is kept for 3 days (`retention-days`
in the workflows). The logs are kept for the repository's log retention setting. Only review
public CI builds there. The workflows never use secrets, and they pass none of
`quick_review.py`'s upload or VirusTotal options.
