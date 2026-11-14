#!/usr/bin/env python3
"""Quick, one-shot review of a single APK against an already-running Android
device/emulator reachable over `adb`: installs it, launches it, records the
screen and network traffic for a fixed duration (default 30s), and writes a
Markdown report (`report.md`) plus a self-contained HTML one with the
recording embedded inline (`report.html`), and the raw screen recording
and pcap.

Deliberately lighter-weight than the full `local-image`/broker flow: this
script doesn't boot or manage a device itself. Point it at whatever's
already up over adb — a real device, an AVD, a `redroid` container's
`localhost:5555`, anything `adb devices` can see.

Usage:
    uv run scripts/quick_review.py --apk /path/to/app.apk
    uv run scripts/quick_review.py --apk app.apk --serial localhost:5555 --duration 60

Requires `adb` on PATH and exactly one connected device (or `--serial` to
pick one of several). `tcpdump` for network capture and `aapt`/`aapt2` for
static permission listing and package-name detection are both optional and
best-effort: their absence only narrows the report, it never fails the
run — same philosophy as `netpolicy.capture` elsewhere in this repository.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import html
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

import device_capture as dc
import screenshot_upload as su
from gitlab_glue.rendering import ReviewTemplateContext, render_review_template
from netpolicy.capture import PassiveCapture
from netpolicy.logger import write_network_log

REPO_ROOT = Path(__file__).resolve().parents[1]

# Android's own hard limit for a single `screenrecord` invocation; there is
# no built-in way to record longer than this in one file. Rather than
# stitching multiple recordings together (more moving parts, another
# dependency on a video tool just for this), a requested duration longer
# than this is clamped, with a clear warning, keeping every artefact
# (screen, network, logcat) covering the same time window.
SCREENRECORD_HARD_LIMIT_SECONDS = 180
DEFAULT_UPLOAD_VIDEO_MBPS = 4
REMOTE_RECORDING_PATH = "/sdcard/quick_review_recording.mp4"
LOGCAT_TAIL_LINES = 40

# Everything below bounds data the *reviewed app* controls the size of. It
# can write to logcat and send DNS queries as fast as it likes for the whole
# recording window, so none of it is naturally bounded; without these the app
# under review would decide how much memory this process uses and how large
# an HTML file the reviewer's browser is asked to open.
MAX_LOGCAT_BYTES = 8 * 1024 * 1024
MAX_LOGCAT_LINE_CHARS = 4000
MAX_RENDERED_CHARS = 2000
MAX_EMBEDDED_NETWORK_EVENTS = 20_000
MAX_REPORTED_ENDPOINTS = 500

VERDICTS = {
    "good": "Good for inclusion",
    "more-testing": "More testing needed",
    "unfit": "Unfit for inclusion",
}

# Android validates these at install time, but this tool must not depend on
# the device for its own safety: `adb shell <argv...>` rejoins its argv with
# spaces and re-parses the result with the *device's* shell (see
# `measure_device_clock`), so a package or component name carrying shell
# metacharacters would run as the `shell` user, and one starting with `-`
# would be eaten by `am`/`dumpsys` as an option instead of an argument.
_PACKAGE_NAME_RE = re.compile(r"\A[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,16}\Z")
_COMPONENT_RE = re.compile(r"\A[A-Za-z0-9_.]{1,256}/\.?[A-Za-z0-9_.$]{1,256}\Z")

# C0/C1 controls plus the zero-width and bidi-override characters: a hostile
# manifest string, logcat line or DNS name reaches both a terminal (`cat
# report.md`) and a browser, where these can drive the terminal or make a
# hostname render backwards, i.e. as a different hostname.
_UNPRINTABLE_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]"
)


class QuickReviewError(Exception):
    pass


def sanitize(value: str, *, max_chars: int = MAX_RENDERED_CHARS) -> str:
    """Bound and de-fang a string the reviewed app controls, before it is
    rendered anywhere a human looks at it.
    """
    truncated = value[:max_chars]
    cleaned = _UNPRINTABLE_RE.sub(" ", truncated)
    return cleaned + "…(truncated)" if len(value) > max_chars else cleaned


def _md_code(value: str) -> str:
    """Renders an app-controlled string as a Markdown code span. A backtick
    in it must not be able to close the span early and have the rest of the
    string rendered as Markdown (a link, an image, a heading).
    """
    return "`" + sanitize(value).replace("`", "'") + "`"


def _code_fence_for(lines: list[str]) -> str:
    """A fence longer than the longest backtick run in the fenced content,
    so an app that logs ``` can't end the block and inject Markdown after it.
    """
    longest = max((len(run) for line in lines for run in re.findall(r"`+", line)), default=0)
    return "`" * max(3, longest + 1)


def _read_text_tail(path: Path, max_bytes: int) -> str:
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > max_bytes:
                handle.seek(size - max_bytes)
                data = handle.read()
                _, separator, rest = data.partition(b"\n")
                if separator:
                    data = rest
            else:
                data = handle.read()
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


# How adb is invoked. A list so the whole prefix can be something other than
# plain `adb`: with --adb-command it carries `sudo nsenter ... adb` into the
# network namespace an emulator is running in, where the host's own adb server
# cannot see it.
ADB: list[str] = ["adb"]


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, check=False)  # noqa: S603


@dataclass(frozen=True, slots=True)
class Args:
    apk: Path | None
    serial: str | None
    duration: int
    output_dir: Path
    capture_interface: str | None
    capture_container: str | None
    container_runtime: str
    package: str | None
    aapt_binary: str | None
    uninstall_after: bool
    mr_iid: int | None
    full_logcat: bool
    adb_command: str | None
    external_pcap: Path | None
    finalize: Path | None
    existing_reviews: bool
    no_grant_permissions: bool
    link_evidence: bool
    virustotal: bool
    virustotal_upload: bool
    verdict: str | None
    screenshot_interval: int
    capture_pcapdroid: bool
    upload_screenshots: bool
    upload_url: str
    upload_days: int
    pcapdroid_api_key: str | None
    fresh_install: bool
    video_bit_rate: int | None
    upload_video: bool
    install_copy: Path | None
    decrypted_log: Path | None
    stop_file: Path | None
    monkey: bool


def parse_args(argv: list[str]) -> Args:
    parser = argparse.ArgumentParser(prog="quick_review.py")
    parser.add_argument("--apk", type=Path, help="path to the APK to review (required)")
    parser.add_argument(
        "--serial",
        default=None,
        help="adb device serial to use; auto-detected if exactly one device is connected",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help=(
            "seconds to record for (default: 30). Clamped to "
            f"{SCREENRECORD_HARD_LIMIT_SECONDS}, Android's own screenrecord limit."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="where to write the report/recording/pcap (default: ./quick-review-<timestamp>)",
    )
    parser.add_argument(
        "--capture-container",
        default=None,
        help=(
            "Container the device under test is running as (e.g. a "
            "redroid sibling) — captures network traffic from *inside that "
            "container's own network namespace* (via `nsenter`), so nothing "
            "else ever shows up, not even other traffic on the same host "
            "interface. This is the precise, recommended option whenever "
            "the device under test is a container; mutually exclusive with "
            "--capture-interface."
        ),
    )
    parser.add_argument(
        "--capture-interface",
        default=None,
        help=(
            "interface to capture network traffic on, from *this host's* "
            "network namespace — use this only when the device under test "
            "isn't a container you can name with --capture-container "
            "(that option is more precise and should be preferred whenever "
            "it applies). No default: network capture is skipped unless "
            "you pass one of these two options, because there usually "
            "isn't a host interface that's *only* the reviewed device's "
            "traffic. Passing 'any' (tcpdump's pseudo-interface for every "
            "interface) is possible but NOT recommended here: confirmed the "
            "hard way that, run in the host's own namespace, it captures "
            "the whole host's traffic, not just the reviewed device's, "
            "indistinguishable from each other after the fact. A real "
            "device reached over USB/Wi-Fi debugging has no host-visible "
            "interface for its own traffic at all; this only works for a "
            "guest actually running on this host (an AVD, a local "
            "Cuttlefish instance, or a container named via "
            "--capture-container instead)."
        ),
    )
    parser.add_argument(
        "--container-runtime",
        default="podman",
        help=(
            "container runtime CLI used to resolve --capture-container's PID "
            "(default: podman; 'docker' takes the identical inspect format). "
            "Unused without --capture-container."
        ),
    )
    parser.add_argument(
        "--package",
        default=None,
        help="Android package name, if it can't be auto-detected from the APK (needs aapt/aapt2)",
    )
    parser.add_argument(
        "--aapt-binary",
        default=None,
        help="path to aapt or aapt2, if not on PATH (used for package name and permissions)",
    )
    parser.add_argument(
        "--uninstall-after",
        action="store_true",
        help="uninstall the APK from the device once the review finishes",
    )
    parser.add_argument(
        "--adb-command",
        default=None,
        help=(
            "how to run adb, as one shell-quoted string (default: adb). For a device adb "
            "can only reach from inside a network namespace, such as an emulator started "
            "by local-image/avd_fallback.sh --capture-pcap: `sudo nsenter --target PID "
            "--net -- sudo -u USER /path/to/adb`."
        ),
    )
    parser.add_argument(
        "--link-evidence",
        action="store_true",
        help=(
            "with --mr-iid: look up the links the review's claims can point at (the head "
            "pipeline, the CI-built APK, the metadata file, the pinned upstream commit and its "
            "tag, the description under test, the policy sections) and put them in the "
            "checklist, so a reader can check each claim. Every upstream link is fetched first "
            "and left out if it does not resolve. Uses GITLAB_TOKEN if set."
        ),
    )
    parser.add_argument(
        "--virustotal",
        action="store_true",
        help=(
            "look the APK's SHA-256 up on VirusTotal and put the result in the checklist. "
            "Needs an API key in the VT_API_KEY environment variable (a free account has "
            "one). Uploads nothing unless --virustotal-upload is also given."
        ),
    )
    parser.add_argument(
        "--virustotal-upload",
        action="store_true",
        help=(
            "if VirusTotal has never seen the APK, upload it (up to 32 MB) and wait for the "
            "result. Only for an APK that is public anyway, such as a CI build. Implies "
            "--virustotal."
        ),
    )
    parser.add_argument(
        "--verdict",
        choices=sorted(VERDICTS),
        default=None,
        help=(
            "set the checklist's verdict line. The tool never picks one itself; without this "
            "the line is a placeholder for you to settle."
        ),
    )
    parser.add_argument(
        "--no-grant-permissions",
        action="store_true",
        help=(
            "install without granting the runtime permissions (no `adb install -g`), so the app "
            "has to ask for them as it would for a user, and you can check that it works "
            "without the optional ones. The recording then waits on whoever is at the device "
            "to answer the prompts."
        ),
    )
    parser.add_argument(
        "--fresh-install",
        action="store_true",
        help=(
            "if the app is already installed on the device, uninstall it first (this DELETES "
            "its data), so the review is of a first run. Without it an existing copy keeps its "
            "data and granted permissions (`adb install -r`), and the tool warns."
        ),
    )
    parser.add_argument(
        "--existing-reviews",
        action="store_true",
        help=(
            "with --mr-iid: read the merge request's comments from GitLab first and print "
            "what they already say about review, including any claimed on-device test, so "
            "you can decide whether this review adds anything. Also put in the local report, "
            "never in the checklist. Uses GITLAB_TOKEN if set. Claims read from free text, "
            "not verified."
        ),
    )
    parser.add_argument(
        "--external-pcap",
        type=Path,
        default=None,
        help=(
            "take the network evidence from this pcap, which something else is capturing "
            "for the whole emulator session (avd_fallback.sh --capture-pcap). It is not "
            "read now: it is not complete until the emulator stops. Afterwards run "
            "--finalize on the output directory. Mutually exclusive with --capture-*."
        ),
    )
    parser.add_argument(
        "--finalize",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "finish a review started with --external-pcap: read the now-complete pcap, keep "
            "the events from the app's launch to the end of the recording, and rewrite the "
            "reports (and the checklist, if --mr-iid was given) in DIR."
        ),
    )
    parser.add_argument(
        "--full-logcat",
        action="store_true",
        help=(
            "put the whole device's logcat in report.md and report.html. By default only "
            "the reviewed app's own process(es) are included, because the rest of the log "
            "can hold unrelated personal details (a real run showed the phone's Wi-Fi "
            "network name). The raw logcat.txt is always written locally either way."
        ),
    )
    parser.add_argument(
        "--mr-iid",
        type=int,
        default=None,
        help=(
            "the fdroiddata merge request number this APK belongs to (the "
            "N in .../merge_requests/N). With it, also writes "
            "review_comment.md: the project's review checklist, pre-filled "
            "with what this run observed, ready to paste into that merge "
            "request. Nothing is ever posted for you."
        ),
    )
    parser.add_argument(
        "--screenshot-interval",
        type=int,
        default=15,
        metavar="SECONDS",
        help=(
            "save a screenshot of the device every this many seconds while recording (the "
            f"first after at most 5), at most {dc.MAX_SCREENSHOTS}, to <output>/screenshots/. "
            "0 turns it off. Screenshots show whatever is on the screen, personal details "
            "included: look at each before you share it. An app that blocks screenshots "
            "gives none."
        ),
    )
    parser.add_argument(
        "--upload-screenshots",
        action="store_true",
        help=(
            "upload the screenshots to a temporary file service and link them from the "
            "checklist, so the reviewer need not attach them. Off by default: anyone with "
            "a link can view the image until it expires, and screenshots can show personal "
            "details. Only this tool's own PNGs are sent, over https. The delete links go "
            "to <output>/uploads.json, never into the checklist."
        ),
    )
    parser.add_argument(
        "--install-apk",
        type=Path,
        default=None,
        metavar="FILE",
        dest="install_copy",
        help=(
            "install this file instead of --apk, which is still what the evidence (hash, "
            "permissions, links, VirusTotal) describes. For a copy patched for inspection, "
            "see apk_trust_user_ca.py."
        ),
    )
    parser.add_argument(
        "--decrypted-log",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "a log written by mitm_log_addon.py while a proxy sat between the app and the "
            "network: what the app sent over TLS. Put in the local report in full and in the "
            "checklist without query strings. A missing file means nothing reached the proxy."
        ),
    )
    parser.add_argument(
        "--stop-file",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "end the recording as soon as this file exists, or after --duration, whichever comes "
            "first. For a session someone drives by hand: set a long --duration, then create the "
            "file when done. The report then gives the time actually recorded."
        ),
    )
    parser.add_argument(
        "--monkey",
        action="store_true",
        help=(
            "during the recording, feed the app seeded pseudo-random touches and drags with "
            "Android's `monkey`, limited to the app's own package (no home or back keys, no app "
            "switching), so that an app waiting behind an onboarding screen does something. It "
            "is not a test of anything: the report says the input was random."
        ),
    )
    parser.add_argument(
        "--upload-video",
        action="store_true",
        help=(
            "upload the screen recording the same way (same service, --upload-url and "
            "--upload-days) and link it from the checklist. A recording shows whatever was on "
            "the screen, notifications from other apps included, and anyone with the link can "
            "watch it until it expires: look at it first if you can (it is saved locally "
            "either way). At most 100 MB. Without --video-bit-rate it records at "
            f"{DEFAULT_UPLOAD_VIDEO_MBPS} Mbit/s, so that it is not tens of MB."
        ),
    )
    parser.add_argument(
        "--video-bit-rate",
        type=int,
        default=None,
        metavar="MBPS",
        help=(
            "screen recording bit rate in Mbit/s (default: the device's own, about 20 on the "
            "phone tried, which made 75 MB for 30 s)"
        ),
    )
    parser.add_argument(
        "--upload-url",
        default=su.DEFAULT_BASE,
        help=f"the transfer.sh-style service to upload to (default: {su.DEFAULT_BASE})",
    )
    parser.add_argument(
        "--upload-days",
        type=int,
        default=su.DEFAULT_DAYS,
        help=f"how long the service keeps the files (default: {su.DEFAULT_DAYS})",
    )
    parser.add_argument(
        "--capture-pcapdroid",
        action="store_true",
        help=(
            "record this app's own network traffic on the phone with PCAPdroid "
            "(com.emanuelef.remote_capture, from F-Droid), filtered to the app. Needs "
            "PCAPdroid installed, and no other VPN running. Someone at the phone has to tap "
            "ALLOW in PCAPdroid (and OK on Android's VPN dialog) when the run starts. The app "
            "can see that a VPN is up, and DNS over HTTPS stays invisible."
        ),
    )
    ns = parser.parse_args(argv)
    if ns.finalize is None and ns.apk is None:
        parser.error("--apk is required (unless --finalize is given)")
    if ns.external_pcap is not None and (
        ns.capture_interface is not None or ns.capture_container is not None
    ):
        parser.error("--external-pcap cannot be combined with --capture-interface/-container")
    if ns.mr_iid is not None and ns.mr_iid < 1:
        parser.error("--mr-iid must be a positive merge request number")
    if ns.existing_reviews and ns.mr_iid is None:
        parser.error("--existing-reviews needs --mr-iid")
    if ns.link_evidence and ns.mr_iid is None:
        parser.error("--link-evidence needs --mr-iid")
    if ns.virustotal_upload:
        ns.virustotal = True
    if ns.virustotal and not os.environ.get("VT_API_KEY", "").strip():
        parser.error("--virustotal needs your VirusTotal API key in the VT_API_KEY variable")
    if ns.capture_interface is not None and ns.capture_container is not None:
        parser.error("--capture-interface and --capture-container are mutually exclusive")
    if ns.screenshot_interval < 0:
        parser.error("--screenshot-interval cannot be negative (0 turns screenshots off)")
    if ns.video_bit_rate is not None and not 1 <= ns.video_bit_rate <= 100:
        parser.error("--video-bit-rate must be between 1 and 100 (Mbit/s)")
    if ns.upload_video:
        if not 1 <= ns.upload_days <= su.MAX_DAYS:
            parser.error(f"--upload-days must be between 1 and {su.MAX_DAYS}")
        try:
            su._check_base(ns.upload_url)
        except su.UploadError as exc:
            parser.error(str(exc))
    if ns.upload_screenshots:
        if ns.screenshot_interval == 0:
            parser.error("--upload-screenshots needs screenshots (--screenshot-interval above 0)")
        if not 1 <= ns.upload_days <= su.MAX_DAYS:
            parser.error(f"--upload-days must be between 1 and {su.MAX_DAYS}")
        try:
            su._check_base(ns.upload_url)
        except su.UploadError as exc:
            parser.error(str(exc))
    pcapdroid_key = os.environ.get(dc.API_KEY_ENV, "").strip() or None
    if ns.capture_pcapdroid and pcapdroid_key is not None and not dc.valid_api_key(pcapdroid_key):
        parser.error(f"{dc.API_KEY_ENV} must be PCAPdroid's key: letters and digits only")
    if ns.capture_pcapdroid and (
        ns.capture_interface is not None
        or ns.capture_container is not None
        or ns.external_pcap is not None
    ):
        parser.error("--capture-pcapdroid cannot be combined with another network capture")
    return Args(
        apk=ns.apk,
        serial=ns.serial,
        duration=ns.duration,
        output_dir=ns.output_dir,
        capture_interface=ns.capture_interface,
        capture_container=ns.capture_container,
        container_runtime=ns.container_runtime,
        package=ns.package,
        aapt_binary=ns.aapt_binary,
        uninstall_after=ns.uninstall_after,
        mr_iid=ns.mr_iid,
        full_logcat=ns.full_logcat,
        adb_command=ns.adb_command,
        external_pcap=ns.external_pcap,
        finalize=ns.finalize,
        existing_reviews=ns.existing_reviews,
        no_grant_permissions=ns.no_grant_permissions,
        link_evidence=ns.link_evidence,
        virustotal=ns.virustotal,
        virustotal_upload=ns.virustotal_upload,
        verdict=ns.verdict,
        screenshot_interval=ns.screenshot_interval,
        capture_pcapdroid=ns.capture_pcapdroid,
        upload_screenshots=ns.upload_screenshots,
        upload_url=ns.upload_url,
        upload_days=ns.upload_days,
        pcapdroid_api_key=pcapdroid_key if ns.capture_pcapdroid else None,
        fresh_install=ns.fresh_install,
        video_bit_rate=ns.video_bit_rate,
        upload_video=ns.upload_video,
        install_copy=ns.install_copy,
        decrypted_log=ns.decrypted_log,
        stop_file=ns.stop_file,
        monkey=ns.monkey,
    )


def resolve_serial(explicit: str | None) -> str:
    if explicit:
        return explicit
    result = run([*ADB, "devices"])
    devices = [
        line.split("\t")[0]
        for line in result.stdout.splitlines()[1:]
        if line.strip() and line.endswith("\tdevice")
    ]
    if not devices:
        raise QuickReviewError("no adb devices connected; connect one or pass --serial")
    if len(devices) > 1:
        raise QuickReviewError(
            f"multiple adb devices connected ({', '.join(devices)}); pass --serial to pick one"
        )
    return devices[0]


def _aapt_binary(explicit: str | None) -> str | None:
    return explicit or shutil.which("aapt2") or shutil.which("aapt")


def detect_package_name(apk_path: Path, aapt_binary: str | None) -> str | None:
    binary = _aapt_binary(aapt_binary)
    if binary is None:
        return None
    result = run([binary, "dump", "badging", str(apk_path)])
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if line.startswith("package:"):
            for field in line.split():
                if field.startswith("name="):
                    return field.split("=", 1)[1].strip("'")
    return None


def list_native_abis(apk_path: Path, aapt_binary: str | None) -> list[str] | None:
    """The ABIs the APK ships native code for. `None`: couldn't check (no aapt);
    `[]`: checked, and it has none (pure Java/Kotlin runs on any device).
    """
    binary = _aapt_binary(aapt_binary)
    if binary is None:
        return None
    result = run([binary, "dump", "badging", str(apk_path)])
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if line.startswith("native-code:"):
            return re.findall(r"'([\w-]{1,32})'", line)
    return []


def list_locales(apk_path: Path, aapt_binary: str | None) -> list[str] | None:
    """The locales the APK has resources for (`--_--` is the default, usually English).
    `None`: couldn't check; `[]`: it declares none.
    """
    binary = _aapt_binary(aapt_binary)
    if binary is None:
        return None
    result = run([binary, "dump", "badging", str(apk_path)])
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if line.startswith("locales:"):
            return re.findall(r"'([\w-]{1,32})'", line)
    return []


def device_android_release(serial: str) -> str | None:
    result = run([*ADB, "-s", serial, "shell", "getprop", "ro.build.version.release"])
    release = result.stdout.strip() if result.returncode == 0 else ""
    return release if re.fullmatch(r"[\w.]{1,16}", release) else None


def locales_summary(locales: list[str]) -> str:
    """Libraries bundle dozens of translations, which buries the one fact the reviewer
    guide asks about: is English there? A long list is summarised.
    """
    if len(locales) <= 8:
        return ", ".join(locales) or "none declared"
    english = [loc for loc in locales if loc.lower().startswith("en")]
    default = "`--_--` (the default resources)" if "--_--" in locales else "no default resources"
    return f"{len(locales)} locales, {default}; English: " + (
        ", ".join(english[:4]) + ("..." if len(english) > 4 else "") if english else "none"
    )


def device_runtime_permissions(serial: str) -> set[str] | None:
    """The permissions this device treats as runtime ("dangerous") ones."""
    result = run([*ADB, "-s", serial, "shell", "pm", "list", "permissions", "-d", "-g"])
    if result.returncode != 0:
        return None
    names = set(re.findall(r"permission:([\w.]{1,200})", result.stdout))
    return names or None


_NOISE_URL_HOSTS = (
    "schemas.android.com",
    "www.w3.org",
    "xmlpull.org",
    "apache.org/licenses",
    "www.apache.org",
    "developer.android.com",
    "java.sun.com",
    "xml.org",
    "javax.xml",
    "ns.adobe.com",
    "creativecommons.org/licenses",
    "www.gnu.org/licenses",
    "source.android.com",
    "goo.gl",
)
_DONATION_HOSTS = (
    "ko-fi.com",
    "patreon.com",
    "liberapay.com",
    "buymeacoffee.com",
    "opencollective.com",
    "paypal.me",
    "github.com/sponsors",
    "flattr.com",
    "donorbox.org",
    "tipeee.com",
)
MAX_EMBEDDED_URLS = 40
MAX_EMBEDDED_URL_CHARS = 80
# A "host" whose last label is one of these is a file name in a string, not a web address.
_FILE_EXTENSIONS = frozenset(
    [
        "css",
        "js",
        "jpg",
        "jpeg",
        "png",
        "gif",
        "svg",
        "html",
        "htm",
        "json",
        "xml",
        "dtd",
        "txt",
        "ttf",
        "woff",
        "woff2",
        "php",
        "java",
        "map",
        "ico",
        "webp",
        "mp3",
        "mp4",
        "wav",
        "pdf",
        "zip",
        "so",
        "dex",
        "bin",
        "cfg",
        "ini",
        "lock",
        "md",
    ]
)
_URL_HOST_RE = re.compile(
    r"^https?://((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24}))"
    r"(?::\d{1,5})?(?:/|$)"
)
_SCANNED_SUFFIXES = (".dex", ".xml", ".arsc", ".json", ".txt", ".html", ".js", ".bundle")


def _embedded_url(raw: str) -> tuple[str, str] | None:
    """(host, url) if `raw` starts with a web address that has a real host name, else None.
    HTML text and JavaScript give plenty of `http://"><span` and `http://.css`; a React Native
    bundle's strings run together (`http://www.` + the next word), so some noise remains.
    """
    url = re.sub(r"[\"'<>\\)\],.;]+$", "", raw)
    match = _URL_HOST_RE.match(url)
    if match is None or match.group(2).lower() in _FILE_EXTENSIONS:
        return None
    return match.group(1).lower(), url[:MAX_EMBEDDED_URL_CHARS]


def apk_embedded_urls(apk_path: Path) -> list[str] | None:
    """The web addresses inside the APK's code and resources, one per host: what a reader needs
    to judge a donation link, an update check or a tracker, none of which need a network capture.
    A React Native app keeps its code in `assets/index.android.bundle`, which is scanned too.
    """
    found: dict[str, str] = {}
    try:
        with zipfile.ZipFile(apk_path) as archive:
            for info in archive.infolist():
                if info.file_size > 64 * 1024 * 1024 or not info.filename.endswith(
                    _SCANNED_SUFFIXES
                ):
                    continue
                for match in re.finditer(rb"https?://[\x21-\x7e]{4,200}", archive.read(info)):
                    cleaned = _embedded_url(match.group(0).decode("ascii", "replace"))
                    if cleaned is None or any(noise in cleaned[1] for noise in _NOISE_URL_HOSTS):
                        continue
                    found.setdefault(cleaned[0], cleaned[1])
    except (OSError, zipfile.BadZipFile):
        return None
    return [found[host] for host in sorted(found)][:MAX_EMBEDDED_URLS]


MAX_DECRYPTED_HOSTS = 12
MAX_DECRYPTED_FULL = 60


def summarise_decrypted(path: Path) -> dict[str, Any]:
    """What a proxy saw, from the log mitm_log_addon.py wrote. A missing file is a result, not an
    error: nothing reached the proxy (an app that ignores the system proxy, or no traffic at all).
    """
    records: list[dict[str, Any]] = []
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict):
                    records.append(record)
    except OSError:
        pass
    requests = [r for r in records if r.get("event") == "request" and isinstance(r.get("url"), str)]
    hosts: dict[str, dict[str, Any]] = {}
    full: list[str] = []
    for record in requests:
        parts = urllib.parse.urlsplit(record["url"])
        host = (parts.hostname or "?").lower()
        entry = hosts.setdefault(
            host, {"host": host, "count": 0, "calls": [], "params": [], "plain": True}
        )
        entry["count"] += 1
        if parts.scheme != "http":
            entry["plain"] = False
        call = f"{record.get('method', '?')} {parts.path or '/'}"
        if call not in entry["calls"] and len(entry["calls"]) < 4:
            entry["calls"].append(call)
        for name in urllib.parse.parse_qs(parts.query, keep_blank_values=True):
            if name not in entry["params"] and len(entry["params"]) < 8:
                entry["params"].append(name)
        if len(full) < MAX_DECRYPTED_FULL:
            status = record.get("status")
            full.append(
                sanitize(f"{record.get('method', '?')} {record['url']}", max_chars=220)
                + (f" -> {status}" if status else "")
            )
    refused: dict[str, int] = {}
    for record in records:
        if record.get("event") == "tls_failed":
            name = str(record.get("sni") or "unknown host")
            refused[name] = refused.get(name, 0) + 1
    return {
        "requests": len(requests),
        "hosts": sorted(hosts.values(), key=lambda h: (-h["count"], h["host"]))[
            :MAX_DECRYPTED_HOSTS
        ],
        "host_count": len(hosts),
        "refused": [{"sni": name, "count": count} for name, count in sorted(refused.items())],
        "full": full,
    }


def donation_urls(urls: list[str]) -> list[str]:
    return [u for u in urls if any(host in u.lower() for host in _DONATION_HOSTS)]


def apk_version_info(apk_path: Path, aapt_binary: str | None) -> str | None:
    """`versionName (versionCode)` from the manifest, or None."""
    binary = _aapt_binary(aapt_binary)
    if binary is None:
        return None
    result = run([binary, "dump", "badging", str(apk_path)])
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if line.startswith("package:"):
            name = re.search(r"versionName='([^']{1,64})'", line)
            code = re.search(r"versionCode='(\d{1,12})'", line)
            if name and code:
                return f"{name.group(1)} ({code.group(1)})"
    return None


def gather_mr_links(
    iid: int, apk_name: str | None = None
) -> tuple[dict[str, Any] | None, str | None]:
    """(links, None) or (None, why not). Never raises: this is context for the reader."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import fetch_review_queue as fetcher  # noqa: PLC0415
    import mr_evidence  # noqa: PLC0415

    try:
        report = fetcher.fetch_code_quality(iid)
        evidence = mr_evidence.collect(
            iid,
            get_json=fetcher.http_get_json,
            get_text=fetcher.http_get,
            code_quality=report,
            apk_name=apk_name,
        )
    except (fetcher.RateLimited, fetcher.AuthRejected) as exc:
        return None, exc.describe()
    except (OSError, ValueError, KeyError) as exc:
        return None, f"{type(exc).__name__}: {sanitize(str(exc), max_chars=200)}"
    return dataclasses.asdict(evidence), None


def sha256_of(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def device_abis(serial: str) -> list[str] | None:
    result = run([*ADB, "-s", serial, "shell", "getprop", "ro.product.cpu.abilist"])
    if result.returncode != 0:
        return None
    abis = [a for a in result.stdout.strip().split(",") if re.fullmatch(r"[\w-]{1,32}", a)]
    return abis or None


def list_permissions(apk_path: Path, aapt_binary: str | None) -> list[str] | None:
    """`None` means "couldn't check" (no aapt/aapt2 available); `[]` means
    "checked, and the manifest declares none" — these are not the same
    thing, and the report says so rather than conflating them.
    """
    binary = _aapt_binary(aapt_binary)
    if binary is None:
        return None
    result = run([binary, "dump", "permissions", str(apk_path)])
    if result.returncode != 0:
        return None
    permissions = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("uses-permission:") or line.startswith("uses-permission-sdk-23:"):
            for field in line.split():
                if field.startswith("name="):
                    permissions.append(field.split("=", 1)[1].strip("'"))
    return permissions


# Every quantifier here is bounded: these run against device-supplied lines
# of unbounded length, and an unbounded `\w*` feeding a digit string into
# `int()` below is both a backtracking and an "Exceeds the limit (4300
# digits) for integer string conversion" hazard.
_APPOPS_HEADER_RE = re.compile(r"^\s*([A-Z][A-Z0-9_]{0,63})\s*\((\w{1,32})\):\s*$")
_APPOPS_ACCESS_RE = re.compile(
    r"Access: \[(?P<state>[\w-]{1,32})\] (?P<abs_ts>\d{4}-\d{2}-\d{2} [\d:.]{1,32}) "
    r"\((?P<ago>[+-]\w{0,32})\) duration=(?P<duration>[+-]\w{0,32})"
)
_COMPACT_DURATION_RE = re.compile(r"(?:(\d{1,6})h)?(?:(\d{1,6})m)?(?:(\d{1,6})s)?(?:(\d{1,6})ms)?")


def _parse_compact_duration_seconds(text: str) -> float:
    """Parses Android's own compact duration format (`1m2s289ms`, `3s701ms`,
    `0ms`, optionally hour-prefixed), as used throughout `dumpsys appops`
    output, into seconds. Sign-agnostic: strip the leading `+`/`-` first.
    """
    match = _COMPACT_DURATION_RE.fullmatch(text.lstrip("+-"))
    if match is None:
        return 0.0
    hours, minutes, seconds, millis = (int(g) if g else 0 for g in match.groups())
    return float(hours * 3600 + minutes * 60 + seconds) + millis / 1000


@dataclass(frozen=True, slots=True)
class PermissionAccess:
    op: str
    mode: str
    state: str
    host_time: float  # seconds since the epoch, on *this host's* own clock
    duration_seconds: float


def parse_appops_dump(output: str, *, dump_host_time: float) -> list[PermissionAccess]:
    """Parses `adb shell dumpsys appops --package <pkg>` output (confirmed
    against a real Android 11 image; there is no documented schema and the
    format has changed across Android versions before). Each `Access:` line
    is attributed to the nearest preceding `OP (mode):` header line above
    it by simple line scanning, rather than a strict structural parse of
    this format's nesting — more robust to the minor formatting
    differences an undocumented, version-varying format is likely to have.

    Deliberately keyed off the *relative* "(-Xs ago)" annotation next to
    each access, not its absolute local-clock timestamp: combined with
    `dump_host_time` (this host's own clock at the moment the dump was
    requested), this never needs to parse or trust the device's timezone,
    only arithmetic on a single relative offset.
    """
    accesses = []
    current_op: str | None = None
    current_mode: str | None = None
    for line in output.splitlines():
        header = _APPOPS_HEADER_RE.match(line)
        if header:
            current_op, current_mode = header.group(1), header.group(2)
            continue
        access = _APPOPS_ACCESS_RE.search(line)
        if access and current_op is not None:
            ago = _parse_compact_duration_seconds(access.group("ago"))
            duration = _parse_compact_duration_seconds(access.group("duration"))
            accesses.append(
                PermissionAccess(
                    op=current_op,
                    mode=current_mode or "unknown",
                    state=access.group("state"),
                    host_time=dump_host_time - ago,
                    duration_seconds=duration,
                )
            )
    return accesses


def poll_permission_accesses(
    serial: str, package: str, stop_event: threading.Event, interval: float = 1.0
) -> list[PermissionAccess]:
    """Polls `dumpsys appops` every `interval` seconds until `stop_event` is
    set, so a discrete access is caught close to when it actually happened
    rather than relying on a single post-hoc dump: this Android version has
    no `--history` flag to dump everything at once (confirmed by asking
    it), and even where one exists it's not guaranteed portable across
    versions. The same discrete access is expected to show up on more than
    one poll (same op, same access timestamp) until it scrolls out of
    Android's own short in-memory history; deduped by (op, rounded
    timestamp), keeping whichever poll saw the largest duration so an
    access that was still ongoing when first seen ends up with its final,
    not partial, duration.
    """
    seen: dict[tuple[str, float], PermissionAccess] = {}
    while True:
        before = time.time()
        result = run([*ADB, "-s", serial, "shell", "dumpsys", "appops", "--package", package])
        after = time.time()
        if result.returncode == 0:
            dump_time = (before + after) / 2
            for access in parse_appops_dump(result.stdout, dump_host_time=dump_time):
                key = (access.op, round(access.host_time, 1))
                existing = seen.get(key)
                if existing is None or access.duration_seconds > existing.duration_seconds:
                    seen[key] = access
        if stop_event.wait(interval):
            break
    return sorted(seen.values(), key=lambda a: a.host_time)


_LOGCAT_LINE_RE = re.compile(
    r"^(?P<month>\d{2})-(?P<day>\d{2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\.(?P<millis>\d{3})\s+"
    r"(?P<pid>\d{1,10})\s+\d{1,10}\s+(?P<level>[A-Z])\s+(?P<tag>.{0,128}?):\s?(?P<message>.*)$"
)


# Android logs this every time any process of an app starts (including a
# later-starting background :service process a single `pidof` snapshot
# right after launch would miss), which makes it the most reliable way to
# know which logcat lines are the reviewed app's own without an extra adb
# round-trip per line.
def _start_proc_re(package: str) -> re.Pattern[str]:
    return re.compile(rf"Start proc (\d{{1,10}}):{re.escape(package)}(?=[/:]|\s|$)")


def extract_app_pids(logcat_text: str, package: str) -> list[int]:
    return sorted({int(m.group(1)) for m in _start_proc_re(package).finditer(logcat_text)})


def resolve_running_pids(serial: str, package: str) -> list[int]:
    """A same-instant supplement to `extract_app_pids`, for the case where
    the app's process was already alive before this run started (no fresh
    "Start proc" line to find): best-effort, ignored on failure.
    """
    result = run([*ADB, "-s", serial, "shell", "pidof", package])
    if result.returncode != 0:
        return []
    try:
        return [int(p) for p in result.stdout.split()]
    except ValueError:
        return []


@dataclass(frozen=True, slots=True)
class DeviceClockReference:
    """Converts a logcat line's local-clock timestamp into this host's own
    clock, without ever needing to know or trust the device's timezone:
    measured empirically once, from a single `adb shell date` call that
    reports its own epoch (timezone-independent by definition) and its
    local-format string in the same breath, so the two can be compared
    directly rather than assumed to agree.
    """

    tz_offset_seconds: float
    device_to_host_offset_seconds: float

    def to_host_time(self, naive_local: datetime) -> float:
        device_epoch = naive_local.replace(tzinfo=UTC).timestamp() + self.tz_offset_seconds
        return device_epoch + self.device_to_host_offset_seconds


def measure_device_clock(serial: str, reference_year: int) -> DeviceClockReference | None:
    """`adb shell <cmd> <args...>` rejoins its argv with spaces and re-parses
    it on the device's own shell — confirmed the hard way that a format
    string containing spaces (`+%s %m-%d %H:%M:%S`) silently only returned
    the first word, since it arrived unquoted on the far end. A single
    space-free format string sidesteps this rather than fighting with
    another layer of shell quoting.
    """
    host_before = time.time()
    result = run([*ADB, "-s", serial, "shell", "date", "+%s_%m-%d_%H:%M:%S"])
    host_after = time.time()
    if result.returncode != 0:
        return None
    parts = result.stdout.strip().split("_")
    if len(parts) != 3:
        return None
    epoch_str, date_str, time_str = parts
    try:
        device_epoch = float(epoch_str)
        month_str, day_str = date_str.split("-")
        hour_str, minute_str, second_str = time_str.split(":")
        naive_local = datetime(
            reference_year,
            int(month_str),
            int(day_str),
            int(hour_str),
            int(minute_str),
            int(second_str),
        )
    except ValueError:
        return None
    host_epoch = (host_before + host_after) / 2
    tz_offset = device_epoch - naive_local.replace(tzinfo=UTC).timestamp()
    return DeviceClockReference(
        tz_offset_seconds=tz_offset,
        device_to_host_offset_seconds=host_epoch - device_epoch,
    )


@dataclass(frozen=True, slots=True)
class LogcatEntry:
    # None for a line this couldn't parse (still shown, just unfilterable by time).
    host_time: float | None
    level: str
    tag: str
    message: str
    raw: str
    pid: int | None


def parse_logcat(
    text: str, clock: DeviceClockReference | None, reference_year: int
) -> list[LogcatEntry]:
    entries = []
    for raw_line in text.splitlines():
        line = sanitize(raw_line, max_chars=MAX_LOGCAT_LINE_CHARS)
        if not line.strip():
            continue
        match = _LOGCAT_LINE_RE.match(line)
        naive_local: datetime | None = None
        if match is not None:
            g = match.groupdict()
            try:
                # The app under review chooses these digits: logcat repeats
                # its header on every line of a multi-line message, so the
                # message body itself can present as a header with a
                # well-formed-looking but nonexistent date such as 99-99.
                naive_local = datetime(
                    reference_year,
                    int(g["month"]),
                    int(g["day"]),
                    int(g["hour"]),
                    int(g["minute"]),
                    int(g["second"]),
                    int(g["millis"]) * 1000,
                )
            except ValueError:
                match = None
        if match is None:
            entries.append(
                LogcatEntry(host_time=None, level="?", tag="", message=line, raw=line, pid=None)
            )
            continue
        host_time = (
            clock.to_host_time(naive_local)
            if clock is not None and naive_local is not None
            else None
        )
        entries.append(
            LogcatEntry(
                host_time=host_time,
                level=match.group("level"),
                tag=match.group("tag").strip(),
                message=match.group("message"),
                raw=line,
                pid=int(match.group("pid")),
            )
        )
    return entries


_NATIVE_CRASH_RE = re.compile(r"Fatal signal (\d{1,3}) \((\w{1,16})\).{0,300}?\bpid (\d{1,10}) ")
MAX_REPORTED_CRASHES = 5
MAX_TRACE_LINES = 120
# A stack frame from these is the platform's, not the app's.
_FRAMEWORK_FRAME_PREFIXES = (
    "android.",
    "java.",
    "javax.",
    "com.android.",
    "dalvik.",
    "libcore.",
    "sun.",
)
FRAMEWORK_ONLY_NOTE = (
    " (all frames are Android's own code, none the app's: possibly a stale process or a "
    "broken install rather than the app; see logcat.txt)"
)


def _trace_is_all_framework(entries: list[LogcatEntry], index: int) -> bool:
    """True when the crash's stack trace has frames and none of them is outside the platform."""
    first = entries[index]
    frames: list[str] = []
    for entry in entries[index + 1 : index + 1 + MAX_TRACE_LINES]:
        if entry.pid != first.pid or entry.tag != "AndroidRuntime":
            break
        match = re.match(r"^\s*at\s+([\w$.<>-]+)", entry.message)
        if match is not None:
            frames.append(match.group(1).removeprefix("-$$Nest$m"))
    return bool(frames) and all(f.startswith(_FRAMEWORK_FRAME_PREFIXES) for f in frames)


def detect_crashes(entries: list[LogcatEntry], package: str, app_pids: list[int]) -> list[str]:
    """What the log says went wrong in the reviewed app: an uncaught Java
    exception, a native signal in one of its processes, or an ANR. Matched on
    the package or the app's own pids, so another app's crash is not reported
    as this one's. One short, sanitised line each; the log has the rest.
    """
    anr_re = re.compile(rf"ANR in {re.escape(package)}(?:[\s(]|$)")
    pids = set(app_pids)
    found: list[str] = []
    for index, entry in enumerate(entries):
        description: str | None = None
        note = ""
        if entry.tag == "AndroidRuntime" and entry.message.startswith("FATAL EXCEPTION"):
            following = [
                e
                for e in entries[index + 1 : index + 12]
                if e.pid == entry.pid and e.tag == "AndroidRuntime"
            ]
            owner = next((e for e in following if e.message.startswith("Process: ")), None)
            if owner is not None and owner.message.startswith(f"Process: {package},"):
                reason = next(
                    (
                        e.message
                        for e in following
                        if not e.message.startswith(("Process: ", "\t", "at "))
                        and e.message != entry.message
                    ),
                    "",
                )
                description = f"uncaught exception: {reason}".strip(": ")
                if _trace_is_all_framework(entries, index):
                    note = FRAMEWORK_ONLY_NOTE
        elif entry.tag == "ActivityManager" and anr_re.search(entry.message):
            description = "the app was not responding (ANR)"
        else:
            native = _NATIVE_CRASH_RE.search(entry.message)
            if native is not None and int(native.group(3)) in pids:
                description = f"native crash: signal {native.group(1)} ({native.group(2)})"
        if description is not None:
            # The note is added after the cut, so a long exception message cannot push it off.
            text = sanitize(description, max_chars=300 - len(note)) + note
            if text not in found:
                found.append(text)
            if len(found) >= MAX_REPORTED_CRASHES:
                break
    return found


def abi_mismatch_note(apk_abis: list[str] | None, device: list[str] | None) -> str | None:
    """The APK ships native code, none of it for this device's primary ABI. An
    emulator can translate another ABI, but not every app survives that, so a
    crash here may be the device's doing, not the app's.
    """
    if not apk_abis or not device or device[0] in apk_abis:
        return None
    return (
        f"The APK ships native code only for {', '.join(apk_abis)}; this device's primary ABI "
        f"is {device[0]}. A crash here may come from that mismatch rather than from the app: "
        f"check on a device whose primary ABI is one of {', '.join(apk_abis)}."
    )


def read_existing_reviews(mr_iid: int) -> tuple[list[str], str | None]:
    """(lines describing what the merge request's comments already say, or [] and the
    reason they could not be read). Never raises: this is context, not part of the review.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import fetch_review_queue as fetcher  # noqa: PLC0415
    from review_coverage import describe  # noqa: PLC0415

    try:
        return describe(fetcher.fetch_coverage_for(mr_iid)), None
    except (fetcher.RateLimited, fetcher.AuthRejected) as exc:
        return [], exc.describe()
    except (OSError, ValueError, KeyError) as exc:
        return [], f"{type(exc).__name__}: {sanitize(str(exc), max_chars=200)}"


def resolve_container_pid(container: str, runtime: str = "podman") -> int | None:
    """`podman` and `docker` both support this exact inspect format."""
    result = run([runtime, "inspect", "--format", "{{.State.Pid}}", container])
    if result.returncode != 0:
        return None
    try:
        pid = int(result.stdout.strip())
    except ValueError:
        return None
    return pid if pid > 0 else None  # 0 means "not running" for both runtimes


def install_apk(serial: str, apk_path: Path, *, grant_permissions: bool = True) -> None:
    """By default `-g` grants every runtime permission the manifest declares, at
    install time: the point of this tool is observing what the app under
    review actually does, and a permission-request dialog only a human can
    dismiss would otherwise block whatever's gated behind it for the
    entire recording window. `--no-grant-permissions` installs without it, which is
    what the reviewer guide's "can be used without granting optional runtime
    permissions" needs: the person at the device answers the prompts.
    """
    flags = ["-r", "-g"] if grant_permissions else ["-r"]
    result = run([*ADB, "-s", serial, "install", *flags, str(apk_path)])
    if result.returncode != 0 or "Success" not in result.stdout:
        output = f"{result.stderr} {result.stdout}"
        if "INSTALL_FAILED_NO_MATCHING_ABIS" in output:
            raise QuickReviewError(
                "adb install failed: the APK's native code does not match this device's CPU "
                "(INSTALL_FAILED_NO_MATCHING_ABIS). An app with native code for ARM only cannot "
                "run on an x86 emulator; that is a finding about the app (no x86 build), not "
                "something to work around here. A phone with an ARM CPU can run it."
            )
        raise QuickReviewError(f"adb install failed: {result.stderr or result.stdout}".strip())


def is_installed(serial: str, package: str) -> bool:
    result = run([*ADB, "-s", serial, "shell", "pm", "list", "packages", package])
    return result.returncode == 0 and f"package:{package}" in result.stdout.split()


def uninstall_apk(serial: str, package: str) -> None:
    run([*ADB, "-s", serial, "uninstall", package])


def resolve_launcher_component(serial: str, package: str) -> str | None:
    """Ask the device itself which activity its launcher would actually
    start, rather than guessing from the APK's manifest: some apps (F-Droid
    among them, for its panic-button disguise mode) declare more than one
    `LAUNCHER` activity, and only the device knows which one is actually
    enabled right now.
    """
    result = run(
        [
            *ADB,
            "-s",
            serial,
            "shell",
            "cmd",
            "package",
            "resolve-activity",
            "--brief",
            "-c",
            "android.intent.category.LAUNCHER",
            "-a",
            "android.intent.action.MAIN",
            package,
        ]
    )
    if result.returncode != 0:
        return None
    # Last line is the component (`pkg/.Activity` or `pkg/full.path.Activity`);
    # earlier lines are resolver metadata (priority=... etc).
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines or not _COMPONENT_RE.match(lines[-1]):
        return None
    return lines[-1]


LAUNCHER_FLAGS = "0x10200000"  # FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_RESET_TASK_IF_NEEDED


def launch_app(serial: str, package: str) -> None:
    """Launching via an explicit `am start -n <component>`, not `monkey -c
    LAUNCHER`, because `monkey` was confirmed the hard way to be unreliable
    here: it reported a non-zero exit code even on a successful launch, and
    on one real run it printed its usual verbose "launching" output but the
    launcher never actually left the foreground (`dumpsys activity
    activities` still showed the home screen resumed, not the app) — a
    silent no-op indistinguishable from success by exit code alone.
    """
    component = resolve_launcher_component(serial, package)
    if component is None:
        raise QuickReviewError(f"could not resolve a launcher activity for {package}")
    # The intent a launcher sends (MAIN, LAUNCHER, NEW_TASK | RESET_TASK_IF_NEEDED), not a bare
    # component: seen on a real app, a bare `am start -n` followed by any launcher-style start
    # (monkey's, or a user's tap) made a SECOND MainActivity in another task, and an app that
    # builds a DataStore per activity then crashed. A real user never gets that, so the review
    # must not either. Checked: launcher-style twice or three times never crashed.
    result = run(
        [
            *ADB, "-s", serial, "shell", "am", "start",
            "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER",
            "-f", LAUNCHER_FLAGS, "-n", component,
        ]
    )  # fmt: skip
    if result.returncode != 0 or "Error" in result.stdout:
        detail = (result.stdout or result.stderr).strip()
        raise QuickReviewError(f"failed to launch {component}: {detail}")


def start_logcat(serial: str, output_path: Path) -> subprocess.Popen[bytes] | None:
    run([*ADB, "-s", serial, "logcat", "-c"])  # clear, so this run's log starts empty
    try:
        handle = output_path.open("wb")
    except OSError:
        return None
    try:
        return subprocess.Popen(  # noqa: S603
            [*ADB, "-s", serial, "logcat"], stdout=handle, stderr=subprocess.DEVNULL
        )
    except OSError:
        handle.close()
        return None


MONKEY_SEED = 1
MONKEY_THROTTLE_MS = 500
MONKEY_PROCESS = "com.android.commands.monkey"


def monkey_events(duration: int) -> int:
    return max(1, duration * 1000 // MONKEY_THROTTLE_MS)


def monkey_command(serial: str, package: str, duration: int) -> list[str]:
    """Seeded touches and drags only, in the app's own package. No home or back keys and no app
    switching, so it cannot leave the app; crashes and timeouts are ignored so that it keeps going
    (the crash is in logcat, where the report looks for it).
    """
    return [
        *ADB, "-s", serial, "shell", "monkey", "-p", package, "-s", str(MONKEY_SEED),
        "--throttle", str(MONKEY_THROTTLE_MS), "--pct-touch", "80", "--pct-motion", "20",
        "--pct-nav", "0", "--pct-majornav", "0", "--pct-syskeys", "0", "--pct-appswitch", "0",
        "--pct-anyevent", "0", "--pct-trackball", "0", "--pct-pinchzoom", "0",
        "--ignore-crashes", "--ignore-timeouts", "--ignore-security-exceptions",
        str(monkey_events(duration)),
    ]  # fmt: skip


def monkey_note(duration: int) -> str:
    return (
        f"seeded pseudo-random touches and drags (Android `monkey`, seed {MONKEY_SEED}, "
        f"{monkey_events(duration)} events, one every {MONKEY_THROTTLE_MS} ms, limited to the "
        "app's package). This is not a test of anything: it only makes an app that waits for a "
        "tap do something, and it can tap anything, including what a reviewer would not."
    )


def start_monkey(
    serial: str, package: str, duration: int, log_path: Path
) -> subprocess.Popen[bytes] | None:
    try:
        handle = log_path.open("wb")
    except OSError:
        return None
    try:
        return subprocess.Popen(  # noqa: S603
            monkey_command(serial, package, duration), stdout=handle, stderr=subprocess.STDOUT
        )
    except OSError:
        return None
    finally:
        handle.close()


def stop_monkey(serial: str, proc: subprocess.Popen[bytes] | None) -> None:
    """Killing the adb client does not stop the process on the device, so stop that too."""
    run([*ADB, "-s", serial, "shell", "pkill", "-f", MONKEY_PROCESS])
    if proc is None:
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def stop_logcat(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def start_screen_recording(
    serial: str, duration: int, bit_rate_mbps: int | None = None
) -> subprocess.Popen[bytes] | None:
    bit_rate = ["--bit-rate", str(bit_rate_mbps * 1_000_000)] if bit_rate_mbps else []
    try:
        return subprocess.Popen(  # noqa: S603
            [
                *ADB,
                "-s",
                serial,
                "shell",
                "screenrecord",
                *bit_rate,
                "--time-limit",
                str(duration),
                REMOTE_RECORDING_PATH,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None


SEGMENT_SECONDS = 170  # below screenrecord's hard limit, so a segment ends cleanly by itself
STOP_FILE_MAX_SECONDS = 3600


def join_segments(segments: list[Path], output: Path, warn: Callable[[str], None]) -> bool:
    """One file from the segments, in order: ffmpeg's concat when there are several. Without
    ffmpeg only the first segment is kept as the recording, and the rest stay where they are.
    """
    if not segments:
        return False
    if len(segments) == 1:
        segments[0].replace(output)
        return output.exists()
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is None:
        segments[0].replace(output)
        warn(
            f"{len(segments)} recording segments and no ffmpeg to join them: screen_recording.mp4 "
            f"is the first {SEGMENT_SECONDS}s only; the others are in {segments[0].parent}"
        )
        return output.exists()
    listing = output.parent / "segments.txt"
    listing.write_text("".join(f"file '{seg.resolve()}'\n" for seg in segments), encoding="utf-8")
    result = run(
        [
            ffmpeg,
            "-y",
            "-loglevel",
            "error",
            "-f",
            "concat",
            "-safe",
            "0",
            "-i",
            str(listing),
            "-c",
            "copy",
            str(output),
        ]  # fmt: skip
    )
    listing.unlink(missing_ok=True)
    if result.returncode != 0 or not output.exists():
        segments[0].replace(output)
        warn(f"ffmpeg could not join the {len(segments)} segments; only the first is kept")
    return output.exists()


class SegmentedRecorder:
    """A screen recording longer than screenrecord's 180 s limit: a new segment whenever one ends,
    a clean stop (SIGINT, so the file is finalised) at the end, and the segments joined.
    The device-facing steps are passed in, so the control flow can be tested without a device.
    """

    def __init__(
        self,
        start: Callable[[], subprocess.Popen[bytes] | None],
        pull: Callable[[Path], bool],
        interrupt: Callable[[], None],
        segments_dir: Path,
        warn: Callable[[str], None],
    ) -> None:
        self._start, self._pull, self._interrupt = start, pull, interrupt
        self._dir, self._warn = segments_dir, warn
        self._dir.mkdir(parents=True, exist_ok=True)
        self.segments: list[Path] = []
        self._proc = start()
        if self._proc is None:
            warn("screen recording did not start")

    def _collect(self) -> None:
        path = self._dir / f"segment-{len(self.segments) + 1:02d}.mp4"
        if self._pull(path):
            self.segments.append(path)
        else:
            self._warn("could not pull a screen recording segment off the device")

    def tick(self) -> None:
        """Call regularly: when the running segment has ended by itself, keep it, start another."""
        if self._proc is not None and self._proc.poll() is not None:
            self._collect()
            self._proc = self._start()

    def finish(self, output: Path) -> Path | None:
        if self._proc is not None:
            if self._proc.poll() is None:
                self._interrupt()
                try:
                    self._proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
            self._collect()
            self._proc = None
        return output if join_segments(self.segments, output, self._warn) else None


def interrupt_screen_recording(serial: str) -> None:
    """SIGINT, which makes screenrecord finalise its file; killing it would leave it unplayable."""
    run([*ADB, "-s", serial, "shell", "pkill", "-2", "screenrecord"])


def pull_screen_recording(serial: str, output_path: Path) -> bool:
    result = run([*ADB, "-s", serial, "pull", REMOTE_RECORDING_PATH, str(output_path)])
    run([*ADB, "-s", serial, "shell", "rm", "-f", REMOTE_RECORDING_PATH])
    return result.returncode == 0 and output_path.exists()


def _direct_flows(data: ReportData) -> list[str]:
    """For an app's own capture with no DNS or TLS names: the addresses it did talk to, so that
    "no names" is not read as "no traffic". Empty when there is nothing to say.
    """
    if (
        data.network_state != "app-filtered"
        or data.pcap_path is None
        or not data.pcap_path.exists()
    ):
        return []
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import pcap_flows  # noqa: PLC0415

    return [
        f"{flow.endpoint} ({flow.proto.upper()}, {flow.packets} packets)"
        for flow in pcap_flows.summarise_flows(data.pcap_path)[:MAX_REPORTED_FLOWS]
    ]


MAX_REPORTED_FLOWS = 8


def _network_summary(network_log_path: Path | None) -> tuple[str, list[str]]:
    if network_log_path is None or not network_log_path.exists():
        return "not captured (see warnings above)", []
    # A dict, not a list, for the dedupe: an app querying a fresh random
    # hostname every time would otherwise make this quadratic in the number
    # of events, which it fully controls.
    endpoints: dict[str, None] = {}
    count = 0
    try:
        with network_log_path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                count += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                value = record.get("sni") or record.get("query_name")
                if isinstance(value, str) and value and len(endpoints) < MAX_REPORTED_ENDPOINTS:
                    endpoints[value] = None
    except OSError:
        return "not captured (see warnings above)", []
    if count == 0:
        return "captured, no DNS/TLS-SNI activity observed", []
    return f"{count} event(s) recorded", list(endpoints)


def select_shareable_logcat(
    entries: list[LogcatEntry], app_pids: list[int], *, full: bool
) -> list[LogcatEntry]:
    """The whole device's logcat carries other apps' and the system's lines,
    and a real run put the phone's Wi-Fi network name in the report. By
    default only the reviewed app's own processes are kept; with no known pid
    that is nothing at all, deliberately: failing closed beats guessing.
    Unparseable lines (no pid) are dropped too, as they can't be attributed.
    """
    if full:
        return entries
    pids = set(app_pids)
    return [entry for entry in entries if entry.pid is not None and entry.pid in pids]


@dataclass(frozen=True, slots=True)
class ReportData:
    apk_path: Path
    package: str | None
    serial: str
    duration: int
    started_at: datetime
    ended_at: datetime
    screen_recording_path: Path | None
    network_log_path: Path | None
    pcap_path: Path | None
    permissions: list[str] | None
    logcat_path: Path | None
    permission_accesses: list[PermissionAccess]
    logcat_entries: list[LogcatEntry]
    app_pids: list[int]
    warnings: list[str]
    # "app": only the reviewed app's own process(es) are in logcat_entries and
    # logcat_text; "full": the whole device's log (--full-logcat). The raw
    # device-wide logcat.txt is a local file and is never embedded in "app" mode.
    logcat_scope: str
    logcat_text: str
    # "": the network section is complete as it stands. "pending": the pcap is
    # still being captured and --finalize will add it. "windowed": it came from
    # a longer capture and was cut to the review's own time window.
    network_state: str = ""
    crashes: list[str] = field(default_factory=list)
    apk_abis: list[str] | None = None
    device_abis: list[str] | None = None
    existing_reviews: list[str] = field(default_factory=list)
    apk_sha256: str | None = None
    locales: list[str] | None = None
    # The declared permissions this device treats as runtime ones, and whether they were
    # granted at install. None: not known (no aapt, or the device would not say).
    runtime_permissions: list[str] | None = None
    permissions_granted: bool = True
    device_android: str | None = None
    # Links the review's claims can point at (mr_evidence.py), and the APK's own facts.
    mr_links: dict[str, Any] | None = None
    mr_links_note: str | None = None
    apk_urls: list[str] | None = None
    apk_version: str | None = None
    virustotal: dict[str, Any] | None = None
    virustotal_note: str | None = None
    verdict: str | None = None
    # Screenshots saved under <output>/screenshots/, whether any were wanted, and the
    # links they were uploaded to (--upload-screenshots), if they were.
    screenshots: list[Path] = field(default_factory=list)
    screenshots_wanted: bool = False
    screenshot_urls: list[str] = field(default_factory=list)
    video_url: str | None = None
    # What a proxy saw of the app's TLS traffic (summarise_decrypted), or None if none was set up.
    decrypted: dict[str, Any] | None = None
    # What fed the app input during the recording, if anything did (see --monkey).
    input_note: str | None = None


def _abi_lines(data: ReportData) -> list[str]:
    if data.apk_abis is None and data.device_abis is None:
        return []
    apk = (
        "unknown (no aapt)"
        if data.apk_abis is None
        else ", ".join(data.apk_abis) or "none (no native code)"
    )
    device = ", ".join(data.device_abis) if data.device_abis else "unknown"
    return [f"- **ABIs**: APK native code: {_md_code(apk)}; device: {_md_code(device)}"]


def _existing_review_lines(data: ReportData) -> list[str]:
    if not data.existing_reviews:
        return []
    return [
        "## Existing reviews on this merge request",
        "",
        "For you, not for the checklist. Read from its comments; claims in free text, "
        "not verified.",
        "",
        *[f"- {sanitize(line)}" for line in data.existing_reviews],
        "",
    ]


def _crash_lines(data: ReportData) -> list[str]:
    if not data.crashes:
        return []
    lines = ["## The app crashed during this run", ""]
    lines += [f"- {_md_code(crash)}" for crash in data.crashes]
    note = abi_mismatch_note(data.apk_abis, data.device_abis)
    if note:
        lines += ["", note]
    lines.append("")
    return lines


APP_FILTERED_NOTE = (
    "Only this app's own traffic was recorded (PCAPdroid, filtered to the app): the phone's "
    "other apps and Android itself are not in it. DNS over TLS was blocked so that lookups "
    "stay visible; DNS over HTTPS would still be invisible, and the app can tell that a VPN "
    "is up. An app that bypasses the VPN is not seen either."
)


def _screenshot_lines(data: ReportData) -> list[str]:
    if not data.screenshots_wanted:
        return []
    if not data.screenshots:
        return [
            "## Screenshots",
            "",
            "None could be taken (the app may block screenshots, or the device refused).",
            "",
        ]
    return [
        "## Screenshots",
        "",
        f"{len(data.screenshots)} saved. They show whatever was on the screen, personal "
        "details included: look at each before you share it.",
        "",
        *(f"- `{path}`" for path in data.screenshots),
        "",
    ]


MAX_CAPTURE_HOSTS = 5000


def _app_capture_hosts(data: ReportData) -> set[str] | None:
    """The host names in the app's OWN capture (PCAPdroid, filtered to the app), to check the
    proxy's hosts against. None when there is no such capture: a whole-emulator capture says
    nothing about who made a request, so it must not be used for this.
    """
    if data.network_state != "app-filtered" or data.network_log_path is None:
        return None
    names: set[str] = set()
    try:
        with data.network_log_path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                value = (
                    record.get("sni") or record.get("query_name")
                    if isinstance(record, dict)
                    else None
                )
                if isinstance(value, str) and value and len(names) < MAX_CAPTURE_HOSTS:
                    names.add(value.lower())
    except OSError:
        return None
    return names


def _attribution(host: str, *, plain: bool, capture: set[str] | None) -> str | None:
    """How far the app's own capture backs a proxy host: a short phrase, or None when it cannot say.
    Plain HTTP cannot be checked: the proxy resolves the name, so the app's capture never shows it.
    """
    if capture is None:
        return None
    if host.lower() in capture:
        return "in the app's own capture"
    if plain:
        return "plain HTTP, cannot be checked against the app's capture"
    return "NOT in the app's own capture: may not be the app's (system or WebView?)"


DECRYPTED_CAVEAT = (
    "These come from a re-signed copy of the APK that trusts a proxy's CA, so it is a different "
    "binary from the one F-Droid ships and may behave differently (the evidence above describes "
    "the original file). The proxy sees the whole emulator, not only the app: check the hosts "
    "against the app's own capture before attributing a request to it."
)


def _decrypted_lines(data: ReportData) -> list[str]:
    summary = data.decrypted
    if summary is None:
        return []
    lines = ["", "## What the app sent over TLS (through a proxy)", "", DECRYPTED_CAVEAT, ""]
    if not summary["requests"] and not summary["refused"]:
        lines += [
            "Nothing reached the proxy. The app may ignore the system proxy, or it made no "
            "requests in this window; this is not proof that it sent nothing.",
            "",
        ]
        return lines
    lines.append(
        f"{summary['requests']} request(s) to {summary['host_count']} host(s). **Read this before "
        "sharing it**: full URLs can contain whatever was typed during the run."
    )
    lines.append("")
    capture = _app_capture_hosts(data)
    if capture is None:
        lines += [
            "No per-app capture to check the hosts against: none of them is attributed to the app.",
            "",
        ]
    elif summary["hosts"]:
        lines += ["Hosts, checked against the app's own capture:", ""]
        for entry in summary["hosts"]:
            note = _attribution(entry["host"], plain=entry.get("plain", False), capture=capture)
            lines.append(f"- {_md_code(entry['host'])} x{entry['count']}: {note}")
        lines.append("")
    lines.extend(f"- {_md_code(entry)}" for entry in summary["full"])
    if summary["refused"]:
        lines += [
            "",
            "TLS handshakes the app refused (it did not accept the proxy's certificate):",
            "",
        ]
        for r in summary["refused"]:
            note = _attribution(r["sni"], plain=False, capture=capture)
            lines.append(f"- {_md_code(r['sni'])} x{r['count']}" + (f": {note}" if note else ""))
        lines += [
            "",
            "A refusal means certificate pinning or the app's own trust store: the proxy could "
            "not read that traffic, so it is not covered above.",
        ]
    lines.append("")
    return lines


def _decrypted_row(data: ReportData) -> str | None:
    """For the posted checklist: hosts, calls and parameter NAMES. Never query values or bodies,
    which can hold what the reviewer typed; the local report has the full requests.
    """
    summary = data.decrypted
    if summary is None:
        return None
    if not summary["requests"] and not summary["refused"]:
        return "nothing reached the proxy (the app may ignore the system proxy)"
    parts = []
    capture = _app_capture_hosts(data)
    for entry in summary["hosts"]:
        note = _attribution(entry["host"], plain=entry.get("plain", False), capture=capture)
        calls = ", ".join(_table_cell_code(c) for c in entry["calls"])
        params = (
            f"; parameters {', '.join(_table_cell_code(p) for p in entry['params'])}"
            if entry["params"]
            else ""
        )
        tag = f" [{note}]" if note else ""
        parts.append(f"{_table_cell_code(entry['host'])} x{entry['count']}: {calls}{params}{tag}")
    text = f"{summary['requests']} request(s) to {summary['host_count']} host(s): " + "; ".join(
        parts
    )
    if summary["refused"]:
        names = ", ".join(
            _table_cell_code(r["sni"])
            + (
                f" [{note}]"
                if (note := _attribution(r["sni"], plain=False, capture=capture))
                else ""
            )
            for r in summary["refused"]
        )
        text += f". Refused the proxy's certificate (pinning or its own trust store): {names}"
    return text + ". From a re-signed copy that trusts a proxy CA (a different binary); no values"


def _no_names_observed(data: ReportData) -> tuple[str, ...]:
    flows = _direct_flows(data)
    if flows:
        return (
            "no DNS or TLS names, but traffic to direct addresses: "
            + ", ".join(_table_cell_code(flow) for flow in flows),
        )
    return ("none: PCAPdroid recorded no packets from the app",)


def build_report(data: ReportData) -> str:
    network_status, endpoints = _network_summary(data.network_log_path)
    if data.network_state == "pending":
        network_status = (
            "pending: the capture covers the whole emulator session and only ends when the "
            "emulator stops. Run `quick_review.py --finalize` on this report's directory "
            "afterwards to add it."
        )
    lines = [
        "# Quick review report",
        "",
        f"- **APK**: {_md_code(str(data.apk_path))}",
        f"- **Package**: {_md_code(data.package or 'unknown')}",
        f"- **Device**: {_md_code(data.serial)}",
        f"- **Duration**: {data.duration}s "
        f"({data.started_at.isoformat()} to {data.ended_at.isoformat()})",
        *([f"- **Input**: {data.input_note}"] if data.input_note else []),
        *([f"- **APK SHA-256**: {_md_code(data.apk_sha256)}"] if data.apk_sha256 else []),
        *_abi_lines(data),
        "",
        *_crash_lines(data),
        *_existing_review_lines(data),
        "## Screen recording",
        "",
        f"`{data.screen_recording_path}`" if data.screen_recording_path else "Not available.",
        *(
            [
                "",
                f"Uploaded for sharing: <{data.video_url}> "
                "(temporary; the delete link is in uploads.json)",
            ]
            if data.video_url
            else []
        ),
        "",
        *_screenshot_lines(data),
        "## Network traffic",
        "",
        f"{network_status}"
        + (
            f" (raw pcap: `{data.pcap_path}`"
            + (f", parsed log: `{data.network_log_path}`" if data.network_log_path else "")
            + ")"
            if data.pcap_path
            else ""
        ),
        "",
    ]
    if data.network_state == "app-filtered":
        lines += [APP_FILTERED_NOTE, ""]
    if data.network_state == "windowed":
        lines += [
            "Only events from the app's launch to the end of the recording are listed. The "
            "raw pcap covers the emulator's whole session, boot included. This is the whole "
            "emulator's traffic, not only the app's: Android and Google services talk in the "
            "background too, and nothing here is attributed to the app.",
            "",
        ]
    if endpoints:
        lines.append("Observed endpoints (DNS query names / TLS SNI values):")
        lines.append("")
        lines.extend(f"- {_md_code(endpoint)}" for endpoint in endpoints)
        lines.append("")
    direct = _direct_flows(data)
    if direct:
        lines.append("Direct addresses the app talked to (from the packets, not from names):")
        lines.append("")
        lines.extend(f"- {_md_code(flow)}" for flow in direct)
        lines.append("")
    lines.append(
        "Passive capture only sees plaintext DNS and single-packet TLS "
        "ClientHellos; DNS-over-TLS and fragmented handshakes are invisible "
        "to it by construction (see `netpolicy/README.md`). An empty result "
        'means "nothing observable this way", not "no network activity".'
    )
    lines += _decrypted_lines(data)
    lines += ["", "## Permissions (static, from the APK manifest)", ""]
    lines.append(
        "All runtime permissions below were pre-granted at install time "
        "(`adb install -g`), so the app never saw a permission-request dialog "
        "during this run and could exercise whatever they gate. This run therefore cannot "
        "show whether the app works without its optional permissions."
        if data.permissions_granted
        else "Runtime permissions were NOT pre-granted (`--no-grant-permissions`): the app "
        "had to ask for them itself, as it would for a user."
    )
    lines.append("")
    if data.permissions is None:
        lines.append(
            "Not checked: no `aapt`/`aapt2` found. Pass `--aapt-binary` to enable this, "
            "or check by hand with `aapt dump permissions <apk>`."
        )
    elif not data.permissions:
        lines.append("None declared.")
    else:
        lines.extend(f"- {_md_code(permission)}" for permission in sorted(data.permissions))
    lines.append(
        "\nThis is what the manifest *declares* it might use, not proof it was used "
        "during this run — that's the next section, and it does not cover every "
        "permission (only the sensitive, AppOps-tracked ones Android itself audits; "
        "see below)."
    )
    lines += ["", "## Permission usage (observed during this run)", ""]
    if not data.permission_accesses:
        lines.append(
            "No AppOps-tracked accesses observed. This covers Android's own audited "
            "operations (location, camera, microphone, wake locks, foreground "
            "service, storage, and similar) — most permissions (`INTERNET` included) "
            "are never tracked this way regardless of how often they're used, so an "
            "empty list here does not mean the app made no use of its permissions, "
            "only that nothing AppOps-audited happened to fire in this window."
        )
    else:
        lines.append("| Offset | Operation | State | Duration |")
        lines.append("| --- | --- | --- | --- |")
        recording_start = data.started_at.timestamp()
        for access in data.permission_accesses:
            offset = access.host_time - recording_start
            lines.append(
                f"| {offset:+.1f}s | `{access.op}` | {access.state} | "
                f"{access.duration_seconds:.2f}s |"
            )
        lines.append(
            "\nTimestamps are Android's own AppOps access log, polled once a second "
            "during the recording window (this build has no `--history` dump to read "
            "it all at once); offsets are relative to when the screen recording "
            "started, so they line up with the video's own timeline."
        )
    lines += ["", f"## Logcat (last {LOGCAT_TAIL_LINES} lines during the run)", ""]
    if data.logcat_path is not None and data.logcat_path.exists():
        if data.logcat_scope == "full":
            lines.append(
                "Whole-device log (`--full-logcat`): this includes other apps' and the "
                "system's lines, which can contain personal details such as the Wi-Fi "
                "network name. Read it before sharing it."
            )
        elif data.app_pids:
            lines.append(
                "Only lines from the app's own process(es) are included. The rest of the "
                "device's log is not, because it can contain unrelated personal details "
                "(a real run showed the Wi-Fi network name). `--full-logcat` includes it."
            )
        else:
            lines.append(
                "The app's process could not be identified, so no log lines are included "
                "(the rest of the device's log can contain unrelated personal details). "
                "`--full-logcat` includes everything."
            )
        lines.append("")
        tail = [sanitize(line) for line in data.logcat_text.splitlines()[-LOGCAT_TAIL_LINES:]] or [
            "(empty)"
        ]
        fence = _code_fence_for(tail)
        lines.append(fence)
        lines.extend(tail)
        lines.append(fence)
        lines.append(f"\nRaw device log, kept locally: {_md_code(str(data.logcat_path))}")
    else:
        lines.append("Not available.")
    if data.warnings:
        lines += ["", "## Warnings", ""]
        lines.extend(f"- {sanitize(warning)}" for warning in data.warnings)
    lines.append("")
    return "\n".join(lines)


MAX_COMMENT_LIST_ITEMS = 30


def _table_cell_code(value: str) -> str:
    """A code span safe to put inside a Markdown table cell: a `|` in an
    app-controlled name would otherwise end the cell even inside backticks,
    letting the app add columns to (or break) the checklist table.
    """
    return _md_code(value).replace("|", "\\|")


def _bounded(items: list[str]) -> tuple[str, ...]:
    shown = [_table_cell_code(item) for item in items[:MAX_COMMENT_LIST_ITEMS]]
    if len(items) > MAX_COMMENT_LIST_ITEMS:
        shown.append(f"…and {len(items) - MAX_COMMENT_LIST_ITEMS} more")
    return tuple(shown)


def _safe_url(url: str) -> str:
    return url.replace("|", "%7C").replace(" ", "%20").replace("(", "%28").replace(")", "%29")


def _link(label: str, url: str | None) -> str:
    clean = re.sub(r"[\[\]|\n]", " ", label)
    return f"[{clean}]({_safe_url(url)})" if url else clean


def _abi_row(data: ReportData) -> str | None:
    """Which CPU architectures this APK can run on, when it carries native code. Pure Java/Kotlin
    runs anywhere and gets no row. Several APKs can come from one merge request (one per ABI),
    so this describes the file that was tested only."""
    if not data.apk_abis:
        return None
    shipped = ", ".join(f"`{abi}`" for abi in sorted(data.apk_abis))
    if any(abi.startswith("x86") for abi in data.apk_abis):
        return shipped
    return (
        f"{shipped}; no x86 or x86_64 code in this APK, so it cannot be installed on an x86 "
        "device (an emulator, ChromeOS, Waydroid) unless that device translates ARM. A merge "
        "request may build another APK per ABI; this describes the one that was tested"
    )


def _screenshot_row(data: ReportData) -> str:
    if data.screenshot_urls:
        shown = ", ".join(
            _link(f"screenshot {number}", url)
            for number, url in enumerate(data.screenshot_urls, start=1)
        )
        return f"{shown} (hosted temporarily by an upload service; they may expire)"
    if data.screenshots:
        return (
            f"{len(data.screenshots)} saved in `screenshots/` next to the report, not yet shared. "
            "Look at each (they can show personal details), then drag the ones worth showing "
            "into this comment box and GitLab hosts them"
        )
    return "none could be taken (the app may block screenshots)"


def _link_rows(data: ReportData) -> tuple[str, str, list[tuple[str, str]]]:
    """(build status, version/tag text, extra rows) with every claim linked to what it rests
    on. Without collected links the first two say the check was not made.
    """
    from mr_evidence import (  # noqa: PLC0415
        CATEGORIES_DOC,
        POLICY_FREE_SOFTWARE,
        POLICY_QUALITY,
        POLICY_SECURITY_LEGAL,
    )

    links = data.mr_links
    rows: list[tuple[str, str]] = []
    urls = data.apk_urls
    if urls is not None:
        shown = ", ".join(f"`{_safe_url(u)}`" for u in urls) if urls else "none"
        rows.append(("URLs embedded in the APK", shown))
        donations = donation_urls(urls)
        if donations:
            funding = (links or {}).get("funding_files") or []
            found = (
                ", ".join(_link(Path(f.split("/blob/")[-1]).name, f) for f in funding)
                if funding
                else "none found upstream (`.github/FUNDING.yml`, `FUNDING.yml`, `funding.json`)"
                if links
                else "not checked (use `--link-evidence`)"
            )
            rows.append(
                (
                    "Donation links",
                    f"{', '.join(f'`{_safe_url(d)}`' for d in donations)}. The "
                    f"{_link('Inclusion Policy', POLICY_SECURITY_LEGAL)} asks upstream to verify "
                    f"donation links. Verification files at the pinned commit: {found}",
                )
            )
    if not links:
        return "not checked (quick review)", "not checked (quick review)", rows

    build_parts = []
    if links.get("pipeline_url"):
        status = links.get("pipeline_status") or "of unknown status"
        build_parts.append(f"{_link('head pipeline', links['pipeline_url'])} is {status}")
    if links.get("apk_url"):
        build_parts.append(
            f"the APK it built: {_link(links.get('apk_kind') or 'APK', links['apk_url'])}"
        )
    joined = "; ".join(build_parts)
    # Only the first letter: str.capitalize() would lowercase the URLs inside the links too.
    build = (joined[0].upper() + joined[1:] + ".") if build_parts else "no pipeline found"

    version = "no pinned upstream commit found in the metadata"
    pinned = links.get("pinned_commit")
    if pinned:
        version = _link(f"pinned commit {pinned[:7]}", links.get("commit_url"))
        tag = links.get("tag")
        version += (
            f" is upstream's tag {_link(tag, links.get('tag_url'))}"
            if tag
            else " has no release tag pointing at it"
        )
        if data.apk_version:
            name = data.apk_version.split(" ")[0]
            verdict = ""
            if tag:
                same = tag.lstrip("vV") == name
                verdict = " (matches the tag)" if same else " (differs from the tag)"
            version += f". The APK reports {data.apk_version}{verdict}"
        version += "."

    descriptions = links.get("descriptions") or {}
    rows.append(
        (
            "Description under test",
            ", ".join(_link(f"full_description.txt ({loc})", u) for loc, u in descriptions.items())
            + f", at the pinned commit. The {_link('policy', POLICY_QUALITY)} asks that the "
            "app implement the features it describes"
            if descriptions
            else "not found at the pinned commit",
        )
    )
    categories = ", ".join(links.get("categories") or []) or "none"
    rows.append(
        (
            "Metadata",
            f"{_link('metadata file', links.get('metadata_url'))} at the merge request's head; "
            f"Categories: {categories} ({_link('what the field means', CATEGORIES_DOC)})",
        )
    )
    rows.append(
        (
            "Policy",
            f"{_link('Free software', POLICY_FREE_SOFTWARE)}, "
            f"{_link('Quality control', POLICY_QUALITY)}, "
            f"{_link('Security and legal compliance', POLICY_SECURITY_LEGAL)}",
        )
    )
    return build, version, rows


def _virustotal_row(data: ReportData) -> tuple[str, str] | None:
    sha = data.apk_sha256
    if not sha:
        return None
    gui = f"https://www.virustotal.com/gui/file/{sha}"
    result = data.virustotal
    if result:
        engines = sum(result[k] for k in ("malicious", "suspicious", "harmless", "undetected"))
        flagged = result["malicious"] + result["suspicious"]
        when = f", analysed {result['analysed_at']}" if result.get("analysed_at") else ""
        up = " (uploaded by this run)" if result.get("uploaded_by_us") else ""
        return (
            "VirusTotal",
            f"{_link(f'{flagged} of {engines} engines flag it', gui)} (malicious "
            f"{result['malicious']}, suspicious {result['suspicious']}){when}{up}",
        )
    if data.virustotal_note:
        return ("VirusTotal", f"{data.virustotal_note}. {_link('Look this hash up', gui)}")
    return (
        "VirusTotal",
        f"{_link('look up this hash', gui)} (a link only: nothing was uploaded or looked up)",
    )


def build_review_comment(data: ReportData, mr_iid: int) -> str:
    """The project's own review checklist (`gitlab_glue`'s template), filled in
    with only what this run can actually know. Build status and the
    version/tag match are checked by the full broker flow, not here, so they
    say so instead of defaulting to something that reads like a pass.
    """
    _, endpoints = _network_summary(data.network_log_path)
    if data.permissions is not None and not any(p.endswith(".INTERNET") for p in data.permissions):
        # Whatever else a capture holds, an app without INTERNET cannot have made those
        # connections: listing the emulator's system traffic here, next to a row saying the
        # app cannot use the network, contradicted itself (seen: 18 Google endpoints).
        observed: tuple[str, ...] = ("none possible: no `INTERNET` permission",)
        if data.network_log_path is not None and endpoints and data.network_state == "windowed":
            observed += (
                "_(the whole-emulator capture also holds system traffic, none of which can be "
                "this app's; see report.md)_",
            )
    elif data.network_log_path is None:
        observed = ("not captured in this run",)
    else:
        observed = _bounded(endpoints)
        if data.network_state == "windowed":
            observed = ("_(whole emulator, system traffic included)_", *observed)
        elif data.network_state == "app-filtered":
            observed = (
                "_(this app's own traffic only, recorded with PCAPdroid)_",
                *(observed or _no_names_observed(data)),
            )
    if data.permissions is None:
        permissions: tuple[str, ...] = ()  # rendered as "not automatically extracted"
    elif not data.permissions:
        permissions = ("none declared",)
    else:
        permissions = _bounded(sorted(data.permissions))
    concerns = [f"The app crashed during the run: {_md_code(crash)}." for crash in data.crashes]
    note = abi_mismatch_note(data.apk_abis, data.device_abis)
    if data.crashes and note:
        concerns.append(note)
    extra_rows: list[tuple[str, str]] = []
    if data.permissions is not None:
        has_internet = any(p.endswith(".INTERNET") for p in data.permissions)
        captured = "captured" if data.network_log_path is not None else "not captured here"
        extra_rows.append(
            (
                "INTERNET permission",
                f"declared; the reviewer guide asks for the app's network traffic to be checked "
                f"(this run: {captured})"
                if has_internet
                else "not declared: the app cannot use the network",
            )
        )
        extra_rows.append(
            (
                "All-files access (`MANAGE_EXTERNAL_STORAGE`)",
                "declared; the guide suggests the Storage Access Framework instead where possible"
                if any(p.endswith(".MANAGE_EXTERNAL_STORAGE") for p in data.permissions)
                else "not declared",
            )
        )
    if data.runtime_permissions is not None:
        shown_runtime = ", ".join(data.runtime_permissions) or None
        if shown_runtime is None:
            release = data.device_android
            on = f"this Android {release} device" if release else "this device"
            runtime_text = (
                f"none that {on} treats as runtime permissions (newer Android versions also "
                "treat some others that way, e.g. `POST_NOTIFICATIONS` from Android 13)"
            )
        elif data.permissions_granted:
            runtime_text = (
                f"{_table_cell_code(shown_runtime)}; **pre-granted in this run**, so it does "
                "not show whether the app works without the optional ones"
            )
        else:
            runtime_text = f"{_table_cell_code(shown_runtime)}; not pre-granted, the app had to ask"
        extra_rows.append(("Runtime permissions declared", runtime_text))
    build_status, version_text, link_rows = _link_rows(data)
    extra_rows.extend(link_rows)
    if data.video_url:
        extra_rows.append(
            (
                "Screen recording",
                f"{_link('recording', data.video_url)} (hosted temporarily by an upload service; "
                "it will expire)",
            )
        )
    if data.input_note:
        extra_rows.append(("Input during the run", data.input_note))
    decrypted_row = _decrypted_row(data)
    if decrypted_row is not None:
        extra_rows.append(("Decrypted requests", decrypted_row))
    abi_row = _abi_row(data)
    if abi_row is not None:
        extra_rows.append(("Native code ABIs", abi_row))
    if data.screenshots_wanted:
        extra_rows.append(("Screenshots", _screenshot_row(data)))
    if data.apk_sha256:
        extra_rows.append(("APK SHA-256", f"`{data.apk_sha256}`"))
    vt_row = _virustotal_row(data)
    if vt_row is not None:
        extra_rows.append(vt_row)
    if data.locales is not None:
        extra_rows.append(("Languages in the APK", locales_summary(data.locales)))
    context = dict(
        mr_iid=mr_iid,
        build_status=build_status,
        version_tag_match=version_text,
        permissions=permissions,
        network_endpoints=observed,
        auto_concerns=tuple(concerns),
        extra_rows=tuple(extra_rows),
    )
    if data.verdict:
        context["verdict"] = data.verdict
    return render_review_template(ReviewTemplateContext(**context))


# The video, the raw pcap and the raw logcat text are all sized by the
# reviewed app's own behaviour (a busier UI, a chattier network stack, a
# noisier log), not just by how long the recording ran for, so embedding
# any of them still needs a cap — generous for a short review, but a cap.
MAX_EMBEDDED_BINARY_BYTES = 32 * 1024 * 1024

# The APK is different: its size is fixed before the review even starts —
# it's the file the operator pointed this tool at, not something the app
# can inflate during the run — so it gets its own, more generous limit,
# comfortably above a typical multi-arch F-Droid APK.
MAX_EMBEDDED_APK_BYTES = 150 * 1024 * 1024


def _file_data_uri(
    path: Path, mime: str, max_bytes: int = MAX_EMBEDDED_BINARY_BYTES
) -> tuple[str | None, str | None]:
    """`(data_uri, None)` on success, `(None, reason)` otherwise — a size
    over the cap or a read failure both degrade to "not embedded, here's
    why" rather than raising or silently truncating binary data.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, str(exc)
    if size > max_bytes:
        return None, f"{size:,} bytes exceeds the {max_bytes:,}-byte embedding limit"
    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, str(exc)
    return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}", None


def _text_data_uri(text: str, mime: str = "text/plain") -> str:
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    return f"data:{mime};charset=utf-8;base64,{encoded}"


def _download_link(uri: str, filename: str, label: str) -> str:
    return f'<a download="{html.escape(filename)}" href="{uri}">{html.escape(label)}</a>'


def _load_network_events(network_log_path: Path | None) -> list[dict[str, object]]:
    if network_log_path is None or not network_log_path.exists():
        return []
    events: list[dict[str, object]] = []
    try:
        with network_log_path.open(encoding="utf-8") as handle:
            for line in handle:
                if len(events) >= MAX_EMBEDDED_NETWORK_EVENTS:
                    break
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                events.append(
                    {
                        str(key): sanitize(value) if isinstance(value, str) else value
                        for key, value in record.items()
                    }
                )
    except OSError:
        return []
    return events


def build_html_report(data: ReportData) -> str:
    """A single, fully self-contained HTML file — the screen recording is
    embedded as a base64 data URI, not linked as a sibling file, and every
    structured record (network events, permission accesses, logcat lines)
    is embedded as JSON and rendered/filtered by a small amount of plain
    JS — no build step, no framework, matching this project's `dashboard/`
    and `local-image/`'s own style. Fine at the sizes a 30-second
    `screenrecord` and a short capture actually produce; would need
    reconsidering for much longer recordings.
    """
    esc = html.escape
    recording_start = data.started_at.timestamp()

    apk_download_html = ""
    if data.apk_path.exists():
        apk_uri, apk_skip_reason = _file_data_uri(
            data.apk_path,
            "application/vnd.android.package-archive",
            max_bytes=MAX_EMBEDDED_APK_BYTES,
        )
        if apk_uri is not None:
            apk_download_html = _download_link(apk_uri, data.apk_path.name, "Download APK")
        else:
            apk_download_html = f"<small>APK not embedded ({esc(str(apk_skip_reason))})</small>"

    video_html = "<p>Not available.</p>"
    if data.screen_recording_path is not None and data.screen_recording_path.exists():
        video_uri, video_skip_reason = _file_data_uri(data.screen_recording_path, "video/mp4")
        if video_uri is not None:
            download = _download_link(video_uri, "screen_recording.mp4", "Download recording")
            video_html = (
                f'<video id="recording" controls preload="metadata" src="{video_uri}"></video>'
                f"<p>{download}</p>"
            )
        else:
            video_html = (
                f"<p>Recorded, but not embedded ({esc(str(video_skip_reason))}): "
                f"<code>{esc(str(data.screen_recording_path))}</code></p>"
            )

    logcat_download_html = ""
    if data.logcat_path is not None and data.logcat_path.exists():
        logcat_uri = _text_data_uri(data.logcat_text)
        scope_label = "whole device" if data.logcat_scope == "full" else "app only"
        logcat_download_html = _download_link(
            logcat_uri, "logcat.txt", f"Download logcat ({scope_label})"
        )

    pcap_download_html = ""
    if data.pcap_path is not None and data.pcap_path.exists() and data.network_state != "pending":
        pcap_uri, pcap_skip_reason = _file_data_uri(data.pcap_path, "application/vnd.tcpdump.pcap")
        if pcap_uri is not None:
            pcap_download_html = _download_link(pcap_uri, "network_capture.pcap", "Download pcap")
        else:
            pcap_download_html = (
                f"<small>Pcap not embedded ({esc(str(pcap_skip_reason))}): "
                f"<code>{esc(str(data.pcap_path))}</code></small>"
            )

    permissions_granted_note = (
        "All permissions below were pre-granted at install time (<code>adb install -g</code>), "
        "so the app never saw a permission-request dialog during this run and could exercise "
        "whatever they gate. This run therefore cannot show whether the app works without its "
        "optional permissions."
        if data.permissions_granted
        else "Runtime permissions were <strong>not</strong> pre-granted "
        "(<code>--no-grant-permissions</code>): the app had to ask for them itself, as it "
        "would for a user."
    )
    permissions_html: str
    if data.permissions is None:
        permissions_html = (
            "<p>Not checked: no <code>aapt</code>/<code>aapt2</code> found. Pass "
            "<code>--aapt-binary</code> to enable this, or check by hand with "
            "<code>aapt dump permissions &lt;apk&gt;</code>.</p>"
        )
    elif not data.permissions:
        permissions_html = "<p>None declared.</p>"
    else:
        items = "".join(
            f"<li><code>{esc(sanitize(p))}</code></li>" for p in sorted(data.permissions)
        )
        permissions_html = f"<ul>{items}</ul>"

    warnings_html = ""
    if data.warnings:
        items = "".join(f"<li>{esc(sanitize(w))}</li>" for w in data.warnings)
        warnings_html = f'<h2>Warnings</h2><ul class="warnings">{items}</ul>'

    logcat_path_display = str(data.logcat_path) if data.logcat_path else "not available"

    network_events = _load_network_events(data.network_log_path)
    abi_html = ""
    if data.apk_abis is not None or data.device_abis is not None:
        apk_text = (
            "unknown (no aapt)"
            if data.apk_abis is None
            else ", ".join(data.apk_abis) or "none (no native code)"
        )
        device_text = ", ".join(data.device_abis) if data.device_abis else "unknown"
        abi_html = (
            f"  <dt>ABIs</dt><dd>APK native code: <code>{esc(sanitize(apk_text))}</code>; "
            f"device: <code>{esc(sanitize(device_text))}</code></dd>\n"
        )
    crash_html = ""
    if data.crashes:
        items = "".join(f"<li><code>{esc(sanitize(c))}</code></li>" for c in data.crashes)
        note = abi_mismatch_note(data.apk_abis, data.device_abis)
        crash_html = f"<h2>The app crashed during this run</h2><ul>{items}</ul>" + (
            f"<p>{esc(note)}</p>" if note else ""
        )
    existing_html = ""
    if data.existing_reviews:
        items = "".join(f"<li>{esc(sanitize(line))}</li>" for line in data.existing_reviews)
        existing_html = (
            "<h2>Existing reviews on this merge request</h2>"
            "<p><small>For you, not for the checklist. Read from its comments; claims in free "
            f"text, not verified.</small></p><ul>{items}</ul>"
        )
    network_note = ""
    if data.network_state == "pending":
        network_note = (
            "<p><strong>Pending:</strong> the capture covers the whole emulator session and "
            "only ends when the emulator stops. Run <code>quick_review.py --finalize</code> "
            "on this report's directory afterwards to add it.</p>"
        )
    elif data.network_state == "app-filtered":
        network_note = f"<p><small>{esc(APP_FILTERED_NOTE)}</small></p>"
    elif data.network_state == "windowed":
        network_note = (
            "<p><small>Only events from the app's launch to the end of the recording are "
            "listed. The raw pcap covers the emulator's whole session, boot included. This is "
            "the whole emulator's traffic, not only the app's: Android and Google services talk "
            "in the background too, and nothing here is attributed to the app.</small></p>"
        )
    if len(network_events) >= MAX_EMBEDDED_NETWORK_EVENTS:
        network_note = (
            f"<p><strong>Note:</strong> only the first {MAX_EMBEDDED_NETWORK_EVENTS} "
            "events are shown here; the capture recorded more (see "
            "<code>network_log.jsonl</code>).</p>"
        )
    payload = {
        "recordingStartedAt": recording_start,
        "recordingDuration": data.duration,
        "network": network_events,
        "appPids": data.app_pids,
        "permissions": [
            {
                "op": a.op,
                "mode": a.mode,
                "state": a.state,
                "time": a.host_time,
                "duration": a.duration_seconds,
            }
            for a in data.permission_accesses
        ],
        "logcat": [
            {
                "time": e.host_time,
                "level": e.level,
                "tag": e.tag,
                "message": e.message,
                "raw": e.raw,
                "pid": e.pid,
            }
            for e in data.logcat_entries
        ],
    }
    # No "<" at all may survive into the <script> data block. Escaping only
    # "</" is not enough: HTML's script-data tokenizer also reacts to a
    # literal "<!--" followed by "<script", after which the block's own real
    # </script> end tag stops closing it and the rest of the document is
    # swallowed as script data. "<" is valid JSON and JSON.parse turns
    # it straight back into "<".
    payload_json = json.dumps(payload).replace("<", "\\u003c")

    title = esc(sanitize(data.package or str(data.apk_path)))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Quick review: {title}</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 60rem; margin: 1.5rem auto;
          padding: 0 1rem; line-height: 1.5; }}
  video {{ width: 100%; max-width: 480px; display: block; background: #000; }}
  pre {{ background: #f4f4f4; padding: 0.75rem; overflow-x: auto; font-size: 0.85rem;
         white-space: pre-wrap; word-break: break-word; }}
  code {{ background: #f4f4f4; padding: 0.1rem 0.3rem; border-radius: 0.2rem; }}
  h2 {{ border-bottom: 1px solid #ddd; padding-bottom: 0.25rem; margin-top: 2rem; }}
  ul.warnings li {{ color: #9a3b00; }}
  dl {{ display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 1rem; }}
  dt {{ font-weight: 600; }}
  .filters {{ display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 0.75rem 0;
              padding: 0.6rem; border: 1px solid #ddd; border-radius: 0.4rem; }}
  .filters label {{ display: flex; flex-direction: column; font-size: 0.8rem; gap: 0.2rem; }}
  .filters label.checkbox-label {{ flex-direction: row; align-items: center; }}
  .filters input, .filters select {{ font: inherit; padding: 0.2rem 0.3rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th, td {{ text-align: left; padding: 0.3rem 0.5rem; border-bottom: 1px solid #eee;
            vertical-align: top; }}
  th {{ position: sticky; top: 0; background: #fff; }}
  tbody tr:hover {{ background: #f8f8f8; }}
  button.seek {{ font: inherit; cursor: pointer; }}
  .row-count {{ color: #666; font-size: 0.8rem; }}
  .table-scroll {{ max-height: 22rem; overflow-y: auto; border: 1px solid #eee; }}
  .level-E, .level-F {{ color: #b3261e; font-weight: 600; }}
  .level-W {{ color: #9a6b00; }}
</style>
</head>
<body>
<h1>Quick review report</h1>
{crash_html}
{existing_html}
<dl>
  <dt>APK</dt><dd><code>{esc(sanitize(str(data.apk_path)))}</code>
    {f" &middot; {apk_download_html}" if apk_download_html else ""}</dd>
  <dt>Package</dt><dd><code>{esc(sanitize(data.package or "unknown"))}</code></dd>
  <dt>Device</dt><dd><code>{esc(sanitize(data.serial))}</code></dd>
  <dt>Duration</dt><dd>{data.duration}s
    ({esc(data.started_at.isoformat())} to {esc(data.ended_at.isoformat())})</dd>
{abi_html}</dl>

<h2>Screen recording</h2>
{video_html}

<h2>Timeline</h2>
<p><small>Every permission access and network event observed, in order. Times are
seconds since the recording started; click one to seek the video there. Passive
network capture only sees plaintext DNS and single-packet TLS ClientHellos, and
permission tracking only covers Android's own AppOps-audited operations &mdash;
see the sections below for what each does and doesn't cover.</small></p>
<div class="row-count" id="timeline-count"></div>
<div class="table-scroll">
<table>
  <thead><tr><th>Offset</th><th>Kind</th><th>Detail</th><th></th></tr></thead>
  <tbody id="timeline-body"></tbody>
</table>
</div>

<h2>Network traffic</h2>
<p><small>Passive capture only sees plaintext DNS and single-packet TLS ClientHellos;
DNS-over-TLS and fragmented handshakes are invisible to it by construction (see
<code>netpolicy/README.md</code>). An empty result means &quot;nothing observable this
way&quot;, not &quot;no network activity&quot;.</small></p>
<p>{pcap_download_html}</p>
{network_note}
<div class="filters">
  <label>Protocol
    <select id="net-filter-type">
      <option value="">all</option>
      <option value="dns">dns</option>
      <option value="tls_sni">tls_sni</option>
    </select>
  </label>
  <label>Port <input type="text" id="net-filter-port" placeholder="e.g. 443"></label>
  <label>Search <input type="text" id="net-filter-text" placeholder="hostname contains..."></label>
  <label>Min offset (s) <input type="number" id="net-filter-min" step="any"></label>
  <label>Max offset (s) <input type="number" id="net-filter-max" step="any"></label>
</div>
<div class="row-count" id="net-count"></div>
<div class="table-scroll">
<table>
  <thead><tr><th>Offset</th><th>Protocol</th><th>Port</th><th>Value</th></tr></thead>
  <tbody id="network-body"></tbody>
</table>
</div>

<h2>Permissions (static, from the APK manifest)</h2>
<p><small>{permissions_granted_note}</small></p>
{permissions_html}
<p><small>This is what the manifest declares it might use, not proof it was used during
this run &mdash; the timeline above and the permission-usage table below cover that,
for the subset of permissions Android's own AppOps mechanism audits.</small></p>

<h2>Logcat</h2>
<div class="filters">
  <label class="checkbox-label">
    <input type="checkbox" id="log-filter-app-only" checked>
    App's own process only
  </label>
  <label>Severity
    <select id="log-filter-level">
      <option value="">all</option>
      <option value="V">V</option>
      <option value="D">D</option>
      <option value="I">I</option>
      <option value="W">W</option>
      <option value="E">E</option>
      <option value="F">F</option>
    </select>
  </label>
  <label>Component <input type="text" id="log-filter-tag" placeholder="e.g. dex2oat32"></label>
  <label>Search <input type="text" id="log-filter-text" placeholder="message contains..."></label>
  <label>Min offset (s) <input type="number" id="log-filter-min" step="any"></label>
  <label>Max offset (s) <input type="number" id="log-filter-max" step="any"></label>
</div>
<div class="row-count" id="log-count"></div>
<div class="table-scroll">
<table>
  <thead><tr><th>Offset</th><th>Lvl</th><th>Component</th><th>Message</th></tr></thead>
  <tbody id="logcat-body"></tbody>
</table>
</div>
<p><small>Raw device log, kept locally: <code>{esc(sanitize(logcat_path_display))}</code></small>
{f" &middot; {logcat_download_html}" if logcat_download_html else ""}</p>

{warnings_html}

<script type="application/json" id="report-data">{payload_json}</script>
<script>
(function () {{
  "use strict";
  var reportData = JSON.parse(document.getElementById("report-data").textContent);

  function fmtOffset(t) {{
    if (t === null || t === undefined) return "—";
    return (t - reportData.recordingStartedAt).toFixed(2) + "s";
  }}

  function offsetValue(t) {{
    if (t === null || t === undefined) return null;
    return t - reportData.recordingStartedAt;
  }}

  function seekVideo(offset) {{
    var v = document.getElementById("recording");
    if (!v) return;
    v.currentTime = Math.max(0, offset);
    v.scrollIntoView({{behavior: "smooth", block: "center"}});
  }}

  function seekButton(offset) {{
    var btn = document.createElement("button");
    btn.className = "seek";
    btn.type = "button";
    btn.textContent = "▶";
    btn.title = "Seek video here";
    btn.addEventListener("click", function () {{ seekVideo(offset); }});
    return btn;
  }}

  function passesRange(offset, min, max) {{
    if (offset === null) return true;
    if (!isNaN(min) && offset < min) return false;
    if (!isNaN(max) && offset > max) return false;
    return true;
  }}

  function renderTimeline() {{
    var rows = [];
    reportData.network.forEach(function (e) {{
      var value = e.query_name || e.sni || "";
      rows.push({{
        time: e.timestamp,
        kind: e.type === "dns" ? "DNS" : "TLS SNI",
        detail: value + (e.port ? " :" + e.port : ""),
      }});
    }});
    reportData.permissions.forEach(function (a) {{
      rows.push({{
        time: a.time,
        kind: "permission",
        detail: a.op + " (" + a.state + ", " + a.duration.toFixed(2) + "s)",
      }});
    }});
    rows.sort(function (a, b) {{ return a.time - b.time; }});

    var tbody = document.getElementById("timeline-body");
    tbody.innerHTML = "";
    rows.forEach(function (row) {{
      var tr = document.createElement("tr");
      var offsetCell = document.createElement("td");
      offsetCell.textContent = fmtOffset(row.time);
      var kindCell = document.createElement("td");
      kindCell.textContent = row.kind;
      var detailCell = document.createElement("td");
      detailCell.textContent = row.detail;
      var seekCell = document.createElement("td");
      seekCell.appendChild(seekButton(offsetValue(row.time) || 0));
      tr.appendChild(offsetCell);
      tr.appendChild(kindCell);
      tr.appendChild(detailCell);
      tr.appendChild(seekCell);
      tbody.appendChild(tr);
    }});
    document.getElementById("timeline-count").textContent =
      rows.length + " event(s)";
  }}

  function renderNetworkTable() {{
    var typeFilter = document.getElementById("net-filter-type").value;
    var portFilter = document.getElementById("net-filter-port").value.trim();
    var textFilter = document.getElementById("net-filter-text").value.trim().toLowerCase();
    var minOffset = parseFloat(document.getElementById("net-filter-min").value);
    var maxOffset = parseFloat(document.getElementById("net-filter-max").value);

    var tbody = document.getElementById("network-body");
    tbody.innerHTML = "";
    var shown = 0;
    reportData.network.forEach(function (e) {{
      if (typeFilter && e.type !== typeFilter) return;
      if (portFilter && String(e.port) !== portFilter) return;
      var value = e.query_name || e.sni || "";
      if (textFilter && value.toLowerCase().indexOf(textFilter) === -1) return;
      if (!passesRange(offsetValue(e.timestamp), minOffset, maxOffset)) return;

      shown++;
      var tr = document.createElement("tr");
      var offsetCell = document.createElement("td");
      offsetCell.textContent = fmtOffset(e.timestamp);
      var typeCell = document.createElement("td");
      typeCell.textContent = e.type;
      var portCell = document.createElement("td");
      portCell.textContent = e.port !== undefined ? e.port : "—";
      var valueCell = document.createElement("td");
      valueCell.textContent = value;
      tr.appendChild(offsetCell);
      tr.appendChild(typeCell);
      tr.appendChild(portCell);
      tr.appendChild(valueCell);
      tbody.appendChild(tr);
    }});
    document.getElementById("net-count").textContent =
      shown + " of " + reportData.network.length + " event(s)";
  }}

  function renderLogcatTable() {{
    var appOnly = document.getElementById("log-filter-app-only").checked;
    var levelFilter = document.getElementById("log-filter-level").value;
    var tagFilter = document.getElementById("log-filter-tag").value.trim().toLowerCase();
    var textFilter = document.getElementById("log-filter-text").value.trim().toLowerCase();
    var minOffset = parseFloat(document.getElementById("log-filter-min").value);
    var maxOffset = parseFloat(document.getElementById("log-filter-max").value);
    var appPids = reportData.appPids || [];

    var tbody = document.getElementById("logcat-body");
    tbody.innerHTML = "";
    var shown = 0;
    reportData.logcat.forEach(function (e) {{
      if (appOnly && appPids.length > 0 && appPids.indexOf(e.pid) === -1) return;
      if (levelFilter && e.level !== levelFilter) return;
      if (tagFilter && e.tag.toLowerCase().indexOf(tagFilter) === -1) return;
      var haystack = (e.tag + " " + e.message).toLowerCase();
      if (textFilter && haystack.indexOf(textFilter) === -1) return;
      if (!passesRange(offsetValue(e.time), minOffset, maxOffset)) return;

      shown++;
      var tr = document.createElement("tr");
      var offsetCell = document.createElement("td");
      offsetCell.textContent = fmtOffset(e.time);
      var levelCell = document.createElement("td");
      levelCell.textContent = e.level;
      levelCell.className = "level-" + e.level;
      var tagCell = document.createElement("td");
      tagCell.textContent = e.tag;
      var msgCell = document.createElement("td");
      msgCell.textContent = e.message || e.raw;
      tr.appendChild(offsetCell);
      tr.appendChild(levelCell);
      tr.appendChild(tagCell);
      tr.appendChild(msgCell);
      tbody.appendChild(tr);
    }});
    document.getElementById("log-count").textContent =
      shown + " of " + reportData.logcat.length + " line(s)";
  }}

  ["net-filter-type", "net-filter-port", "net-filter-text", "net-filter-min", "net-filter-max"]
    .forEach(function (id) {{
      document.getElementById(id).addEventListener("input", renderNetworkTable);
      document.getElementById(id).addEventListener("change", renderNetworkTable);
    }});
  [
    "log-filter-app-only", "log-filter-level", "log-filter-tag",
    "log-filter-text", "log-filter-min", "log-filter-max",
  ].forEach(function (id) {{
      document.getElementById(id).addEventListener("input", renderLogcatTable);
      document.getElementById(id).addEventListener("change", renderLogcatTable);
    }});

  renderTimeline();
  renderNetworkTable();
  renderLogcatTable();
}})();
</script>
</body>
</html>
"""


STATE_FILENAME = "review_state.json"
STATE_VERSION = 1
# Packets a moment after the recording's end still belong to it.
NETWORK_WINDOW_GRACE_SECONDS = 2.0


def _encode_state(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _encode_state(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, list):
        return [_encode_state(item) for item in value]
    return value


def dump_state(data: ReportData, mr_iid: int | None) -> str:
    return json.dumps({"version": STATE_VERSION, "mr_iid": mr_iid, "report": _encode_state(data)})


def load_state(text: str) -> tuple[ReportData, int | None]:
    raw = json.loads(text)
    if raw.get("version") != STATE_VERSION:
        raise ValueError(f"unsupported {STATE_FILENAME} version: {raw.get('version')!r}")
    r = raw["report"]

    def optional_path(value: str | None) -> Path | None:
        return Path(value) if value is not None else None

    data = ReportData(
        apk_path=Path(r["apk_path"]),
        package=r["package"],
        serial=r["serial"],
        duration=r["duration"],
        started_at=datetime.fromisoformat(r["started_at"]),
        ended_at=datetime.fromisoformat(r["ended_at"]),
        screen_recording_path=optional_path(r["screen_recording_path"]),
        network_log_path=optional_path(r["network_log_path"]),
        pcap_path=optional_path(r["pcap_path"]),
        permissions=r["permissions"],
        logcat_path=optional_path(r["logcat_path"]),
        permission_accesses=[PermissionAccess(**p) for p in r["permission_accesses"]],
        logcat_entries=[LogcatEntry(**e) for e in r["logcat_entries"]],
        app_pids=r["app_pids"],
        warnings=r["warnings"],
        logcat_scope=r["logcat_scope"],
        logcat_text=r["logcat_text"],
        network_state=r["network_state"],
        crashes=r.get("crashes", []),
        apk_abis=r.get("apk_abis"),
        device_abis=r.get("device_abis"),
        existing_reviews=r.get("existing_reviews", []),
        apk_sha256=r.get("apk_sha256"),
        locales=r.get("locales"),
        runtime_permissions=r.get("runtime_permissions"),
        permissions_granted=r.get("permissions_granted", True),
        device_android=r.get("device_android"),
        mr_links=r.get("mr_links"),
        mr_links_note=r.get("mr_links_note"),
        apk_urls=r.get("apk_urls"),
        apk_version=r.get("apk_version"),
        virustotal=r.get("virustotal"),
        virustotal_note=r.get("virustotal_note"),
        verdict=r.get("verdict"),
        screenshots=[Path(p) for p in r.get("screenshots", [])],
        screenshots_wanted=r.get("screenshots_wanted", False),
        screenshot_urls=r.get("screenshot_urls", []),
        video_url=r.get("video_url"),
        decrypted=r.get("decrypted"),
        input_note=r.get("input_note"),
    )
    return data, raw.get("mr_iid")


def write_reports(data: ReportData, output_dir: Path) -> tuple[Path, Path]:
    report_path = output_dir / "report.md"
    report_path.write_text(build_report(data), encoding="utf-8")
    html_report_path = output_dir / "report.html"
    html_report_path.write_text(build_html_report(data), encoding="utf-8")
    return report_path, html_report_path


def finalize(output_dir: Path, *, stdout: TextIO, stderr: TextIO) -> int:
    """Second half of a review whose network evidence came from a capture that
    was still running when the device work finished (`--external-pcap`): read
    the finished pcap, keep only the review's own time window, and rewrite the
    reports. Safe to run again.
    """
    state_path = output_dir / STATE_FILENAME
    try:
        data, mr_iid = load_state(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: cannot read {state_path}: {exc}", file=stderr)
        return 1
    if data.pcap_path is None:
        print(f"error: {state_path} records no external pcap to finalize", file=stderr)
        return 1

    warnings = list(data.warnings)
    window = (
        data.started_at.timestamp(),
        data.ended_at.timestamp() + NETWORK_WINDOW_GRACE_SECONDS,
    )
    network_log = write_network_log(data.pcap_path, output_dir / "network_log.jsonl", window=window)
    if network_log is None:
        warnings.append(f"the network capture {data.pcap_path} is missing or unreadable")
    data = dataclasses.replace(
        data,
        network_log_path=network_log,
        network_state="windowed" if network_log is not None else "",
        warnings=warnings,
    )
    report_path, html_report_path = write_reports(data, output_dir)
    print(f"Network evidence added. Report: {report_path} (also: {html_report_path})", file=stdout)
    if mr_iid is not None:
        comment_path = output_dir / "review_comment.md"
        comment_path.write_text(build_review_comment(data, mr_iid), encoding="utf-8")
        print(
            f"Review checklist for !{mr_iid}: {comment_path}\n"
            "Fill in the checkboxes and concerns, then paste it into the merge request. "
            "Nothing was posted.",
            file=stdout,
        )
    return 0


def _write_private(path: Path, text: str) -> None:
    """Owner-only: the delete links in it let anyone remove the uploaded files."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)


def grab_screenshot(serial: str) -> bytes | None:
    try:
        result = subprocess.run(  # noqa: S603
            [*ADB, "-s", serial, "exec-out", "screencap", "-p"],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def _device_adb(serial: str) -> dc.AdbRun:
    return lambda args: run([*ADB, "-s", serial, *args])


def start_pcapdroid_capture(
    serial: str,
    package: str,
    *,
    stdout: TextIO,
    warn: Callable[[str], None],
    on_exit: list[Callable[[], None]],
    api_key: str | None = None,
) -> str | None:
    """Start PCAPdroid on the phone, filtered to `package`. The file's name on the phone when
    the capture is running; None (after a warning) when it could not be started. Whatever
    happens, a stop is queued in `on_exit`: a late tap must not leave a VPN up on the phone.
    """
    adb = _device_adb(serial)
    name = dc.capture_name(package, int(time.time()))
    if not dc.start_capture(adb, package, name, api_key):
        warn("could not start PCAPdroid; no network capture")
        return None
    ran = [False]

    def cleanup() -> None:
        # Not after a normal finish: a second stop would raise another ALLOW dialog on the
        # phone for nothing. A capture that never started is still stopped (a late tap).
        if ran[0] and dc.vpn_up(adb) is False:
            return
        dc.stop_capture(adb, attempts=2, api_key=api_key)

    on_exit.append(cleanup)
    print(
        (
            f"Starting PCAPdroid with {dc.API_KEY_ENV}: it should not ask for ALLOW. The first "
            "time on a phone it still shows an explanation (tap OK) and Android's VPN dialog "
            "(tap OK)."
            if api_key
            else "PCAPdroid is asking for permission on the phone: tap ALLOW there (and OK on "
            "its explanation and Android's VPN dialog the first time)."
        )
        + f" Waiting up to {int(dc.CONSENT_WAIT_SECONDS)}s...",
        file=stdout,
    )
    if not dc.wait_for_vpn(adb):
        warn("PCAPdroid's capture did not start in time (nobody tapped ALLOW?); no network capture")
        return None
    ran[0] = True
    print("PCAPdroid is recording this app's traffic.", file=stdout)
    return name


def finish_pcapdroid_capture(
    serial: str,
    name: str,
    pcap_path: Path,
    window_host: tuple[float, float],
    clock_ref: DeviceClockReference | None,
    network_log: Path,
    *,
    say: Callable[[str], None],
    warn: Callable[[str], None],
    api_key: str | None = None,
) -> Path | None:
    """Stop the capture, bring the file back, delete it on the phone, and read it. The
    phone's clock stamps the packets; the window is in the host's, so it is converted. With
    no clock measurement the whole capture is used, which is only this app's traffic anyway.
    """
    adb = _device_adb(serial)
    say(
        "Stopping PCAPdroid..."
        if api_key
        else "Stopping PCAPdroid: tap ALLOW on the phone again (it asks before every start "
        f"and stop). Waiting up to {int(dc.STOP_ATTEMPTS * 20)}s..."
    )
    if not dc.stop_capture(adb, api_key=api_key):
        warn(
            "PCAPdroid's VPN is still up on the phone: stop it in the PCAPdroid app, or "
            "the phone's traffic keeps going through it"
        )
    size = dc.pull_capture(
        adb,
        lambda remote, local: run([*ADB, "-s", serial, "pull", remote, str(local)]).returncode == 0,
        name,
        pcap_path,
    )
    if size is None:
        pcap_path.unlink(missing_ok=True)
        warn("could not pull PCAPdroid's capture off the phone; no network evidence")
        return None
    if size == 0:
        # PCAPdroid only writes its file once the first packet arrives, so this is a
        # capture that ran and saw nothing from the app, not a failed one.
        pcap_path.unlink(missing_ok=True)
        say("PCAPdroid recorded no packets from the app.")
        network_log.write_text("", encoding="utf-8")
        return network_log
    window = None
    if clock_ref is not None:
        offset = clock_ref.device_to_host_offset_seconds
        window = (window_host[0] - offset, window_host[1] - offset)
    else:
        warn("the phone's clock was not measured, so the capture is not cut to the recording")
    log = write_network_log(pcap_path, network_log, window=window)
    if log is None:
        warn("PCAPdroid's capture could not be read (an unsupported pcap format?)")
    return log


def main(argv: list[str], *, stdout: TextIO = sys.stdout, stderr: TextIO = sys.stderr) -> int:
    """Runs the review, and whatever cleanup it queued (a PCAPdroid VPN left running on the
    phone) even when it is interrupted.
    """
    on_exit: list[Callable[[], None]] = []
    try:
        return _main(argv, stdout, stderr, on_exit)
    finally:
        for cleanup in reversed(on_exit):
            cleanup()


def _main(
    argv: list[str], stdout: TextIO, stderr: TextIO, on_exit: list[Callable[[], None]]
) -> int:
    args = parse_args(argv)
    if args.finalize is not None:
        return finalize(args.finalize, stdout=stdout, stderr=stderr)
    assert args.apk is not None  # parse_args enforces this when not finalizing
    if args.adb_command is not None:
        try:
            ADB[:] = shlex.split(args.adb_command)
        except ValueError as exc:
            print(f"error: cannot parse --adb-command: {exc}", file=stderr)
            return 1
        if not ADB:
            print("error: --adb-command is empty", file=stderr)
            return 1
    warnings: list[str] = []

    if not args.apk.exists():
        print(f"error: APK not found: {args.apk}", file=stderr)
        return 1

    duration = args.duration
    if args.stop_file is not None:
        duration = min(duration, STOP_FILE_MAX_SECONDS)  # recorded in segments: no 180 s limit
    elif duration > SCREENRECORD_HARD_LIMIT_SECONDS:
        print(
            f"warning: --duration {duration}s exceeds screenrecord's "
            f"{SCREENRECORD_HARD_LIMIT_SECONDS}s limit; clamping.",
            file=stderr,
        )
        duration = SCREENRECORD_HARD_LIMIT_SECONDS

    try:
        serial = resolve_serial(args.serial)
    except QuickReviewError as exc:
        print(f"error: {exc}", file=stderr)
        return 1

    if args.capture_pcapdroid:
        adb = _device_adb(serial)
        if not dc.pcapdroid_installed(adb):
            print(
                f"error: --capture-pcapdroid needs PCAPdroid ({dc.PCAPDROID_PACKAGE}) on the "
                "device; install it from F-Droid first",
                file=stderr,
            )
            return 1
        if dc.vpn_up(adb) is not False:
            print(
                "error: a VPN is already running on the device (or the device would not "
                "say): PCAPdroid is a VPN and Android allows only one. Turn the other one "
                "off first",
                file=stderr,
            )
            return 1

    output_dir = args.output_dir or Path(f"quick-review-{int(time.time())}")
    output_dir.mkdir(parents=True, exist_ok=True)

    existing_review_lines: list[str] = []
    if args.existing_reviews and args.mr_iid is not None:
        existing_review_lines, why_not = read_existing_reviews(args.mr_iid)
        if why_not is not None:
            print(
                f"warning: could not read !{args.mr_iid}'s existing comments: {why_not}",
                file=stderr,
            )
        else:
            print(f"Already on !{args.mr_iid}:", file=stdout)
            for line in existing_review_lines:
                print(f"  {line}", file=stdout)

    package = args.package or detect_package_name(args.apk, args.aapt_binary)
    if package is None:
        print(
            "error: could not determine the package name (no aapt/aapt2 found); "
            "pass --package explicitly",
            file=stderr,
        )
        return 1
    if not _PACKAGE_NAME_RE.match(package):
        print(
            f"error: refusing to use the package name {sanitize(package)!r}: it is not a "
            "plain Android package name, and it would be re-parsed by the device's own "
            "shell by `adb shell`",
            file=stderr,
        )
        return 1
    print(f"Package: {package}", file=stdout)

    def _warn(message: str) -> None:
        warnings.append(message)
        print(f"warning: {message}", file=stderr)

    if is_installed(serial, package):
        if args.fresh_install:
            print(
                f"{package} is already installed: uninstalling it first (--fresh-install), "
                "which deletes its data.",
                file=stdout,
            )
            uninstall_apk(serial, package)
        else:
            _warn(
                f"{package} is already installed on this device, so its data and granted "
                "permissions carry over: this is not a first-run review. Pass "
                "--fresh-install to uninstall it first (that deletes its data)."
            )
    to_install = args.install_copy or args.apk
    if args.install_copy is not None and not args.install_copy.is_file():
        print(f"error: --install-apk is not a file: {args.install_copy}", file=stderr)
        return 1
    print(
        f"Installing {to_install} on {serial}"
        + (f" (the evidence describes {args.apk})" if args.install_copy else "")
        + "...",
        file=stdout,
    )
    try:
        install_apk(serial, to_install, grant_permissions=not args.no_grant_permissions)
    except QuickReviewError as exc:
        print(f"error: {exc}", file=stderr)
        return 1

    permissions = list_permissions(args.apk, args.aapt_binary)
    apk_abis = list_native_abis(args.apk, args.aapt_binary)
    apk_locales = list_locales(args.apk, args.aapt_binary)
    device_runtime = device_runtime_permissions(serial)
    runtime_declared = (
        sorted(p for p in permissions if p in device_runtime)
        if permissions is not None and device_runtime is not None
        else None
    )
    apk_sha256 = sha256_of(args.apk)
    abis_on_device = device_abis(serial)

    pcap_path = output_dir / "network_capture.pcap"
    capture = PassiveCapture()
    capture_started = False
    pcapdroid_file: str | None = None
    if args.external_pcap is not None:
        print(
            f"Network evidence will come from {args.external_pcap}, once that capture has ended.",
            file=stdout,
        )
    elif args.capture_container is not None:
        container_pid = resolve_container_pid(args.capture_container, args.container_runtime)
        if container_pid is None:
            _warn(
                f"could not resolve container {args.capture_container!r} "
                "(not found, or not running); no pcap produced"
            )
        else:
            capture_started = capture.start("any", pcap_path, target_pid=container_pid)
            if not capture_started:
                _warn(f"network capture did not start ({capture.last_error}); no pcap produced")
    elif args.capture_interface is not None:
        capture_started = capture.start(args.capture_interface, pcap_path)
        if not capture_started:
            _warn(f"network capture did not start ({capture.last_error}); no pcap produced")
    elif args.capture_pcapdroid:
        pcapdroid_file = start_pcapdroid_capture(
            serial,
            package,
            stdout=stdout,
            warn=_warn,
            on_exit=on_exit,
            api_key=args.pcapdroid_api_key,
        )
    else:
        print(
            "Network capture skipped (neither --capture-container nor "
            "--capture-interface given; see --help).",
            file=stdout,
        )

    logcat_path = output_dir / "logcat.txt"
    logcat_proc = start_logcat(serial, logcat_path)
    if logcat_proc is None:
        _warn("logcat capture did not start")

    video_bit_rate = args.video_bit_rate or (
        DEFAULT_UPLOAD_VIDEO_MBPS if args.upload_video else None
    )
    recorder: SegmentedRecorder | None = None
    screen_recording_proc: subprocess.Popen[bytes] | None = None
    if args.stop_file is not None:
        recorder = SegmentedRecorder(
            lambda: start_screen_recording(serial, SEGMENT_SECONDS, video_bit_rate),
            lambda path: pull_screen_recording(serial, path),
            lambda: interrupt_screen_recording(serial),
            output_dir / "segments",
            _warn,
        )
    else:
        screen_recording_proc = start_screen_recording(serial, duration, video_bit_rate)
        if screen_recording_proc is None:
            _warn("screen recording did not start")

    clock_ref = measure_device_clock(serial, reference_year=datetime.now(UTC).year)
    if clock_ref is None:
        _warn(
            "could not measure the device's clock; logcat entries will be shown "
            "without a timeline position"
        )

    permission_accesses: list[PermissionAccess] = []
    stop_appops = threading.Event()

    def _poll_appops() -> None:
        permission_accesses.extend(poll_permission_accesses(serial, package, stop_appops))

    appops_thread = threading.Thread(target=_poll_appops, daemon=True)
    appops_thread.start()

    shots = dc.ScreenshotTaker(
        lambda: grab_screenshot(serial), output_dir / "screenshots", args.screenshot_interval
    )
    shots.start()

    started_at = datetime.now(UTC)
    print(f"Launching {package}...", file=stdout)
    try:
        launch_app(serial, package)
    except QuickReviewError as exc:
        _warn(f"could not launch the app: {exc}")

    monkey_proc: subprocess.Popen[bytes] | None = None
    input_note: str | None = None
    if args.monkey:
        monkey_proc = start_monkey(serial, package, duration, output_dir / "monkey.txt")
        if monkey_proc is None:
            _warn("could not start monkey: the app got no input")
        else:
            input_note = monkey_note(duration)
            print("Feeding the app pseudo-random input (monkey)...", file=stdout)

    print(f"Recording for {duration}s...", file=stdout)
    if args.stop_file is None:
        time.sleep(duration)
    else:
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline and not args.stop_file.exists():
            if recorder is not None:
                recorder.tick()
            time.sleep(0.5)
    ended_at = datetime.now(UTC)
    if args.stop_file is not None:
        duration = max(1, round((ended_at - started_at).total_seconds()))  # what was recorded
    if args.monkey:
        stop_monkey(serial, monkey_proc)

    stop_appops.set()
    appops_thread.join(timeout=5)
    stop_logcat(logcat_proc)
    screenshots = shots.stop()
    screenshot_urls: list[str] = []
    uploads_log: list[su.Uploaded] = []
    if args.upload_screenshots and screenshots:
        print(
            f"Uploading {len(screenshots)} screenshot(s) to {su.urlsplit(args.upload_url).hostname}"
            f" for {args.upload_days} days. Anyone with the link can view them until they "
            "expire; the delete links are saved in uploads.json.",
            file=stdout,
        )
        uploaded, problems = su.upload_all(screenshots, args.upload_url, args.upload_days)
        for problem in problems:
            _warn(f"could not upload {problem}")
        if uploaded:
            screenshot_urls = [u.url for u in uploaded]
            uploads_log.extend(uploaded)
            _write_private(
                output_dir / "uploads.json",
                json.dumps([dataclasses.asdict(u) for u in uploads_log], indent=2),
            )

    screen_recording_path: Path | None = None
    if recorder is not None:
        screen_recording_path = recorder.finish(output_dir / "screen_recording.mp4")
    if screen_recording_proc is not None:
        try:
            screen_recording_proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            screen_recording_proc.kill()
        candidate = output_dir / "screen_recording.mp4"
        if pull_screen_recording(serial, candidate):
            screen_recording_path = candidate
        else:
            _warn("could not pull the screen recording off the device")

    video_url: str | None = None
    if args.upload_video and screen_recording_path is not None:
        megabytes = screen_recording_path.stat().st_size / (1024 * 1024)
        print(
            f"Uploading the screen recording ({megabytes:.1f} MB) to "
            f"{su.urlsplit(args.upload_url).hostname} for {args.upload_days} days. Anyone with "
            "the link can watch it until it expires; the delete link is saved in uploads.json.",
            file=stdout,
        )
        try:
            video = su.upload_mp4(screen_recording_path, args.upload_url, args.upload_days)
        except su.UploadError as exc:
            _warn(f"could not upload the screen recording: {exc}")
        else:
            video_url = video.url
            uploads_log.append(video)
            _write_private(
                output_dir / "uploads.json",
                json.dumps([dataclasses.asdict(u) for u in uploads_log], indent=2),
            )
    elif args.upload_video:
        _warn("there is no screen recording to upload")

    network_log_path: Path | None = None
    if capture_started:
        capture.stop()
        network_log_path = write_network_log(pcap_path, output_dir / "network_log.jsonl")
    if pcapdroid_file is not None:
        network_log_path = finish_pcapdroid_capture(
            serial,
            pcapdroid_file,
            pcap_path,
            (
                started_at.timestamp(),
                ended_at.timestamp() + dc.PCAPDROID_WINDOW_GRACE_SECONDS,
            ),
            clock_ref,
            output_dir / "network_log.jsonl",
            say=lambda message: print(message, file=stdout),
            warn=_warn,
            api_key=args.pcapdroid_api_key,
        )

    logcat_entries: list[LogcatEntry] = []
    app_pids: list[int] = []
    crashes: list[str] = []
    shared_logcat_text = ""
    if logcat_path.exists():
        logcat_text = _read_text_tail(logcat_path, MAX_LOGCAT_BYTES)
        logcat_entries = parse_logcat(logcat_text, clock_ref, reference_year=started_at.year)
        app_pids = sorted(
            set(extract_app_pids(logcat_text, package)) | set(resolve_running_pids(serial, package))
        )
        crashes = detect_crashes(logcat_entries, package, app_pids)
        if crashes:
            _warn(f"the app crashed during the run: {crashes[0]}")
        logcat_entries = select_shareable_logcat(logcat_entries, app_pids, full=args.full_logcat)
        shared_logcat_text = (
            logcat_text if args.full_logcat else "\n".join(entry.raw for entry in logcat_entries)
        )

    if args.uninstall_after:
        uninstall_apk(serial, package)

    embedded_urls = apk_embedded_urls(args.apk)
    apk_version = apk_version_info(args.apk, args.aapt_binary)

    mr_links: dict[str, Any] | None = None
    mr_links_note: str | None = None
    if args.link_evidence and args.mr_iid is not None:
        print(f"Collecting the links that !{args.mr_iid}'s claims rest on...", file=stdout)
        mr_links, mr_links_note = gather_mr_links(args.mr_iid, args.apk.name)
        if mr_links_note is not None:
            _warn(f"could not collect the evidence links: {mr_links_note}")

    vt_result: dict[str, Any] | None = None
    vt_note: str | None = None
    if args.virustotal and apk_sha256 is not None:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import virustotal  # noqa: PLC0415

        print(
            "Checking VirusTotal"
            + (" (will upload the APK if it is unknown)" if args.virustotal_upload else "")
            + "...",
            file=stdout,
        )
        found, vt_note = virustotal.check(
            args.apk,
            apk_sha256,
            os.environ.get("VT_API_KEY", "").strip(),
            allow_upload=args.virustotal_upload,
        )
        if found is not None:
            vt_result, vt_note = dataclasses.asdict(found), None
        else:
            _warn(f"VirusTotal: {vt_note}")

    decrypted = summarise_decrypted(args.decrypted_log) if args.decrypted_log is not None else None
    if decrypted is not None and not decrypted["requests"] and not decrypted["refused"]:
        _warn("nothing reached the proxy (the app may ignore the system proxy)")

    report_data = ReportData(
        apk_path=args.apk,
        package=package,
        serial=serial,
        duration=duration,
        started_at=started_at,
        ended_at=ended_at,
        screen_recording_path=screen_recording_path,
        network_log_path=network_log_path,
        pcap_path=(
            args.external_pcap
            if args.external_pcap is not None
            else (pcap_path if capture_started or pcap_path.exists() else None)
        ),
        permissions=permissions,
        logcat_path=logcat_path if logcat_path.exists() else None,
        permission_accesses=permission_accesses,
        logcat_entries=logcat_entries,
        app_pids=app_pids,
        warnings=warnings,
        logcat_scope="full" if args.full_logcat else "app",
        logcat_text=shared_logcat_text,
        network_state=(
            "pending"
            if args.external_pcap is not None
            else "app-filtered"
            if pcapdroid_file is not None and network_log_path is not None
            else ""
        ),
        crashes=crashes,
        apk_abis=apk_abis,
        device_abis=abis_on_device,
        existing_reviews=existing_review_lines,
        apk_sha256=apk_sha256,
        locales=apk_locales,
        runtime_permissions=runtime_declared,
        permissions_granted=not args.no_grant_permissions,
        device_android=device_android_release(serial),
        mr_links=mr_links,
        mr_links_note=mr_links_note,
        apk_urls=embedded_urls,
        apk_version=apk_version,
        virustotal=vt_result,
        virustotal_note=vt_note,
        verdict=VERDICTS.get(args.verdict) if args.verdict else None,
        screenshots=screenshots,
        screenshots_wanted=args.screenshot_interval > 0,
        screenshot_urls=screenshot_urls,
        video_url=video_url,
        decrypted=decrypted,
        input_note=input_note,
    )
    report_path, html_report_path = write_reports(report_data, output_dir)

    print(f"\nDone. Report: {report_path} (also: {html_report_path})", file=stdout)
    if args.external_pcap is not None:
        # No checklist yet: it would say the network evidence is missing.
        (output_dir / STATE_FILENAME).write_text(
            dump_state(report_data, args.mr_iid), encoding="utf-8"
        )
        print(
            "The network capture is still running. Once the emulator has stopped, run:\n"
            f"  quick_review.py --finalize {output_dir}\n"
            "to add it to the report"
            + (" and write the review checklist." if args.mr_iid is not None else "."),
            file=stdout,
        )
    elif args.mr_iid is not None:
        comment_path = output_dir / "review_comment.md"
        comment_path.write_text(build_review_comment(report_data, args.mr_iid), encoding="utf-8")
        print(
            f"Review checklist for !{args.mr_iid}: {comment_path}\n"
            "Fill in the checkboxes and concerns, then paste it into the merge request. "
            "Nothing was posted.",
            file=stdout,
        )
    else:
        print(
            "Pass --mr-iid N to also get a pre-filled review checklist to paste "
            "into that merge request.",
            file=stdout,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
