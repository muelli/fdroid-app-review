"""Evidence taken from a phone while an app runs: screenshots, and the app's own network
traffic through PCAPdroid.

Everything that talks to the device goes through an `adb` callable (args after `adb -s
<serial>`, returns the finished process), so the logic is tested without a device. The
PCAPdroid control intent and its extras are from PCAPdroid's documented API and were run on a
real Pixel 3a XL (Android 12) with PCAPdroid 2.0.2; the API-key route was not tried.
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

PCAPDROID_PACKAGE = "com.emanuelef.remote_capture"
PCAPDROID_CTRL = f"{PCAPDROID_PACKAGE}/.activities.CaptureCtrl"
PCAPDROID_DIR = "/sdcard/Download/PCAPdroid"
# PCAPdroid's own key (Settings > Control permissions > menu > Generate API key) lets a control
# intent skip the ALLOW dialog. Read from the environment, never an argument.
API_KEY_ENV = "PCAPDROID_API_KEY"
_API_KEY_RE = re.compile(r"^[A-Za-z0-9]{8,64}$")
# How long to wait for a person to tap ALLOW (and OK on Android's VPN consent) on the phone.
CONSENT_WAIT_SECONDS = 60.0
STOP_ATTEMPTS = 3
# Packets a little after the recording's end still belong to it (the app's last requests).
PCAPDROID_WINDOW_GRACE_SECONDS = 10.0

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MAX_SCREENSHOTS = 12
# A full-screen PNG is a few hundred KB; this stops a runaway or hostile device filling the disk.
MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024

AdbRun = Callable[[list[str]], Any]  # returns an object with .returncode and .stdout (str)
Grab = Callable[[], bytes | None]

_TUN_RE = re.compile(r"^tun\d+\b", re.M)
_PCAP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}\.pcap$")


# ---- screenshots -----------------------------------------------------------------------


def valid_png(data: bytes | None) -> bool:
    return data is not None and data.startswith(PNG_MAGIC) and len(data) <= MAX_SCREENSHOT_BYTES


class ScreenshotTaker:
    """Takes a screenshot every `interval` seconds on a thread, the first after at most 5 s.

    Anything that is not a PNG (a failing `screencap`, a device that answers with an error
    text) is dropped, never saved under a `.png` name. `failures` counts them so the report
    can say screenshots were wanted but not obtained (an app that sets FLAG_SECURE gives a
    black image or an error, and that is not the same as "nothing to see").
    """

    def __init__(
        self,
        grab: Grab,
        directory: Path,
        interval: float,
        *,
        limit: int = MAX_SCREENSHOTS,
        wait: Callable[[threading.Event, float], bool] = lambda e, s: e.wait(s),
    ) -> None:
        self._grab = grab
        self._dir = directory
        self._interval = interval
        self._limit = limit
        self._wait = wait
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self.paths: list[Path] = []
        self.failures = 0

    def start(self) -> None:
        if self._interval > 0 and self._limit > 0:
            self._dir.mkdir(parents=True, exist_ok=True)
            self._thread.start()

    def _loop(self) -> None:
        delay = min(5.0, self._interval)
        while len(self.paths) < self._limit and not self._wait(self._stop, delay):
            delay = self._interval
            self.snap()

    def snap(self) -> Path | None:
        data = self._grab()
        if not valid_png(data):
            self.failures += 1
            return None
        assert data is not None
        path = self._dir / f"screenshot-{len(self.paths) + 1:02d}.png"
        path.write_bytes(data)
        self.paths.append(path)
        return path

    def stop(self) -> list[Path]:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=30)
        return list(self.paths)


# ---- PCAPdroid -------------------------------------------------------------------------


def pcapdroid_installed(adb: AdbRun) -> bool:
    result = adb(["shell", "pm", "list", "packages", PCAPDROID_PACKAGE])
    return result.returncode == 0 and f"package:{PCAPDROID_PACKAGE}" in result.stdout.split()


def vpn_up(adb: AdbRun) -> bool | None:
    """Whether any `tun` interface exists; None if the device would not say."""
    result = adb(["shell", "ip", "-br", "link"])
    if result.returncode != 0:
        return None
    return bool(_TUN_RE.search(result.stdout.replace("\r", "")))


def capture_name(package: str, stamp: int) -> str:
    stem = f"review-{re.sub(r'[^A-Za-z0-9]+', '-', package)}"[:60]
    return f"{stem}-{stamp}.pcap"


def valid_api_key(key: str) -> bool:
    """Plain letters and digits only: the key is passed through the device's shell."""
    return _API_KEY_RE.match(key) is not None


def _key_args(api_key: str | None) -> list[str]:
    if api_key is None:
        return []
    if not valid_api_key(api_key):
        raise ValueError("the PCAPdroid API key is not a plain alphanumeric string")
    return ["-e", "api_key", api_key]


def start_capture(adb: AdbRun, package: str, pcap_name: str, api_key: str | None = None) -> bool:
    """Ask PCAPdroid to record only `package`'s traffic into a file. The first time, the
    person at the phone has to tap ALLOW (PCAPdroid's own prompt) and OK on Android's VPN
    dialog; the intent only starts the request.
    """
    if not _PCAP_NAME_RE.match(pcap_name):
        raise ValueError(f"refusing an unexpected capture file name: {pcap_name!r}")
    result = adb(
        [
            "shell", "am", "start",
            "-e", "action", "start",
            *_key_args(api_key),
            "-e", "pcap_dump_mode", "pcap_file",
            "-e", "pcap_name", pcap_name,
            "-e", "app_filter", package,
            "-e", "auto_block_private_dns", "true",
            "-n", PCAPDROID_CTRL,
        ]
    )  # fmt: skip
    return bool(result.returncode == 0)


def wait_for_vpn(
    adb: AdbRun,
    *,
    timeout: float = CONSENT_WAIT_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> bool:
    deadline = now() + timeout
    while True:
        if vpn_up(adb):
            return True
        if now() >= deadline:
            return False
        sleep(1.0)


def stop_capture(
    adb: AdbRun,
    *,
    wait_seconds: float = 20.0,
    attempts: int = STOP_ATTEMPTS,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
    api_key: str | None = None,
) -> bool:
    """Ask PCAPdroid to stop, then wait for the `tun` interface to go. True when the VPN is
    verifiably down. Without an API key PCAPdroid raises its "control request" dialog for a
    stop just as for a start (seen on the phone), so the person there has to tap ALLOW again:
    the intent is not re-sent more often than every `wait_seconds`, or the dialog is
    re-raised faster than anyone can answer it (seen on the phone).
    """
    for _ in range(attempts):
        adb(
            [
                "shell", "am", "start",
                "-e", "action", "stop",
                *_key_args(api_key),
                "-n", PCAPDROID_CTRL,
            ]
        )  # fmt: skip
        deadline = now() + wait_seconds
        while True:
            if vpn_up(adb) is False:
                return True
            if now() >= deadline:
                break
            sleep(1.0)
    return False


def remote_size(adb: AdbRun, remote: str) -> int | None:
    result = adb(["shell", "stat", "-c", "%s", remote])
    text = result.stdout.strip() if result.returncode == 0 else ""
    return int(text) if text.isdigit() else None


def wait_for_file(
    adb: AdbRun,
    remote: str,
    *,
    timeout: float = 15.0,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> int | None:
    """The file's size once two readings a second apart agree (0 counts: an app that sent
    nothing leaves an empty file). A cheap guard only: on the phone the file was written
    progressively and was already complete when the `tun` interface disappeared, so no race
    was observed. None if it keeps changing for `timeout` seconds.
    """
    deadline = now() + timeout
    last = None
    while True:
        size = remote_size(adb, remote)
        if size is not None and size == last:
            return size
        last = size
        if now() >= deadline:
            return None
        sleep(1.0)


def pull_capture(
    adb: AdbRun,
    pull: Callable[[str, Path], bool],
    pcap_name: str,
    destination: Path,
    *,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> int | None:
    """Copy the file off the phone once it is complete, then delete it there (it is a record
    of the app's traffic, and the phone's Download folder is not a place to leave it).

    The size copied, or None if the copy failed. Size 0 is a result, not a failure:
    PCAPdroid writes its file lazily, so an app that sent no packets leaves it with 0 bytes
    (seen on the phone), not even a pcap header.
    """
    remote = f"{PCAPDROID_DIR}/{pcap_name}"
    wait_for_file(adb, remote, sleep=sleep, now=now)
    ok = pull(remote, destination)
    adb(["shell", "rm", "-f", remote])
    if not ok or not destination.exists():
        return None
    return destination.stat().st_size
