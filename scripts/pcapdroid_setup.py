"""Set PCAPdroid up on a throwaway device (an emulator) so a review can capture with it
without a person at the screen: install it, get past its first-run screens, generate its API
key, and run one short capture so its two one-time dialogs (its own explanation and Android's
VPN consent) are answered. Prints the key, and only the key, on stdout.

This drives another app's UI by on-screen text, as it was on PCAPdroid 2.0.2 (Android 14
emulator, Android 12 phone): Settings > Control permissions > menu > Generate API key. A
different version may word things differently; when a screen is not the one expected this fails
and says what the screen showed, rather than tapping blind. Not for a phone you care about:
it changes PCAPdroid's settings and makes a VPN consent permanent.
"""

from __future__ import annotations

import argparse
import html
import re
import shlex
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

import device_capture as dc

Node = tuple[str, str, tuple[int, int, int, int]]  # text, content description, bounds
_NODE_RE = re.compile(
    r'<node[^>]*?text="([^"]*)"[^>]*?content-desc="([^"]*)"[^>]*?'
    r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"'
)
_KEY_RE = re.compile(r"^[A-Za-z0-9]{16,64}$")
# Dismissed wherever they appear on the way to the main screen. Order matters: first match wins.
_DISMISS = ("got it", "skip", "don’t allow", "don't allow")
# Taps are silently ignored for a while after an emulator boots: one at 59 s of uptime did
# nothing, the same tap at about 100 s worked (two observations, not a measured threshold).
MIN_GUEST_UPTIME = 90.0
_PRIME_PACKAGE = "com.android.shell"  # any app: the capture only has to start and stop once


class SetupError(Exception):
    pass


class Ui(Protocol):
    def screen(self) -> tuple[str, list[Node]]: ...
    def tap(self, label: str) -> bool: ...
    def scroll(self) -> None: ...
    def back(self) -> None: ...


def parse_ui(xml: str) -> tuple[str, list[Node]]:
    package = (re.findall(r'package="([^"]+)"', xml) or ["?"])[0]
    nodes: list[Node] = []
    for match in _NODE_RE.finditer(xml):
        text, desc = html.unescape(match.group(1)), html.unescape(match.group(2))
        if text.strip() or desc.strip():
            bounds = tuple(int(g) for g in match.groups()[2:])
            nodes.append((text, desc, bounds))  # type: ignore[arg-type]
    return package, nodes


def labels(nodes: list[Node]) -> list[str]:
    return [(text or desc).strip().lower() for text, desc, _ in nodes]


def describe(package: str, nodes: list[Node]) -> str:
    shown = [text or f"desc:{desc}" for text, desc, _ in nodes][:10]
    return f"[{package}] {shown}"


class DeviceUi:
    """The real thing: `uiautomator dump` and `input` through adb."""

    def __init__(self, adb: Callable[[list[str]], Any]) -> None:
        self._adb = adb

    def screen(self) -> tuple[str, list[Node]]:
        self._adb(["shell", "uiautomator", "dump", "/sdcard/pcapdroid-setup.xml"])
        return parse_ui(self._adb(["shell", "cat", "/sdcard/pcapdroid-setup.xml"]).stdout)

    def tap(self, label: str) -> bool:
        _, nodes = self.screen()
        want = label.lower()
        for text, desc, b in nodes:
            if want in (text.strip().lower(), desc.strip().lower()):
                self._adb(
                    ["shell", "input", "tap", str((b[0] + b[2]) // 2), str((b[1] + b[3]) // 2)]
                )
                return True
        return False

    def scroll(self) -> None:
        self._adb(["shell", "input", "swipe", "540", "1800", "540", "600", "300"])

    def back(self) -> None:
        self._adb(["shell", "input", "keyevent", "KEYCODE_BACK"])


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def guest_uptime(adb: dc.AdbRun) -> float | None:
    result = adb(["shell", "cat", "/proc/uptime"])
    try:
        return float(str(result.stdout).split()[0]) if result.returncode == 0 else None
    except (ValueError, IndexError):
        return None


def wait_until_settled(
    adb: dc.AdbRun, *, sleep: Callable[[float], None], minimum: float = MIN_GUEST_UPTIME
) -> None:
    """Do not drive the UI of a device that booted moments ago (see MIN_GUEST_UPTIME)."""
    told = False
    while True:
        up = guest_uptime(adb)
        if up is None or up >= minimum:
            return
        if not told:
            _log(
                f"  the device booted {int(up)}s ago and ignores taps this early: "
                f"waiting until it has been up {int(minimum)}s"
            )
            told = True
        sleep(min(5.0, minimum - up))


def _asks_for_notifications(nodes: list[Node]) -> bool:
    return any("uses notifications" in text for text, _, _ in nodes) and "ok" in labels(nodes)


def reach_main_screen(ui: Ui, *, sleep: Callable[[float], None], attempts: int = 25) -> None:
    """From a fresh launch to PCAPdroid's main screen (the one with a Settings button)."""
    for _ in range(attempts):
        package, nodes = ui.screen()
        seen = labels(nodes)
        hit = next((d for d in _DISMISS if d in seen), None)
        if hit is None and package == dc.PCAPDROID_PACKAGE and _asks_for_notifications(nodes):
            hit = "ok"  # its own rationale, shown again when the permission was refused before
        if hit is not None:
            _log(f"  dismissing {hit!r}")
            ui.tap(hit)
        elif package == dc.PCAPDROID_PACKAGE and "open drawer" in seen:
            return  # the main screen: only it has the navigation drawer button
        elif package == dc.PCAPDROID_PACKAGE and "navigate up" in seen:
            _log("  PCAPdroid was left on a sub-page: going back")
            ui.back()
        sleep(1.5)
    raise SetupError(
        f"PCAPdroid's main screen was not reached; the screen showed {describe(*ui.screen())}"
    )


def generate_key(ui: Ui, *, sleep: Callable[[float], None]) -> str:
    def step(label: str, *, scrolls: int = 0) -> None:
        for _ in range(scrolls + 1):
            before = labels(ui.screen()[1])
            if ui.tap(label):
                # A tap that lands while the last dialog is still animating away is dropped
                # without a word (seen on the emulator), so look for an effect and tap again.
                for _ in range(8):
                    sleep(1.5)
                    if labels(ui.screen()[1]) != before:
                        return
                    ui.tap(label)
                raise SetupError(
                    f"tapping {label!r} had no effect; the screen showed {describe(*ui.screen())}"
                )
            if scrolls:
                ui.scroll()
                sleep(1.0)
        raise SetupError(f"no {label!r} on the screen; it showed {describe(*ui.screen())}")

    step("Settings")
    step("Control permissions", scrolls=8)
    step("More options")
    step("Generate API key")
    _, nodes = ui.screen()
    if any("discard the current api key" in text.lower() for text, _, _ in nodes):
        # A key already exists (setup was run before on this device): replace it.
        _log("  replacing the existing API key")
        ui.tap("OK")
        sleep(1.5)
        _, nodes = ui.screen()
    key = next((t.strip() for t, _, _ in nodes if _KEY_RE.match(t.strip())), None)
    if key is None or not dc.valid_api_key(key):
        raise SetupError(f"no API key was shown; the screen showed {describe(*ui.screen())}")
    ui.tap("OK")
    return key


def prime_consent(
    ui: Ui,
    adb: dc.AdbRun,
    key: str,
    *,
    sleep: Callable[[float], None],
    now: Callable[[], float],
    timeout: float = 60.0,
) -> None:
    """One capture, started and stopped, so the one-time dialogs are answered here and not in
    the middle of a review. (PCAPdroid's own explanation, then Android's VPN approval.)
    """
    name = "pcapdroid-setup.pcap"
    if dc.vpn_up(adb):
        raise SetupError("a VPN is already up on the device; PCAPdroid cannot start beside it")
    if not dc.start_capture(adb, _PRIME_PACKAGE, name, key):
        raise SetupError("PCAPdroid did not accept the start request")
    deadline = now() + timeout
    while not dc.vpn_up(adb):
        package, nodes = ui.screen()
        text = " ".join(t for t, _, _ in nodes)
        if package == "com.android.vpndialogs" or "simulates a VPN" in text:
            _log("  answering a one-time VPN dialog")
            ui.tap("OK")
        if now() >= deadline:
            raise SetupError(
                f"the capture did not start; the screen showed {describe(package, nodes)}"
            )
        sleep(1.5)
    if not dc.stop_capture(adb, api_key=key):
        raise SetupError("the setup capture could not be stopped; stop it in PCAPdroid")
    adb(["shell", "rm", "-f", f"{dc.PCAPDROID_DIR}/{name}"])


def setup(
    ui: Ui,
    adb: dc.AdbRun,
    *,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> str:
    wait_until_settled(adb, sleep=sleep)
    adb(["shell", "input", "keyevent", "KEYCODE_WAKEUP"])
    adb(
        [
            "shell",
            "monkey",
            "-p",
            dc.PCAPDROID_PACKAGE,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ]
    )
    sleep(3.0)
    _log("getting past PCAPdroid's first-run screens")
    reach_main_screen(ui, sleep=sleep)
    _log("generating an API key")
    key = generate_key(ui, sleep=sleep)
    _log("one short capture, to answer the one-time VPN dialogs")
    prime_consent(ui, adb, key, sleep=sleep, now=now)
    return key


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="pcapdroid_setup.py", description=__doc__.split("\n\n")[0]
    )
    parser.add_argument("--adb-command", default="adb", help="how to run adb (shell-quoted)")
    parser.add_argument("--serial", default=None)
    parser.add_argument("--apk", type=Path, default=None, help="PCAPdroid's APK, to install first")
    args = parser.parse_args(argv)
    base = shlex.split(args.adb_command) + (["-s", args.serial] if args.serial else [])

    def adb(rest: list[str]) -> Any:
        return subprocess.run([*base, *rest], capture_output=True, text=True, check=False)  # noqa: S603

    try:
        if args.apk is not None:
            result = adb(["install", "-r", str(args.apk)])
            if "Success" not in result.stdout:
                raise SetupError(
                    f"installing PCAPdroid failed: {(result.stderr or result.stdout).strip()}"
                )
        elif not dc.pcapdroid_installed(adb):
            raise SetupError("PCAPdroid is not installed on the device; pass --apk")
        key = setup(DeviceUi(adb), adb)
    except SetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(key)  # the only thing on stdout
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
