#!/usr/bin/env python3
"""A small automatic explorer for an installed Android app, driven by `uiautomator dump`.

Loop, up to --steps times: dump the accessibility tree, pick an element of the reviewed app that
has not been tried on this screen yet (text fields first, then clickable elements), type into it
or tap it, take a screenshot, and record what happened. A screen with nothing left to try gets
BACK; leaving the app relaunches it. Blockers it can recognise (permission dialogs, login screens,
camera/QR, WebViews, an empty tree) are recorded, not solved.

`--monkey-events N` runs Android's `monkey` afterwards on a fresh start of the app, in chunks, and
records the same measures, so the two can be compared on one device.

Standard library only. Every adb call goes through `Adb.run`, so the logic is tested offline
against a fake (test_explore.py).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

PERMISSION_PACKAGES = {
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
    "com.android.packageinstaller",
}
# Buttons on a runtime permission dialog that let the app carry on.
PERMISSION_ALLOW = re.compile(r"^(allow|while using the app|only this time|ok)$", re.IGNORECASE)
LOGIN_WORDS = re.compile(
    r"\b(log ?in|sign ?in|password|username|e-?mail|server url|homeserver)\b", re.IGNORECASE
)
CAMERA_WORDS = re.compile(r"\b(scan|qr|camera|barcode)\b", re.IGNORECASE)
# Never tap these: they end the session or send something somewhere.
AVOID_WORDS = re.compile(
    r"\b(uninstall|delete account|log ?out|sign ?out|report|buy|purchase|donate|pay)\b",
    re.IGNORECASE,
)
DISPLAYED = re.compile(r"Displayed ([\w.]+)/([\w.$]+)")
BOUNDS = re.compile(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]")
SAMPLE_TEXT = "test"


@dataclass(frozen=True)
class Element:
    cls: str
    package: str
    resource_id: str
    text: str
    desc: str
    bounds: tuple[int, int, int, int]
    clickable: bool
    editable: bool
    password: bool

    @property
    def center(self) -> tuple[int, int]:
        x1, y1, x2, y2 = self.bounds
        return (x1 + x2) // 2, (y1 + y2) // 2

    @property
    def label(self) -> str:
        return (
            self.text
            or self.desc
            or self.resource_id.rsplit("/", 1)[-1]
            or self.cls.rsplit(".", 1)[-1]
        )

    @property
    def key(self) -> str:
        """Identity within a screen: what it is, not what it currently says (text fields change)."""
        text = "" if self.editable else self.text
        return f"{self.cls}|{self.resource_id}|{text}|{self.desc}|{self.bounds}"


@dataclass
class Screen:
    elements: list[Element]
    packages: set[str]
    classes: set[str]
    structure: list[str] = field(default_factory=list)

    @property
    def signature(self) -> str:
        """What decides 'have I been here': every node's class and id, plus the labels of buttons.
        Not the text of fields or of plain text views, which change while the screen stays the same."""
        parts = sorted(self.structure) + sorted(
            e.label for e in self.elements if e.clickable and not e.editable
        )
        return hashlib.sha1("\n".join(parts).encode()).hexdigest()[:12]


def parse_bounds(value: str) -> tuple[int, int, int, int] | None:
    m = BOUNDS.fullmatch(value.strip())
    return tuple(int(g) for g in m.groups()) if m else None  # type: ignore[return-value]


def parse_dump(xml_text: str) -> Screen:
    """Parse a `uiautomator dump` document. Raises ValueError if it is not one."""
    start = xml_text.find("<?xml")
    if start < 0:
        start = xml_text.find("<hierarchy")
    end = xml_text.rfind("</hierarchy>")
    if start < 0 or end < 0:
        raise ValueError("not a uiautomator dump")
    root = ET.fromstring(xml_text[start : end + len("</hierarchy>")])
    elements: list[Element] = []
    packages: set[str] = set()
    classes: set[str] = set()
    structure: list[str] = []
    for node in root.iter("node"):
        a = node.attrib
        pkg = a.get("package", "")
        cls = a.get("class", "")
        packages.add(pkg)
        classes.add(cls)
        structure.append(f"{pkg}|{cls}|{a.get('resource-id', '')}")
        bounds = parse_bounds(a.get("bounds", ""))
        if bounds is None or bounds[2] - bounds[0] < 4 or bounds[3] - bounds[1] < 4:
            continue
        if a.get("enabled", "true") != "true":
            continue
        editable = "EditText" in cls
        clickable = a.get("clickable") == "true"
        if not (clickable or editable):
            continue
        elements.append(
            Element(
                cls=cls,
                package=pkg,
                resource_id=a.get("resource-id", ""),
                text=a.get("text", ""),
                desc=a.get("content-desc", ""),
                bounds=bounds,
                clickable=clickable,
                editable=editable,
                password=a.get("password") == "true",
            )
        )
    return Screen(elements=elements, packages=packages, classes=classes, structure=structure)


def blockers(screen: Screen, app_package: str) -> list[str]:
    """What on this screen an unattended explorer cannot get past on its own."""
    found: list[str] = []
    if not screen.elements and not screen.classes:
        found.append("empty-tree")
    if screen.packages & PERMISSION_PACKAGES:
        found.append("permission-dialog")
    words = " ".join(f"{e.text} {e.desc} {e.resource_id}" for e in screen.elements)
    if any(e.password for e in screen.elements) or (
        any(e.editable for e in screen.elements) and LOGIN_WORDS.search(words)
    ):
        found.append("login")
    if CAMERA_WORDS.search(words) or any(
        c.endswith(("SurfaceView", "TextureView")) for c in screen.classes
    ):
        found.append("camera-or-qr")
    if any(c.endswith("WebView") for c in screen.classes):
        found.append("webview")
    app_elements = [e for e in screen.elements if e.package == app_package]
    if (
        app_package in screen.packages
        and not app_elements
        and screen.classes - {"android.widget.FrameLayout"}
    ):
        # The app is on screen but exposes nothing to tap: a canvas, game engine or custom view.
        found.append("no-accessible-elements")
    return found


def choose(screen: Screen, app_package: str, tried: set[str]) -> Element | None:
    """The next element to try on this screen: untried text fields, then untried taps, in reading order."""
    if screen.packages & PERMISSION_PACKAGES:
        for e in screen.elements:
            if PERMISSION_ALLOW.match(e.text.strip()) and e.key not in tried:
                return e
    candidates = [
        e
        for e in screen.elements
        if e.package == app_package
        and e.key not in tried
        and not AVOID_WORDS.search(f"{e.text} {e.desc}")
    ]
    candidates.sort(key=lambda e: (not e.editable, e.bounds[1], e.bounds[0]))
    return candidates[0] if candidates else None


class Adb:
    """Runs adb. `runner` is replaceable for tests; it gets the argv and returns (rc, stdout bytes)."""

    def __init__(
        self,
        adb: str = "adb",
        serial: str | None = None,
        runner: Callable[[list[str], float], tuple[int, bytes]] | None = None,
    ) -> None:
        self.base = shlex.split(adb) + (["-s", serial] if serial else [])
        self.runner = runner or self._run

    @staticmethod
    def _run(argv: list[str], timeout: float) -> tuple[int, bytes]:
        try:
            p = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return 124, b""
        return p.returncode, p.stdout

    def run(self, *args: str, timeout: float = 30) -> tuple[int, bytes]:
        return self.runner([*self.base, *args], timeout)

    def shell(self, cmd: str, timeout: float = 30) -> str:
        return self.run("shell", cmd, timeout=timeout)[1].decode(errors="replace")

    def dump(self) -> str:
        # Dump to a file and read it back: `uiautomator dump /dev/tty` mixes in its own status line.
        self.shell(
            "rm -f /sdcard/explore-ui.xml; uiautomator dump /sdcard/explore-ui.xml", timeout=40
        )
        return self.shell("cat /sdcard/explore-ui.xml", timeout=15)

    def screenshot(self, path: Path) -> bool:
        rc, png = self.run("exec-out", "screencap", "-p", timeout=20)
        if rc == 0 and png.startswith(b"\x89PNG"):
            path.write_bytes(png)
            return True
        return False

    def focused(self) -> str:
        out = self.shell("dumpsys window | grep -E 'mCurrentFocus|mFocusedApp' | head -2")
        m = re.search(r"([\w.]+)/([\w.$]+)", out)
        return f"{m.group(1)}/{m.group(2)}" if m else ""

    def launch(self, package: str) -> None:
        self.shell(f"monkey -p {shlex.quote(package)} -c android.intent.category.LAUNCHER 1")

    def tap(self, x: int, y: int) -> None:
        self.shell(f"input tap {x} {y}")

    def type_text(self, text: str) -> None:
        self.shell(f"input text {shlex.quote(text)}")

    def back(self) -> None:
        self.shell("input keyevent KEYCODE_BACK")

    def hide_keyboard(self) -> None:
        self.shell("input keyevent KEYCODE_ESCAPE")


@dataclass
class Step:
    n: int
    action: str
    target: str
    screen: str
    focus: str
    blockers: list[str]
    screenshot: str | None


@dataclass
class Summary:
    mode: str
    package: str
    steps: int = 0
    seconds: float = 0.0
    screens: list[str] = field(default_factory=list)
    activities: list[str] = field(default_factory=list)
    blockers: dict[str, int] = field(default_factory=dict)
    relaunches: int = 0
    crashes: list[str] = field(default_factory=list)
    dump_failures: int = 0
    stopped_because: str = ""


def displayed_activities(logcat: str, package: str) -> set[str]:
    return {f"{p}/{a}" for p, a in DISPLAYED.findall(logcat) if p == package}


def crash_lines(logcat: str, package: str) -> list[str]:
    out = []
    lines = logcat.splitlines()
    for i, line in enumerate(lines):
        if "FATAL EXCEPTION" in line or "ANR in" in line:
            window = "\n".join(lines[i : i + 3])
            if package in window:
                out.append(window[:300])
    return out


def explore(
    adb: Adb,
    package: str,
    out: Path,
    max_steps: int,
    sleep: float = 1.5,
    clock: Callable[[], float] = time.monotonic,
    pause: Callable[[float], None] = time.sleep,
) -> Summary:
    out.mkdir(parents=True, exist_ok=True)
    shots = out / "screens"
    shots.mkdir(exist_ok=True)
    summary = Summary(mode="uiautomator", package=package)
    tried: dict[str, set[str]] = {}
    screens: list[str] = []
    focus_seen: set[str] = set()
    t0 = clock()
    adb.shell("logcat -c")
    adb.launch(package)
    pause(sleep * 2)
    steps_log = (out / "steps.jsonl").open("w")
    stuck = 0
    for n in range(1, max_steps + 1):
        focus = adb.focused()
        if focus:
            focus_seen.add(focus)
        try:
            screen = parse_dump(adb.dump())
        except (ValueError, ET.ParseError):
            summary.dump_failures += 1
            screen = Screen(elements=[], packages=set(), classes=set())
        sig = screen.signature
        if sig not in screens:
            screens.append(sig)
        found = blockers(screen, package)
        for b in found:
            summary.blockers[b] = summary.blockers.get(b, 0) + 1

        shot = shots / f"step-{n:03d}.png"
        has_shot = adb.screenshot(shot)
        target = ""
        if package not in screen.packages and not (screen.packages & PERMISSION_PACKAGES):
            action = "relaunch"
            summary.relaunches += 1
            adb.launch(package)
        else:
            element = choose(screen, package, tried.setdefault(sig, set()))
            if element is None:
                action = "back"
                stuck += 1
                adb.back()
            else:
                stuck = 0
                tried[sig].add(element.key)
                target = element.label[:60]
                x, y = element.center
                adb.tap(x, y)
                if element.editable:
                    action = "type"
                    pause(0.3)
                    adb.type_text(SAMPLE_TEXT)
                    adb.hide_keyboard()
                else:
                    action = "tap"
        step = Step(n, action, target, sig, focus, found, shot.name if has_shot else None)
        steps_log.write(json.dumps(asdict(step)) + "\n")
        steps_log.flush()
        summary.steps = n
        if summary.relaunches >= 8:
            summary.stopped_because = "left the app 8 times"
            break
        if stuck >= 4:
            summary.stopped_because = "nothing new to try on 4 screens in a row"
            break
        pause(sleep)
    else:
        summary.stopped_because = "step limit"
    steps_log.close()
    logcat = adb.shell("logcat -d", timeout=60)
    summary.activities = sorted(
        displayed_activities(logcat, package)
        | {f for f in focus_seen if f.startswith(package + "/")}
    )
    summary.crashes = crash_lines(logcat, package)
    summary.screens = screens
    summary.seconds = round(clock() - t0, 1)
    return summary


def monkey(
    adb: Adb,
    package: str,
    out: Path,
    events: int,
    chunk: int = 100,
    seed: int = 42,
    pause: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Summary:
    """`monkey` restricted to the app, in chunks, with a dump and screenshot between chunks."""
    shots = out / "screens"
    shots.mkdir(parents=True, exist_ok=True)
    summary = Summary(mode="monkey", package=package)
    screens: list[str] = []
    t0 = clock()
    adb.shell(f"am force-stop {shlex.quote(package)}")
    adb.shell("logcat -c")
    adb.launch(package)
    pause(3)
    done = 0
    i = 0
    while done < events:
        n = min(chunk, events - done)
        i += 1
        adb.shell(
            f"monkey -p {shlex.quote(package)} -s {seed + i} --throttle 250 --pct-syskeys 0 "
            f"--pct-appswitch 0 --pct-anyevent 0 --ignore-crashes --ignore-timeouts -v {n}",
            timeout=n * 2 + 60,
        )
        done += n
        try:
            screen = parse_dump(adb.dump())
            sig = screen.signature
            if sig not in screens:
                screens.append(sig)
            for b in blockers(screen, package):
                summary.blockers[b] = summary.blockers.get(b, 0) + 1
        except (ValueError, ET.ParseError):
            summary.dump_failures += 1
        adb.screenshot(shots / f"monkey-{i:03d}.png")
        summary.steps = done
    logcat = adb.shell("logcat -d", timeout=60)
    summary.activities = sorted(displayed_activities(logcat, package))
    summary.crashes = crash_lines(logcat, package)
    summary.screens = screens
    summary.seconds = round(clock() - t0, 1)
    summary.stopped_because = "event limit"
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--package", required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--steps", type=int, default=40, help="explorer step limit; 0 skips it")
    ap.add_argument(
        "--monkey-events", type=int, default=0, help="also run monkey with this many events"
    )
    ap.add_argument("--adb", default="adb", help="how to run adb, one shell-quoted string")
    ap.add_argument("--serial")
    args = ap.parse_args(argv)
    adb = Adb(args.adb, args.serial)
    results = []
    if args.steps:
        results.append(explore(adb, args.package, args.out / "uiautomator", args.steps))
    if args.monkey_events:
        results.append(monkey(adb, args.package, args.out / "monkey", args.monkey_events))
    data = [asdict(r) for r in results]
    args.out.mkdir(parents=True, exist_ok=True)
    name = "summary.json" if args.steps else "summary-monkey.json"
    (args.out / name).write_text(json.dumps(data, indent=2))
    for r in results:
        print(
            f"{r.mode}: {r.steps} steps in {r.seconds}s, {len(r.screens)} distinct screens, "
            f"{len(r.activities)} activities {r.activities}, blockers {r.blockers}, "
            f"relaunches {r.relaunches}, dump failures {r.dump_failures}, crashes {len(r.crashes)}, "
            f"stopped: {r.stopped_because}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
