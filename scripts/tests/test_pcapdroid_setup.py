from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import device_capture as dc  # noqa: E402
import pcapdroid_setup as ps  # noqa: E402

KEY = "sulZUwN6wIohYTEZf3PBx5VL3f6pANEF"
PD = dc.PCAPDROID_PACKAGE


def node(text: str = "", desc: str = "") -> ps.Node:
    return (text, desc, (0, 0, 100, 100))


class FakeDevice:
    """PCAPdroid 2.0.2 on a fresh Android 14 emulator, as its screens were observed."""

    def __init__(
        self,
        *,
        has_key: bool = False,
        drop_taps: int = 0,
        booted_ago: float = 10_000.0,
        start: str = "tip",
        scrolls_needed: int = 3,
        key_shown: bool = True,
        consent_works: bool = True,
        vpn_up: bool = False,
    ) -> None:
        self.state = start
        self.has_key = has_key
        self.drop_taps = drop_taps
        self.booted_ago = booted_ago
        self.scrolls_needed = scrolls_needed
        self.scrolled = 0
        self.key_shown = key_shown
        self.consent_works = consent_works
        self.tun = vpn_up
        self.taps: list[str] = []
        self.calls: list[list[str]] = []
        self.explained = False
        self.clock = 0.0

    # --- screens
    def screen(self) -> tuple[str, list[ps.Node]]:
        s = self.state
        if s == "tip":
            return "android", [node("Viewing full screen"), node("Got it")]
        if s == "intro":
            return PD, [node("Welcome to PCAPdroid"), node("SKIP"), node(desc="Next")]
        if s == "rationale":
            return PD, [
                node(
                    "The app uses notifications to send alerts in case of anomalous events. "
                    "Grant it the permission to send notifications in the next screen"
                ),
                node("OK"),
            ]
        if s == "notif":
            return "com.google.android.permissioncontroller", [
                node("Allow PCAPdroid to send you notifications?"),
                node("Allow"),
                node("Don’t allow"),
            ]
        if s == "main":
            return PD, [
                node(desc="Open drawer"),
                node("PCAPdroid"),
                node(desc="Settings"),
                node(desc="Start"),
            ]
        if s == "subpage":  # e.g. left on Settings: its title is also "Settings"
            return PD, [node(desc="Navigate up"), node("Settings"), node("HTTP server")]
        if s == "settings":
            shown = [node("Block QUIC")] + (
                [node("Control permissions")] if self.scrolled >= self.scrolls_needed else []
            )
            return PD, shown
        if s == "control":
            return PD, [node("No permissions set."), node(desc="More options")]
        if s == "menu":
            return PD, [node("Generate API key")]
        if s == "discard":
            return PD, [
                node("Warning"),
                node("Do you really want to discard the current API key and generate a new one?"),
                node("CANCEL"),
                node("OK"),
            ]
        if s == "keydlg":
            return PD, [node("API key")] + ([node(KEY)] if self.key_shown else []) + [
                node("COPY"),
                node("OK"),
            ]
        if s == "explain":
            return PD, [
                node("PCAPdroid simulates a VPN in order to capture the network traffic"),
                node("OK"),
            ]
        if s == "vpn":
            return "com.android.vpndialogs", [
                node("Connection request"),
                node("Cancel"),
                node("OK"),
            ]
        if s == "odd":
            return "com.example.surprise", [node("Rate this app"), node("Maybe later")]
        return PD, [node("PCAPdroid")]

    def tap(self, label: str) -> bool:
        pkg, nodes = self.screen()
        if label.lower() not in ps.labels(nodes):
            return False
        if self.booted_ago + self.clock < ps.MIN_GUEST_UPTIME:
            return True  # an emulator this fresh ignores the tap
        if self.drop_taps and self.state not in ("tip", "intro", "notif", "rationale"):
            self.drop_taps -= 1  # the tap was "delivered" and did nothing
            return True
        self.taps.append(label)
        nxt = {
            ("tip", "got it"): "intro",
            ("intro", "skip"): "notif",
            ("rationale", "ok"): "notif",
            ("notif", "don’t allow"): "main",
            ("main", "settings"): "settings",
            ("settings", "control permissions"): "control",
            ("control", "more options"): "menu",
            ("menu", "generate api key"): "discard" if self.has_key else "keydlg",
            ("discard", "ok"): "keydlg",
            ("keydlg", "ok"): "control",
        }.get((self.state, label.lower()))
        if self.state == "explain" and label.lower() == "ok":
            nxt = "vpn"
        elif self.state == "vpn" and label.lower() == "ok" and self.consent_works:
            self.tun = True
            nxt = "control"
        if nxt:
            self.state = nxt
        return True

    def scroll(self) -> None:
        self.scrolled += 1

    def back(self) -> None:
        self.backs = getattr(self, "backs", 0) + 1
        if self.state == "subpage":
            self.state = "main"

    # --- adb
    def adb(self, args: list[str]) -> Any:
        self.calls.append(args)
        out = ""
        if args[:3] == ["shell", "cat", "/proc/uptime"]:
            out = f"{self.booted_ago + self.clock:.2f} 12.00\n"
        elif args[:3] == ["shell", "ip", "-br"]:
            out = "lo UNKNOWN\ntunl0@NONE DOWN\nwlan0 UP\n" + ("tun0 UNKNOWN\n" if self.tun else "")
        elif (
            args[:3] == ["shell", "am", "start"] and "start" in args[args.index("action") + 1 :][:1]
        ):
            if not self.tun and not self.explained:
                self.state, self.explained = "explain", True
            elif not self.tun:
                self.tun = True
        elif args[:3] == ["shell", "am", "start"]:
            self.tun = False
        return SimpleNamespace(returncode=0, stdout=out)


def run_setup(dev: FakeDevice) -> str:
    def sleep(seconds: float) -> None:
        dev.clock += seconds

    return ps.setup(dev, dev.adb, sleep=sleep, now=lambda: dev.clock)


def test_a_fresh_install_ends_with_the_key_and_the_one_time_dialogs_answered() -> None:
    dev = FakeDevice()
    assert run_setup(dev) == KEY
    assert dev.taps == [
        "got it",
        "skip",
        "don’t allow",
        "Settings",
        "Control permissions",
        "More options",
        "Generate API key",
        "OK",
        "OK",
        "OK",
    ]
    starts = [c for c in dev.calls if c[:3] == ["shell", "am", "start"] and "start" in c]
    assert starts and "api_key" in starts[0] and KEY in starts[0]
    assert not dev.tun  # the setup capture was stopped
    assert ["shell", "rm", "-f", f"{dc.PCAPDROID_DIR}/pcapdroid-setup.pcap"] in dev.calls


def test_it_does_not_need_the_tip_or_the_intro_to_be_there() -> None:
    dev = FakeDevice(start="main")
    assert run_setup(dev) == KEY
    assert "skip" not in dev.taps and "got it" not in dev.taps


def test_the_settings_list_is_scrolled_until_control_permissions_shows() -> None:
    dev = FakeDevice(scrolls_needed=6)
    assert run_setup(dev) == KEY and dev.scrolled == 6


def test_a_screen_that_is_not_there_is_a_failure_that_says_what_it_saw() -> None:
    dev = FakeDevice(scrolls_needed=99)
    with pytest.raises(ps.SetupError, match="Control permissions") as info:
        run_setup(dev)
    assert "Block QUIC" in str(info.value)  # what the screen showed


def test_an_unexpected_first_screen_is_not_tapped_blind() -> None:
    dev = FakeDevice(start="odd")
    with pytest.raises(ps.SetupError, match="main screen was not reached") as info:
        run_setup(dev)
    assert "Rate this app" in str(info.value)
    assert dev.taps == []


def test_no_key_on_screen_is_a_failure() -> None:
    with pytest.raises(ps.SetupError, match="no API key was shown"):
        run_setup(FakeDevice(key_shown=False))


def test_a_vpn_that_is_already_up_stops_the_setup_before_it_starts_anything() -> None:
    dev = FakeDevice(start="main", vpn_up=True)
    with pytest.raises(ps.SetupError, match="already up"):
        run_setup(dev)
    assert not any(c[:3] == ["shell", "am", "start"] and "start" in c for c in dev.calls)


def test_a_capture_that_never_starts_gives_up_with_the_screen() -> None:
    dev = FakeDevice(consent_works=False)
    with pytest.raises(ps.SetupError, match="did not start") as info:
        run_setup(dev)
    assert "Connection request" in str(info.value)


def test_a_real_uiautomator_dump_is_read_with_entities_and_without_empty_nodes() -> None:
    xml = (
        '<hierarchy><node index="0" text="" resource-id="" class="x" '
        'package="com.android.settings" '
        'content-desc="" bounds="[0,0][1080,2400]"/>'
        '<node index="1" text="Alarms &amp; reminders" resource-id="" class="y" '
        'package="com.android.settings" content-desc="" bounds="[10,20][110,220]"/>'
        '<node index="2" text="" resource-id="" class="z" package="com.android.settings" '
        'content-desc="Settings" bounds="[0,0][50,50]"/></hierarchy>'
    )
    package, nodes = ps.parse_ui(xml)
    assert package == "com.android.settings"
    assert [(t, d) for t, d, _ in nodes] == [("Alarms & reminders", ""), ("", "Settings")]
    assert nodes[0][2] == (10, 20, 110, 220)


def test_the_command_prints_only_the_key_on_stdout_and_errors_go_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    adb = tmp_path / "adb"
    adb.write_text("#!/bin/sh\nexit 0\n")  # a device that has nothing installed
    adb.chmod(0o755)
    assert ps.main(["--adb-command", str(adb)]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "not installed" in captured.err


def test_pcapdroids_own_notification_rationale_is_answered_when_it_comes_first() -> None:
    """Seen on an AVD where PCAPdroid had been set up before and the permission was refused."""
    dev = FakeDevice(start="rationale")
    assert run_setup(dev) == KEY
    assert dev.taps[:2] == ["ok", "don\u2019t allow"]


def test_an_existing_key_is_replaced_after_the_confirmation_it_asks_for() -> None:
    """Seen when setup is run twice on one device: PCAPdroid asks before discarding the old key."""
    dev = FakeDevice(start="main", has_key=True)
    assert run_setup(dev) == KEY
    assert "Generate API key" in dev.taps and dev.taps.count("OK") >= 3


def test_a_tap_that_is_silently_dropped_is_repeated_not_assumed() -> None:
    """Seen on the emulator: the tap on Settings right after a dialog closed did nothing."""
    dev = FakeDevice(start="main", drop_taps=2)
    assert run_setup(dev) == KEY
    assert dev.taps.count("Settings") == 1  # it took effect once the taps stopped being dropped


def test_taps_that_never_take_effect_are_a_failure_with_the_screen() -> None:
    dev = FakeDevice(start="main", drop_taps=99)
    with pytest.raises(ps.SetupError, match="had no effect") as info:
        run_setup(dev)
    assert "PCAPdroid" in str(info.value)


def test_the_screen_is_woken_first() -> None:
    dev = FakeDevice(start="main")
    run_setup(dev)
    wake = dev.calls.index(["shell", "input", "keyevent", "KEYCODE_WAKEUP"])
    launch = next(i for i, c in enumerate(dev.calls) if c[:2] == ["shell", "monkey"])
    assert wake < launch  # before the app is started, so before any tap


def test_pcapdroid_left_on_a_sub_page_is_taken_back_to_the_main_screen_first() -> None:
    """Seen on the emulator: the app relaunched into Settings, whose title is also 'Settings'."""
    dev = FakeDevice(start="subpage")
    assert run_setup(dev) == KEY
    assert dev.backs == 1
    assert dev.taps[0] == "Settings"  # the real button, not the page's title


def test_a_device_that_booted_moments_ago_is_waited_for_before_any_tap() -> None:
    """Seen on the emulator: taps at 59 s of uptime did nothing; later ones worked."""
    dev = FakeDevice(booted_ago=20.0)
    assert run_setup(dev) == KEY
    assert dev.clock >= ps.MIN_GUEST_UPTIME - 20.0  # it really waited
    assert dev.taps[0] == "got it"  # and the first tap then took effect


def test_a_phone_that_has_been_on_for_days_is_not_made_to_wait() -> None:
    dev = FakeDevice(booted_ago=86_400.0, start="main")
    start = dev.clock
    run_setup(dev)
    assert dev.calls[0] == ["shell", "cat", "/proc/uptime"]
    assert dev.clock - start < 60  # only the setup's own short pauses


def test_an_unreadable_uptime_does_not_block_the_setup() -> None:
    dev = FakeDevice(start="main")
    real = dev.adb

    def adb(args: list[str]) -> Any:
        if args[:3] == ["shell", "cat", "/proc/uptime"]:
            return SimpleNamespace(returncode=1, stdout="")
        return real(args)

    assert ps.guest_uptime(adb) is None
    ps.wait_until_settled(adb, sleep=lambda s: None)  # returns at once
