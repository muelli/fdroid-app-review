from __future__ import annotations

import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import device_capture as dc  # noqa: E402

PNG = dc.PNG_MAGIC + b"fake-image-data"


def _out(text: str = "", code: int = 0) -> Any:
    return SimpleNamespace(returncode=code, stdout=text)


class FakeAdb:
    """A phone: answers `pm list`, `ip link` and the stop intent."""

    def __init__(self, *, installed: bool = True, vpn: list[bool] | None = None) -> None:
        self.installed = installed
        self.vpn = vpn if vpn is not None else [False]
        self.calls: list[list[str]] = []
        self.sizes = [4096]

    def __call__(self, args: list[str]) -> Any:
        self.calls.append(args)
        if args[:3] == ["shell", "pm", "list"]:
            return _out(f"package:{dc.PCAPDROID_PACKAGE}\r\n" if self.installed else "")
        if args[:3] == ["shell", "stat", "-c"]:
            sizes = self.sizes
            return _out(f"{sizes.pop(0) if len(sizes) > 1 else sizes[0]}\n")
        if args[:2] == ["shell", "ip"]:
            up = self.vpn.pop(0) if len(self.vpn) > 1 else self.vpn[0]
            return _out("lo UNKNOWN\r\nwlan0 UP\r\n" + ("tun0 UNKNOWN\r\n" if up else ""))
        return _out()


def test_pcapdroid_is_detected_by_exact_package_name() -> None:
    assert dc.pcapdroid_installed(FakeAdb(installed=True))
    assert not dc.pcapdroid_installed(FakeAdb(installed=False))

    def lookalike(args: list[str]) -> Any:
        return _out(f"package:{dc.PCAPDROID_PACKAGE}.fork\r\n")

    assert not dc.pcapdroid_installed(lookalike)


def test_a_vpn_is_a_tun_interface_and_nothing_else_is() -> None:
    assert dc.vpn_up(FakeAdb(vpn=[True])) is True
    assert dc.vpn_up(FakeAdb(vpn=[False])) is False
    assert dc.vpn_up(lambda args: _out("", 1)) is None
    assert dc.vpn_up(lambda args: _out("tunnel0 UP\r\nwlan0 UP\r\n")) is False


def test_the_start_intent_filters_to_the_app_and_blocks_private_dns() -> None:
    adb = FakeAdb()
    assert dc.start_capture(adb, "org.example.app", "review-org-example-app-1.pcap")
    args = adb.calls[0]
    pairs = {args[i + 1]: args[i + 2] for i, a in enumerate(args) if a == "-e"}
    assert pairs == {
        "action": "start",
        "pcap_dump_mode": "pcap_file",
        "pcap_name": "review-org-example-app-1.pcap",
        "app_filter": "org.example.app",
        "auto_block_private_dns": "true",
    }
    assert args[-2:] == ["-n", dc.PCAPDROID_CTRL]


@pytest.mark.parametrize("name", ["a b.pcap", "x;rm -rf /.pcap", "../a.pcap", "a.txt", ""])
def test_an_odd_capture_name_is_refused_before_it_reaches_the_device_shell(name: str) -> None:
    with pytest.raises(ValueError):
        dc.start_capture(FakeAdb(), "a.b", name)


def test_the_capture_file_name_is_plain() -> None:
    assert dc.capture_name("org.example.app", 5) == "review-org-example-app-5.pcap"
    assert dc._PCAP_NAME_RE.match(dc.capture_name("a" * 200 + ".b", 5)) is not None


def test_waiting_for_the_vpn_returns_when_it_comes_up_or_gives_up() -> None:
    clock = [0.0]
    adb = FakeAdb(vpn=[False, False, True])
    assert dc.wait_for_vpn(
        adb, timeout=60, sleep=lambda s: clock.__setitem__(0, clock[0] + s), now=lambda: clock[0]
    )
    never = FakeAdb(vpn=[False])
    assert not dc.wait_for_vpn(
        never, timeout=5, sleep=lambda s: clock.__setitem__(0, clock[0] + s), now=lambda: clock[0]
    )


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def sleep(self, seconds: float) -> None:
        self.t += seconds

    def now(self) -> float:
        return self.t


def test_stop_waits_for_the_vpn_and_asks_again_only_after_the_wait() -> None:
    clock = _Clock()
    adb = FakeAdb(vpn=[True, True, True, False])
    assert dc.stop_capture(adb, wait_seconds=2, sleep=clock.sleep, now=clock.now)
    assert len([c for c in adb.calls if "stop" in c]) == 2


def test_stop_does_not_hammer_the_phone_while_someone_is_tapping() -> None:
    clock = _Clock()
    adb = FakeAdb(vpn=[True, True, True, True, True, False])  # up for 5 polls, then gone
    assert dc.stop_capture(adb, wait_seconds=20, sleep=clock.sleep, now=clock.now)
    assert len([c for c in adb.calls if "stop" in c]) == 1  # one intent, one dialog


def test_stop_reports_failure_when_the_vpn_stays_up() -> None:
    clock = _Clock()
    adb = FakeAdb(vpn=[True])
    assert not dc.stop_capture(adb, wait_seconds=2, attempts=2, sleep=clock.sleep, now=clock.now)
    assert len([c for c in adb.calls if "stop" in c]) == 2


def test_the_capture_is_pulled_and_then_deleted_from_the_phone(tmp_path: Path) -> None:
    adb = FakeAdb()
    dest = tmp_path / "c.pcap"

    def pull(remote: str, local: Path) -> bool:
        assert remote == f"{dc.PCAPDROID_DIR}/x.pcap"
        local.write_bytes(b"data")
        return True

    assert dc.pull_capture(adb, pull, "x.pcap", dest, sleep=lambda s: None) == 4
    assert ["shell", "rm", "-f", f"{dc.PCAPDROID_DIR}/x.pcap"] in adb.calls


def test_a_failed_pull_is_none_and_an_empty_file_is_zero_and_the_phone_is_cleaned(
    tmp_path: Path,
) -> None:
    adb = FakeAdb()
    dest = tmp_path / "c.pcap"
    assert (
        dc.pull_capture(adb, lambda r, local: False, "x.pcap", dest, sleep=lambda s: None) is None
    )

    def empty(remote: str, local: Path) -> bool:
        local.write_bytes(b"")
        return True

    assert dc.pull_capture(adb, empty, "x.pcap", dest, sleep=lambda s: None) == 0
    assert len([c for c in adb.calls if c[:3] == ["shell", "rm", "-f"]]) == 2


def test_only_real_pngs_become_screenshots(tmp_path: Path) -> None:
    answers = iter([PNG, b"error: closed", None, PNG])
    taker = dc.ScreenshotTaker(lambda: next(answers), tmp_path, 15)
    assert [taker.snap() is not None for _ in range(4)] == [True, False, False, True]
    assert [p.name for p in taker.paths] == ["screenshot-01.png", "screenshot-02.png"]
    assert taker.failures == 2
    assert all(p.read_bytes() == PNG for p in taker.paths)
    assert not dc.valid_png(dc.PNG_MAGIC + b"x" * (dc.MAX_SCREENSHOT_BYTES + 1))


def test_the_thread_takes_one_early_then_every_interval_up_to_the_limit(tmp_path: Path) -> None:
    waits: list[float] = []

    def fake_wait(event: threading.Event, seconds: float) -> bool:
        waits.append(seconds)
        return False  # the time always elapses

    taker = dc.ScreenshotTaker(lambda: PNG, tmp_path / "s", 15, limit=3, wait=fake_wait)
    taker.start()
    assert len(taker.stop()) == 3
    assert waits == [5.0, 15, 15]
    assert (tmp_path / "s" / "screenshot-03.png").exists()


def test_a_stop_ends_the_loop_without_a_late_shot(tmp_path: Path) -> None:
    taker = dc.ScreenshotTaker(lambda: PNG, tmp_path / "s", 15, wait=lambda e, s: True)
    taker.start()
    assert taker.stop() == []


def test_an_interval_of_zero_takes_nothing_and_creates_nothing(tmp_path: Path) -> None:
    taker = dc.ScreenshotTaker(lambda: PNG, tmp_path / "s", 0)
    taker.start()
    assert taker.stop() == [] and not (tmp_path / "s").exists()


def test_the_size_is_read_once_two_readings_agree() -> None:
    clock = _Clock()
    adb = FakeAdb()
    adb.sizes = [300, 842, 842]  # still being written, then settled
    assert dc.wait_for_file(adb, "/x", sleep=clock.sleep, now=clock.now) == 842
    assert clock.t == 2.0


def test_an_empty_file_is_settled_at_once_and_not_waited_for() -> None:
    """An app that sent nothing leaves a 0-byte file: that must not cost the whole timeout."""
    clock = _Clock()
    adb = FakeAdb()
    adb.sizes = [0]
    assert dc.wait_for_file(adb, "/x", sleep=clock.sleep, now=clock.now) == 0
    assert clock.t == 1.0


def test_a_file_that_never_settles_is_not_waited_for_forever() -> None:
    clock = _Clock()
    adb = FakeAdb()
    adb.sizes = list(range(1, 200))
    assert dc.wait_for_file(adb, "/x", timeout=5, sleep=clock.sleep, now=clock.now) is None
    assert clock.t == 5.0


def _extras(args: list[str]) -> dict[str, str]:
    return {args[i + 1]: args[i + 2] for i, a in enumerate(args) if a == "-e"}


def test_the_api_key_is_sent_with_start_and_stop_and_only_when_given() -> None:
    adb = FakeAdb(vpn=[True, False])
    assert dc.start_capture(adb, "a.b", "x.pcap", "AbC123xyz789")
    assert dc.stop_capture(adb, sleep=lambda s: None, api_key="AbC123xyz789")
    start, stop = adb.calls[0], [c for c in adb.calls if "stop" in c][0]
    assert (
        _extras(start)["api_key"] == "AbC123xyz789" and _extras(stop)["api_key"] == "AbC123xyz789"
    )
    plain = FakeAdb(vpn=[False])
    dc.start_capture(plain, "a.b", "x.pcap")
    dc.stop_capture(plain, sleep=lambda s: None)
    assert all("api_key" not in " ".join(c) for c in plain.calls)


@pytest.mark.parametrize("key", ["a;reboot", "a b", "$(id)", "short", "x" * 65, "", "k\nk"])
def test_a_key_that_is_not_plain_alphanumeric_never_reaches_the_device_shell(key: str) -> None:
    adb = FakeAdb()
    with pytest.raises(ValueError):
        dc.start_capture(adb, "a.b", "x.pcap", key)
    with pytest.raises(ValueError):
        dc.stop_capture(adb, sleep=lambda s: None, api_key=key)
    assert adb.calls == []
    assert not dc.valid_api_key(key)
