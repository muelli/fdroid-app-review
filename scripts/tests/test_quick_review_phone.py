"""Screenshots and PCAPdroid through `quick_review.main`, against a stub phone."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import device_capture as dc  # noqa: E402
import test_quick_review_crash as crash_helpers  # noqa: E402

qr = crash_helpers.qr
helpers = crash_helpers.helpers
PNG = dc.PNG_MAGIC + b"fake-screen"
CLOCK_SKEW = 1000  # the stub phone's clock is this many seconds behind the host's


def _phone(
    tmp_path: Path, *, installed: bool = True, other_vpn: bool = False, tapped: bool = True
) -> list[str]:
    """A stub `adb` with state in tmp_path/phone: PCAPdroid installed or not, another VPN up
    or not, and whether anybody taps ALLOW (without which the start intent does nothing).
    """  # fmt: skip
    state = tmp_path / "phone"
    state.mkdir()
    for flag, on in (("installed", installed), ("other-vpn", other_vpn), ("consent", tapped)):
        if on:
            (state / flag).touch()
    (state / "shot.png").write_bytes(PNG)
    argv = crash_helpers._stub_toolchain(tmp_path, "")
    adb = Path(argv[argv.index("--adb-command") + 1])
    adb.write_text(
        "#!/bin/sh\n"
        f"S={state}\n"
        'echo "$*" >> $S/calls.txt\n'
        "for last; do :; done\n"
        'case "$*" in\n'
        "  *install*) echo Success ;;\n"
        "  *getprop*abilist*) echo x86_64 ;;\n"
        '  *"pm list packages"*) [ -f $S/installed ] &&\n'
        "      echo package:com.emanuelef.remote_capture ;;\n"
        '  *"ip -br link"*) echo "lo UNKNOWN"; [ -f $S/tun ] && echo "tun0 UNKNOWN";\n'
        '      [ -f $S/other-vpn ] && echo "tun1 UNKNOWN" ;;\n'
        '  *"action start"*) [ -f $S/consent ] && touch $S/tun ;;\n'
        '  *"action stop"*) rm -f $S/tun ;;\n'
        '  *"pull "*PCAPdroid*) cp $S/phone.pcap "$last" ;;\n'
        '  *"stat -c"*) wc -c < $S/phone.pcap ;;\n'
        "  *exec-out*screencap*) cat $S/shot.png ;;\n"
        f'  *date*) echo "$(( $(date +%s) - {CLOCK_SKEW} ))_10-28_12:00:00" ;;\n'
        "esac\n"
        "exit 0\n"
    )
    return argv


def _calls(tmp_path: Path) -> str:
    return (tmp_path / "phone" / "calls.txt").read_text()


def _device_pcap(tmp_path: Path, names_at: list[tuple[str, float]]) -> None:
    helpers._dns_pcap(tmp_path / "phone" / "phone.pcap", names_at)


@pytest.fixture(autouse=True)
def _fast(monkeypatch: pytest.MonkeyPatch) -> None:
    stop, wait = dc.stop_capture, dc.wait_for_vpn
    clock = [0.0]

    def fake_sleep(seconds: float) -> None:
        clock[0] += seconds

    monkeypatch.setattr(
        dc,
        "stop_capture",
        lambda adb, **kw: stop(adb, sleep=fake_sleep, now=lambda: clock[0], **kw),
    )
    pull = dc.pull_capture
    monkeypatch.setattr(
        dc,
        "pull_capture",
        lambda adb, fn, name, dest: pull(
            adb, fn, name, dest, sleep=fake_sleep, now=lambda: clock[0]
        ),
    )
    monkeypatch.setattr(
        dc, "wait_for_vpn", lambda adb: wait(adb, timeout=1.5, sleep=lambda s: time.sleep(0.1))
    )


def test_screenshots_are_saved_listed_and_offered_for_dragging(tmp_path: Path) -> None:
    argv = _phone(tmp_path)
    code, _, _ = crash_helpers._run([*argv, "--duration", "3", "--screenshot-interval", "1"])
    out = tmp_path / "out"
    assert code == 0
    shots = sorted((out / "screenshots").glob("*.png"))
    assert shots and all(p.read_bytes() == PNG for p in shots)
    report = (out / "report.md").read_text()
    assert "## Screenshots" in report and "personal details" in report
    assert f"`{shots[0]}`" in report
    row = crash_helpers_rows(out)["Screenshots"]
    assert f"{len(shots)} saved in `screenshots/`" in row and "drag" in row


def crash_helpers_rows(out: Path) -> dict[str, str]:
    import test_quick_review_links as links

    return links._rows((out / "review_comment.md").read_text())


def test_screenshots_can_be_turned_off_and_then_nothing_is_said_or_made(tmp_path: Path) -> None:
    code, _, _ = crash_helpers._run([*_phone(tmp_path), "--screenshot-interval", "0"])
    out = tmp_path / "out"
    assert code == 0 and not (out / "screenshots").exists()
    assert "Screenshots" not in (out / "report.md").read_text()
    assert "Screenshots" not in crash_helpers_rows(out)


def test_a_device_that_will_not_screenshot_is_said_not_silently_ignored(tmp_path: Path) -> None:
    argv = _phone(tmp_path)
    (tmp_path / "phone" / "shot.png").write_text("Screenshot disabled by security policy")
    code, _, _ = crash_helpers._run([*argv, "--duration", "3", "--screenshot-interval", "1"])
    out = tmp_path / "out"
    assert code == 0 and not list((out / "screenshots").glob("*.png"))
    assert "None could be taken" in (out / "report.md").read_text()
    assert "none could be taken" in crash_helpers_rows(out)["Screenshots"]


def test_a_negative_interval_is_an_error() -> None:
    with pytest.raises(SystemExit):
        qr.parse_args(["--apk", "a.apk", "--screenshot-interval", "-1"])


def test_pcapdroid_capture_is_filtered_windowed_pulled_and_cleaned_up(tmp_path: Path) -> None:
    argv = _phone(tmp_path)
    now = time.time()
    device_now = now - CLOCK_SKEW
    _device_pcap(
        tmp_path,
        [
            ("long-before.example", device_now - 300),
            ("during.example", device_now + 5),
            ("host-clock.example", now + 5),  # a packet that is only "now" if skew were ignored
            ("long-after.example", device_now + 200),
        ],
    )
    code, out_text, err = crash_helpers._run([*argv, "--capture-pcapdroid"])
    out = tmp_path / "out"
    assert code == 0, err
    assert "tap ALLOW" in out_text and "is recording this app's traffic" in out_text
    assert "Stopping PCAPdroid: tap ALLOW on the phone again" in out_text
    # One stop only: the exit cleanup must not raise a second dialog after a clean finish.
    assert _calls(tmp_path).count("action stop") == 1
    calls = _calls(tmp_path)
    assert "-e app_filter org.example.app" in calls and "auto_block_private_dns true" in calls
    assert "rm -f /sdcard/Download/PCAPdroid/review-org-example-app-" in calls
    assert not (tmp_path / "phone" / "tun").exists()  # stopped: no VPN left on the phone
    log = [json.loads(line) for line in (out / "network_log.jsonl").read_text().splitlines()]
    assert {r.get("query_name") for r in log} == {"during.example"}
    report = (out / "report.md").read_text()
    assert "Only this app's own traffic" in report and "`during.example`" in report
    comment = (out / "review_comment.md").read_text()
    assert "this app's own traffic only, recorded with PCAPdroid" in comment
    assert "`during.example`" in comment
    assert (out / "network_capture.pcap").exists()


def test_pcapdroid_missing_is_an_error_before_anything_is_installed(tmp_path: Path) -> None:
    argv = _phone(tmp_path, installed=False)
    code, _, err = crash_helpers._run([*argv, "--capture-pcapdroid"])
    assert code == 1 and "needs PCAPdroid" in err
    assert "install" not in _calls(tmp_path).replace("pm list packages", "")


def test_another_vpn_is_an_error_before_anything_is_installed(tmp_path: Path) -> None:
    argv = _phone(tmp_path, other_vpn=True)
    code, _, err = crash_helpers._run([*argv, "--capture-pcapdroid"])
    assert code == 1 and "a VPN is already running" in err
    assert "action start" not in _calls(tmp_path)


def test_nobody_tapping_allow_is_a_warning_and_the_review_still_completes(
    tmp_path: Path,
) -> None:
    argv = _phone(tmp_path, tapped=False)
    code, _, err = crash_helpers._run([*argv, "--capture-pcapdroid"])
    out = tmp_path / "out"
    assert code == 0 and "did not start in time" in err
    assert "action stop" in _calls(tmp_path)  # a late tap must not leave the VPN up
    assert "this app's own traffic" not in (out / "review_comment.md").read_text()
    assert not (out / "network_log.jsonl").exists()


def test_a_vpn_that_cannot_be_stopped_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    argv = _phone(tmp_path)
    _device_pcap(tmp_path, [("a.example", time.time() - CLOCK_SKEW + 5)])
    stubborn: Any = lambda adb, **kw: False  # noqa: E731
    monkeypatch.setattr(dc, "stop_capture", stubborn)
    code, _, err = crash_helpers._run([*argv, "--capture-pcapdroid"])
    assert code == 0 and "VPN is still up on the phone" in err


def test_an_interrupt_still_stops_the_vpn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = _phone(tmp_path)

    def interrupted(seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(qr.time, "sleep", interrupted)
    with pytest.raises(KeyboardInterrupt):
        crash_helpers._run([*argv, "--capture-pcapdroid"])
    assert "action stop" in _calls(tmp_path)
    assert not (tmp_path / "phone" / "tun").exists()


def test_pcapdroid_cannot_be_combined_with_another_capture() -> None:
    for other in (["--capture-interface", "eth0"], ["--external-pcap", "x.pcap"]):
        with pytest.raises(SystemExit):
            qr.parse_args(["--apk", "a.apk", "--capture-pcapdroid", *other])


def test_an_empty_capture_means_the_app_sent_nothing_and_is_not_a_failure(tmp_path: Path) -> None:
    """PCAPdroid writes its file lazily: no packets, 0 bytes (seen on the phone)."""
    argv = _phone(tmp_path)
    (tmp_path / "phone" / "phone.pcap").write_bytes(b"")
    code, out_text, err = crash_helpers._run([*argv, "--capture-pcapdroid"])
    out = tmp_path / "out"
    assert code == 0 and "PCAPdroid" not in err  # the stub's other warnings are unrelated
    assert "PCAPdroid recorded no packets from the app" in out_text
    assert not (out / "network_capture.pcap").exists()  # an empty file is not a pcap
    assert (out / "network_log.jsonl").read_text() == ""
    assert "captured, no DNS/TLS-SNI activity observed" in (out / "report.md").read_text()
    row = crash_helpers_rows(out)["Network endpoints observed"]
    assert "none: PCAPdroid recorded no packets from the app" in row


def test_a_pull_that_fails_is_a_warning_and_no_evidence(tmp_path: Path) -> None:
    argv = _phone(tmp_path)  # no phone.pcap on the stub phone: the pull fails
    code, _, err = crash_helpers._run([*argv, "--capture-pcapdroid"])
    out = tmp_path / "out"
    assert code == 0 and "could not pull PCAPdroid's capture" in err
    assert not (out / "network_log.jsonl").exists()


KEY = "dG2d142tp45aOTP1F3VhSRX4cOaYWFXi"


def test_with_an_api_key_the_run_needs_no_allow_taps_and_never_prints_the_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(dc.API_KEY_ENV, KEY)
    argv = _phone(tmp_path)
    _device_pcap(tmp_path, [("during.example", time.time() - CLOCK_SKEW + 5)])
    code, out_text, err = crash_helpers._run([*argv, "--capture-pcapdroid"])
    out = tmp_path / "out"
    assert code == 0, err
    assert f"Starting PCAPdroid with {dc.API_KEY_ENV}: it should not ask for ALLOW" in out_text
    assert "tap ALLOW on the phone again" not in out_text
    calls = _calls(tmp_path)
    assert calls.count(f"-e api_key {KEY}") == 2  # start and stop
    for path in [*out.glob("*.md"), *out.glob("*.html"), *out.glob("*.json*")]:
        assert KEY not in path.read_text(errors="replace"), path.name
    assert KEY not in out_text + err
    assert "`during.example`" in (out / "report.md").read_text()


def test_a_key_in_the_environment_is_ignored_without_the_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(dc.API_KEY_ENV, KEY)
    code, _, _ = crash_helpers._run([*_phone(tmp_path)])
    assert code == 0 and KEY not in _calls(tmp_path)


def test_a_malformed_key_in_the_environment_is_an_error_before_anything_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(dc.API_KEY_ENV, "a;reboot")
    with pytest.raises(SystemExit):
        qr.parse_args(["--apk", "a.apk", "--capture-pcapdroid"])
    assert qr.parse_args(["--apk", "a.apk"]).pcapdroid_api_key is None


def _already_installed(tmp_path: Path, argv: list[str]) -> None:
    """Make the stub phone say the app under review is installed already."""
    adb = Path(argv[argv.index("--adb-command") + 1])
    text = adb.read_text()
    marker = '  *"pm list packages"*)'
    line = '  *"pm list packages org.example.app"*) echo package:org.example.app ;;\n'
    assert marker in text
    adb.write_text(text.replace(marker, line + marker, 1))


def test_an_app_already_on_the_device_is_warned_about_and_keeps_its_data(
    tmp_path: Path,
) -> None:
    argv = _phone(tmp_path)
    _already_installed(tmp_path, argv)
    code, _, err = crash_helpers._run(argv)
    assert code == 0
    assert "already installed on this device" in err and "not a first-run review" in err
    calls = _calls(tmp_path)
    assert "uninstall" not in calls  # warned, nothing deleted
    assert "install -r -g" in calls  # reinstalled over the old copy, data kept
    assert "already installed" in (tmp_path / "out" / "report.md").read_text()


def test_fresh_install_uninstalls_first_and_only_when_asked(tmp_path: Path) -> None:
    argv = _phone(tmp_path)
    _already_installed(tmp_path, argv)
    code, out_text, err = crash_helpers._run([*argv, "--fresh-install"])
    assert code == 0 and "uninstalling it first (--fresh-install)" in out_text
    assert "already installed on this device" not in err
    calls = _calls(tmp_path).splitlines()
    uninstall = next(i for i, c in enumerate(calls) if "uninstall org.example.app" in c)
    install = next(i for i, c in enumerate(calls) if " install " in c)
    assert uninstall < install  # the old copy goes before the new one arrives


def test_an_app_not_on_the_device_gets_no_warning_and_no_uninstall(tmp_path: Path) -> None:
    code, _, err = crash_helpers._run([*_phone(tmp_path), "--fresh-install"])
    assert code == 0 and "already installed" not in err
    assert "uninstall" not in _calls(tmp_path)


def test_a_lookalike_package_is_not_taken_for_the_app(tmp_path: Path) -> None:
    argv = _phone(tmp_path)
    adb = Path(argv[argv.index("--adb-command") + 1])
    text = adb.read_text()
    marker = '  *"pm list packages"*)'
    adb.write_text(
        text.replace(
            marker,
            '  *"pm list packages org.example.app"*) echo package:org.example.app.other ;;\n'
            + marker,
            1,
        )
    )
    code, _, err = crash_helpers._run(argv)
    assert code == 0 and "already installed" not in err


def test_an_abi_mismatch_at_install_says_what_it_means_and_what_to_do(tmp_path: Path) -> None:
    argv = _phone(tmp_path)
    adb = Path(argv[argv.index("--adb-command") + 1])
    adb.write_text(
        adb.read_text().replace(
            "  *install*) echo Success ;;",
            "  *install*) echo 'Failure [INSTALL_FAILED_NO_MATCHING_ABIS: Failed to extract]' ;;",
        )
    )
    code, _, err = crash_helpers._run(argv)
    assert code == 1 and "native code for ARM only cannot run on an x86 emulator" in err
    assert "a finding about the app (no x86 build)" in err and "google" not in err.lower()
