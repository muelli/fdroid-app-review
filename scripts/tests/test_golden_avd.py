"""build_golden_avd.sh and `avd_fallback.sh --golden`, run against stand-ins for the SDK tools."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

LOCAL_IMAGE = Path(__file__).resolve().parents[2] / "local-image"
BUILD = LOCAL_IMAGE / "build_golden_avd.sh"
REVIEW = LOCAL_IMAGE / "avd_fallback.sh"
GOLDEN = "fdroid-review-golden"
AOSP = "system-images;android-34;default;x86_64"


def _run(
    script: Path, tmp_path: Path, *args: str, avds: tuple[str, ...] = (), key: bool = False
) -> tuple[int, str, list[str]]:
    """(exit status, stderr, what the stand-in SDK tools were asked). The stand-in emulator exits
    at once, so nothing ever waits for a device.
    """
    bin_dir, avd_home = tmp_path / "bin", tmp_path / "avd"
    bin_dir.mkdir(exist_ok=True)
    avd_home.mkdir(exist_ok=True)
    log = tmp_path / "calls.log"
    listing = "; ".join(f'echo "Name: {name}"' for name in avds) or "true"
    stubs = {
        "sdkmanager": f'echo "sdkmanager $*" >> {log}',
        "avdmanager": (
            f'if [ "$1 $2" = "list avd" ]; then {listing}; exit 0; fi; '
            f'cat >/dev/null; echo "avdmanager $*" >> {log}'
        ),
        "emulator": f'echo "emulator $*" >> {log}; exit 1',
        "adb": "exit 1",
    }
    for name, body in stubs.items():
        path = bin_dir / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)
    if key:
        (avd_home / f"{GOLDEN}.pcapdroid-key").write_text("abcdefgh12345678\n")
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "ANDROID_AVD_HOME": str(avd_home),
    }
    env.pop("DISPLAY", None)
    result = subprocess.run(
        ["bash", str(script), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    calls = log.read_text().splitlines() if log.exists() else []
    return result.returncode, result.stderr, calls


def _pcapdroid(tmp_path: Path) -> str:
    apk = tmp_path / "pcapdroid.apk"
    apk.write_bytes(b"x")
    return str(apk)


# ---- build_golden_avd.sh ---------------------------------------------------------------------


def test_the_build_needs_a_pcapdroid_apk_that_exists(tmp_path: Path) -> None:
    assert _run(BUILD, tmp_path)[0] == 1
    status, err, calls = _run(BUILD, tmp_path, "--pcapdroid-apk", "nope.apk")
    assert status == 1 and "not a file" in err and calls == []


def test_an_existing_golden_avd_is_not_replaced_unless_asked(tmp_path: Path) -> None:
    status, err, calls = _run(
        BUILD, tmp_path, "--pcapdroid-apk", _pcapdroid(tmp_path), avds=(GOLDEN,)
    )
    assert status == 1 and "already exists" in err and "--rebuild" in err
    assert calls == []  # not deleted, not created


def test_a_rebuild_deletes_the_old_one_then_creates_from_the_aosp_image(tmp_path: Path) -> None:
    _, _, calls = _run(
        BUILD, tmp_path, "--pcapdroid-apk", _pcapdroid(tmp_path), "--rebuild", avds=(GOLDEN,)
    )
    delete = next(i for i, c in enumerate(calls) if c.startswith("avdmanager delete avd"))
    create = next(i for i, c in enumerate(calls) if c.startswith("avdmanager create avd"))
    assert delete < create and f"--name {GOLDEN}" in calls[create] and AOSP in calls[create]
    assert f"sdkmanager --install {AOSP}" in calls


def test_the_emulator_is_booted_wiped_and_without_snapshots(tmp_path: Path) -> None:
    _, _, calls = _run(BUILD, tmp_path, "--pcapdroid-apk", _pcapdroid(tmp_path))
    boot = next(c for c in calls if c.startswith("emulator "))
    assert f"-avd {GOLDEN}" in boot and "-wipe-data" in boot and "-no-snapshot" in boot


def test_a_failed_build_leaves_no_key_so_nothing_half_built_looks_usable(tmp_path: Path) -> None:
    key = tmp_path / "avd" / f"{GOLDEN}.pcapdroid-key"
    status, err, _ = _run(BUILD, tmp_path, "--pcapdroid-apk", _pcapdroid(tmp_path))
    assert status != 0 and "was not completed" in err and not key.exists()


def test_a_stale_key_never_survives_a_failed_rebuild(tmp_path: Path) -> None:
    key = tmp_path / "avd" / f"{GOLDEN}.pcapdroid-key"
    status, _, _ = _run(
        BUILD,
        tmp_path,
        "--pcapdroid-apk",
        _pcapdroid(tmp_path),
        "--rebuild",
        avds=(GOLDEN,),
        key=True,
    )
    assert status != 0 and not key.exists()  # the old key described an AVD that was just replaced


# ---- avd_fallback.sh --golden ----------------------------------------------------------------


def _review_args(tmp_path: Path) -> list[str]:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"x")
    return ["--apk", str(apk), "--review", "--output-dir", str(tmp_path / "out")]


def test_golden_needs_review(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"x")
    status, err, _ = _run(REVIEW, tmp_path, "--apk", str(apk), "--golden")
    assert status == 1 and "are for --review" in err


def test_golden_is_not_combined_with_another_capture(tmp_path: Path) -> None:
    for extra in (["--pcapdroid-apk", _pcapdroid(tmp_path)], ["--capture-pcap", "x.pcap"]):
        status, err, _ = _run(
            REVIEW, tmp_path, *_review_args(tmp_path), "--golden", *extra, key=True
        )
        assert status == 1 and "already has PCAPdroid" in err


def test_golden_without_its_key_says_how_to_build_it(tmp_path: Path) -> None:
    status, err, calls = _run(REVIEW, tmp_path, *_review_args(tmp_path), "--golden", avds=(GOLDEN,))
    assert status == 1 and "build_golden_avd.sh" in err and calls == []


def test_golden_without_its_avd_is_not_created_blank_under_that_name(tmp_path: Path) -> None:
    status, err, calls = _run(REVIEW, tmp_path, *_review_args(tmp_path), "--golden", key=True)
    assert status == 1 and "golden AVD" in err and "does not exist" in err
    assert not any(c.startswith(("avdmanager create", "sdkmanager")) for c in calls)


def test_golden_boots_that_avd_read_only_and_creates_nothing(tmp_path: Path) -> None:
    _, _, calls = _run(
        REVIEW, tmp_path, *_review_args(tmp_path), "--golden", avds=(GOLDEN,), key=True
    )
    boot = next(c for c in calls if c.startswith("emulator "))
    assert f"-avd {GOLDEN}" in boot and "-read-only" in boot and "-wipe-data" not in boot
    assert not any(c.startswith(("avdmanager create", "sdkmanager")) for c in calls)


# ---- shutting the build emulator down ------------------------------------------------------


def _stop_emulator(tmp_path: Path, *, poweroff_works: bool) -> list[str]:
    """Run the script's own _stop_emulator against a fake emulator (a background child of the same
    bash, as the real one is, so that bash reaps it) and a fake adb.
    """
    import re

    function = re.search(r"^_stop_emulator\(\) \{\n.*?^\}\n", BUILD.read_text(), re.S | re.M)
    assert function is not None
    log = tmp_path / "adb.log"
    on_poweroff = 'kill "$EMULATOR_PID"' if poweroff_works else ":"
    adb = tmp_path / "adb"
    adb.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> {log}\n'
        'case "$*" in\n'
        f'  "-e shell reboot -p") {on_poweroff} ;;\n'
        '  "-e emu kill") kill "$EMULATOR_PID" ;;\n'
        "esac\n"
    )
    adb.chmod(0o755)
    script = (
        f"export PATH={tmp_path}:$PATH\n"
        "command sleep 300 & export EMULATOR_PID=$!\n"
        "sleep() { command sleep 0.05; }\n"
        f"{function.group(0)}\n_stop_emulator\n"
    )
    subprocess.run(["bash", "-c", script], check=False, timeout=60)
    return log.read_text().splitlines() if log.exists() else []


def test_the_build_emulator_is_powered_off_gracefully_not_killed(tmp_path: Path) -> None:
    calls = _stop_emulator(tmp_path, poweroff_works=True)
    assert calls == ["-e shell sync", "-e shell reboot -p"]  # nothing abrupt was needed


def test_the_abrupt_kill_is_only_the_fallback_when_the_poweroff_does_nothing(
    tmp_path: Path,
) -> None:
    calls = _stop_emulator(tmp_path, poweroff_works=False)
    assert calls[:2] == ["-e shell sync", "-e shell reboot -p"] and calls[-1] == "-e emu kill"


def test_a_golden_review_grants_the_vpn_approval_as_root_before_anything_else(
    tmp_path: Path,
) -> None:
    """The approval did not persist in the image, so avd_fallback.sh grants it at boot."""
    (tmp_path / "bin").mkdir()
    (tmp_path / "avd").mkdir()
    (tmp_path / "avd" / f"{GOLDEN}.pcapdroid-key").write_text("abcdefgh12345678\n")
    log = tmp_path / "calls.log"
    stubs = {
        "sdkmanager": "exit 0",
        "avdmanager": f'[ "$1 $2" = "list avd" ] && echo "Name: {GOLDEN}"; exit 0',
        "emulator": "exec sleep 120",
        "adb": (
            f'echo "$*" >> {log}\n'
            'case "$*" in\n'
            "  *get-state*) echo device ;;\n"
            '  *"sys.boot_completed"*) echo 1 ;;\n'
            "  *get-serialno*) echo emulator-5554 ;;\n"
            "esac\nexit 0"
        ),
    }
    for name, body in stubs.items():
        path = tmp_path / "bin" / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"x")
    env = {
        **os.environ,
        "PATH": f"{tmp_path / 'bin'}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "ANDROID_AVD_HOME": str(tmp_path / "avd"),
    }
    env.pop("DISPLAY", None)
    subprocess.run(
        ["bash", str(REVIEW), "--apk", str(apk), "--review", "--golden",
         "--output-dir", str(tmp_path / "out")],
        capture_output=True, text=True, env=env, timeout=90, check=False,
    )  # fmt: skip
    calls = log.read_text().splitlines()
    grant = "shell cmd appops set com.emanuelef.remote_capture ACTIVATE_VPN allow"
    assert grant in calls
    assert calls.index("root") < calls.index("wait-for-device") < calls.index(grant)
