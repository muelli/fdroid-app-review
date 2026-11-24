"""avd_fallback.sh starts the emulator with ANDROID_AVD_HOME set to wherever avdmanager put the AVD.

On a GitHub runner, avdmanager created it under $XDG_CONFIG_HOME/.android/avd and the emulator,
started through sudo and nsntrace, looked under $HOME/.android/avd and stopped with "Unknown AVD
name" (ci-spike/FINDINGS.md). Run against stand-ins for the SDK tools, without --capture-pcap, so
no sudo is involved: what is tested is which directory the emulator is given.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "local-image" / "avd_fallback.sh"
NAME = "fdroid-review-default-34"


def _run(
    tmp_path: Path, list_output: str, env_extra: dict[str, str] | None = None
) -> tuple[str, str]:
    """(the ANDROID_AVD_HOME the emulator saw, the script's output)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    seen = tmp_path / "emulator-env"
    listing = tmp_path / "listing.txt"
    listing.write_text(list_output)
    stubs = {
        "sdkmanager": "exit 0",
        "avdmanager": f'if [ "$1 $2" = "list avd" ]; then cat {listing}; fi; exit 0',
        "emulator": f'echo "${{ANDROID_AVD_HOME-<unset>}}" > {seen}; exit 1',
        "adb": "exit 1",
    }
    for name, body in stubs.items():
        path = bin_dir / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k != "ANDROID_AVD_HOME"}
    env.update({"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path / "home")})
    env.update(env_extra or {})
    result = subprocess.run(
        ["bash", str(SCRIPT), "--apk", "unused.apk"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    return (seen.read_text().strip() if seen.exists() else ""), result.stdout + result.stderr


def _avd_under(directory: Path, name: str = NAME) -> str:
    """An AVD as avdmanager leaves it: NAME.ini next to NAME.avd/, and its `list avd` entry."""
    (directory / f"{name}.avd").mkdir(parents=True)
    (directory / f"{name}.ini").write_text("path=...\n")
    return (
        "Available Android Virtual Devices:\n"
        f"    Name: {name}\n"
        "  Device: pixel_6 (Google)\n"
        f"    Path: {directory / (name + '.avd')}\n"
        "  Target: Default Android System Image\n"
    )


def test_the_emulator_is_pointed_at_the_xdg_directory_avdmanager_used(tmp_path: Path) -> None:
    xdg = tmp_path / "home" / ".config" / ".android" / "avd"
    seen, out = _run(tmp_path, _avd_under(xdg))
    assert seen == str(xdg)
    assert f"Using the AVD directory avdmanager reports: {xdg}" in out


def test_a_wrong_android_avd_home_is_replaced_by_the_real_one(tmp_path: Path) -> None:
    """The first workaround tried in the spike: an ANDROID_AVD_HOME without the AVD in it."""
    xdg = tmp_path / "xdg" / ".android" / "avd"
    seen, _ = _run(
        tmp_path, _avd_under(xdg), {"ANDROID_AVD_HOME": str(tmp_path / "home" / ".android" / "avd")}
    )
    assert seen == str(xdg)


def test_only_the_named_avd_counts_when_there_are_several(tmp_path: Path) -> None:
    other = _avd_under(tmp_path / "elsewhere", "someone-elses")
    ours = _avd_under(tmp_path / "ours")
    seen, _ = _run(tmp_path, other + ours)
    assert seen == str(tmp_path / "ours")


def test_a_path_with_spaces_survives(tmp_path: Path) -> None:
    spaced = tmp_path / "my avds" / "avd"
    seen, _ = _run(tmp_path, _avd_under(spaced))
    assert seen == str(spaced)


def test_without_a_usable_entry_android_avd_home_is_left_alone_with_a_warning(
    tmp_path: Path,
) -> None:
    # A Path whose directory has no .ini (avdmanager's view and the disk disagree): do not guess.
    listing = f"    Name: {NAME}\n    Path: {tmp_path / 'gone' / (NAME + '.avd')}\n"
    seen, out = _run(tmp_path, listing, {"ANDROID_AVD_HOME": "/kept"})
    assert seen == "/kept"
    assert "could not find" in out
