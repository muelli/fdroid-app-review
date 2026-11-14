"""Which system image and AVD avd_fallback.sh creates, run against stand-ins for the SDK tools."""

from __future__ import annotations

import os
import subprocess
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "local-image" / "avd_fallback.sh"
AOSP = "system-images;android-34;default;x86_64"


def _run(
    tmp_path: Path, *args: str, existing_avd: str = "", apk: str = "unused.apk"
) -> tuple[int, list[str]]:
    """(exit status, what the stand-in sdkmanager/avdmanager were asked), up to the emulator
    boot, which fails at once so that nothing waits for a device.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    stubs = {
        "sdkmanager": f'echo "sdkmanager $*" >> {log}',
        "avdmanager": (
            'if [ "$1 $2" = "list avd" ]; then '
            f'[ -n "{existing_avd}" ] && echo "Name: {existing_avd}"; exit 0; fi; '
            f'cat >/dev/null; echo "avdmanager $*" >> {log}'
        ),
        "emulator": "exit 1",
        "adb": "exit 1",
    }
    for name, body in stubs.items():
        path = bin_dir / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path)}
    result = subprocess.run(
        ["bash", str(SCRIPT), "--apk", apk, *args],
        capture_output=True,
        text=True,
        env={**os.environ, **env},
        timeout=60,
        check=False,
    )
    calls = log.read_text().splitlines() if log.exists() else []
    return result.returncode, calls


def test_the_default_is_the_aosp_image_with_a_name_derived_from_it(tmp_path: Path) -> None:
    _, calls = _run(tmp_path)
    assert f"sdkmanager --install {AOSP}" in calls
    created = next(c for c in calls if c.startswith("avdmanager create avd"))
    assert "--name fdroid-review-default-34" in created and f"--package {AOSP}" in created


def test_another_image_gets_its_own_avd_so_two_images_never_share_one(tmp_path: Path) -> None:
    _, calls = _run(tmp_path, "--system-image", "system-images;android-34;google_apis;x86_64")
    created = next(c for c in calls if c.startswith("avdmanager create avd"))
    assert "--name fdroid-review-google_apis-34" in created
    assert "--package system-images;android-34;google_apis;x86_64" in created


def test_an_explicit_avd_name_wins(tmp_path: Path) -> None:
    _, calls = _run(tmp_path, "--avd-name", "mine")
    assert "--name mine" in next(c for c in calls if c.startswith("avdmanager create avd"))


def test_an_avd_that_already_exists_is_reused_not_recreated(tmp_path: Path) -> None:
    _, calls = _run(tmp_path, existing_avd="fdroid-review-default-34")
    assert calls == []  # no download and no create


def test_the_old_google_avd_is_not_picked_up_by_the_new_default(tmp_path: Path) -> None:
    """An AVD left from before the switch must not silently stand in for the AOSP one."""
    _, calls = _run(tmp_path, existing_avd="fdroid-review-session")
    assert any(c.startswith("avdmanager create avd") for c in calls)


def _apk(tmp_path: Path, *libs: str) -> str:
    path = tmp_path / "app.apk"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("classes.dex", b"dex")
        for lib in libs:
            z.writestr(lib, b"\x7fELF")
    return str(path)


def test_an_arm_only_apk_is_refused_up_front_on_the_aosp_image(tmp_path: Path) -> None:
    """Seen on the real AOSP image: INSTALL_FAILED_NO_MATCHING_ABIS for an arm64-only app."""
    status, calls = _run(tmp_path, apk=_apk(tmp_path, "lib/arm64-v8a/libhermes.so"))
    assert status == 3 and calls == []  # skipped, not failed; nothing downloaded or booted


def test_an_apk_with_x86_code_or_no_native_code_is_not_refused(tmp_path: Path) -> None:
    for libs in (("lib/x86_64/libx.so", "lib/arm64-v8a/libx.so"), ()):
        sub = tmp_path / str(len(libs))
        sub.mkdir()
        _, calls = _run(sub, apk=_apk(sub, *libs))
        assert any(c.startswith("avdmanager create avd") for c in calls)


def test_an_explicit_other_image_is_not_second_guessed(tmp_path: Path) -> None:
    _, calls = _run(
        tmp_path,
        "--system-image",
        "system-images;android-34;google_apis;x86_64",
        apk=_apk(tmp_path, "lib/arm64-v8a/libhermes.so"),
    )
    assert any("google_apis" in c for c in calls)  # the caller chose it knowingly


def test_the_apk_is_read_without_unzip_too(tmp_path: Path) -> None:
    """The EC2 host had no unzip, so the check was silently skipped."""
    import re
    import shutil

    text = SCRIPT.read_text()
    function = re.search(r"^_apk_entries\(\) \{\n.*?^\}\n", text, re.S | re.M)
    assert function is not None
    only_python = tmp_path / "bin"
    only_python.mkdir()
    python3 = shutil.which("python3")
    assert python3 is not None
    (only_python / "python3").symlink_to(python3)
    apk = _apk(tmp_path, "lib/arm64-v8a/libx.so")
    result = subprocess.run(
        [
            "/bin/bash",
            "-c",
            f"PATH={only_python}; command -v unzip && exit 9; "
            f'{function.group(0)}\n_apk_entries "$1"',
            "x",
            apk,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "lib/arm64-v8a/libx.so" in result.stdout.splitlines()


def test_a_file_that_is_not_a_zip_does_not_end_the_script_silently(tmp_path: Path) -> None:
    """unzip exits 9 on it; under errexit and pipefail that once ended the script silently."""
    bad = tmp_path / "broken.apk"
    bad.write_bytes(b"this is not a zip file")
    status, calls = _run(tmp_path, apk=str(bad))
    assert status != 9
    assert any(c.startswith("avdmanager create avd") for c in calls)  # it went on; install will say
