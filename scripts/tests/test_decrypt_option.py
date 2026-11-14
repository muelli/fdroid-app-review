"""`avd_fallback.sh --golden --decrypt`, run against stand-ins for the SDK, apktool and mitmdump."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REVIEW = Path(__file__).resolve().parents[2] / "local-image" / "avd_fallback.sh"
GOLDEN = "fdroid-review-golden"

# A stand-in `java -jar apktool.jar`: `d` writes a decoded tree, `b` writes the rebuilt APK.
FAKE_JAVA = r"""#!/bin/sh
shift 2   # -jar JAR
mode=$1; shift
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift 2;; *) last=$1; shift;; esac; done
if [ "$mode" = d ]; then
    mkdir -p "$out/res/xml"
    echo '<manifest><application android:label="x"/></manifest>' > "$out/AndroidManifest.xml"
else
    echo rebuilt > "$out"
fi
"""
FAKE_COPY_LAST = r"""#!/bin/sh
for a; do prev=$last; last=$a; done
case "$1" in verify) exit 0;; esac
out=""
while [ $# -gt 0 ]; do case "$1" in --out) out=$2; shift 2;; *) shift;; esac; done
[ -n "$out" ] && cp "$last" "$out" || cp "$prev" "$last"
"""
FAKE_KEYTOOL = r"""#!/bin/sh
while [ $# -gt 0 ]; do case "$1" in -keystore) echo k > "$2"; shift 2;; *) shift;; esac; done
"""
# Writes the CA the way mitmdump does, then stays alive until it is killed.
FAKE_MITMDUMP = r"""#!/bin/sh
while [ $# -gt 0 ]; do case "$1" in confdir=*) dir=${1#confdir=}; shift;; *) shift;; esac; done
mkdir -p "$dir"
echo "PRIVATE KEY" > "$dir/mitmproxy-ca.pem"
echo CERT > "$dir/mitmproxy-ca-cert.pem"
exec sleep 120
"""


def _setup(tmp_path: Path, *, with_tools: bool = True) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (tmp_path / "avd").mkdir(exist_ok=True)
    (tmp_path / "tmp").mkdir(exist_ok=True)
    (tmp_path / "avd" / f"{GOLDEN}.pcapdroid-key").write_text("abcdefgh12345678\n")
    log = tmp_path / "adb.log"
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
            "  *'pm list packages'*) echo package:com.emanuelef.remote_capture ;;\n"
            "esac\nexit 0"
        ),
    }
    if with_tools:
        stubs |= {
            "java": FAKE_JAVA.split("\n", 1)[1],
            "zipalign": FAKE_COPY_LAST.split("\n", 1)[1],
            "apksigner": FAKE_COPY_LAST.split("\n", 1)[1],
            "keytool": FAKE_KEYTOOL.split("\n", 1)[1],
            "mitmdump": FAKE_MITMDUMP.split("\n", 1)[1],
            "openssl": "echo abcd1234",
        }
    for name, body in stubs.items():
        path = bin_dir / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)
    jar = tmp_path / "apktool.jar"
    jar.write_bytes(b"x")
    return {
        **os.environ,
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "ANDROID_AVD_HOME": str(tmp_path / "avd"),
        "TMPDIR": str(tmp_path / "tmp"),
        "APKTOOL_JAR": str(jar),
        "ANDROID_SDK_ROOT": str(tmp_path / "no-sdk"),
    }


def _run(tmp_path: Path, env: dict[str, str], *extra: str) -> subprocess.CompletedProcess[str]:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"x")
    env.pop("DISPLAY", None)
    return subprocess.run(
        ["bash", str(REVIEW), "--apk", str(apk), "--review", "--output-dir", str(tmp_path / "out"),
         *extra],
        capture_output=True, text=True, env=env, timeout=120, check=False,
    )  # fmt: skip


def _adb_calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "adb.log"
    return log.read_text().splitlines() if log.exists() else []


def test_decrypt_needs_the_golden_avd(tmp_path: Path) -> None:
    result = _run(tmp_path, _setup(tmp_path), "--decrypt")
    assert result.returncode == 1 and "--golden" in result.stderr
    assert _adb_calls(tmp_path) == []


def test_decrypt_without_apktool_says_so_and_boots_nothing(tmp_path: Path) -> None:
    env = _setup(tmp_path)
    del env["APKTOOL_JAR"]
    result = _run(tmp_path, env, "--golden", "--decrypt")
    assert result.returncode == 1 and "APKTOOL_JAR" in result.stderr
    assert _adb_calls(tmp_path) == []


def test_decrypt_without_the_proxy_says_so_and_boots_nothing(tmp_path: Path) -> None:
    env = _setup(tmp_path)
    (tmp_path / "bin" / "mitmdump").unlink()
    result = _run(tmp_path, env, "--golden", "--decrypt")
    assert result.returncode == 1 and "mitmdump" in result.stderr
    assert _adb_calls(tmp_path) == []


def test_an_apk_that_cannot_be_patched_stops_before_the_emulator(tmp_path: Path) -> None:
    env = _setup(tmp_path)
    (tmp_path / "bin" / "java").write_text("#!/bin/sh\necho boom >&2; exit 1\n")
    result = _run(tmp_path, env, "--golden", "--decrypt")
    assert result.returncode == 1 and "could not be patched" in result.stderr
    assert _adb_calls(tmp_path) == []


def test_the_ca_goes_in_as_a_user_ca_and_the_proxy_is_set_before_the_review(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path, _setup(tmp_path), "--golden", "--decrypt", "--package", "org.example.app"
    )
    calls = _adb_calls(tmp_path)
    ca = "/data/misc/user/0/cacerts-added/abcd1234.0"
    push = next(i for i, c in enumerate(calls) if c.startswith("push") and c.endswith(ca))
    proxy = calls.index("shell settings put global http_proxy 10.0.2.2:8081")
    assert calls.index("root") < push < proxy, result.stderr
    assert any("chown system:system" in c and ca in c for c in calls)
    assert "shell settings put global captive_portal_mode 0" in calls
    install = [c for c in calls if " install " in f" {c} "]
    assert install and all("trust-user-ca.apk" in c for c in install)
    assert calls.index(install[0]) > proxy


def test_the_proxys_ca_key_is_deleted_when_the_run_ends(tmp_path: Path) -> None:
    _run(tmp_path, _setup(tmp_path), "--golden", "--decrypt")
    assert list((tmp_path / "tmp").iterdir()) == []  # the CA's private key is not left behind


def test_the_patch_report_is_kept_next_to_the_other_evidence(tmp_path: Path) -> None:
    _run(tmp_path, _setup(tmp_path), "--golden", "--decrypt")
    assert (tmp_path / "out" / "trust-user-ca.apk").is_file()
    assert (tmp_path / "out" / "trust-user-ca.json").is_file()


def test_without_decrypt_nothing_about_proxies_happens(tmp_path: Path) -> None:
    _run(tmp_path, _setup(tmp_path), "--golden")
    calls = _adb_calls(tmp_path)
    assert not any("http_proxy" in c or "cacerts-added" in c for c in calls)
