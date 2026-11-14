#!/usr/bin/env bash
# One app on an already-booted emulator: the uiautomator explorer on a fresh install, then monkey
# on another fresh install, so neither benefits from the other's state.
# Usage: run_one.sh APK PACKAGE OUT_DIR [STEPS] [MONKEY_EVENTS]
set -uo pipefail
apk="$1" pkg="$2" out="$3" steps="${4:-40}" events="${5:-400}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$out"
adb shell settings put global private_dns_mode off >/dev/null 2>&1 || true
fresh_install() {
    adb uninstall "$pkg" >/dev/null 2>&1 || true
    adb install -r -g "$apk" 2>&1 | tail -1 | tee -a "$out/install.txt"
}
if ! fresh_install | grep -q Success; then
    echo "install failed" | tee -a "$out/install.txt"
    exit 0
fi
python3 "$here/explore.py" --package "$pkg" --out "$out" --steps "$steps" 2>&1 | tee "$out/explore.txt"
if [[ "$events" -gt 0 ]]; then
    fresh_install >/dev/null
    python3 "$here/explore.py" --package "$pkg" --out "$out" --steps 0 --monkey-events "$events" 2>&1 | tee "$out/monkey.txt"
fi
adb uninstall "$pkg" >/dev/null 2>&1 || true
