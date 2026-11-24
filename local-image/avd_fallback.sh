#!/usr/bin/env bash
# Fallback for hosts without binder/ashmem support (so redroid cannot run):
# creates a stock AVD with the Android emulator, boots it, and installs the
# APK under test. Requires the Android command-line tools (avdmanager,
# sdkmanager, emulator, adb) to already be on PATH; see
# docs/manual-testing.md for how to get those and for what this script
# cannot be verified without real hardware (or at least nested
# virtualisation) to boot the emulator against.
#
# With --review it goes on to run scripts/quick_review.py against the emulator
# and writes the report, the network evidence and (with --mr-iid) the review
# checklist, then shuts the emulator down. That implies --capture-pcap, unless
# --pcapdroid-apk is given: then no nsntrace, and PCAPdroid records just the app's own traffic.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The AOSP image: no Google apps, no Play services, no Play Store, so no background traffic from
# them (a stock google_apis emulator sent 1.3 MB in its first 150 s) and nothing for the app under
# review to lean on: an F-Droid app must not depend on Google services, and one that does breaks
# here, which is the right answer. --system-image picks another image if you need one.
AVD_NAME=""  # derived from the image unless --avd-name is given, so two images never share an AVD
SYSTEM_IMAGE="system-images;android-34;default;x86_64"
APK=""
CAPTURE_PCAP=""
REVIEW=0
MR_IID=""
DURATION=""
OUTPUT_DIR=""
PACKAGE=""
REVIEW_ARGS=()
PCAPDROID_APK=""
GOLDEN=0
DECRYPT=0
MITM_PORT="${MITM_PORT:-8081}"

usage() {
    echo "Usage: $0 --apk <path-or-url> [--avd-name NAME] [--system-image PKG] [--capture-pcap FILE]" >&2
    echo "       $0 --apk <file> --review [--mr-iid N] [--duration S] [--output-dir DIR]" >&2
    echo "                [--package NAME] [--review-arg ARG]..." >&2
    echo "                [--pcapdroid-apk FILE]   (per-app capture with PCAPdroid, no nsntrace)" >&2
    echo "                [--golden]   (boot the prepared AVD from build_golden_avd.sh, read-only)" >&2
    echo "                [--decrypt]  (with --golden: also show what the app sends over TLS, through a proxy;" >&2
    echo "                              needs APKTOOL_JAR, mitmdump (or MITM_BIN) and openssl)" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --apk)
            APK="$2"
            shift 2
            ;;
        --avd-name)
            AVD_NAME="$2"
            shift 2
            ;;
        --system-image)
            SYSTEM_IMAGE="$2"
            shift 2
            ;;
        --capture-pcap)
            CAPTURE_PCAP="$2"
            shift 2
            ;;
        --review)
            REVIEW=1
            shift
            ;;
        --pcapdroid-apk)
            PCAPDROID_APK="$2"
            shift 2
            ;;
        --golden)
            GOLDEN=1
            shift
            ;;
        --decrypt)
            DECRYPT=1
            shift
            ;;
        --mr-iid)
            MR_IID="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --package)
            PACKAGE="$2"
            shift 2
            ;;
        --review-arg)
            REVIEW_ARGS+=("$2")
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

if [[ -z "$APK" ]]; then
    usage
fi

if [[ -z "$AVD_NAME" ]]; then
    # system-images;android-34;default;x86_64 -> fdroid-review-default-34
    IFS=';' read -r _ SYSTEM_IMAGE_API SYSTEM_IMAGE_FLAVOR _ <<<"$SYSTEM_IMAGE"
    AVD_NAME="fdroid-review-${SYSTEM_IMAGE_FLAVOR:-custom}-${SYSTEM_IMAGE_API#android-}"
fi

# The golden AVD is built once by build_golden_avd.sh, with PCAPdroid installed, its API key made
# and its VPN consent given. It is booted read-only: every run starts from that state and nothing
# a reviewed app does is kept. The key is in a private file next to the AVD.
GOLDEN_AVD_NAME="fdroid-review-golden"
GOLDEN_KEY_FILE="${ANDROID_AVD_HOME:-$HOME/.android/avd}/${GOLDEN_AVD_NAME}.pcapdroid-key"
if [[ "$GOLDEN" == 1 ]]; then
    AVD_NAME="$GOLDEN_AVD_NAME"
fi

if [[ "$REVIEW" == 1 ]]; then
    if [[ ! -f "$APK" ]]; then
        echo "error: --review needs --apk to be a file on this machine, not: $APK" >&2
        exit 1
    fi
    if ! command -v python3 >/dev/null 2>&1 ||
        ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
        echo "error: --review needs python3 3.11 or newer (it runs scripts/quick_review.py)" >&2
        exit 1
    fi
    OUTPUT_DIR="${OUTPUT_DIR:-quick-review-$(date +%s)}"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
    if [[ "$GOLDEN" == 1 ]]; then
        if [[ -n "$PCAPDROID_APK" || -n "$CAPTURE_PCAP" ]]; then
            echo "error: --golden already has PCAPdroid; it cannot be combined with --pcapdroid-apk or --capture-pcap" >&2
            exit 1
        fi
        if [[ ! -f "$GOLDEN_KEY_FILE" ]]; then
            echo "error: no golden AVD key at $GOLDEN_KEY_FILE; build it first with:" >&2
            echo "       local-image/build_golden_avd.sh --pcapdroid-apk <PCAPdroid.apk>" >&2
            exit 1
        fi
    elif [[ -n "$PCAPDROID_APK" ]]; then
        if [[ -n "$CAPTURE_PCAP" ]]; then
            echo "error: --pcapdroid-apk and --capture-pcap are two different captures; pick one" >&2
            exit 1
        fi
        if [[ ! -f "$PCAPDROID_APK" ]]; then
            echo "error: --pcapdroid-apk is not a file: $PCAPDROID_APK" >&2
            exit 1
        fi
    else
        # The capture covers the whole emulator session; quick_review cuts it down to
        # the review's own window afterwards.
        CAPTURE_PCAP="${CAPTURE_PCAP:-$OUTPUT_DIR/network_capture.pcap}"
    fi
elif [[ -n "$PCAPDROID_APK" || "$GOLDEN" == 1 ]]; then
    echo "error: --pcapdroid-apk and --golden are for --review" >&2
    exit 1
fi

# --decrypt: a re-signed copy of the APK that trusts the proxy's CA, and the proxy. Checked and patched
# before anything boots, so a missing tool or an APK that cannot be patched costs nothing.
PATCHED_APK=""
MITM_BIN="${MITM_BIN:-mitmdump}"
if [[ "$DECRYPT" == 1 ]]; then
    if [[ "$REVIEW" != 1 || "$GOLDEN" != 1 ]]; then
        echo "error: --decrypt is for --review with --golden (it needs the rooted, read-only golden AVD)" >&2
        exit 1
    fi
    if [[ -z "${APKTOOL_JAR:-}" || ! -f "$APKTOOL_JAR" ]]; then
        echo "error: --decrypt needs APKTOOL_JAR to be apktool's jar (https://apktool.org)" >&2
        exit 1
    fi
    for binary in "$MITM_BIN" openssl java; do
        if ! command -v "$binary" >/dev/null 2>&1; then
            echo "error: --decrypt needs $binary on PATH" >&2
            exit 1
        fi
    done
    PATCHED_APK="$OUTPUT_DIR/trust-user-ca.apk"
    echo "Re-signing a copy of the APK that trusts a proxy CA (a different binary from the original)..."
    if ! python3 "$REPO_ROOT/scripts/apk_trust_user_ca.py" --apk "$APK" --out "$PATCHED_APK" \
        --apktool "$APKTOOL_JAR" >"$OUTPUT_DIR/trust-user-ca.json"; then
        echo "error: the APK could not be patched (see above); run without --decrypt" >&2
        exit 1
    fi
fi

# The file names inside an APK: unzip if there is one, else python3's zipfile, else nothing.
_apk_entries() {
    if command -v unzip >/dev/null 2>&1; then
        unzip -Z1 "$1" 2>/dev/null
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c 'import sys, zipfile; print("\n".join(zipfile.ZipFile(sys.argv[1]).namelist()))' "$1" 2>/dev/null
    fi
}

# An ARM-only APK cannot be installed on the AOSP x86_64 image: it has no ARM translation
# (checked on a real boot: INSTALL_FAILED_NO_MATCHING_ABIS), and an app without an x86 build is
# a finding, not a candidate. Say so now, not after a download and a boot, with a status of its
# own (3) so that a caller can tell "skipped" from "failed".
if [[ -f "$APK" && "$SYSTEM_IMAGE" == *";default;x86"* ]]; then
    # `|| true`: unzip exits 9 on a file that is not a zip, and under errexit and pipefail that
    # ended the whole script without a word. A bad APK is for the install to report.
    APK_ABIS="$(_apk_entries "$APK" 2>/dev/null | sed -n 's#^lib/\([^/]*\)/.*#\1#p' | sort -u | tr '\n' ' ' || true)"
    if [[ -n "${APK_ABIS// /}" && "$APK_ABIS" != *x86* ]]; then
        echo "skipped: this APK ships native code only for: ${APK_ABIS}" >&2
        echo "        and no x86 build exists, so it cannot run on the x86 emulator (Android refuses" >&2
        echo "        the install: INSTALL_FAILED_NO_MATCHING_ABIS). An app that runs on ARM only is a" >&2
        echo "        finding, not a candidate for this review path." >&2
        exit 3
    fi
fi

for binary in avdmanager sdkmanager emulator adb; do
    if ! command -v "$binary" >/dev/null 2>&1; then
        echo "error: $binary not found on PATH; install the Android command-line tools first" >&2
        exit 1
    fi
done

# Absolute paths: once the emulator is launched via `sudo nsntrace ... -u`
# below, it runs with sudo's own secure_path, not this shell's PATH, so a
# PATH-only lookup of a custom SDK install would silently fail to resolve.
EMULATOR_BIN="$(command -v emulator)"
ADB_BIN="$(command -v adb)"

if [[ -n "$CAPTURE_PCAP" ]]; then
    for binary in nsntrace sudo nsenter; do
        if ! command -v "$binary" >/dev/null 2>&1; then
            echo "error: $binary not found on PATH; required for --capture-pcap" >&2
            exit 1
        fi
    done
    if ! sudo -n true 2>/dev/null; then
        echo "error: --capture-pcap needs passwordless sudo (nsntrace itself must run as root; see DECISIONS.md)" >&2
        exit 1
    fi
    # Confirmed on a fresh Ubuntu 26.04 EC2 instance, where it is off by default:
    # nsntrace prints "Please enable IP forwarding" and never starts its program,
    # which the retry loop below would otherwise report as an interface race.
    # Not enabled for the caller: it makes this host route packets between
    # interfaces for as long as it is on, which is the caller's call.
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]]; then
        echo "error: --capture-pcap needs IP forwarding, and nsntrace refuses to start without it." >&2
        echo "       enable it with: sudo sysctl -w net.ipv4.ip_forward=1" >&2
        echo "       (it makes this host a router while on; undo with ...ip_forward=0 afterwards)" >&2
        exit 1
    fi
fi

# Finds the first descendant of $1 (searched depth-first) whose command name
# matches $2. Used to locate the emulator's actual process once nsntrace has
# forked it into the new network namespace; nsntrace's own pid is not it.
_find_descendant_pid() {
    local root_pid="$1" pattern="$2" pid comm
    for pid in $(pgrep -P "$root_pid" 2>/dev/null); do
        comm="$(ps -p "$pid" -o comm= 2>/dev/null || true)"
        if [[ "$comm" =~ $pattern ]]; then
            printf '%s\n' "$pid"
            return 0
        fi
        if _find_descendant_pid "$pid" "$pattern"; then
            return 0
        fi
    done
    return 1
}

# Launches the emulator under nsntrace and waits for its process to appear
# in the new namespace, retrying the whole launch on failure. Confirmed the
# hard way (not just in short-lived test programs, contrary to nsntrace's own
# flakiness being assumed program-length-dependent): nsntrace can lose the
# race between creating its capture interface and opening it ("Couldn't open
# iface: ... That device is not up"), and when it does, the traced program
# never starts at all rather than merely losing its output. Sets the globals
# NSNTRACE_PID and EMULATOR_NS_PID on success.
_start_emulator_under_nsntrace() {
    local max_attempts=5 attempt waited
    for attempt in $(seq 1 "$max_attempts"); do
        sudo rm -f "$CAPTURE_PCAP"
        # The wrapper holds the emulator back until loopback is up inside the
        # namespace: nsntrace leaves it down, the emulator binds its ports on
        # 127.0.0.1, and on a warm second boot it got there first and aborted
        # with "too many emulator instances are running" (confirmed on a real
        # instance). `ip`, not /sys/class/net: sysfs still shows the host's
        # interfaces from inside the new namespace. The caller raises loopback
        # from outside as soon as this process appears; exec keeps its pid.
        sudo --preserve-env=ANDROID_SDK_ROOT,ANDROID_HOME,ANDROID_AVD_HOME \
            nsntrace -o "$CAPTURE_PCAP" -u "$(id -un)" -- \
            bash -c 'for _ in $(seq 1 100); do
                         [[ "$(ip -o link show lo)" == *LOOPBACK,UP* ]] && break
                         sleep 0.1
                     done
                     exec "$@"' fdroid-wait-for-lo \
            "$EMULATOR_BIN" -avd "$AVD_NAME" -no-snapshot -no-boot-anim \
            -dns-server 9.9.9.9 "${EMULATOR_EXTRA_ARGS[@]}" &
        NSNTRACE_PID=$!

        EMULATOR_NS_PID=""
        waited=0
        while (( waited < 30 )); do
            EMULATOR_NS_PID="$(_find_descendant_pid "$NSNTRACE_PID" '^(bash|qemu-system|emulator)' || true)"
            [[ -n "$EMULATOR_NS_PID" ]] && return 0
            sudo kill -0 "$NSNTRACE_PID" 2>/dev/null || break
            sleep 1
            waited=$((waited + 1))
        done

        echo "warning: nsntrace attempt ${attempt}/${max_attempts} did not start the emulator" \
            "(usually its interface race; any other reason is in nsntrace's own message above); retrying" >&2
        sudo kill -9 "$NSNTRACE_PID" 2>/dev/null || true
        wait "$NSNTRACE_PID" 2>/dev/null || true
    done
    return 1
}

# The host's own adb server cannot see into the namespace nsntrace creates
# (confirmed: different netns, `adb devices` empty on the host), so every
# adb call in capture mode is run from inside it via nsenter instead, and
# dropped back to the invoking user (nsenter itself must run as root to join
# another process's namespace) rather than left running as root.
#
# Confirmed the hard way: the inner sudo's own `--preserve-env=HOME` would
# NOT give the right answer here. By the time it runs, the outer sudo has
# already reset HOME to /root; "preserving" it at that point just carries
# /root through, not ubuntu's real home. Leaving HOME out of the inner
# preserve-env list lets that sudo's own `-u` resolve it correctly instead
# (same getpwnam-based lookup confirmed in nsntrace's own `-u` handling,
# see DECISIONS.md). ANDROID_SDK_ROOT/ANDROID_HOME/ANDROID_AVD_HOME have no
# such fallback and so need preserving at *both* layers, the outer sudo
# before it would otherwise reset them and the inner one after.
adb_cmd() {
    if [[ -n "$CAPTURE_PCAP" ]]; then
        sudo --preserve-env=ANDROID_SDK_ROOT,ANDROID_HOME,ANDROID_AVD_HOME \
            nsenter --target "$EMULATOR_NS_PID" --net -- \
            sudo -u "$(id -un)" --preserve-env=ANDROID_SDK_ROOT,ANDROID_HOME,ANDROID_AVD_HOME \
            "$ADB_BIN" "$@"
    else
        adb "$@"
    fi
}

# The pids of everything in the emulator's network namespace, found by the
# namespace's identity (not its name, which nsntrace removes on exit): the
# emulator's helper daemons and an adb server started inside a namespace that
# was already dying all outlive nsntrace's own cleanup (all confirmed on a real
# instance), pinning the namespace and the AVD's lock. Never the host's own.
# shellcheck disable=SC2016  # a script for the root shell to expand, not this one
_NETNS_PIDS_SCRIPT='
    [[ "$(readlink /proc/1/ns/net)" == "$1" ]] && exit 0
    for p in /proc/[0-9]*; do
        [[ "$(readlink "$p/ns/net" 2>/dev/null)" == "$1" ]] && echo "${p#/proc/}"
    done
    exit 0'
_netns_pids() {
    [[ "${NETNS_ID:-}" == net:\[* ]] || return 0
    sudo bash -c "$_NETNS_PIDS_SCRIPT" _ "$NETNS_ID"
}

# Runs on any exit, including the signal traps below. Safe to run at any point
# of startup: each step only acts on what has been set so far.
_cleanup_capture() {
    local pids
    if [[ -n "${EMULATOR_NS_PID:-}" ]]; then
        adb_cmd kill-server 2>/dev/null || true
    fi
    # Stop everything in the namespace first, so nsntrace sees its program end
    # and finalises the pcap itself; then hard-kill whatever ignored that.
    pids="$(_netns_pids)"
    if [[ -n "$pids" ]]; then
        # shellcheck disable=SC2086
        sudo kill -TERM $pids 2>/dev/null || true
        for _ in $(seq 1 100); do
            [[ -z "$(_netns_pids)" ]] && break
            sleep 0.1
        done
        pids="$(_netns_pids)"
        # shellcheck disable=SC2086
        [[ -n "$pids" ]] && sudo kill -KILL $pids 2>/dev/null
    fi
    if [[ -n "${NSNTRACE_PID:-}" ]]; then
        for _ in $(seq 1 150); do
            sudo kill -0 "$NSNTRACE_PID" 2>/dev/null || break
            sleep 0.1
        done
        if sudo kill -0 "$NSNTRACE_PID" 2>/dev/null; then
            sudo kill -TERM "$NSNTRACE_PID" 2>/dev/null || true
            sleep 2
            sudo kill -KILL "$NSNTRACE_PID" 2>/dev/null || true
        fi
        wait "$NSNTRACE_PID" 2>/dev/null || true
    fi
    sudo chown "$(id -u):$(id -g)" "$CAPTURE_PCAP" 2>/dev/null || true
}

_cleanup_capture_or_kill() {
    # Cleanup must never stop at the first thing that fails. Confirmed on a real
    # instance: after a terminal hangup (SIGHUP) the `echo` below failed, with
    # nowhere to write to, and errexit ended the script before any of it ran,
    # leaving the emulator, its helpers and the namespace behind.
    set +e
    if [[ -n "${REVIEW_PID:-}" ]]; then
        echo "Interrupted: the review was not completed, and no network evidence was added." \
            >&2 || true
        kill -TERM "$REVIEW_PID" 2>/dev/null || true
        wait "$REVIEW_PID" 2>/dev/null || true
    fi
    if [[ -n "${MITM_PID:-}" ]]; then
        kill "$MITM_PID" 2>/dev/null || true
        wait "$MITM_PID" 2>/dev/null || true
    fi
    # The proxy's directory holds the private key of its CA: never leave it behind.
    [[ -n "${MITM_CONF:-}" ]] && rm -rf "$MITM_CONF"
    if [[ -n "$CAPTURE_PCAP" ]]; then
        _cleanup_capture
    elif [[ -n "${EMULATOR_PID:-}" ]]; then
        kill "$EMULATOR_PID" 2>/dev/null || true
    fi
}

if [[ "$GOLDEN" == 1 ]] && ! avdmanager list avd | grep -q "Name: ${AVD_NAME}\$"; then
    echo "error: the golden AVD ${AVD_NAME} does not exist; build it with local-image/build_golden_avd.sh" >&2
    exit 1
fi
if ! avdmanager list avd | grep -q "Name: ${AVD_NAME}\$"; then
    echo "Creating AVD ${AVD_NAME}..."
    sdkmanager --install "$SYSTEM_IMAGE"
    echo "no" | avdmanager create avd \
        --name "$AVD_NAME" \
        --package "$SYSTEM_IMAGE" \
        --device "pixel_6"
fi

# Point the emulator at the directory avdmanager actually put the AVD in. Confirmed on a GitHub
# runner (ci-spike/FINDINGS.md): the image sets XDG_CONFIG_HOME, avdmanager then created the AVD
# under $XDG_CONFIG_HOME/.android/avd, and the emulator launched through sudo and nsntrace looked
# in $HOME/.android/avd instead and stopped with "Unknown AVD name". avdmanager also ignored an
# ANDROID_AVD_HOME that named another directory. Why the emulator misses the XDG location only
# through sudo is not established; this sidesteps the question. ANDROID_AVD_HOME is passed
# through both sudo layers below.
_avd_dir() {
    local path dir
    path="$(avdmanager list avd 2>/dev/null | awk -v name="$AVD_NAME" '
        $1 == "Name:" { found = ($2 == name) }
        found && $1 == "Path:" { sub(/^[ \t]*Path:[ \t]*/, ""); print; exit }')"
    [[ -n "$path" ]] || return 1
    dir="$(dirname "$path")"
    # The AVD's .ini sits next to its .avd directory; without it the emulator cannot use dir.
    [[ -f "$dir/${AVD_NAME}.ini" ]] || return 1
    printf '%s\n' "$dir"
}
if AVD_DIR="$(_avd_dir)"; then
    if [[ "${ANDROID_AVD_HOME:-}" != "$AVD_DIR" ]]; then
        echo "Using the AVD directory avdmanager reports: ${AVD_DIR}"
    fi
    export ANDROID_AVD_HOME="$AVD_DIR"
else
    echo "warning: could not find ${AVD_NAME}'s directory in 'avdmanager list avd';" \
        "leaving ANDROID_AVD_HOME as it is" >&2
fi

EMULATOR_EXTRA_ARGS=()
if [[ "$GOLDEN" == 1 ]]; then
    EMULATOR_EXTRA_ARGS+=(-read-only)
fi
if [[ -z "${DISPLAY:-}" ]]; then
    # Confirmed the hard way: without a DISPLAY, the emulator's default (GUI)
    # mode crashes immediately with "no Qt platform plugin could be
    # initialized" rather than falling back gracefully, which otherwise
    # leaves the next step (adb wait-for-device) hanging forever waiting for
    # a device that will never come up. A real volunteer reviewing an app
    # interactively will have a DISPLAY and never hits this branch; this
    # exists so the script fails usefully (or runs at all, for automated
    # testing) on a server/CI host instead.
    echo "no DISPLAY detected; running headless (-no-window)." >&2
    echo "You will not see the emulator's screen. This is only useful for" >&2
    echo "automated testing, not for actually reviewing an app's UI." >&2
    EMULATOR_EXTRA_ARGS+=(-no-window)
fi

# Confirmed on a real instance: bash does not run an EXIT trap when the script
# is killed by a signal it has not trapped, so a SIGTERM or a closed terminal
# (SIGHUP) left the emulator, nsntrace, the network namespace and a growing
# root-owned pcap behind. Trapping the signals and exiting runs the EXIT trap.
# Installed before the emulator is launched, so a signal during startup is
# covered too.
NSNTRACE_PID=""
EMULATOR_NS_PID=""
NETNS_ID=""
REVIEW_PID=""
MITM_PID=""
MITM_CONF=""
trap '_cleanup_capture_or_kill' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if [[ -n "$CAPTURE_PCAP" ]]; then
    echo "Booting ${AVD_NAME} under nsntrace, capturing to ${CAPTURE_PCAP}..."
    if ! _start_emulator_under_nsntrace; then
        echo "error: emulator did not start under nsntrace after several attempts" >&2
        exit 1
    fi
    EMULATOR_PID="$NSNTRACE_PID"
    NETNS_ID="$(sudo readlink "/proc/${EMULATOR_NS_PID}/ns/net" 2>/dev/null || true)"
    _emulator_alive() { sudo kill -0 "$EMULATOR_PID" 2>/dev/null; }

    # nsntrace leaves loopback down in the namespace it creates (confirmed
    # against the installed nsntrace package), and the unprivileged emulator
    # can't raise it itself (RTNETLINK: Operation not permitted, confirmed),
    # so it is raised from outside, as root. The wrapper started above is
    # already waiting for exactly this, so nothing depends on winning a race.
    sudo nsenter --target "$EMULATOR_NS_PID" --net -- ip link set lo up
else
    echo "Booting ${AVD_NAME} (this can take a few minutes)..."
    emulator -avd "$AVD_NAME" -no-snapshot -no-boot-anim "${EMULATOR_EXTRA_ARGS[@]}" &
    EMULATOR_PID=$!
    _emulator_alive() { kill -0 "$EMULATOR_PID" 2>/dev/null; }
fi

# `adb wait-for-device` blocks forever if the emulator process has already
# died (e.g. crashed on startup) rather than simply taking a while to boot;
# confirmed the hard way when the DISPLAY-less crash above left this step
# hanging indefinitely with no indication anything was wrong. Poll instead,
# so a dead emulator process is a fast, clear failure, not a silent hang.
echo "Waiting for the device to connect..."
CONNECT_TIMEOUT=60
SECONDS_WAITED=0
until adb_cmd get-state >/dev/null 2>&1; do
    if ! _emulator_alive; then
        echo "error: the emulator process exited before the device came up;" >&2
        echo "run without --apk piped through this script to see its output" >&2
        exit 1
    fi
    if (( SECONDS_WAITED >= CONNECT_TIMEOUT )); then
        echo "error: no device connected within ${CONNECT_TIMEOUT}s" >&2
        exit 1
    fi
    sleep 2
    SECONDS_WAITED=$((SECONDS_WAITED + 2))
done

BOOT_TIMEOUT=180
SECONDS_WAITED=0
until [[ "$(adb_cmd shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]]; do
    if ! _emulator_alive; then
        echo "error: the emulator process exited while waiting for boot to complete" >&2
        exit 1
    fi
    if (( SECONDS_WAITED >= BOOT_TIMEOUT )); then
        echo "error: emulator did not finish booting within ${BOOT_TIMEOUT}s" >&2
        exit 1
    fi
    sleep 2
    SECONDS_WAITED=$((SECONDS_WAITED + 2))
done

if [[ -n "$CAPTURE_PCAP" ]]; then
    # Confirmed on a real instance: with Android's default (opportunistic)
    # Private DNS, the guest upgrades to DNS-over-TLS as soon as the resolver
    # offers it (Quad9 does), and the app's lookups then sit inside TLS on
    # port 853, invisible to the passive capture (ping lookups of fdroid.org
    # and f-droid.org were missing from the pcap; with this setting they
    # appear). Only worth doing when capturing. A guest with this off differs
    # from a stock phone, and an app that does its own DoT or DoH stays
    # invisible either way.
    adb_cmd shell settings put global private_dns_mode off
fi

if [[ "$REVIEW" == 1 && ( -n "$PCAPDROID_APK" || "$GOLDEN" == 1 ) ]]; then
    SERIAL="$(adb_cmd get-serialno | tr -d '\r')"
    if [[ "$GOLDEN" == 1 ]]; then
        PCAPDROID_API_KEY="$(<"$GOLDEN_KEY_FILE")"
        # Android's VPN approval did not survive in the golden image (PCAPdroid asked for it again
        # on every boot, whatever was baked in), but it is only an app-op, and this image is rooted:
        # grant it here, with no dialog to answer.
        echo "Granting PCAPdroid's VPN approval (root app-op)..."
        adb_cmd root >/dev/null 2>&1 || true
        adb_cmd wait-for-device
        adb_cmd shell cmd appops set com.emanuelef.remote_capture ACTIVATE_VPN allow
    else
        echo "Setting PCAPdroid up on the emulator (about a minute)..."
        if ! PCAPDROID_API_KEY="$(python3 "$REPO_ROOT/scripts/pcapdroid_setup.py" \
            --apk "$PCAPDROID_APK" --serial "$SERIAL")"; then
            echo "error: PCAPdroid setup failed (see above)" >&2
            exit 1
        fi
    fi
    export PCAPDROID_API_KEY

    if [[ "$DECRYPT" == 1 ]]; then
        # A fresh CA per run, in a private directory that is deleted on exit. The proxy listens on
        # loopback only: the emulator reaches it as 10.0.2.2.
        MITM_CONF="$(mktemp -d)"
        rm -f "$OUTPUT_DIR/decrypted.jsonl"
        MITM_LOG="$OUTPUT_DIR/decrypted.jsonl" "$MITM_BIN" -q -s "$REPO_ROOT/scripts/mitm_log_addon.py" \
            --listen-host 127.0.0.1 --listen-port "$MITM_PORT" --set "confdir=$MITM_CONF" \
            >"$OUTPUT_DIR/mitmdump.log" 2>&1 &
        MITM_PID=$!
        for _ in $(seq 1 30); do
            [[ -f "$MITM_CONF/mitmproxy-ca-cert.pem" ]] && break
            kill -0 "$MITM_PID" 2>/dev/null || break
            sleep 1
        done
        if [[ ! -f "$MITM_CONF/mitmproxy-ca-cert.pem" ]] || ! kill -0 "$MITM_PID" 2>/dev/null; then
            echo "error: the proxy did not start (see $OUTPUT_DIR/mitmdump.log)" >&2
            exit 1
        fi
        CA_HASH="$(openssl x509 -inform PEM -subject_hash_old -noout -in "$MITM_CONF/mitmproxy-ca-cert.pem")"
        echo "Trusting the proxy's CA as a user CA, and pointing the emulator at the proxy..."
        adb_cmd shell mkdir -p /data/misc/user/0/cacerts-added
        adb_cmd push "$MITM_CONF/mitmproxy-ca-cert.pem" "/data/misc/user/0/cacerts-added/${CA_HASH}.0" >/dev/null
        adb_cmd shell "chown system:system /data/misc/user/0/cacerts-added/${CA_HASH}.0; chmod 644 /data/misc/user/0/cacerts-added/${CA_HASH}.0; restorecon -R /data/misc/user/0/cacerts-added"
        adb_cmd shell settings put global http_proxy "10.0.2.2:${MITM_PORT}"
        # Seen on the first live run: with the proxy set, Android's own connectivity checks
        # (generate_204, from the system, not the app) filled the log. Switch them off.
        adb_cmd shell settings put global captive_portal_mode 0
    fi

    review_cmd=(python3 "$REPO_ROOT/scripts/quick_review.py"
        --apk "$APK" --serial "$SERIAL" --adb-command "$ADB_BIN"
        --capture-pcapdroid --output-dir "$OUTPUT_DIR")
    if [[ "$DECRYPT" == 1 ]]; then
        review_cmd+=(--install-apk "$PATCHED_APK" --decrypted-log "$OUTPUT_DIR/decrypted.jsonl")
    fi
    [[ -n "$MR_IID" ]] && review_cmd+=(--mr-iid "$MR_IID")
    [[ -n "$DURATION" ]] && review_cmd+=(--duration "$DURATION")
    [[ -n "$PACKAGE" ]] && review_cmd+=(--package "$PACKAGE")
    review_cmd+=("${REVIEW_ARGS[@]}")
    export PYTHONPATH="$REPO_ROOT/gitlab-glue:$REPO_ROOT/netpolicy${PYTHONPATH:+:$PYTHONPATH}"
    review_status=0
    "${review_cmd[@]}" &
    REVIEW_PID=$!
    wait "$REVIEW_PID" || review_status=$?
    REVIEW_PID=""
    exit "$review_status"
fi

if [[ "$REVIEW" == 1 ]]; then
    SERIAL="$(adb_cmd get-serialno | tr -d '\r')"
    # quick_review runs adb the way adb_cmd does: from inside the namespace, as
    # the invoking user. printf %q so it survives being one argument.
    printf -v ADB_PREFIX '%q ' \
        sudo --preserve-env=ANDROID_SDK_ROOT,ANDROID_HOME,ANDROID_AVD_HOME \
        nsenter --target "$EMULATOR_NS_PID" --net -- \
        sudo -u "$(id -un)" --preserve-env=ANDROID_SDK_ROOT,ANDROID_HOME,ANDROID_AVD_HOME \
        "$ADB_BIN"

    review_cmd=(python3 "$REPO_ROOT/scripts/quick_review.py"
        --apk "$APK" --serial "$SERIAL" --adb-command "$ADB_PREFIX"
        --external-pcap "$CAPTURE_PCAP" --output-dir "$OUTPUT_DIR")
    [[ -n "$MR_IID" ]] && review_cmd+=(--mr-iid "$MR_IID")
    [[ -n "$DURATION" ]] && review_cmd+=(--duration "$DURATION")
    [[ -n "$PACKAGE" ]] && review_cmd+=(--package "$PACKAGE")
    review_cmd+=("${REVIEW_ARGS[@]}")

    # The packages quick_review imports are all standard library on their own.
    export PYTHONPATH="$REPO_ROOT/gitlab-glue:$REPO_ROOT/netpolicy${PYTHONPATH:+:$PYTHONPATH}"
    # In the background and waited for, not run in the foreground: bash holds a
    # trapped signal back until a foreground command ends, so a Ctrl-C or kill
    # would otherwise wait out the whole recording. (Confirmed on a real run.)
    review_status=0
    "${review_cmd[@]}" &
    REVIEW_PID=$!
    wait "$REVIEW_PID" || review_status=$?
    REVIEW_PID=""

    # The capture only ends, and the pcap is only complete, when the emulator
    # has stopped; quick_review's network section is the second step for that
    # reason. A failed review has nothing to finalize.
    _cleanup_capture
    if [[ -f "$OUTPUT_DIR/review_state.json" ]]; then
        python3 "$REPO_ROOT/scripts/quick_review.py" --finalize "$OUTPUT_DIR" || review_status=$?
    else
        echo "No review state was written, so the network evidence was not added." >&2
        [[ "$review_status" == 0 ]] && review_status=1
    fi
    exit "$review_status"
fi

echo "Installing ${APK}..."
adb_cmd install -r "$APK"

echo "Ready. The emulator window is the review session; close it (or Ctrl-C this script) when done."
wait "$EMULATOR_PID"
