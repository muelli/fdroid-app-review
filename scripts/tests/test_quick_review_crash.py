from __future__ import annotations

import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import test_quick_review_emulator as helpers  # noqa: E402  (loads quick_review once)

qr = helpers.qr

# Verbatim from a real emulator run (21Life, an arm64-only React Native app).
REAL_CRASH = """\
10-28 17:14:56.623  4462  4462 D AndroidRuntime: Shutting down VM
10-28 17:14:56.623  4462  4462 E AndroidRuntime: FATAL EXCEPTION: main
10-28 17:14:56.623  4462  4462 E AndroidRuntime: Process: com.phyrexianarena.app, PID: 4462
10-28 17:14:56.623  4462  4462 E AndroidRuntime: com.facebook.soloader.SoLoaderDSONotFoundError: couldn't find DSO to load: libreactnative.so
10-28 17:14:56.623  4462  4462 E AndroidRuntime: \texisting SO sources:
10-28 17:14:56.624   542  1068 W ActivityTaskManager: Force finishing activity
"""  # noqa: E501


def _entries(text: str) -> list[object]:
    return qr.parse_logcat(text, None, reference_year=2026)


def test_real_java_crash_is_described() -> None:
    crashes = qr.detect_crashes(_entries(REAL_CRASH), "com.phyrexianarena.app", [4462])
    assert crashes == [
        "uncaught exception: com.facebook.soloader.SoLoaderDSONotFoundError: "
        "couldn't find DSO to load: libreactnative.so"
    ]


def test_another_apps_crash_is_not_reported_as_this_one() -> None:
    assert qr.detect_crashes(_entries(REAL_CRASH), "com.someone.else", [4462]) == []


def test_native_crash_needs_one_of_the_apps_pids() -> None:
    line = (
        "10-28 17:14:56.623  4462  4462 F libc    : Fatal signal 11 (SIGSEGV), code 1 "
        "(SEGV_MAPERR), fault addr 0x0 in tid 4462 (Thread-3), pid 4462 (rpnet)"
    )
    assert qr.detect_crashes(_entries(line), "a.b", [4462]) == ["native crash: signal 11 (SIGSEGV)"]
    assert qr.detect_crashes(_entries(line), "a.b", [9999]) == []


def test_anr_matches_the_package_exactly() -> None:
    anr = (
        "10-28 17:14:56.623   542   562 E ActivityManager: "
        "ANR in com.example.app (com.example.app/.Main)"
    )
    assert qr.detect_crashes(_entries(anr), "com.example.app", []) == [
        "the app was not responding (ANR)"
    ]
    assert qr.detect_crashes(_entries(anr), "com.example.ap", []) == []
    assert qr.detect_crashes(_entries(anr.replace("app (", "app2 (")), "com.example.app", []) == []


def test_no_crash_in_a_quiet_log() -> None:
    quiet = "10-28 17:14:56.623  4462  4462 I MyApp   : hello\n"
    assert qr.detect_crashes(_entries(quiet), "a.b", [4462]) == []


def test_abi_mismatch_note() -> None:
    note = qr.abi_mismatch_note(["arm64-v8a"], ["x86_64", "arm64-v8a"])
    assert note is not None and "arm64-v8a" in note and "x86_64" in note
    assert qr.abi_mismatch_note(["arm64-v8a"], ["arm64-v8a", "armeabi-v7a"]) is None
    assert qr.abi_mismatch_note([], ["x86_64"]) is None  # pure Java: runs anywhere
    assert qr.abi_mismatch_note(None, ["x86_64"]) is None
    assert qr.abi_mismatch_note(["arm64-v8a"], None) is None


def _stub_toolchain(tmp_path: Path, logcat: str) -> list[str]:
    aapt = tmp_path / "stub-aapt"
    aapt.write_text(
        "#!/bin/sh\n"
        'if [ "$2" = permissions ]; then\n'
        "  echo \"uses-permission: name='android.permission.INTERNET'\"\n"
        "  echo \"uses-permission: name='android.permission.CAMERA'\"\n"
        "  echo \"uses-permission: name='android.permission.MANAGE_EXTERNAL_STORAGE'\"\n"
        "  exit 0\n"
        "fi\n"
        "echo \"package: name='org.example.app' versionCode='1' versionName='1.2.3'\"\n"
        "echo \"native-code: 'arm64-v8a'\"\n"
    )
    aapt.chmod(0o755)
    log_file = tmp_path / "logcat-lines.txt"
    log_file.write_text(logcat)
    adb = tmp_path / "stub-adb"
    adb.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        "  *install*) echo Success ;;\n"
        "  *getprop*abilist*) echo x86_64,arm64-v8a ;;\n"
        "  *list*permissions*) printf 'group:g\\n  permission:android.permission.CAMERA\\n' ;;\n"
        f"  *logcat*-c*) ;;\n  *logcat*) cat {log_file} ;;\n"
        "esac\n"
        "exit 0\n"
    )
    adb.chmod(0o755)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"x")
    return [
        "--apk", str(apk), "--serial", "emulator-5554", "--duration", "1",
        "--output-dir", str(tmp_path / "out"), "--adb-command", str(adb),
        "--aapt-binary", str(aapt), "--mr-iid", "5",
    ]  # fmt: skip


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    return qr.main(argv, stdout=out, stderr=err), out.getvalue(), err.getvalue()


def test_a_crash_reaches_the_warning_the_report_and_the_checklist(tmp_path: Path) -> None:
    crash = REAL_CRASH.replace("com.phyrexianarena.app", "org.example.app")
    code, _, err = _run(_stub_toolchain(tmp_path, crash))
    assert code == 0
    assert "the app crashed during the run" in err
    out = tmp_path / "out"
    report = (out / "report.md").read_text()
    assert "## The app crashed during this run" in report
    assert "libreactnative.so" in report
    assert "primary ABI is x86_64" in report
    assert "arm64-v8a" in report.split("**ABIs**")[1].splitlines()[0]
    assert "The app crashed during this run" in (out / "report.html").read_text()
    comment = (out / "review_comment.md").read_text()
    assert "The app crashed during the run" in comment
    assert "libreactnative.so" in comment
    assert "primary ABI is x86_64" in comment
    assert "_(fill in)_" in comment  # the reviewer's own space is still there


def test_a_quiet_run_has_no_crash_section_and_the_plain_checklist(tmp_path: Path) -> None:
    quiet = "10-28 17:14:56.623  4462  4462 I MyApp   : hello\n"
    code, _, err = _run(_stub_toolchain(tmp_path, quiet))
    assert code == 0 and "crashed" not in err
    out = tmp_path / "out"
    assert "crashed" not in (out / "report.md").read_text()
    comment = (out / "review_comment.md").read_text()
    assert "crashed" not in comment
    concerns_heading = "**Concerns (permissions, network activity, anti-features, anything else):**"
    assert f"{concerns_heading}\n\n_(fill in)_" in comment


def test_hostile_exception_text_stays_inside_a_code_span(tmp_path: Path) -> None:
    evil = REAL_CRASH.replace(
        "couldn't find DSO to load: libreactnative.so", "`](https://evil.example)[`"
    ).replace("com.phyrexianarena.app", "org.example.app")
    _run(_stub_toolchain(tmp_path, evil))
    comment = (tmp_path / "out" / "review_comment.md").read_text()
    assert "](https://evil.example)" not in comment.replace("'](https://evil.example)['", "")


def test_state_round_trips_the_new_fields(tmp_path: Path) -> None:
    pcap = tmp_path / "s.pcap"
    helpers._dns_pcap(pcap, [("x.example", 1.0)])
    crash = REAL_CRASH.replace("com.phyrexianarena.app", "org.example.app")
    _run([*_stub_toolchain(tmp_path, crash), "--external-pcap", str(pcap)])
    text = (tmp_path / "out" / "review_state.json").read_text()
    data, mr_iid = qr.load_state(text)
    assert data.crashes
    assert data.apk_abis == ["arm64-v8a"]
    assert data.device_abis == ["x86_64", "arm64-v8a"]
    assert qr.dump_state(data, mr_iid) == text


def test_state_from_before_these_fields_still_loads(tmp_path: Path) -> None:
    pcap = tmp_path / "s.pcap"
    helpers._dns_pcap(pcap, [("x.example", 1.0)])
    _run([*_stub_toolchain(tmp_path, ""), "--external-pcap", str(pcap)])
    import json

    state = json.loads((tmp_path / "out" / "review_state.json").read_text())
    for key in ("crashes", "apk_abis", "device_abis"):
        del state["report"][key]
    data, _ = qr.load_state(json.dumps(state))
    assert data.crashes == [] and data.apk_abis is None and data.device_abis is None


def test_the_checklist_carries_the_hash_a_lookup_link_and_the_languages(tmp_path: Path) -> None:
    import hashlib

    argv = _stub_toolchain(tmp_path, "")
    code, _, _ = _run(argv)
    assert code == 0
    sha = hashlib.sha256(b"x").hexdigest()  # the stub APK's contents
    comment = (tmp_path / "out" / "review_comment.md").read_text()
    assert f"| APK SHA-256 | `{sha}` |" in comment
    assert f"https://www.virustotal.com/gui/file/{sha}" in comment
    assert "a link only: nothing was uploaded or looked up" in comment
    report = (tmp_path / "out" / "report.md").read_text()
    assert f"**APK SHA-256**: `{sha}`" in report


def test_languages_come_from_the_apk_and_are_omitted_when_unknown(tmp_path: Path) -> None:
    argv = _stub_toolchain(tmp_path, "")
    aapt = Path(argv[argv.index("--aapt-binary") + 1])
    aapt.write_text(aapt.read_text() + "echo \"locales: '--_--' 'de' 'fr'\"\n")
    _run(argv)
    comment = (tmp_path / "out" / "review_comment.md").read_text()
    assert "| Languages in the APK | --_--, de, fr |" in comment


def test_an_official_checklist_table_is_in_the_comment_and_nothing_is_ticked(
    tmp_path: Path,
) -> None:
    _run(_stub_toolchain(tmp_path, ""))
    comment = (tmp_path / "out" / "review_comment.md").read_text()
    assert "<td>Basic Function</td>" in comment and "<td>Security Scan</td>" in comment
    assert "- [x]" not in comment.lower() and comment.count("- [ ] ") == 17


def test_the_checklist_states_internet_storage_and_runtime_permissions(tmp_path: Path) -> None:
    _run(_stub_toolchain(tmp_path, ""))
    comment = (tmp_path / "out" / "review_comment.md").read_text()
    assert "| INTERNET permission | declared; the reviewer guide asks for" in comment
    assert "(this run: not captured here)" in comment
    assert "`MANAGE_EXTERNAL_STORAGE`) | declared; the guide suggests" in comment
    runtime_row = "| Runtime permissions declared | `android.permission.CAMERA`; **pre-granted"
    assert runtime_row in comment


def test_without_internet_the_row_says_the_network_is_unreachable(tmp_path: Path) -> None:
    argv = _stub_toolchain(tmp_path, "")
    aapt = Path(argv[argv.index("--aapt-binary") + 1])
    aapt.write_text(aapt.read_text().replace("INTERNET", "WAKE_LOCK"))
    _run(argv)
    comment = (tmp_path / "out" / "review_comment.md").read_text()
    assert "| INTERNET permission | not declared: the app cannot use the network |" in comment


def test_not_granting_permissions_changes_the_install_and_the_wording(tmp_path: Path) -> None:
    code, _, _ = _run([*_stub_toolchain(tmp_path, ""), "--no-grant-permissions"])
    assert code == 0
    comment = (tmp_path / "out" / "review_comment.md").read_text()
    assert "not pre-granted, the app had to ask" in comment
    report = (tmp_path / "out" / "report.md").read_text()
    assert "were NOT pre-granted" in report and "pre-granted at install time" not in report
    assert "NOT</strong> pre-granted" not in report
    assert "<strong>not</strong> pre-granted" in (tmp_path / "out" / "report.html").read_text()


def test_a_long_locale_list_is_summarised_around_english() -> None:
    many = ["--_--", "af", "de", "en-AU", "en-CA", "en-GB", "en-IN", "en-XC", "es", "fr", "ja"]
    summary = qr.locales_summary(many)
    assert summary.startswith("11 locales, `--_--` (the default resources); English: en-AU, en-CA")
    assert summary.endswith("...")
    assert qr.locales_summary(["--_--", "de"]) == "--_--, de"
    assert qr.locales_summary([]) == "none declared"
    no_english = [f"x{i}" for i in range(12)]
    assert qr.locales_summary(no_english).endswith("English: none")


def test_the_runtime_row_names_the_android_version_it_is_judged_by(tmp_path: Path) -> None:
    import dataclasses

    base_data = crash_helpers_data(tmp_path)
    data = dataclasses.replace(base_data, runtime_permissions=[], device_android="12")
    comment = qr.build_review_comment(data, 1)
    assert "none that this Android 12 device treats as runtime permissions" in comment
    assert "`POST_NOTIFICATIONS` from Android 13" in comment


def test_no_internet_means_the_network_row_says_none_possible(tmp_path: Path) -> None:
    import dataclasses

    data = dataclasses.replace(
        crash_helpers_data(tmp_path), permissions=["android.permission.WAKE_LOCK"]
    )
    comment = qr.build_review_comment(data, 1)
    assert "| Network endpoints observed | none possible: no `INTERNET` permission |" in comment
    with_internet = dataclasses.replace(data, permissions=["android.permission.INTERNET"])
    assert "not captured in this run" in qr.build_review_comment(with_internet, 1)


def crash_helpers_data(tmp_path: Path):  # type: ignore[no-untyped-def]
    import test_quick_review_comment as comment_helpers

    return comment_helpers._data(tmp_path, names=None, permissions=None)


# A real trace from an Android 14 emulator review (a boot broadcast hit the previous install,
# whose APK had just been removed): the process died inside the framework before any app code.
FRAMEWORK_CRASH = """\
10-28 21:39:04.335  3866  3866 E AndroidRuntime: FATAL EXCEPTION: main
10-28 21:39:04.335  3866  3866 E AndroidRuntime: Process: com.covertwogames.dozeoff.foss, PID: 3866
10-28 21:39:04.335  3866  3866 E AndroidRuntime: java.lang.NullPointerException: Attempt to invoke virtual method 'android.content.res.Configuration android.content.res.Resources.getConfiguration()' on a null object reference
10-28 21:39:04.335  3866  3866 E AndroidRuntime: \tat android.app.ConfigurationController.updateLocaleListFromAppContext(ConfigurationController.java:266)
10-28 21:39:04.335  3866  3866 E AndroidRuntime: \tat android.app.ActivityThread.handleBindApplication(ActivityThread.java:6880)
10-28 21:39:04.335  3866  3866 E AndroidRuntime: \tat android.app.ActivityThread.-$$Nest$mhandleBindApplication(Unknown Source:0)
10-28 21:39:04.335  3866  3866 E AndroidRuntime: \tat android.os.Handler.dispatchMessage(Handler.java:106)
10-28 21:39:04.335  3866  3866 E AndroidRuntime: \tat com.android.internal.os.ZygoteInit.main(ZygoteInit.java:971)
"""  # noqa: E501

APP_CODE_CRASH = FRAMEWORK_CRASH.replace(
    "\tat android.os.Handler.dispatchMessage",
    "\tat com.covertwogames.dozeoff.MainActivity.onCreate(MainActivity.kt:41)\n"
    "10-28 21:39:04.335  3866  3866 E AndroidRuntime: \tat android.os.Handler.dispatchMessage",
)


def test_a_crash_with_only_platform_frames_says_it_may_not_be_the_apps() -> None:
    crashes = qr.detect_crashes(_entries(FRAMEWORK_CRASH), "com.covertwogames.dozeoff.foss", [3866])
    assert len(crashes) == 1 and crashes[0].startswith(
        "uncaught exception: java.lang.NullPointerException"
    )
    assert crashes[0].endswith(qr.FRAMEWORK_ONLY_NOTE)  # whole, even after a long message
    assert len(crashes[0]) < 330  # the long reason was cut; the note was not


def test_a_crash_through_the_apps_own_code_is_not_second_guessed() -> None:
    crashes = qr.detect_crashes(_entries(APP_CODE_CRASH), "com.covertwogames.dozeoff.foss", [3866])
    assert len(crashes) == 1 and "all frames are Android's own code" not in crashes[0]


def test_the_real_react_native_crash_is_still_reported_plainly() -> None:
    crash = REAL_CRASH.replace("com.phyrexianarena.app", "org.example.app")
    crashes = qr.detect_crashes(_entries(crash), "org.example.app", [4462])
    assert crashes and "all frames are Android's own code" not in crashes[0]
