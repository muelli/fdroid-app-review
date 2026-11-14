from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import code_quality as cq  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> cq.CodeQuality:
    return cq.parse(json.loads((FIXTURES / name).read_text()))


def test_a_ci_signed_apk_is_found() -> None:
    """The shape the fetcher used to miss: no reproducible build, so no tmp/binaries URL."""
    report = _load("code_quality_signed_apk.json")
    assert [(a.kind, a.url.rsplit("/", 1)[-1]) for a in report.apks] == [
        ("Signed APK", "com.covertwogames.dozeoff.foss_14.signed.apk")
    ]
    assert "/artifacts/raw/tmp/signed/" in report.apks[0].url


def test_a_reproducible_build_apk_is_found() -> None:
    report = _load("code_quality_reproducible.json")
    assert [a.kind for a in report.apks] == ["Reproducible build APK"]
    assert report.apks[0].url.endswith("/tmp/binaries/com.Obscrum.pchwmonitor_8.binary.apk")


def test_permissions_are_listed_and_the_notable_ones_are_marked() -> None:
    report = _load("code_quality_reproducible.json")
    assert "android.permission.INTERNET" in report.permissions
    assert "android.permission.CAMERA" in report.permissions
    assert report.notable_permissions == [
        "android.permission.INTERNET",
        "android.permission.CAMERA",
    ]
    assert report.needs_network_check


def test_an_app_without_internet_needs_no_network_check() -> None:
    report = _load("code_quality_signed_apk.json")
    assert "android.permission.WAKE_LOCK" in report.permissions
    assert not any(p.endswith(".INTERNET") for p in report.permissions)
    assert not report.needs_network_check and report.notable_permissions == []


def test_the_fastlane_locales_say_whether_there_is_english() -> None:
    assert _load("code_quality_signed_apk.json").fastlane.keys() == {"en-US"}
    both = _load("code_quality_reproducible.json")
    assert set(both.fastlane) == {"en-US", "tr"} and both.english is True
    assert cq.parse({}).english is None
    turkish_only = "Fastlane/Triple-T in tr: summary (x), name (y), description (z)"
    only_tr = cq.parse({"new_errors": [{"description": turkish_only}]})
    assert only_tr.english is False


def test_signing_key_and_abis() -> None:
    report = _load("code_quality_signed_apk.json")
    assert report.signing_key and report.signing_key.startswith("CN=")
    assert report.abi_and_size == "No native lib, 3.8M"


def test_unknown_warnings_above_routine_severity_are_surfaced() -> None:
    report = cq.parse(
        {
            "new_errors": [
                {"description": "Scanner: found a tracker library", "severity": "major"},
                {"description": "Some routine note", "severity": "info"},
                {"description": "Permission android.permission.CAMERA", "severity": "minor"},
            ],
            "existing_errors": [],
        }
    )
    assert report.flagged == ["Scanner: found a tracker library"]
    assert report.permissions == ["android.permission.CAMERA"]


def test_duplicates_across_new_and_existing_are_collapsed() -> None:
    entry = {"description": "Permission android.permission.WAKE_LOCK", "severity": "info"}
    report = cq.parse({"new_errors": [entry], "existing_errors": [entry]})
    assert report.permissions == ["android.permission.WAKE_LOCK"]


def test_an_empty_or_odd_report_does_not_raise() -> None:
    odd_reports = [
        {},
        {"new_errors": []},
        {"new_errors": [{}]},
        {"new_errors": [{"description": 5}]},
    ]
    for odd in odd_reports:
        assert isinstance(cq.parse(odd), cq.CodeQuality)


def test_every_abi_line_is_kept_and_arm_only_is_decided_from_all_of_them() -> None:
    def report(*texts: str) -> cq.CodeQuality:
        return cq.parse({"new_errors": [{"description": f"APK ABI and size: {t}"} for t in texts]})

    both = report("armeabi-v7a, 24M", "arm64-v8a, 25M")
    assert both.abi_texts == ["armeabi-v7a, 24M", "arm64-v8a, 25M"]
    assert both.native_abis == ["arm64-v8a", "armeabi-v7a"] and both.arm_only
    assert report("arm64-v8a (2.2M) armeabi-v7a (2.1M)").arm_only  # the shape seen on !44635
    assert not report("arm64-v8a, 1M", "x86_64, 1M").arm_only
    assert not report("x86_64, 70M").arm_only  # !45850
    assert (
        not report("No native lib, 6.5M").arm_only
        and report("No native lib, 6.5M").native_abis == []
    )
    assert not report().arm_only  # nothing known is not ARM-only
