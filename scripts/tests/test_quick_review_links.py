from __future__ import annotations

import dataclasses
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_quick_review_comment as comment_helpers  # noqa: E402
import test_quick_review_crash as crash_helpers  # noqa: E402
import virustotal  # noqa: E402

qr = crash_helpers.qr
PIN = "e2e0a263c538f1ad3f2881116f2aa316c56d34ff"
SHA = "a" * 64

LINKS: dict[str, Any] = {
    "mr_url": "https://gitlab.com/fdroid/fdroiddata/-/merge_requests/1",
    "pipeline_url": "https://gitlab.com/fdroid/fdroiddata/-/pipelines/7",
    "pipeline_status": "success",
    "apk_url": "https://gitlab.com/fdroid/fdroiddata/-/jobs/9/artifacts/raw/tmp/signed/a.signed.apk",
    "apk_kind": "Signed APK",
    "metadata_url": "https://gitlab.com/fdroid/fdroiddata/-/blob/abc/metadata/a.yml",
    "categories": ["System"],
    "pinned_commit": PIN,
    "commit_url": f"https://github.com/o/r/commit/{PIN}",
    "tag": "v2.0.4",
    "tag_url": "https://github.com/o/r/tree/v2.0.4",
    "descriptions": {
        "en-US": f"https://github.com/o/r/blob/{PIN}/fastlane/metadata/android/en-US/full_description.txt"
    },
    "funding_files": [],
}


def _data(tmp_path: Path, **changes: Any) -> Any:
    base = comment_helpers._data(tmp_path, names=None, permissions=["android.permission.WAKE_LOCK"])
    return dataclasses.replace(base, apk_sha256=SHA, **changes)


def _rows(comment: str) -> dict[str, str]:
    table = comment.split("### Evidence")[1].split("### Reviewer checklist")[0]
    rows = {}
    for line in table.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split(" | ", 1)]
        if len(cells) == 2 and cells[0] not in ("Check", "---"):
            rows[cells[0]] = cells[1]
    return rows


def test_without_collected_links_the_claims_say_they_were_not_checked(tmp_path: Path) -> None:
    rows = _rows(qr.build_review_comment(_data(tmp_path), 1))
    assert rows["Build status"] == "not checked (quick review)"
    assert rows["Version/tag matches upstream"] == "not checked (quick review)"
    assert "Description under test" not in rows


def test_every_claim_links_to_what_it_rests_on(tmp_path: Path) -> None:
    data = _data(tmp_path, mr_links=LINKS, apk_version="2.0.4 (14)")
    rows = _rows(qr.build_review_comment(data, 1))
    assert rows["Build status"].startswith(f"[head pipeline]({LINKS['pipeline_url']}) is success")
    assert f"({LINKS['apk_url']})" in rows["Build status"] and "is success" in rows["Build status"]
    version = rows["Version/tag matches upstream"]
    assert f"[pinned commit {PIN[:7]}]({LINKS['commit_url']})" in version
    assert f"[v2.0.4]({LINKS['tag_url']})" in version
    assert "The APK reports 2.0.4 (14) (matches the tag)" in version
    description = rows["Description under test"]
    assert f"({LINKS['descriptions']['en-US']})" in description and "pinned commit" in description
    assert "#quality-control" in description
    assert f"({LINKS['metadata_url']})" in rows["Metadata"] and "System" in rows["Metadata"]
    policy = rows["Policy"]
    assert "#free-software-requirement" in policy and "#security--legal-compliance" in policy


def test_a_version_that_differs_from_the_tag_is_said_so(tmp_path: Path) -> None:
    rows = _rows(qr.build_review_comment(_data(tmp_path, mr_links=LINKS, apk_version="9.9 (1)"), 1))
    assert "(differs from the tag)" in rows["Version/tag matches upstream"]


def test_a_pin_with_no_tag_says_so(tmp_path: Path) -> None:
    links = {**LINKS, "tag": None, "tag_url": None}
    rows = _rows(qr.build_review_comment(_data(tmp_path, mr_links=links), 1))
    assert "has no release tag pointing at it" in rows["Version/tag matches upstream"]


def test_a_missing_description_is_not_silently_dropped(tmp_path: Path) -> None:
    links = {**LINKS, "descriptions": {}}
    rows = _rows(qr.build_review_comment(_data(tmp_path, mr_links=links), 1))
    assert rows["Description under test"] == "not found at the pinned commit"


def test_urls_in_the_apk_and_an_unverified_donation_link_are_stated(tmp_path: Path) -> None:
    data = _data(
        tmp_path, mr_links=LINKS, apk_urls=["https://ko-fi.com/someone", "https://example.org/x"]
    )
    rows = _rows(qr.build_review_comment(data, 1))
    assert "`https://ko-fi.com/someone`" in rows["URLs embedded in the APK"]
    donation = rows["Donation links"]
    assert "`https://ko-fi.com/someone`" in donation and "#security--legal-compliance" in donation
    assert "none found upstream" in donation and "FUNDING.yml" in donation


def test_a_funding_file_upstream_is_linked_as_the_verification(tmp_path: Path) -> None:
    funding = f"https://github.com/o/r/blob/{PIN}/.github/FUNDING.yml"
    data = _data(
        tmp_path,
        mr_links={**LINKS, "funding_files": [funding]},
        apk_urls=["https://ko-fi.com/someone"],
    )
    donation = _rows(qr.build_review_comment(data, 1))["Donation links"]
    assert f"[FUNDING.yml]({funding})" in donation and "none found" not in donation


def test_an_app_without_a_donation_url_has_no_donation_row(tmp_path: Path) -> None:
    rows = _rows(qr.build_review_comment(_data(tmp_path, apk_urls=["https://example.org/x"]), 1))
    assert "Donation links" not in rows and "URLs embedded in the APK" in rows


def test_the_virustotal_row_in_each_state(tmp_path: Path) -> None:
    gui = f"https://www.virustotal.com/gui/file/{SHA}"
    hit = {
        "sha256": SHA,
        "malicious": 0,
        "suspicious": 1,
        "harmless": 10,
        "undetected": 60,
        "analysed_at": "2026-10-26",
        "uploaded_by_us": True,
    }
    row = _rows(qr.build_review_comment(_data(tmp_path, virustotal=hit), 1))["VirusTotal"]
    assert f"[1 of 71 engines flag it]({gui})" in row and "analysed 2026-10-26" in row
    assert "(uploaded by this run)" in row
    unknown = _rows(
        qr.build_review_comment(
            _data(tmp_path, virustotal_note="unknown to VirusTotal (not uploaded)"), 1
        )
    )["VirusTotal"]
    assert "unknown to VirusTotal" in unknown and f"({gui})" in unknown
    plain = _rows(qr.build_review_comment(_data(tmp_path), 1))["VirusTotal"]
    assert "nothing was uploaded or looked up" in plain


def test_a_url_cannot_break_out_of_its_table_cell(tmp_path: Path) -> None:
    evil = {**LINKS, "pipeline_url": "https://x.example/A|b c)(d"}
    comment = qr.build_review_comment(_data(tmp_path, mr_links=evil), 1)
    build = _rows(comment)["Build status"]
    # The case of the path survives, and nothing in it can end the link or the cell.
    assert "(https://x.example/A%7Cb%20c%29%28d)" in build


def test_the_verdict_is_set_only_when_asked(tmp_path: Path) -> None:
    plain = qr.build_review_comment(_data(tmp_path), 1)
    assert "**Verdict:** _(good for inclusion" in plain
    chosen = qr.build_review_comment(_data(tmp_path, verdict=qr.VERDICTS["more-testing"]), 1)
    assert "**Verdict:** More testing needed" in chosen
    assert set(qr.VERDICTS.values()) == {
        "Good for inclusion",
        "More testing needed",
        "Unfit for inclusion",
    }


def test_urls_are_found_inside_an_apk_and_framework_noise_is_dropped(tmp_path: Path) -> None:
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr(
            "classes.dex", b"xx https://ko-fi.com/someone\x00 https://schemas.android.com/apk/res"
        )
        z.writestr("res/a.xml", b"<a href='https://example.org/page'>")
        z.writestr("lib/x.so", b"https://hidden.example/in-native-lib")  # not scanned
    assert qr.apk_embedded_urls(apk) == ["https://example.org/page", "https://ko-fi.com/someone"]
    assert qr.donation_urls(["https://ko-fi.com/s", "https://example.org"]) == [
        "https://ko-fi.com/s"
    ]
    assert qr.apk_embedded_urls(tmp_path / "missing.apk") is None


def test_the_version_comes_from_the_manifest(tmp_path: Path) -> None:
    argv = crash_helpers._stub_toolchain(tmp_path, "")
    aapt = argv[argv.index("--aapt-binary") + 1]
    assert qr.apk_version_info(Path(argv[1]), aapt) == "1.2.3 (1)"


# ---- through main ------------------------------------------------------------------------


def test_link_evidence_reaches_the_checklist_through_main(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(qr, "gather_mr_links", lambda iid, apk_name=None: (LINKS, None))
    code, out, _ = crash_helpers._run(
        [*crash_helpers._stub_toolchain(tmp_path, ""), "--link-evidence"]
    )
    assert code == 0 and "Collecting the links" in out
    comment = (tmp_path / "out" / "review_comment.md").read_text()
    assert f"({LINKS['pipeline_url']})" in comment and "[v2.0.4]" in comment


def test_a_failed_link_lookup_warns_and_the_review_carries_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(qr, "gather_mr_links", lambda iid, apk_name=None: (None, "boom"))
    code, _, err = crash_helpers._run(
        [*crash_helpers._stub_toolchain(tmp_path, ""), "--link-evidence"]
    )
    assert code == 0 and "could not collect the evidence links: boom" in err
    rows = _rows((tmp_path / "out" / "review_comment.md").read_text())
    assert rows["Build status"] == "not checked (quick review)"


def test_virustotal_through_main_uses_the_key_and_reports_the_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("VT_API_KEY", "k-123")
    seen: dict[str, Any] = {}

    def fake_check(path: Path, sha: str, key: str, *, allow_upload: bool, **_: Any) -> Any:
        seen.update(key=key, upload=allow_upload, sha=sha)
        return virustotal.VtResult(sha, 0, 0, 5, 60, "2026-10-26"), "ok"

    monkeypatch.setattr(virustotal, "check", fake_check)
    code, out, _ = crash_helpers._run(
        [*crash_helpers._stub_toolchain(tmp_path, ""), "--virustotal-upload"]
    )
    assert code == 0 and "will upload the APK if it is unknown" in out
    assert seen["key"] == "k-123" and seen["upload"] is True
    row = _rows((tmp_path / "out" / "review_comment.md").read_text())["VirusTotal"]
    assert "0 of 65 engines flag it" in row
    assert "k-123" not in (tmp_path / "out" / "review_comment.md").read_text()
    assert "k-123" not in (tmp_path / "out" / "report.md").read_text()


def test_the_virustotal_flags_need_a_key_and_link_evidence_needs_a_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VT_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        qr.parse_args(["--apk", "a.apk", "--virustotal"])
    with pytest.raises(SystemExit):
        qr.parse_args(["--apk", "a.apk", "--virustotal-upload"])
    with pytest.raises(SystemExit):
        qr.parse_args(["--apk", "a.apk", "--link-evidence"])
    monkeypatch.setenv("VT_API_KEY", "k")
    assert qr.parse_args(["--apk", "a.apk", "--virustotal-upload"]).virustotal is True


def _emulator_data(tmp_path: Path, permissions: list[str]) -> Any:
    log = tmp_path / "network_log.jsonl"
    log.write_text('{"type": "dns", "query_name": "youtubei.googleapis.com", "timestamp": 1}\n')
    base = comment_helpers._data(tmp_path, names=None, permissions=permissions)
    return dataclasses.replace(base, network_log_path=log, network_state="windowed")


def test_an_app_without_internet_is_not_shown_the_emulators_system_endpoints(
    tmp_path: Path,
) -> None:
    """Seen on a real emulator review: 18 Google endpoints next to 'cannot use the network'."""
    data = _emulator_data(tmp_path, ["android.permission.WAKE_LOCK"])
    rows = _rows(qr.build_review_comment(data, 1))
    observed = rows["Network endpoints observed"]
    assert observed.startswith("none possible: no `INTERNET` permission")
    assert "youtubei.googleapis.com" not in observed
    assert "none of which can be this app's" in observed
    assert "cannot use the network" in rows["INTERNET permission"]


def test_an_app_with_internet_still_lists_the_emulators_endpoints_with_the_caveat(
    tmp_path: Path,
) -> None:
    data = _emulator_data(tmp_path, ["android.permission.INTERNET"])
    observed = _rows(qr.build_review_comment(data, 1))["Network endpoints observed"]
    assert "`youtubei.googleapis.com`" in observed and "whole emulator" in observed


def _apk_with(tmp_path: Path, files: dict[str, bytes]) -> Path:
    apk = tmp_path / "x.apk"
    with zipfile.ZipFile(apk, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return apk


def test_html_and_script_junk_is_not_taken_for_a_web_address(tmp_path: Path) -> None:
    """Seen in a React Native app: 'http://\"><span', 'http://.css', 'http://UA-Compatible'."""
    junk = (
        b'<a href="http://"><span> http://.css http://.jpg|right|thumb|.js"></script> '
        b'http://</a></li><li http://<div http://encoding="utf-8"? '
        b"http://Descriptionrelatively real: https://good.example.org/path?q=1"
    )
    urls = qr.apk_embedded_urls(_apk_with(tmp_path, {"assets/page.html": junk}))
    assert urls == ["https://good.example.org/path?q=1"]


def test_a_file_name_is_not_a_host_even_with_a_dot(tmp_path: Path) -> None:
    data = b"http://styles.css http://app.js http://icon.png https://cdn.example.com/a.css"
    assert qr.apk_embedded_urls(_apk_with(tmp_path, {"a.js": data})) == [
        "https://cdn.example.com/a.css"
    ]


def test_a_react_native_bundle_is_scanned_where_its_endpoints_are(tmp_path: Path) -> None:
    bundle = b"\x00\x01https://flagcdn.com/w80/\x00https://nominatim.openstreetmap.org/search?x\x00"
    urls = qr.apk_embedded_urls(_apk_with(tmp_path, {"assets/index.android.bundle": bundle}))
    assert urls == [
        "https://flagcdn.com/w80/",
        "https://nominatim.openstreetmap.org/search?x",
    ]


def test_one_address_per_host_and_a_cap_that_cannot_hide_the_rest_by_repeating(
    tmp_path: Path,
) -> None:
    many = b" ".join(
        f"https://h{i:03d}.example.org/p{j}".encode() for i in range(60) for j in (1, 2)
    )
    urls = qr.apk_embedded_urls(_apk_with(tmp_path, {"a.json": many}))
    assert urls is not None and len(urls) == qr.MAX_EMBEDDED_URLS
    assert len({u.split("/")[2] for u in urls}) == len(urls)  # no host twice
    long_path = b"https://x.example.org/" + b"a" * 300
    one = qr.apk_embedded_urls(_apk_with(tmp_path, {"b.json": long_path}))
    assert one is not None and len(one[0]) <= qr.MAX_EMBEDDED_URL_CHARS


def test_an_arm_only_apk_says_so_and_what_that_means(tmp_path: Path) -> None:
    """!45651 builds armeabi-v7a and arm64-v8a APKs and no x86: worth a line in every review."""
    data = dataclasses.replace(_data(tmp_path), apk_abis=["arm64-v8a"])
    row = _rows(qr.build_review_comment(data, 1))["Native code ABIs"]
    assert row.startswith("`arm64-v8a`; no x86 or x86_64 code in this APK")
    assert "cannot be installed on an x86 device" in row and "another APK per ABI" in row


def test_an_apk_with_x86_code_is_just_listed_and_pure_java_gets_no_row(tmp_path: Path) -> None:
    both = dataclasses.replace(_data(tmp_path), apk_abis=["x86_64", "arm64-v8a"])
    assert _rows(qr.build_review_comment(both, 1))["Native code ABIs"] == "`arm64-v8a`, `x86_64`"
    for abis in ([], None):
        plain = dataclasses.replace(_data(tmp_path), apk_abis=abis)
        assert "Native code ABIs" not in _rows(qr.build_review_comment(plain, 1))
