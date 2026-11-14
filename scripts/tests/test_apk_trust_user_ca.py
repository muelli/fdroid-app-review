from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import apk_trust_user_ca as t  # noqa: E402


def _anchors(xml: str, path: str) -> list[str]:
    root = ET.fromstring(xml)
    return [c.get("src") or "" for c in root.findall(f"{path}/trust-anchors/certificates")]


def test_an_app_without_a_config_gets_one_that_trusts_system_and_user_cas() -> None:
    xml, report = t.patch_config(None)
    assert _anchors(xml, "base-config") == ["system", "user"]
    assert not report.had_own_config and "added a base-config" in report.changes


def test_a_base_config_keeps_its_other_settings_and_gains_user_trust() -> None:
    original = (
        '<network-security-config><base-config cleartextTrafficPermitted="false">'
        '<trust-anchors><certificates src="system"/></trust-anchors></base-config>'
        "</network-security-config>"
    )
    xml, report = t.patch_config(original)
    assert _anchors(xml, "base-config") == ["system", "user"]
    assert 'cleartextTrafficPermitted="false"' in xml  # the app's own policy is not changed
    assert report.had_own_config and report.changes == ["base-config trusts user CAs"]


def test_a_config_with_only_domain_rules_gets_a_base_config_too() -> None:
    """Otherwise every other host would still trust the system store only."""
    original = (
        "<network-security-config><domain-config cleartextTrafficPermitted='true'>"
        "<domain>192.168.1.1</domain></domain-config></network-security-config>"
    )
    xml, _ = t.patch_config(original)
    assert _anchors(xml, "base-config") == ["system", "user"]
    assert ET.fromstring(xml).find("domain-config/domain").text == "192.168.1.1"  # type: ignore[union-attr]


def test_a_base_config_without_trust_anchors_is_made_explicit() -> None:
    original = (
        '<network-security-config><base-config cleartextTrafficPermitted="true"/>'
        "</network-security-config>"
    )
    xml, report = t.patch_config(original)
    assert _anchors(xml, "base-config") == ["system", "user"]
    assert any("system CAs explicitly" in c for c in report.changes)


def test_a_domain_config_with_its_own_anchors_gains_user_trust_including_nested_ones() -> None:
    original = (
        "<network-security-config><base-config><trust-anchors><certificates src='system'/>"
        "</trust-anchors></base-config>"
        "<domain-config><domain>example.org</domain>"
        "<trust-anchors><certificates src='@raw/own_ca'/></trust-anchors>"
        "<domain-config><domain>api.example.org</domain>"
        "<trust-anchors><certificates src='system'/></trust-anchors></domain-config>"
        "</domain-config></network-security-config>"
    )
    xml, _ = t.patch_config(original)
    root = ET.fromstring(xml)
    for config in root.iter("domain-config"):
        assert "user" in [c.get("src") for c in config.findall("trust-anchors/certificates")]
    assert "@raw/own_ca" in xml  # the app's own anchor is kept


def test_pins_are_reported_and_removed_by_default() -> None:
    original = (
        "<network-security-config><domain-config><domain>api.example.org</domain>"
        "<domain>cdn.example.org</domain><pin-set expiration='2030-01-01'>"
        "<pin digest='SHA-256'>AAAA</pin></pin-set></domain-config></network-security-config>"
    )
    xml, report = t.patch_config(original)
    assert report.pinned_domains == ["api.example.org", "cdn.example.org"] and report.pins_removed
    assert "pin-set" not in xml and "AAAA" not in xml


def test_pins_can_be_kept_and_are_still_reported() -> None:
    original = (
        "<network-security-config><domain-config><domain>api.example.org</domain>"
        "<pin-set><pin digest='SHA-256'>AAAA</pin></pin-set></domain-config>"
        "</network-security-config>"
    )
    xml, report = t.patch_config(original, strip_pins=False)
    assert "pin-set" in xml and report.pinned_domains == ["api.example.org"]
    assert not report.pins_removed


def test_patching_twice_changes_nothing_the_second_time() -> None:
    once, _ = t.patch_config(None)
    twice, report = t.patch_config(once)
    assert twice == once and report.changes == []


@pytest.mark.parametrize(
    "bad", ["", "not xml at all", "<other-root/>", "<network-security-config>"]
)
def test_a_config_that_is_not_one_is_an_error_not_a_guess(bad: str) -> None:
    with pytest.raises(t.PatchError):
        t.patch_config(bad)


MANIFEST = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">'
    '<uses-permission android:name="android.permission.INTERNET"/>'
    '<application android:label="x" android:icon="@mipmap/i"><activity android:name=".A"/>'
    "</application></manifest>"
)


def test_the_manifest_is_pointed_at_a_new_config_when_it_has_none() -> None:
    patched, existing = t.patch_manifest(MANIFEST)
    assert existing is None
    assert 'android:networkSecurityConfig="@xml/network_security_config"' in patched
    assert patched.count("networkSecurityConfig") == 1
    ET.fromstring(patched)  # still well-formed


def test_an_existing_reference_is_found_and_the_manifest_is_left_alone() -> None:
    own = MANIFEST.replace(
        "<application ", '<application android:networkSecurityConfig="@xml/my_net" ', 1
    )
    patched, existing = t.patch_manifest(own)
    assert existing == "my_net" and patched == own


def test_a_manifest_without_an_application_is_an_error() -> None:
    with pytest.raises(t.PatchError, match="no <application>"):
        t.patch_manifest('<manifest package="a.b"/>')
