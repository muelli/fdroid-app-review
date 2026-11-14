"""Read the Code Quality report GitLab shows on an fdroiddata merge request.

F-Droid's own reviewer guide says where to look: "The apk url can be found in Code
Quality reports" and "Permissions are listed in Code Quality". The report
(`/-/merge_requests/N/codequality_reports.json`) holds, from one request: the built APK's
URL (a reproducible build's binary, or a CI-signed one), every permission, the signing key,
the ABIs and size, and the Fastlane description per locale. Pure functions here, no network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_APK_RE = re.compile(
    r"^(?P<kind>[A-Za-z][A-Za-z ]*?APK):\s*(?P<url>https://gitlab\.com/\S+?\.apk)\s*$"
)
_PERMISSION_PREFIX = "Permission "
_ABI_RE = re.compile(r"\b(arm64-v8a|armeabi-v7a|armeabi|x86_64|x86|mips64|mips)\b")
_FASTLANE_RE = re.compile(
    r"^Fastlane/Triple-T in (?P<locale>[\w-]+): summary \((?P<summary>.*?)\), name \("
)
# GitLab's severities, least to most serious; "info" is the report's ordinary level.
_ROUTINE = {"info"}


@dataclass(frozen=True, slots=True)
class BuiltApk:
    kind: str  # e.g. "Reproducible build APK", "Signed APK"
    url: str


@dataclass(frozen=True, slots=True)
class CodeQuality:
    apks: list[BuiltApk] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    signing_key: str | None = None
    abi_and_size: str | None = None
    # Every "APK ABI and size" line: a merge request that builds one APK per ABI has several,
    # and abi_and_size above keeps only the last.
    abi_texts: list[str] = field(default_factory=list)
    # locale -> the Fastlane summary found for it
    fastlane: dict[str, str] = field(default_factory=dict)
    # Descriptions of entries above routine severity that are not just a permission:
    # warnings the reviewer guide says to look at.
    flagged: list[str] = field(default_factory=list)
    # Permissions the report itself marks above routine severity (INTERNET, CAMERA, ...).
    notable_permissions: list[str] = field(default_factory=list)

    @property
    def native_abis(self) -> list[str]:
        """The CPU architectures named in the "APK ABI and size" lines, e.g. arm64-v8a."""
        found = re.findall(_ABI_RE, " ".join(self.abi_texts))
        return sorted(set(found))

    @property
    def arm_only(self) -> bool:
        """Native code, and none of it for x86: the APKs cannot be installed on an x86 device."""
        abis = self.native_abis
        return bool(abis) and not any(abi.startswith("x86") for abi in abis)

    @property
    def english(self) -> bool | None:
        """None when no Fastlane metadata was found at all."""
        if not self.fastlane:
            return None
        return any(locale.lower().startswith("en") for locale in self.fastlane)

    @property
    def needs_network_check(self) -> bool:
        """The guide only asks for network monitoring when the app can use the network."""
        return any(p.endswith(".INTERNET") for p in self.permissions)


def parse(report: dict[str, Any]) -> CodeQuality:
    entries = [
        *report.get("new_errors", []),
        *report.get("existing_errors", []),
    ]
    apks: list[BuiltApk] = []
    permissions: list[str] = []
    notable: list[str] = []
    flagged: list[str] = []
    fastlane: dict[str, str] = {}
    signing_key = abi_and_size = None
    abi_texts: list[str] = []
    for entry in entries:
        text = str(entry.get("description", ""))
        severity = str(entry.get("severity", "info"))
        if text.startswith(_PERMISSION_PREFIX):
            name = text[len(_PERMISSION_PREFIX) :].strip()
            if name not in permissions:
                permissions.append(name)
            if severity not in _ROUTINE and name not in notable:
                notable.append(name)
        elif (apk := _APK_RE.match(text)) is not None:
            apks.append(BuiltApk(kind=apk.group("kind"), url=apk.group("url")))
        elif text.startswith("Signing Key:"):
            signing_key = text[len("Signing Key:") :].strip()
        elif text.startswith("APK ABI and size:"):
            abi_and_size = text[len("APK ABI and size:") :].strip()
            abi_texts.append(abi_and_size)
        elif (meta := _FASTLANE_RE.match(text)) is not None:
            fastlane[meta.group("locale")] = meta.group("summary")
        elif severity not in _ROUTINE:
            flagged.append(text.replace("\n", " ")[:300])
    return CodeQuality(
        apks=apks,
        permissions=permissions,
        signing_key=signing_key,
        abi_and_size=abi_and_size,
        abi_texts=abi_texts,
        fastlane=fastlane,
        flagged=flagged,
        notable_permissions=notable,
    )
