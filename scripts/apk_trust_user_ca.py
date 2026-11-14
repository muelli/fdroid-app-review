"""Make an APK trust a CA the reviewer installed, so a proxy can show what the app sends over TLS.

Since Android 7 an app trusts only the system's CAs unless its network security config says
otherwise. This decodes an APK with apktool (resources and manifest only: the code is untouched),
adds `<certificates src="user"/>` to the app's network security config (creating one if there is
none), re-signs it with a throwaway key and says what it changed. The result is a DIFFERENT binary
from the one F-Droid ships: signature and hash differ, so it is only ever installed for this
inspection, and the review's evidence is about the original file.

Certificate pinning declared in the app's own config (`<pin-set>`) is noted and removed by default,
because it would stop the proxy; pins done in code (OkHttp's CertificatePinner, a custom
TrustManager) are not touched, and show up instead as a TLS failure in the proxy's log.

    python3 apk_trust_user_ca.py --apk in.apk --out patched.apk --apktool apktool.jar
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_NAME = "network_security_config"
KEYSTORE_PASSWORD = "android"  # a throwaway key for a throwaway re-signing
_NAME_RE = re.compile(r'android:networkSecurityConfig="@xml/([A-Za-z0-9_]+)"')
_APPLICATION_RE = re.compile(r"<application\b")


@dataclass
class PatchReport:
    had_own_config: bool = False
    config_file: str = f"res/xml/{DEFAULT_CONFIG_NAME}.xml"
    changes: list[str] = field(default_factory=list)
    pinned_domains: list[str] = field(default_factory=list)
    pins_removed: bool = False


class PatchError(Exception):
    pass


def _ensure_user_anchor(anchors: ET.Element) -> bool:
    if any(c.get("src") == "user" for c in anchors.findall("certificates")):
        return False
    ET.SubElement(anchors, "certificates", {"src": "user"})
    return True


def patch_config(text: str | None, *, strip_pins: bool = True) -> tuple[str, PatchReport]:
    """The network security config with user CAs trusted: (new XML, what was done)."""
    report = PatchReport(had_own_config=text is not None)
    if text is None:
        root = ET.Element("network-security-config")
    else:
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise PatchError(f"the app's network security config is not valid XML: {exc}") from exc
        if root.tag != "network-security-config":
            raise PatchError(f"unexpected root element {root.tag!r} in the network security config")

    base = root.find("base-config")
    if base is None:
        base = ET.Element("base-config")
        root.insert(0, base)
        report.changes.append("added a base-config")
    base_anchors = base.find("trust-anchors")
    if base_anchors is None:
        # The default for an app targeting Android 7 or later is the system store only, so say so.
        base_anchors = ET.SubElement(base, "trust-anchors")
        ET.SubElement(base_anchors, "certificates", {"src": "system"})
        report.changes.append("base-config now trusts the system CAs explicitly")
    if _ensure_user_anchor(base_anchors):
        report.changes.append("base-config trusts user CAs")

    for domain_config in root.iter("domain-config"):
        domains = [d.text.strip() for d in domain_config.findall("domain") if d.text]
        anchors = domain_config.find("trust-anchors")
        if anchors is not None and _ensure_user_anchor(anchors):
            report.changes.append(f"domain-config {', '.join(domains) or '?'} trusts user CAs")
        pin_set = domain_config.find("pin-set")
        if pin_set is not None:
            report.pinned_domains.extend(domains or ["?"])
            if strip_pins:
                domain_config.remove(pin_set)
                report.pins_removed = True
                report.changes.append(f"removed the pin-set for {', '.join(domains) or '?'}")

    ET.indent(root)
    xml = ET.tostring(root, encoding="unicode")
    return '<?xml version="1.0" encoding="utf-8"?>\n' + xml + "\n", report


def patch_manifest(text: str) -> tuple[str, str | None]:
    """(manifest that points at a network security config, the existing config's name or None)."""
    existing = _NAME_RE.search(text)
    if existing is not None:
        return text, existing.group(1)
    if _APPLICATION_RE.search(text) is None:
        raise PatchError("the manifest has no <application> element")
    patched = _APPLICATION_RE.sub(
        f'<application android:networkSecurityConfig="@xml/{DEFAULT_CONFIG_NAME}"', text, count=1
    )
    return patched, None


def _run(command: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(command, capture_output=True, text=True, cwd=cwd, check=False)  # noqa: S603
    if result.returncode != 0:
        tail = (result.stderr or result.stdout).strip().splitlines()[-6:]
        raise PatchError(f"{Path(command[0]).name} failed: " + " | ".join(tail))
    return result.stdout


def ensure_keystore(path: Path) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    _run(
        [
            "keytool", "-genkeypair", "-keystore", str(path), "-storepass", KEYSTORE_PASSWORD,
            "-keypass", KEYSTORE_PASSWORD, "-alias", "review", "-keyalg", "RSA", "-keysize", "2048",
            "-validity", "10000", "-dname", "CN=fdroid-review-session throwaway",
        ]
    )  # fmt: skip


def _build_tool(name: str) -> str:
    """apksigner or zipalign: on PATH, or in the newest build-tools of the SDK."""
    found = shutil.which(name)
    if found:
        return found
    for root_var in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        import os

        root = os.environ.get(root_var)
        if root:
            candidates = sorted(Path(root, "build-tools").glob(f"*/{name}"))
            if candidates:
                return str(candidates[-1])
    raise PatchError(f"{name} not found: put the Android build-tools on PATH")


def patch_apk(
    apk: Path, out: Path, *, apktool_jar: Path, keystore: Path, strip_pins: bool = True
) -> PatchReport:
    """Decode, patch, rebuild, align and sign. The code (dex) is not decoded or changed."""
    ensure_keystore(keystore)
    with tempfile.TemporaryDirectory(prefix="trust-ca-") as tmp:
        work = Path(tmp) / "decoded"
        _run(["java", "-jar", str(apktool_jar), "d", "-s", "-f", "-o", str(work), str(apk)])
        manifest_path = work / "AndroidManifest.xml"
        manifest, existing = patch_manifest(manifest_path.read_text(encoding="utf-8"))
        config_name = existing or DEFAULT_CONFIG_NAME
        config_path = work / "res" / "xml" / f"{config_name}.xml"
        old_config = config_path.read_text(encoding="utf-8") if config_path.exists() else None
        new_config, report = patch_config(old_config, strip_pins=strip_pins)
        if existing is not None and old_config is None:
            raise PatchError(
                f"the manifest names @xml/{existing} but res/xml/{existing}.xml is missing"
            )
        report.config_file = f"res/xml/{config_name}.xml"
        if existing is None:
            report.changes.append("pointed the manifest at a new network security config")
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(new_config, encoding="utf-8")
        manifest_path.write_text(manifest, encoding="utf-8")

        unsigned, aligned = Path(tmp) / "unsigned.apk", Path(tmp) / "aligned.apk"
        _run(["java", "-jar", str(apktool_jar), "b", "-o", str(unsigned), str(work)])
        _run([_build_tool("zipalign"), "-f", "-p", "4", str(unsigned), str(aligned)])
        out.parent.mkdir(parents=True, exist_ok=True)
        _run(
            [
                _build_tool("apksigner"), "sign", "--ks", str(keystore),
                "--ks-pass", f"pass:{KEYSTORE_PASSWORD}", "--key-pass", f"pass:{KEYSTORE_PASSWORD}",
                "--ks-key-alias", "review", "--out", str(out), str(aligned),
            ]
        )  # fmt: skip
        _run([_build_tool("apksigner"), "verify", str(out)])
    return report


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="apk_trust_user_ca.py", description=__doc__.split("\n\n")[0]
    )
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--apktool", type=Path, required=True, help="apktool's jar")
    parser.add_argument(
        "--keystore", type=Path, default=Path.home() / ".cache" / "fdroid-review" / "resign.jks"
    )
    parser.add_argument("--keep-pins", action="store_true", help="note pins but do not remove them")
    args = parser.parse_args(argv)
    try:
        report = patch_apk(
            args.apk, args.out, apktool_jar=args.apktool, keystore=args.keystore,
            strip_pins=not args.keep_pins,
        )  # fmt: skip
    except PatchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report.__dict__, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
