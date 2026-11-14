"""Add the link evidence and the VirusTotal result to a checklist that was made without them.

An emulator run on a remote host should not carry a GitLab token or a VirusTotal key, so
`quick_review.py` is run there without `--link-evidence` and `--virustotal`. This runs on your own
machine afterwards, on the checklist it wrote: it collects the same links (the head pipeline and the
CI-built APK, the pinned commit and its tag, the description under test, the metadata, the policy)
and the VirusTotal result with the same code, and puts them in the same rows. Nothing is posted.
Running it again replaces the rows it owns, so the result is the same.

    GITLAB_TOKEN=... VT_API_KEY=... enrich_checklist.py --comment review_comment.md --mr-iid 1234 \
        --apk the-original.apk [--virustotal-upload]
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

ANCHOR = "URLs embedded in the APK"
# Rows this script writes; the others (permissions, screenshots...) are left exactly as they were.
OWNED = {"Build status", "Version/tag matches upstream", "VirusTotal"}


def _row_re(label: str) -> str:
    import re

    return rf"^\| {re.escape(label)} \| .* \|$"


def enrich(text: str, rows: list[tuple[str, str]]) -> str:
    """The checklist with each (label, cell) row replaced in place, or inserted after the row
    for the URLs embedded in the APK (or, without one, at the end of the evidence table).
    """
    import re

    lines = text.split("\n")
    for label, cell in rows:
        new = f"| {label} | {cell} |"
        index = next((i for i, line in enumerate(lines) if re.match(_row_re(label), line)), None)
        if index is not None:
            lines[index] = new
            continue
        anchor = next((i for i, line in enumerate(lines) if line.startswith(f"| {ANCHOR} |")), None)
        if anchor is None:
            table_end = max(
                (i for i, line in enumerate(lines) if line.startswith("| ")), default=None
            )
            if table_end is None:
                raise ValueError("no evidence table in the checklist")
            anchor = table_end
        lines.insert(anchor + 1, new)
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="enrich_checklist.py", description=__doc__.split("\n\n")[0]
    )
    parser.add_argument("--comment", type=Path, required=True, help="the checklist to update")
    parser.add_argument("--mr-iid", type=int, required=True)
    parser.add_argument("--apk", type=Path, required=True, help="the original APK, as fetched")
    parser.add_argument("--virustotal", action="store_true", help="needs VT_API_KEY")
    parser.add_argument("--virustotal-upload", action="store_true", help="upload if unknown")
    args = parser.parse_args(argv)
    if args.virustotal_upload:
        args.virustotal = True
    if args.virustotal and not os.environ.get("VT_API_KEY", "").strip():
        parser.error("--virustotal needs your VirusTotal API key in the VT_API_KEY variable")

    here = Path(__file__).resolve().parent
    sys.path[:0] = [str(here), str(here.parent / "gitlab-glue"), str(here.parent / "netpolicy")]
    import quick_review as qr  # noqa: PLC0415

    if not args.apk.is_file():
        print(f"error: --apk is not a file: {args.apk}", file=sys.stderr)
        return 1
    sha = qr.sha256_of(args.apk)
    links, links_note = qr.gather_mr_links(args.mr_iid, args.apk.name)
    if links_note:
        print(f"warning: no evidence links: {links_note}", file=sys.stderr)
    vt: dict | None = None
    vt_note: str | None = None
    if args.virustotal and sha:
        import virustotal  # noqa: PLC0415

        found, vt_note = virustotal.check(
            args.apk, sha, os.environ["VT_API_KEY"].strip(), allow_upload=args.virustotal_upload
        )
        if found is not None:
            import dataclasses

            vt, vt_note = dataclasses.asdict(found), None
        else:
            print(f"warning: VirusTotal: {vt_note}", file=sys.stderr)

    now = datetime.now(UTC)
    data = qr.ReportData(
        apk_path=args.apk, package=None, serial="", duration=0, started_at=now, ended_at=now,
        screen_recording_path=None, network_log_path=None, pcap_path=None, permissions=None,
        logcat_path=None, permission_accesses=[], logcat_entries=[], app_pids=[], warnings=[],
        logcat_scope="", logcat_text="", apk_sha256=sha, apk_urls=qr.apk_embedded_urls(args.apk),
        apk_version=qr.apk_version_info(args.apk, None), mr_links=links, mr_links_note=links_note,
        virustotal=vt, virustotal_note=vt_note,
    )  # fmt: skip
    build, version, extra = qr._link_rows(data)
    rows = [("Build status", build), ("Version/tag matches upstream", version)]
    rows += [(label, cell) for label, cell in extra if label != ANCHOR]
    vt_row = qr._virustotal_row(data)
    if vt_row is not None:
        rows.append(vt_row)
    updated = enrich(args.comment.read_text(encoding="utf-8"), rows)
    args.comment.write_text(updated, encoding="utf-8")
    print(f"updated {args.comment}: " + ", ".join(label for label, _ in rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
