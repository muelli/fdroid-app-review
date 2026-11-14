"""Putting link and VirusTotal rows into a checklist that lacks them (the rows' content is
quick_review's; this tests only where they go)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import enrich_checklist as ec  # noqa: E402

TABLE = """| Check | Result |
| --- | --- |
| Build status | not checked (quick review) |
| Version/tag matches upstream | not checked (quick review) |
| Permissions requested | `a` |
| URLs embedded in the APK | `https://x.example` |
| Screenshots | none |
| VirusTotal | [look up this hash](https://v) (a link only) |

### Reviewer checklist
"""


def test_existing_rows_are_replaced_in_place() -> None:
    out = ec.enrich(TABLE, [("Build status", "[pipeline](https://p) is success")])
    lines = out.split("\n")
    assert lines[2] == "| Build status | [pipeline](https://p) is success |"
    assert "not checked (quick review) |" in lines[3]  # the other row is untouched


def test_new_rows_go_after_the_urls_row_in_order() -> None:
    out = ec.enrich(TABLE, [("Metadata", "m"), ("Policy", "p")])
    rows = [line.split(" | ")[0].strip("| ") for line in out.split("\n") if line.startswith("| ")]
    assert rows.index("Metadata") == rows.index(ec.ANCHOR) + 2  # Policy was inserted first
    assert rows.index("Policy") == rows.index(ec.ANCHOR) + 1


def test_running_twice_gives_the_same_checklist() -> None:
    rows = [("Build status", "b"), ("Metadata", "m"), ("VirusTotal", "0 of 68")]
    once = ec.enrich(TABLE, rows)
    assert ec.enrich(once, rows) == once
    assert once.count("| Metadata |") == 1 and once.count("| VirusTotal |") == 1


def test_other_rows_and_the_rest_of_the_text_are_not_touched() -> None:
    out = ec.enrich(TABLE, [("VirusTotal", "x")])
    for keep in (
        "| Permissions requested | `a` |",
        "| Screenshots | none |",
        "### Reviewer checklist",
    ):
        assert keep in out


def test_without_the_urls_row_new_rows_go_at_the_end_of_the_table() -> None:
    text = "| Check | Result |\n| --- | --- |\n| Permissions requested | `a` |\n\nafter\n"
    out = ec.enrich(text, [("Metadata", "m")])
    assert out.split("\n")[3] == "| Metadata | m |" and out.endswith("after\n")
