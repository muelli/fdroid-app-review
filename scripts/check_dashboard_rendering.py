#!/usr/bin/env python3
"""Actually renders the dashboard in a real headless Chromium and checks it.

Not part of `make test` or CI: it needs Playwright and a real Chromium
binary, which are a heavier dependency than this static, framework-free
dashboard should require just to run its own test suite (there is no test
suite here, by design; see dashboard/README.md). Run this by hand after
touching dashboard/ code:

    pip install --user playwright
    python3 -m playwright install chromium
    python3 scripts/check_dashboard_rendering.py [--live]

Without --live, only the file:// path is checked (no broker needed).
With --live, `make dev` must already be running (docker compose -f
deploy/docker-compose.yml up -d); the live-broker checks claim a merge
request through the broker's real API and confirm the dashboard reflects
it, then leave that claim in place (tear the stack down afterwards with
`make dev-down` if you want a clean slate).

Defaults to Chromium; pass --browser firefox or --browser webkit to check
the other two engines (install them first with e.g.
`python3 -m playwright install firefox`).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_HTML = REPO_ROOT / "dashboard" / "index.html"
LIVE_BASE = "http://localhost:8080"
SCREENSHOT_DIR = Path("/tmp/dashboard-check")


def _console_error_collector(page: Page) -> list[str]:
    errors: list[str] = []
    page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
    return errors


def check_file_url(browser_name: str) -> list[str]:
    problems: list[str] = []
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = getattr(p, browser_name).launch()
        page = browser.new_page()
        console_errors = _console_error_collector(page)

        page.goto(f"file://{DASHBOARD_HTML}")
        page.wait_for_selector("#queue-body tr", timeout=5000)

        row_count = page.locator("#queue-body tr").count()
        if row_count != 3:
            problems.append(f"file://: expected 3 sample rows, got {row_count}")

        data_source = page.locator("#data-source").inner_text()
        if "sample" not in data_source:
            problems.append(f"file://: expected sample-data fallback text, got {data_source!r}")

        page.fill("#search", "quickse")
        page.wait_for_timeout(100)
        if page.locator("#queue-body tr").count() != 1:
            problems.append("file://: search filter did not narrow to 1 row")
        page.fill("#search", "")

        page.select_option("#claim-filter", "claimed")
        page.wait_for_timeout(100)
        if page.locator("#queue-body tr").count() != 1:
            problems.append("file://: claim-state filter did not narrow to 1 row")
        page.select_option("#claim-filter", "all")

        page.fill("#staging-repo-base-url", "https://example.org/staging-repo")
        page.wait_for_timeout(200)
        qr_images = page.locator("img.qr")
        if qr_images.count() == 0:
            problems.append("file://: no QR code images rendered")
        else:
            src = qr_images.first.get_attribute("src") or ""
            if not src.startswith("data:image/gif;base64,"):
                problems.append(f"file://: QR image src not a data URL: {src[:50]!r}")

        page.screenshot(path=str(SCREENSHOT_DIR / f"file-url-{browser_name}.png"), full_page=True)
        browser.close()

    if console_errors:
        problems.append(f"file://: unexpected console errors: {console_errors}")
    return problems


def _api_post(path: str, body: dict, token: str | None = None) -> dict:
    req = urllib.request.Request(
        f"{LIVE_BASE}{path}",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)


def check_live_broker(mr_iid: int = 32058) -> list[str]:
    problems: list[str] = []
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        console_errors = _console_error_collector(page)

        page.goto(LIVE_BASE)
        page.wait_for_selector("#queue-body tr", timeout=5000)

        if "live broker" not in page.locator("#data-source").inner_text():
            problems.append("live: dashboard did not report reading the live broker")

        page.screenshot(path=str(SCREENSHOT_DIR / "live-before-claim.png"), full_page=True)
        browser.close()

    login = _api_post("/auth/mock-login", {"username": "rendering-check"})
    _api_post("/claims", {"mr_iid": mr_iid}, token=login["token"])

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(LIVE_BASE)
        page.wait_for_selector("#queue-body tr", timeout=5000)

        row = page.locator("#queue-body tr", has=page.locator("a", has_text=str(mr_iid)))
        claim_text = row.locator(".claim-state").inner_text()
        if "rendering-check" not in claim_text:
            problems.append(f"live: claim not reflected after reload, badge said {claim_text!r}")

        page.screenshot(path=str(SCREENSHOT_DIR / "live-after-claim.png"), full_page=True)
        browser.close()

    if console_errors:
        problems.append(f"live: unexpected console errors: {console_errors}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--live", action="store_true", help="also check against a running `make dev` stack"
    )
    parser.add_argument(
        "--browser",
        choices=["chromium", "firefox", "webkit"],
        default="chromium",
        help="engine to check the file:// rendering with (install it first via "
        "`python3 -m playwright install <name>`)",
    )
    args = parser.parse_args()

    problems = check_file_url(args.browser)
    if args.live:
        problems += check_live_broker()

    if problems:
        print("PROBLEMS FOUND:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print(f"All checks passed. Screenshots in {SCREENSHOT_DIR}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
