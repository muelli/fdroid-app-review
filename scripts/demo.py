#!/usr/bin/env python3
"""`make demo`: a scripted end-to-end review session against the fakes.

Logs in as a demo volunteer, claims a merge request, starts a session,
follows the one-time open URL, tears the session down, and prints where
the resulting evidence bundle and outbox comment landed. Everything runs
in-process against `FakeRuntime` and `MockGitLab`: no Docker, no network,
no real GitLab, so this is also exactly what `broker`'s own test suite
exercises, just narrated for a human instead of asserted by pytest.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from broker.app import create_app
from broker.config import Settings
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "demo-output"


def banner(text: str) -> None:
    print(f"\n=== {text} ===")


def main() -> int:
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True)

    settings = Settings(
        database_url=f"sqlite:///{OUTPUT_DIR / 'broker.db'}",
        secret_key="demo-secret",
        gitlab_mode="mock",
        gitlab_fixtures_path=REPO_ROOT / "fixtures" / "merge_requests.json",
        gitlab_outbox_dir=OUTPUT_DIR / "outbox",
        runtime_mode="fake",
        evidence_root=OUTPUT_DIR / "evidence",
        apk_source_mode="local_file",
        apk_local_dir=REPO_ROOT / "fixtures" / "apks",
        oauth_mode="mock",
    )

    app = create_app(settings)
    mr_iid = 32058

    with TestClient(app) as client:
        banner("Logging in as demo-volunteer")
        login = client.post("/auth/mock-login", json={"username": "demo-volunteer"})
        login.raise_for_status()
        token = login.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"Logged in as {login.json()['username']} (user_id={login.json()['user_id']})")

        banner(f"Claiming MR !{mr_iid}")
        claim = client.post("/claims", json={"mr_iid": mr_iid}, headers=headers)
        claim.raise_for_status()
        print(f"Claim {claim.json()['id']} active until {claim.json()['expires_at']}")

        banner("Starting a review session")
        session = client.post("/sessions", json={"mr_iid": mr_iid}, headers=headers)
        session.raise_for_status()
        session_body = session.json()
        print(f"Session {session_body['id']} running, expires {session_body['expires_at']}")
        print(f"Open URL: {session_body['open_url']}")

        banner("Following the one-time open URL")
        opened = client.get(session_body["open_url"], follow_redirects=False)
        print(f"Redirects (once) to: {opened.headers.get('location')}")

        banner("Volunteer finishes and tears the session down")
        teardown = client.post(
            f"/sessions/{session_body['id']}/teardown",
            json={"reason": "demo script finished"},
            headers=headers,
        )
        teardown.raise_for_status()
        print(f"Session status: {teardown.json()['status']}")

    banner("Evidence and outbox comment")
    evidence_dir = settings.evidence_root / session_body["id"]
    outbox_comments = sorted((settings.gitlab_outbox_dir / str(mr_iid)).glob("*.md"))
    print(f"Evidence bundle: {evidence_dir}")
    for artefact in sorted(evidence_dir.iterdir()):
        print(f"  - {artefact.name}")
    for outbox_comment in outbox_comments:
        print(f"\nOutbox comment: {outbox_comment}")
        print("-" * 70)
        print(outbox_comment.read_text())
        print("-" * 70)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
