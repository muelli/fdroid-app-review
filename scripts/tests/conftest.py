from __future__ import annotations

import sys
from typing import Any

import pytest


@pytest.fixture(autouse=True)
def _no_real_code_quality_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fetcher asks GitLab for each merge request's Code Quality report. Tests must
    never reach the network, so by default there is "no report"; a test that wants one
    sets its own.
    """
    module: Any = sys.modules.get("fetch_review_queue")
    if module is not None:
        if not hasattr(module, "real_fetch_code_quality"):
            module.real_fetch_code_quality = module.fetch_code_quality
        monkeypatch.setattr(module, "fetch_code_quality", lambda iid: None)
