from __future__ import annotations

import io
import json
import sys
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import test_fetch_review_queue as base  # noqa: E402  (loads fetch_review_queue once)

frq = base.frq
TOKEN = "glpat-test-0000000000000000000000"
API = "https://gitlab.com/api/v4/projects/84901782/pipelines?per_page=5"
JOB_LOG = "https://gitlab.com/some/fork/-/jobs/9/raw"
ARTIFACT = "https://gitlab.com/some/fork/-/jobs/9/artifacts/raw/tmp/binaries/a.apk"


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    frq._DENIED_ENDPOINTS.clear()
    yield
    frq._DENIED_ENDPOINTS.clear()


def _http_error(code: int, body: dict[str, str] | None = None) -> urllib.error.HTTPError:
    data = json.dumps(body).encode() if body is not None else b""
    return urllib.error.HTTPError("https://x", code, "err", Message(), io.BytesIO(data))


def _script_open(
    monkeypatch: pytest.MonkeyPatch, outcomes: list[Any]
) -> list[urllib.request.Request]:
    seen: list[urllib.request.Request] = []

    def fake_open(request: urllib.request.Request, timeout: float) -> Any:
        seen.append(request)
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return base._Response(outcome)

    monkeypatch.setattr(frq, "_open", fake_open)
    return seen


def test_the_token_goes_to_the_api_and_only_the_api(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", TOKEN)
    seen = _script_open(monkeypatch, [b"[]", b"log", b"apk"])
    frq.http_get_bytes(API)
    frq.http_get_bytes(JOB_LOG)
    frq.http_get_bytes(ARTIFACT)
    assert [r.get_header("Private-token") for r in seen] == [TOKEN, None, None]


def test_no_token_means_no_header(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _script_open(monkeypatch, [b"[]"])
    frq.http_get_bytes(API)
    assert seen[0].get_header("Private-token") is None


def test_a_blank_token_is_treated_as_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", "   ")
    seen = _script_open(monkeypatch, [b"[]"])
    frq.http_get_bytes(API)
    assert seen[0].get_header("Private-token") is None


def test_a_redirect_off_the_api_drops_the_token() -> None:
    handler = frq._StripTokenOnRedirect()
    request = urllib.request.Request(API, headers={"PRIVATE-TOKEN": TOKEN})
    elsewhere = handler.redirect_request(
        request, None, 302, "Found", Message(), "https://storage.example/object?sig=1"
    )
    assert elsewhere is not None and "Private-token" not in elsewhere.headers
    same_api = handler.redirect_request(
        request, None, 302, "Found", Message(), "https://gitlab.com/api/v4/projects/2/pipelines"
    )
    assert same_api is not None and same_api.headers["Private-token"] == TOKEN


def test_a_rejected_token_stops_with_a_clear_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", TOKEN)
    _script_open(monkeypatch, [_http_error(401, {"message": "401 Unauthorized"})])
    with pytest.raises(frq.AuthRejected) as caught:
        frq.http_get_bytes(API)
    assert "HTTP 401" in str(caught.value) and "expired or revoked" in str(caught.value)
    assert TOKEN not in str(caught.value)


def test_missing_permission_falls_back_to_no_token_and_says_what_is_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", TOKEN)
    denied = _http_error(
        403,
        {
            "error": "insufficient_granular_scope",
            "error_description": "requires the project permissions: [Pipeline: Read].",
        },
    )
    jobs = "https://gitlab.com/api/v4/projects/84901782/pipelines/5/jobs?per_page=100"
    seen = _script_open(monkeypatch, [denied, b"[]", b"[]"])
    assert frq.http_get_bytes(jobs) == b"[]"
    assert [r.get_header("Private-token") for r in seen] == [TOKEN, None]
    err = capsys.readouterr().err
    assert "Pipeline: Read" in err and TOKEN not in err

    # The same endpoint, another project and pipeline: no second refused attempt.
    other = "https://gitlab.com/api/v4/projects/111/pipelines/222/jobs?per_page=100"
    frq.http_get_bytes(other)
    assert seen[-1].get_header("Private-token") is None
    assert len(seen) == 3
    assert capsys.readouterr().err == ""


def test_other_403s_are_not_mistaken_for_a_permission_problem(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", TOKEN)
    _script_open(monkeypatch, [_http_error(403, {"message": "403 Forbidden"})])
    with pytest.raises(urllib.error.HTTPError):
        frq.http_get_bytes(API)
    assert not frq._DENIED_ENDPOINTS


def test_rate_limit_wording_says_whether_a_token_was_in_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", TOKEN)
    headers = Message()
    headers["Retry-After"] = "3000"
    _script_open(
        monkeypatch,
        [urllib.error.HTTPError("https://x", 429, "Too Many", headers, io.BytesIO(b""))],
    )
    with pytest.raises(frq.RateLimited) as caught:
        frq.http_get_bytes(API)
    assert "rate limiting this token" in caught.value.describe()
    assert "unauthenticated" not in caught.value.describe()
    assert "this IP (unauthenticated traffic)" not in frq.RateLimited(5.0).describe()
    assert "carried no token" in frq.RateLimited(5.0).describe()
    monkeypatch.delenv("GITLAB_TOKEN")
    assert "this IP (unauthenticated traffic)" in frq.RateLimited(5.0).describe()


@pytest.mark.parametrize(
    "failure", [frq.AuthRejected("GitLab rejected GITLAB_TOKEN (HTTP 401): it may be expired"),
                frq.RateLimited(3000.0, authenticated=True)]
)  # fmt: skip
def test_the_token_never_reaches_any_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: Exception
) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", TOKEN)
    monkeypatch.setattr(frq, "fetch_all_open_review_mrs", lambda **_: base._mrs(3))

    def resolve(project_id: int, *, stderr: Any = None) -> Any:
        raise failure

    monkeypatch.setattr(frq, "resolve_apk_urls", resolve)
    out, err = io.StringIO(), io.StringIO()
    code = frq.main(["--limit", "3", "--output-dir", str(tmp_path)], stdout=out, stderr=err)
    assert code == 0
    assert "Using GITLAB_TOKEN" in out.getvalue()
    everything = out.getvalue() + err.getvalue()
    everything += "".join(p.read_text() for p in tmp_path.iterdir() if p.is_file())
    assert TOKEN not in everything
    statuses = [e["apk_status"] for e in json.loads((tmp_path / "index.json").read_text())]
    assert all(s.startswith("not checked:") for s in statuses)
