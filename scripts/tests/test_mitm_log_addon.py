from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mitm_log_addon as m  # noqa: E402


class Headers(dict[str, str]):
    def get(self, key: str, default: Any = None) -> Any:  # case-insensitive, like mitmproxy's
        for name, value in self.items():
            if name.lower() == key.lower():
                return value
        return default


def _flow(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    status: int | None = 200,
) -> Any:
    request = SimpleNamespace(
        method=method, pretty_url=url, headers=Headers(headers or {}), content=body,
        timestamp_start=1000.5,
    )  # fmt: skip
    response = SimpleNamespace(status_code=status) if status is not None else None
    return SimpleNamespace(request=request, response=response)


def test_the_full_url_with_its_query_is_kept_because_that_is_often_what_leaks() -> None:
    record = m.describe_request(
        _flow("https://nominatim.openstreetmap.org/search?q=Test+Room&format=jsonv2")
    )
    assert record["url"].endswith("/search?q=Test+Room&format=jsonv2")
    assert record["method"] == "GET" and record["status"] == 200 and record["ts"] == 1000.5


def test_secret_header_values_are_never_written_only_that_they_were_there() -> None:
    record = m.describe_request(
        _flow(
            "https://x.example/a",
            headers={
                "Authorization": "Bearer SECRET",
                "Cookie": "sid=SECRET",
                "User-Agent": "okhttp/4",
            },
        )
    )
    assert "SECRET" not in json.dumps(record)
    assert record["secret_headers_present"] == ["authorization", "cookie"]
    assert record["headers"] == {"user-agent": "okhttp/4"}
    assert {"authorization", "cookie", "user-agent"} <= set(record["header_names"])


def test_a_text_body_is_kept_up_to_a_limit_and_a_binary_one_only_counted() -> None:
    form = _flow(
        "https://x.example/a", method="POST", body=b"q=" + b"a" * 5000,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )  # fmt: skip
    record = m.describe_request(form)
    assert record["body"].startswith("q=aaa") and len(record["body"]) == m.MAX_BODY_CHARS
    assert record["body_bytes"] == 5002
    binary = _flow(
        "https://x.example/a", body=b"\x00\x01\x02", headers={"Content-Type": "image/png"}
    )
    assert (
        "body" not in m.describe_request(binary) and m.describe_request(binary)["body_bytes"] == 3
    )


def test_an_exchange_without_a_response_is_still_described() -> None:
    assert "status" not in m.describe_request(_flow("https://x.example/", status=None))


def test_a_tls_failure_is_logged_as_the_sign_of_pinning(tmp_path: Path) -> None:
    log = tmp_path / "log.jsonl"
    logger = m.Logger(str(log))
    data = SimpleNamespace(conn=SimpleNamespace(sni="api.example.org", error="unknown ca"))
    logger.tls_failed_client(data)
    logger.response(_flow("https://ok.example/"))
    lines = [json.loads(line) for line in log.read_text().splitlines()]
    assert lines[0]["event"] == "tls_failed" and lines[0]["sni"] == "api.example.org"
    assert "unknown ca" in lines[0]["error"] and lines[1]["event"] == "request"


def test_the_log_path_comes_from_the_environment(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setenv("MITM_LOG", str(tmp_path / "from-env.jsonl"))
    logger = m.Logger()
    logger.response(_flow("https://x.example/"))
    assert (tmp_path / "from-env.jsonl").exists()
