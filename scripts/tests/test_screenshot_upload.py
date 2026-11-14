from __future__ import annotations

import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import device_capture as dc  # noqa: E402
import screenshot_upload as su  # noqa: E402
import test_quick_review_crash as crash_helpers  # noqa: E402

PNG = dc.PNG_MAGIC + b"fake"


class _Service:
    """A transfer.sh look-alike on loopback; `answer` decides what it says."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.status = 200
        self.body: str | None = None  # None: a good link on this server
        self.delete: str | None = "good"

    def start(self) -> str:
        service = self

        class Handler(BaseHTTPRequestHandler):
            def do_PUT(self) -> None:  # noqa: N802
                length = int(self.headers["Content-Length"])
                service.requests.append(
                    {
                        "path": self.path,
                        "max_days": self.headers.get("Max-Days"),
                        "type": self.headers.get("Content-Type"),
                        "body": self.rfile.read(length),
                    }
                )
                base = f"http://127.0.0.1:{self.server.server_port}"
                text = service.body if service.body is not None else f"{base}/Ab12{self.path}\n"
                self.send_response(service.status)
                if service.delete == "good":
                    self.send_header("x-url-delete", f"{base}/Ab12{self.path}/secret")
                elif service.delete:
                    self.send_header("x-url-delete", service.delete)
                self.end_headers()
                self.wfile.write(text.encode())

            def log_message(self, *args: object) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.server.server_port}"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()  # otherwise the port still accepts and a client waits


@pytest.fixture
def service() -> Iterator[tuple[_Service, str]]:
    s = _Service()
    base = s.start()
    yield s, base
    s.stop()


def _png(tmp_path: Path, name: str = "screenshot-01.png", data: bytes = PNG) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_a_screenshot_is_put_with_its_retention_and_the_link_and_delete_url_come_back(
    tmp_path: Path, service: tuple[_Service, str]
) -> None:
    svc, base = service
    done = su.upload_png(_png(tmp_path), base, 7)
    req = svc.requests[0]
    assert req["path"] == "/screenshot-01.png" and req["max_days"] == "7"
    assert req["type"] == "image/png" and req["body"] == PNG
    assert done.url == f"{base}/Ab12/screenshot-01.png"
    assert done.delete_url == f"{base}/Ab12/screenshot-01.png/secret"


def test_only_a_real_png_is_ever_sent(tmp_path: Path, service: tuple[_Service, str]) -> None:
    svc, base = service
    for data in (b"just text", b"", dc.PNG_MAGIC + b"x" * (dc.MAX_SCREENSHOT_BYTES + 1)):
        with pytest.raises(su.UploadError, match="not a PNG"):
            su.upload_png(_png(tmp_path, data=data), base, 7)
    assert svc.requests == []


@pytest.mark.parametrize("base", ["http://example.org", "ftp://example.org", "example.org", ""])
def test_a_plaintext_or_odd_service_url_is_refused_before_anything_is_sent(
    tmp_path: Path, base: str
) -> None:
    with pytest.raises(su.UploadError, match="https"):
        su.upload_png(_png(tmp_path), base, 7)


@pytest.mark.parametrize("days", [0, -1, su.MAX_DAYS + 1])
def test_retention_must_be_sensible(
    tmp_path: Path, service: tuple[_Service, str], days: int
) -> None:
    with pytest.raises(su.UploadError, match="between 1 and"):
        su.upload_png(_png(tmp_path), service[1], days)
    assert service[0].requests == []


@pytest.mark.parametrize(
    "answer",
    [
        "Upload failed\n",
        "http://127.0.0.1:1/a\nsecond line",
        "http://evil.example/x.png",
        "javascript:alert(1)",
        "http://127.0.0.1:9/a b](http://evil.example)",
        "",
    ],
)
def test_an_answer_that_is_not_one_plain_link_on_the_service_is_refused(
    tmp_path: Path, service: tuple[_Service, str], answer: str
) -> None:
    svc, base = service
    svc.body = answer.replace("127.0.0.1:1", base.split("//")[1]).replace(
        "127.0.0.1:9", base.split("//")[1]
    )
    with pytest.raises(su.UploadError):
        su.upload_png(_png(tmp_path), base, 7)


def test_a_bad_delete_url_is_dropped_but_the_upload_stands(
    tmp_path: Path, service: tuple[_Service, str]
) -> None:
    svc, base = service
    svc.delete = "http://evil.example/delete"
    done = su.upload_png(_png(tmp_path), base, 7)
    assert done.url.startswith(base) and done.delete_url is None


def test_a_server_error_or_an_unreachable_service_is_a_message_not_a_crash(
    tmp_path: Path, service: tuple[_Service, str]
) -> None:
    svc, base = service
    svc.status = 500
    done, problems = su.upload_all([_png(tmp_path)], base, 7)
    assert done == [] and "upload failed" in problems[0]
    svc.stop()
    done, problems = su.upload_all([_png(tmp_path, "b.png")], base, 7)
    assert done == [] and len(problems) == 1


def test_upload_all_keeps_going_after_one_bad_file(
    tmp_path: Path, service: tuple[_Service, str]
) -> None:
    good, bad = _png(tmp_path, "a.png"), _png(tmp_path, "b.png", b"not a png")
    done, problems = su.upload_all([bad, good], service[1], 7)
    assert [d.name for d in done] == ["a.png"] and "b.png" in problems[0]


# ---- through quick_review ----------------------------------------------------------------


def _phone_argv(tmp_path: Path) -> list[str]:
    argv = crash_helpers._stub_toolchain(tmp_path, "")
    adb = Path(argv[argv.index("--adb-command") + 1])
    shot = tmp_path / "shot.png"
    shot.write_bytes(PNG)
    adb.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n  *install*) echo Success ;;\n'
        f"  *exec-out*screencap*) cat {shot} ;;\nesac\nexit 0\n"
    )
    return [*argv, "--duration", "3", "--screenshot-interval", "1"]


def test_nothing_is_uploaded_unless_asked(tmp_path: Path, service: tuple[_Service, str]) -> None:
    svc, base = service
    code, out, _ = crash_helpers._run([*_phone_argv(tmp_path), "--upload-url", base])
    assert code == 0 and svc.requests == [] and "Uploading" not in out
    assert not (tmp_path / "out" / "uploads.json").exists()


def test_uploaded_screenshots_are_linked_and_the_delete_urls_stay_local(
    tmp_path: Path, service: tuple[_Service, str]
) -> None:
    import json

    import test_quick_review_links as links

    svc, base = service
    argv = [*_phone_argv(tmp_path), "--upload-screenshots", "--upload-url", base]
    code, out, _ = crash_helpers._run([*argv, "--upload-days", "5"])
    out_dir = tmp_path / "out"
    assert code == 0 and svc.requests and svc.requests[0]["max_days"] == "5"
    assert "Uploading" in out and "for 5 days" in out and "Anyone with the link" in out
    saved = json.loads((out_dir / "uploads.json").read_text())
    assert saved[0]["url"].startswith(base) and saved[0]["delete_url"].endswith("/secret")
    assert (out_dir / "uploads.json").stat().st_mode & 0o077 == 0  # owner only
    comment = (out_dir / "review_comment.md").read_text()
    assert "/secret" not in comment and "/secret" not in (out_dir / "report.md").read_text()
    row = links._rows(comment)["Screenshots"]
    assert f"[screenshot 1]({saved[0]['url']})" in row and "may expire" in row


def test_a_failed_upload_warns_and_the_screenshots_stay_local(tmp_path: Path) -> None:
    argv = [*_phone_argv(tmp_path), "--upload-screenshots", "--upload-url", "http://127.0.0.1:1"]
    code, _, err = crash_helpers._run(argv)
    assert code == 0 and "could not upload" in err
    row = __import__("test_quick_review_links")._rows(
        (tmp_path / "out" / "review_comment.md").read_text()
    )["Screenshots"]
    assert "saved in `screenshots/`" in row


def test_the_upload_options_are_checked_up_front() -> None:
    for bad in (
        ["--upload-screenshots", "--screenshot-interval", "0"],
        ["--upload-screenshots", "--upload-url", "http://example.org"],
        ["--upload-screenshots", "--upload-days", "0"],
    ):
        with pytest.raises(SystemExit):
            crash_helpers.qr.parse_args(["--apk", "a.apk", *bad])


# ---- the screen recording ------------------------------------------------------------------

MP4 = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom" + b"\x00" * 64


def _mp4(tmp_path: Path, name: str = "screen_recording.mp4", data: bytes = MP4) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_a_recording_is_streamed_with_its_length_type_and_retention(
    tmp_path: Path, service: tuple[_Service, str]
) -> None:
    svc, base = service
    done = su.upload_mp4(_mp4(tmp_path), base, 9)
    req = svc.requests[0]
    assert req["path"] == "/screen_recording.mp4" and req["max_days"] == "9"
    assert req["type"] == "video/mp4" and req["body"] == MP4
    assert done.url == f"{base}/Ab12/screen_recording.mp4" and done.delete_url.endswith("/secret")


@pytest.mark.parametrize("data", [b"", b"just text, not a video", b"\x89PNG\r\n\x1a\n" + b"x" * 40])
def test_only_an_mp4_is_ever_sent_as_the_recording(
    tmp_path: Path, service: tuple[_Service, str], data: bytes
) -> None:
    with pytest.raises(su.UploadError, match="not an MP4"):
        su.upload_mp4(_mp4(tmp_path, data=data), service[1], 7)
    assert service[0].requests == []


def test_a_recording_over_the_size_cap_is_refused_before_anything_is_sent(
    tmp_path: Path, service: tuple[_Service, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(su, "MAX_VIDEO_BYTES", 50)
    with pytest.raises(su.UploadError, match="at most"):
        su.upload_mp4(_mp4(tmp_path), service[1], 7)
    assert service[0].requests == []


def test_a_recording_to_a_plaintext_service_is_refused(tmp_path: Path) -> None:
    with pytest.raises(su.UploadError, match="https"):
        su.upload_mp4(_mp4(tmp_path), "http://example.org", 7)


def _video_argv(tmp_path: Path) -> list[str]:
    """A stub phone whose screenrecord produces a real MP4 header and which hands it over."""
    argv = crash_helpers._stub_toolchain(tmp_path, "")
    adb = Path(argv[argv.index("--adb-command") + 1])
    movie = tmp_path / "movie.mp4"
    movie.write_bytes(MP4)
    log = tmp_path / "adb-calls.log"
    adb.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> {log}\n'
        "for last; do :; done\n"
        'case "$*" in\n  *install*) echo Success ;;\n'
        f'  *pull*quick_review_recording*) cp {movie} "$last" ;;\n'
        "esac\nexit 0\n"
    )
    return [*argv, "--duration", "2", "--screenshot-interval", "0"]


def test_the_recording_is_uploaded_linked_and_its_delete_link_stays_local(
    tmp_path: Path, service: tuple[_Service, str]
) -> None:
    import json

    import test_quick_review_links as links

    svc, base = service
    argv = [*_video_argv(tmp_path), "--upload-video", "--upload-url", base, "--upload-days", "4"]
    code, out, _ = crash_helpers._run(argv)
    out_dir = tmp_path / "out"
    assert code == 0 and svc.requests and svc.requests[0]["type"] == "video/mp4"
    assert svc.requests[0]["max_days"] == "4"
    assert "Uploading the screen recording" in out and "Anyone with the link can watch" in out
    saved = json.loads((out_dir / "uploads.json").read_text())
    assert saved[-1]["name"] == "screen_recording.mp4" and saved[-1]["delete_url"].endswith(
        "/secret"
    )
    assert (out_dir / "uploads.json").stat().st_mode & 0o077 == 0
    comment = (out_dir / "review_comment.md").read_text()
    row = links._rows(comment)["Screen recording"]
    assert f"[recording]({saved[-1]['url']})" in row and "will expire" in row
    assert "/secret" not in comment and "/secret" not in (out_dir / "report.md").read_text()
    assert saved[-1]["url"] in (out_dir / "report.md").read_text()


def test_nothing_of_the_recording_is_uploaded_unless_asked(
    tmp_path: Path, service: tuple[_Service, str]
) -> None:
    svc, base = service
    code, out, _ = crash_helpers._run([*_video_argv(tmp_path), "--upload-url", base])
    assert code == 0 and svc.requests == []
    assert "Uploading the screen recording" not in out
    assert not (tmp_path / "out" / "uploads.json").exists()


def test_a_failed_recording_upload_warns_and_the_file_stays_local(tmp_path: Path) -> None:
    argv = [*_video_argv(tmp_path), "--upload-video", "--upload-url", "http://127.0.0.1:1"]
    code, _, err = crash_helpers._run(argv)
    assert code == 0 and "could not upload the screen recording" in err
    assert (tmp_path / "out" / "screen_recording.mp4").exists()
    assert "Screen recording" not in __import__("test_quick_review_links")._rows(
        (tmp_path / "out" / "review_comment.md").read_text()
    )


def test_screenshots_and_the_recording_share_one_uploads_file(
    tmp_path: Path, service: tuple[_Service, str]
) -> None:
    import json

    svc, base = service
    argv = _video_argv(tmp_path)
    shot = tmp_path / "shot.png"
    shot.write_bytes(PNG)
    adb = Path(argv[argv.index("--adb-command") + 1])
    adb.write_text(
        adb.read_text().replace(
            'case "$*" in', f'case "$*" in\n  *exec-out*screencap*) cat {shot} ;;', 1
        )
    )
    argv = [
        *argv,
        "--screenshot-interval",
        "1",
        "--duration",
        "3",
        "--upload-screenshots",
        "--upload-video",
        "--upload-url",
        base,
    ]
    code, _, _ = crash_helpers._run(argv)
    names = [e["name"] for e in json.loads((tmp_path / "out" / "uploads.json").read_text())]
    assert code == 0 and names[-1] == "screen_recording.mp4"
    assert any(n.endswith(".png") for n in names[:-1])  # the screenshots were not overwritten


def test_the_bit_rate_reaches_screenrecord_and_uploading_lowers_it_by_default(
    tmp_path: Path, service: tuple[_Service, str]
) -> None:
    calls = tmp_path / "adb-calls.log"
    crash_helpers._run([*_video_argv(tmp_path), "--video-bit-rate", "8"])
    assert "screenrecord --bit-rate 8000000 --time-limit" in calls.read_text()
    calls.unlink()
    crash_helpers._run([*_video_argv(tmp_path), "--upload-video", "--upload-url", service[1]])
    assert "--bit-rate 4000000" in calls.read_text()
    calls.unlink()
    crash_helpers._run(_video_argv(tmp_path))
    assert "--bit-rate" not in calls.read_text()  # the device's own default otherwise


def test_the_video_options_are_checked_up_front() -> None:
    for bad in (
        ["--video-bit-rate", "0"],
        ["--video-bit-rate", "500"],
        ["--upload-video", "--upload-url", "http://example.org"],
        ["--upload-video", "--upload-days", "0"],
    ):
        with pytest.raises(SystemExit):
            crash_helpers.qr.parse_args(["--apk", "a.apk", *bad])
