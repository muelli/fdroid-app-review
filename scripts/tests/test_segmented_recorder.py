"""Screen recording longer than screenrecord's 180 s limit: the control flow, without a device."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "quick_review.py"
if str(SCRIPT.parent) not in sys.path:
    sys.path.insert(0, str(SCRIPT.parent))
_spec = importlib.util.spec_from_file_location("quick_review", SCRIPT)
assert _spec is not None and _spec.loader is not None
qr = importlib.util.module_from_spec(_spec)
sys.modules["quick_review"] = qr
_spec.loader.exec_module(qr)


class FakeProc:
    """A screenrecord process: running until `ended`, then it has an exit status."""

    def __init__(self) -> None:
        self.ended = False
        self.killed = False

    def poll(self) -> int | None:
        return 0 if self.ended else None

    def wait(self, timeout: float | None = None) -> int:
        self.ended = True
        return 0

    def kill(self) -> None:
        self.killed = True
        self.ended = True


class Rig:
    def __init__(self, tmp_path: Path, *, start_ok: bool = True, pull_ok: bool = True) -> None:
        self.procs: list[FakeProc] = []
        self.pulled: list[Path] = []
        self.interrupts = 0
        self.warnings: list[str] = []
        self.start_ok, self.pull_ok = start_ok, pull_ok
        self.recorder = qr.SegmentedRecorder(
            self._start, self._pull, self._interrupt, tmp_path / "segments", self.warnings.append
        )

    def _start(self) -> FakeProc | None:
        if not self.start_ok:
            return None
        self.procs.append(FakeProc())
        return self.procs[-1]

    def _pull(self, path: Path) -> bool:
        if self.pull_ok:
            path.write_bytes(f"video {len(self.pulled)}".encode())
            self.pulled.append(path)
        return self.pull_ok

    def _interrupt(self) -> None:
        self.interrupts += 1
        self.procs[-1].ended = True  # SIGINT: screenrecord finalises and exits


def test_a_running_segment_is_left_alone(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.recorder.tick()
    rig.recorder.tick()
    assert len(rig.procs) == 1 and rig.pulled == []


def test_a_segment_that_ended_by_itself_is_kept_and_the_next_one_started(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.procs[0].ended = True
    rig.recorder.tick()
    assert len(rig.procs) == 2 and [p.name for p in rig.pulled] == ["segment-01.mp4"]
    rig.procs[1].ended = True
    rig.recorder.tick()
    assert [p.name for p in rig.recorder.segments] == ["segment-01.mp4", "segment-02.mp4"]


def test_finishing_early_stops_the_device_recorder_cleanly_not_by_killing_it(
    tmp_path: Path,
) -> None:
    rig = Rig(tmp_path)
    out = rig.recorder.finish(tmp_path / "screen_recording.mp4")
    assert rig.interrupts == 1 and not rig.procs[0].killed
    assert out == tmp_path / "screen_recording.mp4" and out.read_bytes() == b"video 0"


def test_finishing_after_the_segment_ended_needs_no_interrupt(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.procs[0].ended = True
    rig.recorder.finish(tmp_path / "screen_recording.mp4")
    assert rig.interrupts == 0 and len(rig.pulled) == 1


def test_a_recorder_that_never_started_gives_no_video_and_a_warning(tmp_path: Path) -> None:
    rig = Rig(tmp_path, start_ok=False)
    rig.recorder.tick()
    assert rig.recorder.finish(tmp_path / "screen_recording.mp4") is None
    assert any("did not start" in w for w in rig.warnings)


def test_a_segment_that_cannot_be_pulled_is_a_warning_not_a_crash(tmp_path: Path) -> None:
    rig = Rig(tmp_path, pull_ok=False)
    assert rig.recorder.finish(tmp_path / "screen_recording.mp4") is None
    assert any("could not pull" in w for w in rig.warnings)


def test_several_segments_without_ffmpeg_keep_the_first_and_say_so(
    tmp_path: Path, monkeypatch: object
) -> None:
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: None)  # type: ignore[attr-defined]
    segments = []
    for n in (1, 2):
        path = tmp_path / f"segment-0{n}.mp4"
        path.write_bytes(b"x")
        segments.append(path)
    warnings: list[str] = []
    assert qr.join_segments(segments, tmp_path / "out.mp4", warnings.append)
    assert (tmp_path / "out.mp4").exists() and segments[1].exists()
    assert "no ffmpeg" in warnings[0] and str(qr.SEGMENT_SECONDS) in warnings[0]


def test_ffmpeg_is_asked_to_copy_not_re_encode_in_order(
    tmp_path: Path, monkeypatch: object
) -> None:
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/ffmpeg")  # type: ignore[attr-defined]
    seen: list[list[str]] = []

    def fake_run(argv: list[str]) -> object:
        seen.append(argv)
        Path(argv[-1]).write_bytes(b"joined")
        listing = Path(argv[argv.index("-i") + 1]).read_text()
        assert listing.index("segment-01") < listing.index("segment-02")

        class Done:
            returncode = 0

        return Done()

    monkeypatch.setattr(qr, "run", fake_run)  # type: ignore[attr-defined]
    segments = []
    for n in (1, 2):
        path = tmp_path / f"segment-0{n}.mp4"
        path.write_bytes(b"x")
        segments.append(path)
    assert qr.join_segments(segments, tmp_path / "out.mp4", lambda m: None)
    assert "-c" in seen[0] and seen[0][seen[0].index("-c") + 1] == "copy"
    assert (tmp_path / "out.mp4").read_bytes() == b"joined"
