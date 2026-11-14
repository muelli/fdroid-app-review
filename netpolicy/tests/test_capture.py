import shutil
from pathlib import Path

import pytest
from netpolicy.capture import PassiveCapture


def test_unavailable_when_binary_missing() -> None:
    capture = PassiveCapture(tcpdump_binary="definitely-not-a-real-binary-xyz")
    assert capture.available() is False


def test_start_returns_false_when_binary_missing(tmp_path: Path) -> None:
    capture = PassiveCapture(tcpdump_binary="definitely-not-a-real-binary-xyz")
    started = capture.start("eth0", tmp_path / "out.pcap")
    assert started is False
    assert capture.last_error is not None


def test_stop_without_start_does_not_raise() -> None:
    capture = PassiveCapture(tcpdump_binary="definitely-not-a-real-binary-xyz")
    capture.stop()  # must not raise


class _FakeProcess:
    """Stays "running" (`poll()` returns `None`) unless told to have
    already exited, matching what `subprocess.Popen` looks like from the
    outside in each case `PassiveCapture.start` has to distinguish.
    """

    def __init__(self, *, exited_with: int | None = None, stderr: bytes = b"") -> None:
        self.returncode = exited_with
        self._stderr = stderr
        self.terminated = False

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True


def _patch_popen(monkeypatch: pytest.MonkeyPatch, process: _FakeProcess) -> list[list[str]]:
    real_tcpdump = shutil.which("tcpdump") or "/usr/sbin/tcpdump"
    monkeypatch.setattr("netpolicy.capture.shutil.which", lambda _: real_tcpdump)
    monkeypatch.setattr("netpolicy.capture.time.sleep", lambda _: None)
    recorded: list[list[str]] = []

    def fake_popen(command: list[str], *, stderr: object, **kwargs: object) -> _FakeProcess:
        recorded.append(command)
        stderr.write(process._stderr)  # type: ignore[attr-defined]
        return process

    monkeypatch.setattr("netpolicy.capture.subprocess.Popen", fake_popen)
    return recorded


def test_start_uses_packet_buffered_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _patch_popen(monkeypatch, _FakeProcess())
    capture = PassiveCapture(tcpdump_binary="tcpdump")
    started = capture.start("eth0", tmp_path / "out.pcap")

    assert started is True
    assert recorded == [["tcpdump", "-U", "-i", "eth0", "-w", str(tmp_path / "out.pcap")]]


def test_start_wraps_in_netns_when_given(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _patch_popen(monkeypatch, _FakeProcess())
    capture = PassiveCapture(tcpdump_binary="tcpdump")
    capture.start("eth0", tmp_path / "out.pcap", netns="fdroid-sess1")

    pcap_path = str(tmp_path / "out.pcap")
    assert recorded == [
        ["ip", "netns", "exec", "fdroid-sess1", "tcpdump", "-U", "-i", "eth0", "-w", pcap_path]
    ]


def test_start_returns_false_when_tcpdump_exits_immediately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `Popen` call succeeding only means the process launched, not that
    tcpdump is actually capturing: confirmed the hard way that tcpdump
    exits almost immediately on a permissions error or an unknown
    interface, with `Popen` reporting no failure at all. `start()` must
    catch this rather than reporting success for a capture that never ran.
    """
    error = b"tcpdump: eth0: You don't have permission to perform this capture\n"
    _patch_popen(monkeypatch, _FakeProcess(exited_with=1, stderr=error))
    capture = PassiveCapture(tcpdump_binary="tcpdump")

    started = capture.start("eth0", tmp_path / "out.pcap")

    assert started is False
    assert capture.last_error is not None
    assert "permission" in capture.last_error


def test_start_wraps_with_nsenter_when_target_pid_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The precise-isolation path for a plain Docker container (e.g. a
    redroid sibling), which already has its own network namespace with
    nothing to name or provision — join the namespace of a process already
    in it (the container's own PID 1) instead of a named `ip netns`
    namespace. See `scripts/quick_review.py --capture-container`.
    """
    recorded = _patch_popen(monkeypatch, _FakeProcess())
    capture = PassiveCapture(tcpdump_binary="tcpdump")
    capture.start("any", tmp_path / "out.pcap", target_pid=4242)

    pcap_path = str(tmp_path / "out.pcap")
    assert recorded == [
        [
            "nsenter",
            "--target",
            "4242",
            "--net",
            "--",
            "tcpdump",
            "-U",
            "-i",
            "any",
            "-w",
            pcap_path,
        ]
    ]


def test_start_rejects_both_netns_and_target_pid(tmp_path: Path) -> None:
    capture = PassiveCapture(tcpdump_binary="tcpdump")
    with pytest.raises(ValueError, match="mutually exclusive"):
        capture.start("any", tmp_path / "out.pcap", netns="fdroid-sess1", target_pid=4242)
