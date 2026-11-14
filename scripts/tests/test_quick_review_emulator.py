from __future__ import annotations

import importlib.util
import io
import json
import struct
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "quick_review.py"


def _load() -> object:
    existing = sys.modules.get("quick_review")
    if existing is not None:
        return existing
    # quick_review imports its sibling modules (device_capture, screenshot_upload, ...) the way
    # it does when run as a script, with scripts/ first on the path. Without this, this file
    # only imported cleanly when another test had already put the directory there.
    if str(SCRIPT.parent) not in sys.path:
        sys.path.insert(0, str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("quick_review", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["quick_review"] = module
    spec.loader.exec_module(module)
    return module


qr = _load()


@pytest.fixture(autouse=True)
def _restore_adb(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(qr, "ADB", ["adb"])


def _stub_adb(tmp_path: Path) -> tuple[Path, Path]:
    log = tmp_path / "adb-calls.log"
    stub = tmp_path / "stub-adb"
    stub.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> {log}\n'
        'case "$*" in\n'
        '  *install*) echo Success ;;\n'
        "esac\n"
        "exit 0\n"
    )
    stub.chmod(0o755)
    return stub, log


def _dns_pcap(path: Path, names_and_times: list[tuple[str, float]]) -> None:
    def qname(name: str) -> bytes:
        labels = [struct.pack(">B", len(p)) + p.encode("ascii") for p in name.split(".")]
        return b"".join(labels) + b"\x00"

    def frame(name: str) -> bytes:
        dns = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        dns += qname(name) + struct.pack(">HH", 1, 1)
        udp = struct.pack(">HHHH", 54321, 53, 8 + len(dns), 0)
        src, dst = bytes([10, 1, 2, 3]), bytes([8, 8, 8, 8])
        ip = struct.pack(
            ">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp) + len(dns), 0, 0, 64, 17, 0, src, dst
        )
        ethernet = bytes.fromhex("bbbbbbbbbbbb") + bytes.fromhex("aaaaaaaaaaaa") + b"\x08\x00"
        return ethernet + ip + udp + dns

    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for name, ts in names_and_times:
        data = frame(name)
        sec = int(ts)
        header = struct.pack("<IIII", sec, int((ts - sec) * 1_000_000), len(data), len(data))
        out += header + data
    path.write_bytes(out)


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = qr.main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def _review(tmp_path: Path, *extra: str) -> tuple[Path, Path, int, str]:
    stub, log = _stub_adb(tmp_path)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"x")
    out_dir = tmp_path / "out"
    code, stdout, _ = _run(
        [
            "--apk", str(apk), "--package", "org.example.app", "--serial", "emulator-5554",
            "--duration", "1", "--output-dir", str(out_dir),
            "--adb-command", f"{stub} NAMESPACE-MARKER", *extra,
        ]
    )  # fmt: skip
    return out_dir, log, code, stdout


def test_every_adb_call_goes_through_the_prefix(tmp_path: Path) -> None:
    _, log, code, _ = _review(tmp_path)
    assert code == 0
    calls = log.read_text().splitlines()
    assert len(calls) >= 6, calls
    assert all(call.startswith("NAMESPACE-MARKER ") for call in calls), calls
    joined = "\n".join(calls)
    for expected in ("install", "logcat", "screenrecord", "pidof", "resolve-activity"):
        assert expected in joined, f"no {expected!r} call went through the prefix"


def test_adb_prefix_with_quoting_is_split_like_a_shell(tmp_path: Path) -> None:
    stub, log = _stub_adb(tmp_path)
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"x")
    _run(["--apk", str(apk), "--package", "a.b", "--serial", "s", "--duration", "1",
          "--output-dir", str(tmp_path / "o"),
          "--adb-command", f"{stub} 'two words' plain"])  # fmt: skip
    first = log.read_text().splitlines()[0]
    assert first.startswith("two words plain ")


def test_unparsable_or_empty_adb_command_is_refused(tmp_path: Path) -> None:
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"x")
    for bad in ("'unterminated", "  "):
        code, _, err = _run(["--apk", str(apk), "--package", "a.b", "--adb-command", bad])
        assert code == 1 and "--adb-command" in err


def test_external_pcap_review_is_pending_and_writes_no_checklist(tmp_path: Path) -> None:
    pcap = tmp_path / "session.pcap"
    _dns_pcap(pcap, [("not-read-yet.example", 1.0)])
    out_dir, _, code, stdout = _review(tmp_path, "--external-pcap", str(pcap), "--mr-iid", "7")
    assert code == 0
    assert (out_dir / "review_state.json").exists()
    assert not (out_dir / "review_comment.md").exists()
    assert not (out_dir / "network_log.jsonl").exists()
    assert "pending" in (out_dir / "report.md").read_text()
    assert "--finalize" in stdout
    assert "not-read-yet.example" not in (out_dir / "report.html").read_text()


def test_finalize_keeps_only_the_review_window_and_writes_the_checklist(tmp_path: Path) -> None:
    pcap = tmp_path / "session.pcap"
    _dns_pcap(pcap, [("boot.example", 1.0)])
    out_dir, _, code, _ = _review(tmp_path, "--external-pcap", str(pcap), "--mr-iid", "7")
    assert code == 0
    state = json.loads((out_dir / "review_state.json").read_text())["report"]
    start = datetime.fromisoformat(state["started_at"])
    end = datetime.fromisoformat(state["ended_at"])
    _dns_pcap(
        pcap,
        [
            ("boot.example", (start - timedelta(seconds=90)).timestamp()),
            ("during.example", (start + (end - start) / 2).timestamp()),
            ("just-after.example", (end + timedelta(seconds=1)).timestamp()),
            ("long-after.example", (end + timedelta(seconds=60)).timestamp()),
        ],
    )

    code, stdout, _ = _run(["--finalize", str(out_dir)])
    assert code == 0 and "Network evidence added" in stdout
    names = [json.loads(line)["query_name"] for line in (out_dir / "network_log.jsonl").open()]
    assert names == ["during.example", "just-after.example"]
    report = (out_dir / "report.md").read_text()
    assert "pending" not in report
    assert "whole session" in report or "whole emulator session" in report
    assert "during.example" in report and "boot.example" not in report
    assert "nothing here is attributed to the app" in report
    comment = (out_dir / "review_comment.md").read_text()
    assert "!7" in comment and "during.example" in comment
    assert "not captured" not in comment
    assert "whole emulator, system traffic included" in comment
    assert "nothing here is attributed to the app" in (out_dir / "report.html").read_text()

    first = (out_dir / "network_log.jsonl").read_text()
    assert _run(["--finalize", str(out_dir)])[0] == 0
    assert (out_dir / "network_log.jsonl").read_text() == first


def test_finalize_without_a_readable_pcap_says_so(tmp_path: Path) -> None:
    pcap = tmp_path / "session.pcap"
    _dns_pcap(pcap, [("x.example", 1.0)])
    out_dir, _, _, _ = _review(tmp_path, "--external-pcap", str(pcap), "--mr-iid", "7")
    pcap.unlink()
    code, _, _ = _run(["--finalize", str(out_dir)])
    assert code == 0
    assert "missing or unreadable" in (out_dir / "report.md").read_text()
    assert "not captured in this run" in (out_dir / "review_comment.md").read_text()


def test_finalize_refuses_a_directory_that_is_not_a_review(tmp_path: Path) -> None:
    code, _, err = _run(["--finalize", str(tmp_path)])
    assert code == 1 and "review_state.json" in err


def test_finalize_refuses_a_review_that_had_no_external_pcap(tmp_path: Path) -> None:
    out_dir, _, code, _ = _review(tmp_path)
    assert code == 0 and not (out_dir / "review_state.json").exists()
    code, _, err = _run(["--finalize", str(out_dir)])
    assert code == 1 and "review_state.json" in err


def test_state_round_trips_exactly(tmp_path: Path) -> None:
    pcap = tmp_path / "s.pcap"
    _dns_pcap(pcap, [("x.example", 1.0)])
    out_dir, _, _, _ = _review(tmp_path, "--external-pcap", str(pcap), "--mr-iid", "9")
    text = (out_dir / "review_state.json").read_text()
    data, mr_iid = qr.load_state(text)
    assert mr_iid == 9
    assert qr.dump_state(data, mr_iid) == text
    assert data.network_state == "pending" and data.pcap_path == pcap


def test_argument_combinations_are_checked() -> None:
    with pytest.raises(SystemExit):
        qr.parse_args(["--apk", "a.apk", "--external-pcap", "p", "--capture-interface", "any"])
    with pytest.raises(SystemExit):
        qr.parse_args([])
    assert qr.parse_args(["--finalize", "somewhere"]).finalize == Path("somewhere")


def test_permissions_are_granted_at_install_unless_told_not_to(tmp_path: Path) -> None:
    _, log, code, _ = _review(tmp_path)
    assert code == 0
    install = next(line for line in log.read_text().splitlines() if " install " in f" {line} ")
    assert " -g " in f" {install} "

    other = tmp_path / "second"
    other.mkdir()
    _, log2, code2, _ = _review(other, "--no-grant-permissions")
    assert code2 == 0
    install2 = next(line for line in log2.read_text().splitlines() if " install " in f" {line} ")
    assert " -g " not in f" {install2} " and " -r " in f" {install2} "


# ---- --monkey ---------------------------------------------------------------------------------


def test_monkey_is_off_unless_asked_for(tmp_path: Path) -> None:
    out_dir, log, code, _ = _review(tmp_path)
    assert code == 0 and " shell monkey " not in log.read_text()
    assert "**Input**" not in (out_dir / "report.md").read_text()


def test_monkey_is_confined_seeded_and_stopped_on_the_device(tmp_path: Path) -> None:
    out_dir, log, code, stdout = _review(tmp_path, "--monkey")
    calls = log.read_text().splitlines()
    assert code == 0 and "pseudo-random input" in stdout
    start = next(c for c in calls if " shell monkey " in c)
    assert " -p org.example.app " in start and " -s 1 " in start
    for off in ("--pct-syskeys 0", "--pct-appswitch 0", "--pct-nav 0", "--pct-majornav 0"):
        assert off in start  # it must not be able to leave the app
    stop = next(i for i, c in enumerate(calls) if "shell pkill -f com.android.commands.monkey" in c)
    assert calls.index(start) < stop
    assert (out_dir / "monkey.txt").exists()


def test_the_report_and_checklist_say_the_input_was_random(tmp_path: Path) -> None:
    out_dir, _, _, _ = _review(tmp_path, "--monkey", "--mr-iid", "7")
    assert "- **Input**: seeded pseudo-random touches" in (out_dir / "report.md").read_text()
    comment = (out_dir / "review_comment.md").read_text()
    assert "Input during the run" in comment and "not a test of anything" in comment


def test_the_event_count_fills_the_window() -> None:
    assert qr.monkey_events(30) == 60 and qr.monkey_events(0) == 1


def test_the_app_is_started_the_way_a_launcher_starts_it(tmp_path: Path) -> None:
    """A bare `am start -n` plus a later launcher-style start made two MainActivity instances, and
    an app with a DataStore per activity crashed: a crash no user can get.
    """
    stub, log = _stub_adb(tmp_path)
    stub.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> {log}\n'
        'case "$*" in\n'
        "  *resolve-activity*) echo priority=0; echo org.example.app/.MainActivity ;;\n"
        "  *install*) echo Success ;;\n"
        "esac\n"
        "exit 0\n"
    )
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"x")
    code, _, _ = _run(
        [
            "--apk", str(apk), "--package", "org.example.app", "--serial", "emulator-5554",
            "--duration", "1", "--output-dir", str(tmp_path / "out"),
            "--adb-command", f"{stub} NAMESPACE-MARKER",
        ]
    )  # fmt: skip
    start = next(c for c in log.read_text().splitlines() if " shell am start " in c)
    assert code == 0
    assert "-a android.intent.action.MAIN" in start
    assert "-c android.intent.category.LAUNCHER" in start
    assert "-f 0x10200000" in start and "-n org.example.app/.MainActivity" in start


def test_a_stop_file_ends_the_recording_early_and_the_report_says_how_long(tmp_path: Path) -> None:
    import time

    stop = tmp_path / "stop"
    stop.write_text("")
    began = time.monotonic()
    out_dir, _, code, _ = _review(tmp_path, "--stop-file", str(stop), "--duration", "120")
    assert code == 0 and time.monotonic() - began < 60
    report = (out_dir / "report.md").read_text()
    assert "**Duration**: 120s" not in report and "**Duration**:" in report


def test_without_a_stop_file_the_whole_duration_is_recorded(tmp_path: Path) -> None:
    out_dir, _, code, _ = _review(tmp_path)
    assert code == 0 and "**Duration**: 1s" in (out_dir / "report.md").read_text()
