"""Flows in a capture, and the wording when an app has addresses but no names."""

from __future__ import annotations

import dataclasses
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pcap_flows  # noqa: E402
from test_quick_review_comment import _data, quick_review  # noqa: E402

PHONE, SERVER = bytes([192, 168, 118, 109]), bytes([192, 168, 118, 114])
TRAILER = b"\x01\x07\x20\x21" + b"\0" * 28  # PCAPdroid's per-packet trailer


def _tcp(src: bytes, dst: bytes, sport: int, dport: int, payload: int = 10) -> bytes:
    transport = (
        struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x18, 0, 0, 0) + b"x" * payload
    )
    total = 20 + len(transport)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0, src, dst)
    return b"\0" * 12 + b"\x08\x00" + ip + transport + TRAILER


def _pcap(path: Path, frames: list[bytes]) -> Path:
    body = b"".join(struct.pack("<IIII", 1, 0, len(f), len(f)) + f for f in frames)
    path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + body)
    return path


def test_the_remote_side_is_where_the_app_opened_the_connection_to(tmp_path: Path) -> None:
    frames = [_tcp(PHONE, SERVER, 40000, 2222), _tcp(SERVER, PHONE, 2222, 40000, 30)]
    frames += [_tcp(PHONE, SERVER, 40000, 2222)]
    flows = pcap_flows.summarise_flows(_pcap(tmp_path / "a.pcap", frames))
    assert [(f.proto, f.remote, f.port, f.packets) for f in flows] == [
        ("tcp", "192.168.118.114", 2222, 3)
    ]
    assert flows[0].endpoint == "192.168.118.114:2222"


def test_busiest_first_and_each_destination_counted_apart(tmp_path: Path) -> None:
    other = bytes([10, 0, 0, 7])
    frames = [_tcp(PHONE, other, 41000, 443)] + [_tcp(PHONE, SERVER, 40000, 2222)] * 3
    flows = pcap_flows.summarise_flows(_pcap(tmp_path / "b.pcap", frames))
    assert [f.endpoint for f in flows] == ["192.168.118.114:2222", "10.0.0.7:443"]


def test_unreadable_or_foreign_files_give_nothing_not_an_error(tmp_path: Path) -> None:
    assert pcap_flows.summarise_flows(tmp_path / "missing.pcap") == []
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"not a pcap at all, just text" * 4)
    assert pcap_flows.summarise_flows(junk) == []


def test_packets_that_are_not_tcp_or_udp_are_skipped(tmp_path: Path) -> None:
    icmp = (
        b"\0" * 12
        + b"\x08\x00"
        + struct.pack(">BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 1, 0, PHONE, SERVER)
        + b"\0" * 8
    )
    assert pcap_flows.summarise_flows(_pcap(tmp_path / "c.pcap", [icmp])) == []


def _app_data(tmp_path: Path, pcap: Path | None) -> object:
    base = _data(tmp_path, names=[], permissions=["android.permission.INTERNET"])
    return dataclasses.replace(base, network_state="app-filtered", pcap_path=pcap)


def test_no_names_but_traffic_is_not_reported_as_no_packets(tmp_path: Path) -> None:
    """Seen live: an SSH client's 1,339 packets to one address read as "recorded no packets"."""
    pcap = _pcap(tmp_path / "d.pcap", [_tcp(PHONE, SERVER, 40000, 2222)] * 5)
    comment = quick_review.build_review_comment(_app_data(tmp_path, pcap), 1)  # type: ignore[arg-type]
    row = next(line for line in comment.splitlines() if line.startswith("| Network endpoints"))
    assert "192.168.118.114:2222" in row and "TCP, 5 packets" in row
    assert "recorded no packets" not in row
    report = quick_review.build_report(_app_data(tmp_path, pcap))  # type: ignore[arg-type]
    assert "Direct addresses the app talked to" in report and "192.168.118.114:2222" in report


def test_no_capture_file_still_says_no_packets(tmp_path: Path) -> None:
    comment = quick_review.build_review_comment(_app_data(tmp_path, None), 1)  # type: ignore[arg-type]
    row = next(line for line in comment.splitlines() if line.startswith("| Network endpoints"))
    assert "none: PCAPdroid recorded no packets from the app" in row


def test_a_whole_emulator_capture_is_not_summarised_as_the_apps(tmp_path: Path) -> None:
    pcap = _pcap(tmp_path / "e.pcap", [_tcp(PHONE, SERVER, 40000, 2222)])
    data = dataclasses.replace(_app_data(tmp_path, pcap), network_state="windowed")  # type: ignore[type-var]
    assert quick_review._direct_flows(data) == []  # type: ignore[arg-type]
