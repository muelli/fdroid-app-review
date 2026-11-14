from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).parent))
import pcapdroid_by_app as pba  # noqa: E402
import test_quick_review_emulator as helpers  # noqa: E402


def _with_trailers(source: Path, destination: Path, apps: list[tuple[int, str]]) -> None:
    """Give each packet of `source` PCAPdroid's trailer, cycling through `apps`."""
    data = source.read_bytes()
    out, offset, index = bytearray(data[:24]), 24, 0
    while offset + 16 <= len(data):
        sec, usec, caplen, _ = struct.unpack("<IIII", data[offset : offset + 16])
        packet = data[offset + 16 : offset + 16 + caplen]
        offset += 16 + caplen
        uid, name = apps[index % len(apps)]
        index += 1
        trailer = (
            pba.MAGIC + struct.pack(">i", uid) + name.encode()[:19].ljust(20, b"\0") + b"\x00" * 4
        )
        packet += trailer
        out += struct.pack("<IIII", sec, usec, len(packet), len(packet)) + packet
    destination.write_bytes(bytes(out))


def test_packets_are_split_by_the_uid_in_their_trailer(tmp_path: Path) -> None:
    plain = tmp_path / "plain.pcap"
    helpers._dns_pcap(plain, [("a.example", 1.0), ("b.example", 2.0), ("c.example", 3.0)])
    tagged = tmp_path / "tagged.pcap"
    _with_trailers(
        tagged_source := plain, tagged, [(10125, "Google Play services"), (10200, "Mine")]
    )
    assert tagged_source == plain
    result = pba.split_by_app(tagged)
    assert set(result) == {10125, 10200}
    # The field is 20 bytes with a NUL, so 19 characters: the real capture said
    # "Google Play service" for "Google Play services".
    assert result[10125].name == "Google Play service"
    assert result[10125].packets == 2 and result[10200].packets == 1
    assert sorted(result[10125].names) == ["a.example", "c.example"]
    assert sorted(result[10200].names) == ["b.example"]


def test_a_name_longer_than_twenty_bytes_is_cut_so_the_uid_is_what_identifies_an_app(
    tmp_path: Path,
) -> None:
    plain = tmp_path / "p.pcap"
    helpers._dns_pcap(plain, [("a.example", 1.0)])
    tagged = tmp_path / "t.pcap"
    _with_trailers(plain, tagged, [(10125, "Google Play services (long name)")])
    assert pba.split_by_app(tagged)[10125].name == "Google Play service"


def test_packets_without_a_trailer_are_unattributed_not_dropped(tmp_path: Path) -> None:
    plain = tmp_path / "p.pcap"
    helpers._dns_pcap(plain, [("a.example", 1.0), ("b.example", 2.0)])
    result = pba.split_by_app(plain)
    assert set(result) == {pba.UNATTRIBUTED} and result[pba.UNATTRIBUTED].packets == 2
    assert sorted(result[pba.UNATTRIBUTED].names) == ["a.example", "b.example"]


def test_an_empty_file_is_no_traffic_and_the_command_says_so(
    tmp_path: Path, capsys: object
) -> None:
    empty = tmp_path / "e.pcap"
    empty.write_bytes(b"")
    assert pba.split_by_app(empty) == {}
    assert pba.main([str(empty)]) == 0
    assert "no packets" in capsys.readouterr().out  # type: ignore[attr-defined]


def test_the_command_prints_each_app_with_its_names(tmp_path: Path, capsys: object) -> None:
    plain = tmp_path / "p.pcap"
    helpers._dns_pcap(plain, [("a.example", 1.0)])
    tagged = tmp_path / "t.pcap"
    _with_trailers(plain, tagged, [(2000, "Shell")])
    assert pba.main([str(tagged)]) == 0
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "Shell (uid 2000): 1 packets" in out and "a.example" in out
