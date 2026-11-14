import json
from pathlib import Path

from netpolicy.logger import write_network_log

SAMPLE_PCAP = Path(__file__).parent / "fixtures" / "sample.pcap"


def test_write_network_log_from_pcap(tmp_path: Path) -> None:
    output = tmp_path / "network_log.jsonl"
    result = write_network_log(SAMPLE_PCAP, output)
    assert result == output
    records = [json.loads(line) for line in output.read_text().splitlines()]
    assert any(
        r["type"] == "dns" and r["query_name"] == "f-droid.org" and "timestamp" in r
        for r in records
    )
    assert any(
        r["type"] == "tls_sni" and r["sni"] == "f-droid.org" and "timestamp" in r
        for r in records
    )


def test_write_network_log_missing_pcap_degrades_gracefully(tmp_path: Path) -> None:
    result = write_network_log(tmp_path / "does-not-exist.pcap", tmp_path / "out.jsonl")
    assert result is None


def test_write_network_log_unparsable_pcap_degrades_gracefully(tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.pcap"
    bogus.write_bytes(b"not a pcap")
    result = write_network_log(bogus, tmp_path / "out.jsonl")
    assert result is None


def _dns_pcap_with_times(path: Path, names_and_times: list[tuple[str, float]]) -> None:
    import struct

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


def test_write_network_log_window_keeps_only_events_inside_it(tmp_path: Path) -> None:
    pcap = tmp_path / "w.pcap"
    _dns_pcap_with_times(
        pcap,
        [
            ("boot.example", 100.0),
            ("edge-start.example", 200.0),
            ("during.example", 250.5),
            ("edge-end.example", 300.0),
            ("after.example", 400.0),
        ],
    )
    everything = write_network_log(pcap, tmp_path / "all.jsonl")
    assert everything is not None
    assert len(everything.read_text().splitlines()) == 5

    windowed = write_network_log(pcap, tmp_path / "w.jsonl", window=(200.0, 300.0))
    assert windowed is not None
    names = [json.loads(line)["query_name"] for line in windowed.read_text().splitlines()]
    assert names == ["edge-start.example", "during.example", "edge-end.example"]


def test_write_network_log_empty_window_writes_an_empty_log(tmp_path: Path) -> None:
    pcap = tmp_path / "w.pcap"
    _dns_pcap_with_times(pcap, [("only.example", 100.0)])
    result = write_network_log(pcap, tmp_path / "e.jsonl", window=(500.0, 600.0))
    assert result is not None
    assert result.read_text() == ""
