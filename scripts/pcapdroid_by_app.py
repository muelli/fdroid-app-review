"""Who sent what: split a PCAPdroid capture by app, using the trailer it adds to every packet.

PCAPdroid, started with `dump_extensions`, appends 32 bytes to each packet: the magic
0x01072021, the sending app's uid (a big-endian int32), its name in 20 bytes (so at most 19
characters, NUL-terminated), and a 4-byte checksum field. Seen on PCAPdroid 2.0.2 (Ethernet
frames, link type 1); the layout is from that output, not from a specification I checked.
Packets PCAPdroid could not attribute carry uid -1.

Match on the uid, not the name: the name is truncated and not unique (a real capture showed
"Google Play service" for "Google Play services"). Typical use: capture an
emulator with no app filter and see which apps were chatty (that is how the baseline of a stock
Android 14 emulator was traced to Play services, the Google app, YouTube and YouTube Music).

    python3 pcapdroid_by_app.py capture.pcap
"""

from __future__ import annotations

import collections
import struct
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

TRAILER = 32
MAGIC = b"\x01\x07\x20\x21"
UNATTRIBUTED = -1


@dataclass
class AppTraffic:
    uid: int
    name: str
    packets: int = 0
    names: collections.Counter[str] = field(default_factory=collections.Counter)


def split_by_app(path: Path) -> dict[int, AppTraffic]:
    """uid -> that app's packet count and the DNS names / TLS server names it used."""
    # Imported here so this file can be run on its own from the scripts directory.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "netpolicy"))
    from netpolicy.parser import iter_pcap_events  # noqa: PLC0415

    data = path.read_bytes()
    if len(data) < 24:
        return {}
    header, offset = data[:24], 24
    packets: dict[int, list[tuple[int, int, bytes]]] = collections.defaultdict(list)
    names: dict[int, str] = {}
    while offset + 16 <= len(data):
        seconds, micros, captured, _ = struct.unpack("<IIII", data[offset : offset + 16])
        offset += 16
        packet = data[offset : offset + captured]
        offset += captured
        uid = UNATTRIBUTED
        if len(packet) >= TRAILER and packet[-TRAILER : -TRAILER + 4] == MAGIC:
            trailer = packet[-TRAILER:]
            uid = struct.unpack(">i", trailer[4:8])[0]
            names[uid] = trailer[8:28].split(b"\0")[0].decode("utf-8", "replace")
            packet = packet[:-TRAILER]
        packets[uid].append((seconds, micros, packet))

    result: dict[int, AppTraffic] = {}
    for uid, group in packets.items():
        body = b"".join(struct.pack("<IIII", s, us, len(p), len(p)) + p for s, us, p in group)
        with tempfile.NamedTemporaryFile(suffix=".pcap") as handle:
            handle.write(header + body)
            handle.flush()
            events = list(iter_pcap_events(Path(handle.name)))
        traffic = AppTraffic(uid=uid, name=names.get(uid, "unattributed"), packets=len(group))
        for event in events:
            traffic.names[
                getattr(event, "query_name", None) or getattr(event, "sni", None) or "?"
            ] += 1
        result[uid] = traffic
    return result


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    traffic = split_by_app(Path(argv[0]))
    if not traffic:
        print("no packets (an empty file is what PCAPdroid leaves when nothing was sent)")
        return 0
    for app in sorted(traffic.values(), key=lambda a: -a.packets):
        print(f"{app.name} (uid {app.uid}): {app.packets} packets, {sum(app.names.values())} named")
        for name, count in app.names.most_common():
            print(f"    {count:3d}  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
