"""Which addresses a capture talked to: the flows in a pcap, by remote IP and port.

quick_review lists the DNS names and TLS server names in a capture. An app that connects straight to
an address (an SSH client, a peer-to-peer app) has neither, and "no names" must not read as "no
traffic". This reads the packets themselves: IPv4 and IPv6, TCP and UDP, over Ethernet or raw IP
(what PCAPdroid writes), ignoring PCAPdroid's per-packet trailer (the IP header says how long the
packet is). The remote side of a flow is the destination of its first packet, which for a
capture filtered to one app is the app opening the connection.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from pathlib import Path

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
ETHERTYPE_IPV4, ETHERTYPE_IPV6 = 0x0800, 0x86DD
PROTO_TCP, PROTO_UDP = 6, 17
MAX_TRACKED_FLOWS = 200_000  # an app controls how many connections it makes
MAX_PCAP_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class Flow:
    proto: str
    remote: str
    port: int
    packets: int
    bytes: int

    @property
    def endpoint(self) -> str:
        host = f"[{self.remote}]" if ":" in self.remote else self.remote
        return f"{host}:{self.port}"


def _ip_payload(packet: bytes, linktype: int) -> bytes | None:
    if linktype == LINKTYPE_ETHERNET:
        if len(packet) < 14:
            return None
        if struct.unpack(">H", packet[12:14])[0] not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
            return None
        return packet[14:]
    return packet if linktype == LINKTYPE_RAW else None


def _parse(ip: bytes) -> tuple[str, str, str, int, int, int] | None:
    """(proto, src, dst, sport, dport, length) of a TCP or UDP packet, else None."""
    if not ip:
        return None
    version = ip[0] >> 4
    if version == 4 and len(ip) >= 20:
        header = (ip[0] & 0x0F) * 4
        proto, src, dst = ip[9], ipaddress.IPv4Address(ip[12:16]), ipaddress.IPv4Address(ip[16:20])
        total = struct.unpack(">H", ip[2:4])[0]
    elif version == 6 and len(ip) >= 40:
        header, proto = 40, ip[6]  # extension headers are not followed: a rare case here
        src, dst = ipaddress.IPv6Address(ip[8:24]), ipaddress.IPv6Address(ip[24:40])
        total = 40 + struct.unpack(">H", ip[4:6])[0]
    else:
        return None
    if proto not in (PROTO_TCP, PROTO_UDP) or len(ip) < header + 4:
        return None
    sport, dport = struct.unpack(">HH", ip[header : header + 4])
    name = "tcp" if proto == PROTO_TCP else "udp"
    return name, str(src), str(dst), sport, dport, total


def summarise_flows(path: Path) -> list[Flow]:
    """Remote endpoints with packet and byte counts, busiest first. [] for an unreadable file."""
    try:
        if path.stat().st_size > MAX_PCAP_BYTES:
            return []
        data = path.read_bytes()
    except OSError:
        return []
    if len(data) < 24 or data[:4] != b"\xd4\xc3\xb2\xa1":  # little-endian classic pcap
        return []
    linktype = struct.unpack("<I", data[20:24])[0]
    first_dst: dict[tuple[str, tuple[str, int], tuple[str, int]], tuple[str, int]] = {}
    totals: dict[tuple[str, str, int], list[int]] = {}
    offset = 24
    while offset + 16 <= len(data):
        captured = struct.unpack("<I", data[offset + 8 : offset + 12])[0]
        offset += 16
        packet = data[offset : offset + captured]
        offset += captured
        ip = _ip_payload(packet, linktype)
        parsed = _parse(ip) if ip is not None else None
        if parsed is None:
            continue
        proto, src, dst, sport, dport, length = parsed
        a, b = (src, sport), (dst, dport)
        key = (proto, *sorted((a, b)))  # type: ignore[arg-type]
        remote = first_dst.get(key)
        if remote is None:
            if len(first_dst) >= MAX_TRACKED_FLOWS:
                continue
            remote = first_dst[key] = b
        entry = totals.setdefault((proto, remote[0], remote[1]), [0, 0])
        entry[0] += 1
        entry[1] += length
    flows = [Flow(p, ip, port, n, size) for (p, ip, port), (n, size) in totals.items()]
    return sorted(flows, key=lambda f: (-f.packets, f.endpoint))
