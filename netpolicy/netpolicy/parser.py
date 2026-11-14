"""A small, dependency-free classic-pcap parser.

Extracts exactly two things: DNS query names (UDP/53) and TLS SNI values
(the server_name extension of a single-packet TLS ClientHello on any TCP
port, typically 443). It does not attempt IPv6, VLAN tags, or TCP stream
reassembly: a ClientHello split across TCP segments will simply not be
seen. That is an acceptable gap for best-effort review evidence, and is
called out in `netpolicy/README.md` and `docs/SECURITY.md`.

Understands three link-layer framings: standard Ethernet, and Linux
"cooked" capture v1 and v2 (`SLL`/`SLL2`). The latter two matter because
`tcpdump -i any` — capturing every interface at once, which is what makes
sense when you don't know or don't want to hard-code a specific interface
name (see `scripts/quick_review.py`) — always produces cooked-capture
framing regardless of what the underlying interfaces actually are, never
Ethernet. Confirmed the hard way: a real `-i any` capture parsed as zero
events under the original Ethernet-only assumption despite genuinely
containing TLS ClientHellos, because the first 14 bytes of each record
were being misread as an Ethernet header that was never there.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

_PCAP_MAGIC_LE = 0xA1B2C3D4
_ETHERTYPE_IPV4 = 0x0800
_PROTO_UDP = 17
_PROTO_TCP = 6
_DNS_PORT = 53
_TLS_HANDSHAKE_RECORD = 0x16
_TLS_CLIENT_HELLO = 0x01
_TLS_EXTENSION_SNI = 0x0000

_LINKTYPE_ETHERNET = 1
_LINKTYPE_RAW = 101  # bare IP packets: what PCAPdroid's VPN-based capture writes
_LINKTYPE_LINUX_SLL = 113
_LINKTYPE_LINUX_SLL2 = 276
_SUPPORTED_LINKTYPES = frozenset(
    {_LINKTYPE_ETHERNET, _LINKTYPE_RAW, _LINKTYPE_LINUX_SLL, _LINKTYPE_LINUX_SLL2}
)

# Every packet this parses is written by the app under review, which is
# assumed hostile (that is the point of capturing it), so nothing a packet
# claims about its own sizes may be trusted. These are the protocols' own
# hard limits; anything beyond them is a malformed or crafted packet and
# yields no event rather than a giant, garbage one.
_MAX_DNS_LABEL_LENGTH = 63
_MAX_DNS_NAME_LENGTH = 255
_MAX_SNI_LENGTH = 255
_MIN_IPV4_HEADER_LENGTH = 20
_MIN_TCP_HEADER_LENGTH = 20
# Comfortably above any snaplen tcpdump is run with here, and above a jumbo
# frame, so a corrupt record length can't turn into a multi-gigabyte read.
_MAX_CAPTURED_PACKET_BYTES = 1 << 20


@dataclass(frozen=True, slots=True)
class DnsQueryEvent:
    query_name: str
    timestamp: float  # seconds since the epoch, from the pcap record header
    port: int = _DNS_PORT


@dataclass(frozen=True, slots=True)
class TlsSniEvent:
    sni: str
    timestamp: float  # seconds since the epoch, from the pcap record header
    port: int  # the TCP port the ClientHello was sent to; typically 443


NetworkEvent = DnsQueryEvent | TlsSniEvent


class PcapParseError(Exception):
    pass


def _read_dns_name(payload: bytes, offset: int) -> str:
    """Empty string for anything that isn't a well-formed, uncompressed
    QNAME, so a crafted packet yields no event instead of a bogus one.
    """
    labels = []
    total_length = 0
    while offset < len(payload):
        length = payload[offset]
        if length == 0:
            break
        # A question section's QNAME is never compressed, so a length byte
        # above 63 is a compression pointer (or reserved) that only a
        # hostile or corrupt packet can put here.
        if length > _MAX_DNS_LABEL_LENGTH:
            return ""
        offset += 1
        if offset + length > len(payload):
            return ""
        total_length += length + 1
        if total_length > _MAX_DNS_NAME_LENGTH:
            return ""
        labels.append(payload[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels)


def _parse_dns(udp_payload: bytes, timestamp: float) -> DnsQueryEvent | None:
    if len(udp_payload) < 12:
        return None
    qdcount = struct.unpack(">H", udp_payload[4:6])[0]
    if qdcount < 1:
        return None
    name = _read_dns_name(udp_payload, 12)
    if not name:
        return None
    return DnsQueryEvent(query_name=name, timestamp=timestamp)


def _parse_tls_client_hello_sni(
    tcp_payload: bytes, timestamp: float, port: int
) -> TlsSniEvent | None:
    if len(tcp_payload) < 6:
        return None
    if tcp_payload[0] != _TLS_HANDSHAKE_RECORD:
        return None
    record_length = struct.unpack(">H", tcp_payload[3:5])[0]
    handshake = tcp_payload[5 : 5 + record_length]
    if len(handshake) < 4 or handshake[0] != _TLS_CLIENT_HELLO:
        return None

    pos = 4  # handshake type (1) + length (3)
    pos += 2  # client_version
    pos += 32  # random
    if pos >= len(handshake):
        return None
    session_id_len = handshake[pos]
    pos += 1 + session_id_len
    if pos + 2 > len(handshake):
        return None
    cipher_suites_len = struct.unpack(">H", handshake[pos : pos + 2])[0]
    pos += 2 + cipher_suites_len
    if pos >= len(handshake):
        return None
    compression_len = handshake[pos]
    pos += 1 + compression_len
    if pos + 2 > len(handshake):
        return None
    extensions_len = struct.unpack(">H", handshake[pos : pos + 2])[0]
    pos += 2
    extensions_end = pos + extensions_len

    while pos + 4 <= extensions_end and pos + 4 <= len(handshake):
        ext_type, ext_len = struct.unpack(">HH", handshake[pos : pos + 4])
        ext_body = handshake[pos + 4 : pos + 4 + ext_len]
        if ext_type == _TLS_EXTENSION_SNI and len(ext_body) >= 5:
            name_len = struct.unpack(">H", ext_body[3:5])[0]
            if not 0 < name_len <= _MAX_SNI_LENGTH or 5 + name_len > len(ext_body):
                return None
            server_name = ext_body[5 : 5 + name_len].decode("ascii", errors="replace")
            return TlsSniEvent(sni=server_name, timestamp=timestamp, port=port)
        pos += 4 + ext_len
    return None


def _strip_link_header(packet: bytes, linktype: int) -> bytes | None:
    """Return the IPv4 payload past the link-layer header, or `None` if
    this isn't a link type this parser understands or isn't carrying IPv4.
    """
    if linktype == _LINKTYPE_ETHERNET:
        if len(packet) < 14:
            return None
        ethertype = struct.unpack(">H", packet[12:14])[0]
        if ethertype != _ETHERTYPE_IPV4:
            return None
        return packet[14:]

    if linktype == _LINKTYPE_RAW:
        return packet

    if linktype == _LINKTYPE_LINUX_SLL:
        if len(packet) < 16:
            return None
        protocol_type = struct.unpack(">H", packet[14:16])[0]
        if protocol_type != _ETHERTYPE_IPV4:
            return None
        return packet[16:]

    if linktype == _LINKTYPE_LINUX_SLL2:
        if len(packet) < 20:
            return None
        protocol_type = struct.unpack(">H", packet[0:2])[0]
        if protocol_type != _ETHERTYPE_IPV4:
            return None
        return packet[20:]

    return None


def _parse_packet(packet: bytes, linktype: int, timestamp: float) -> NetworkEvent | None:
    ip_header = _strip_link_header(packet, linktype)
    if ip_header is None:
        return None
    if len(ip_header) < _MIN_IPV4_HEADER_LENGTH:
        return None
    ihl = (ip_header[0] & 0x0F) * 4
    if ihl < _MIN_IPV4_HEADER_LENGTH:
        return None
    protocol = ip_header[9]
    ip_payload = ip_header[ihl:]

    if protocol == _PROTO_UDP:
        if len(ip_payload) < 8:
            return None
        src_port, dst_port = struct.unpack(">HH", ip_payload[0:4])
        udp_payload = ip_payload[8:]
        if dst_port == _DNS_PORT or src_port == _DNS_PORT:
            return _parse_dns(udp_payload, timestamp)
        return None

    if protocol == _PROTO_TCP:
        if len(ip_payload) < _MIN_TCP_HEADER_LENGTH:
            return None
        _src_port, dst_port = struct.unpack(">HH", ip_payload[0:4])
        data_offset = (ip_payload[12] >> 4) * 4
        if data_offset < _MIN_TCP_HEADER_LENGTH:
            return None
        tcp_payload = ip_payload[data_offset:]
        return _parse_tls_client_hello_sni(tcp_payload, timestamp, dst_port)

    return None


def iter_pcap_events(pcap_path: Path) -> Iterator[NetworkEvent]:
    """Yield `DnsQueryEvent`/`TlsSniEvent` records found in a classic-format pcap file.

    Each event's `timestamp` comes from its own pcap record header (the
    capturing process's own clock — the host's, even when capture ran
    inside a container's network namespace via `nsenter`, since only the
    network namespace changes there, not the clock), so events from this
    parser can be placed on the same timeline as anything else timestamped
    against that same clock.
    """
    # Read record by record rather than slurping the file: the app under
    # review decides how much traffic there is to capture, so the file's
    # size is its choice, not ours.
    with pcap_path.open("rb") as handle:
        global_header = handle.read(24)
        if len(global_header) < 24:
            raise PcapParseError(f"{pcap_path}: too short to be a pcap file")

        magic = struct.unpack("<I", global_header[0:4])[0]
        if magic != _PCAP_MAGIC_LE:
            raise PcapParseError(f"{pcap_path}: unrecognised pcap magic number {magic:#x}")
        linktype = struct.unpack("<I", global_header[20:24])[0]
        # An unsupported framing used to yield no events at all, which reads as "no
        # traffic" when the truth is "could not read it" (a real PCAPdroid capture hit
        # this: raw IP, 151 packets, zero events, no error).
        if linktype not in _SUPPORTED_LINKTYPES:
            raise PcapParseError(f"{pcap_path}: unsupported pcap link type {linktype}")

        while True:
            record_header = handle.read(16)
            if len(record_header) < 16:
                break
            ts_sec, ts_usec, incl_len = struct.unpack("<III", record_header[0:12])
            if incl_len > _MAX_CAPTURED_PACKET_BYTES:
                handle.seek(incl_len, 1)
                continue
            packet = handle.read(incl_len)
            # A short read is the trailing record of a capture still being
            # written (see `netpolicy.capture`'s `-U`), not a parse failure.
            if len(packet) < incl_len:
                break
            timestamp = ts_sec + ts_usec / 1_000_000
            event = _parse_packet(packet, linktype, timestamp)
            if event is not None:
                yield event
