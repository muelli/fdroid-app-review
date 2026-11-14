#!/usr/bin/env python3
"""Regenerate the pcap fixtures: `sample.pcap` (one DNS query for
f-droid.org and one TLS ClientHello with SNI `f-droid.org`),
`sample_sll2.pcap` (the same two in Linux cooked v2 framing), and
`sample_hostile.pcap` (crafted malformed packets, see `hostile_ip_packets`),
all hand-built byte for byte so the fixtures have no dependency on any
packet-capture library. Run this file directly to regenerate them if the
parser's expectations ever change.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from pathlib import Path

ETH_SRC = bytes.fromhex("aaaaaaaaaaaa")
ETH_DST = bytes.fromhex("bbbbbbbbbbbb")
ETHERTYPE_IPV4 = 0x0800


def ipv4_header(
    protocol: int, payload_len: int, src: str, dst: str, version_ihl: int = 0x45
) -> bytes:
    total_length = 20 + payload_len

    def ip_bytes(addr: str) -> bytes:
        return bytes(int(part) for part in addr.split("."))

    return struct.pack(
        ">BBHHHBBH4s4s",
        version_ihl,
        0,  # tos
        total_length,
        0,  # identification
        0,  # flags/fragment offset
        64,  # ttl
        protocol,
        0,  # checksum (unvalidated by our parser)
        ip_bytes(src),
        ip_bytes(dst),
    )


def ethernet_frame(payload: bytes) -> bytes:
    return ETH_DST + ETH_SRC + struct.pack(">H", ETHERTYPE_IPV4) + payload


def linux_sll2_frame(payload: bytes) -> bytes:
    """`tcpdump -i any` always frames packets this way (LINKTYPE_LINUX_SLL2 =
    276), regardless of what the underlying interface actually is."""
    return (
        struct.pack(">H", ETHERTYPE_IPV4)  # protocol_type
        + b"\x00\x00"  # reserved
        + b"\x00\x00\x00\x00"  # interface_index
        + b"\x00\x00"  # arphrd_type
        + b"\x00"  # packet_type
        + b"\x00"  # link_addr_length
        + b"\x00" * 8  # link_addr
        + payload
    )


def dns_ip_packet(qname: bytes, version_ihl: int = 0x45) -> bytes:
    dns = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
    udp_header = struct.pack(">HHHH", 54321, 53, 8 + len(dns), 0)
    ip = ipv4_header(
        protocol=17,
        payload_len=len(udp_header) + len(dns),
        src="10.1.2.3",
        dst="8.8.8.8",
        version_ihl=version_ihl,
    )
    return ip + udp_header + dns


def dns_query_ip_packet() -> bytes:
    qname = b"".join(
        struct.pack(">B", len(label)) + label.encode("ascii")
        for label in ["f-droid", "org"]
    ) + b"\x00"
    return dns_ip_packet(qname)


def sni_extension(host: bytes, name_len: int | None = None) -> bytes:
    return (
        struct.pack(">H", 0x0000)  # extension type: server_name
        + struct.pack(">H", 2 + 1 + 2 + len(host))  # extension length
        + struct.pack(">H", 1 + 2 + len(host))  # server_name_list length
        + b"\x00"  # name type: host_name
        + struct.pack(">H", len(host) if name_len is None else name_len)
        + host
    )


def client_hello_record(
    extensions: bytes, cipher_suites_len: int = 2, extensions_len: int | None = None
) -> bytes:
    handshake_body = (
        struct.pack(">H", 0x0303)  # client_version
        + b"\x00" * 32  # random
        + b"\x00"  # session_id length
        + struct.pack(">H", cipher_suites_len) + b"\x13\x01"  # cipher suites
        + b"\x01" + b"\x00"  # compression methods
        + struct.pack(">H", len(extensions) if extensions_len is None else extensions_len)
        + extensions
    )
    handshake = (
        struct.pack(">B", 0x01) + struct.pack(">I", len(handshake_body))[1:] + handshake_body
    )
    return (
        bytes([0x16]) + struct.pack(">H", 0x0301) + struct.pack(">H", len(handshake)) + handshake
    )


def tcp_ip_packet(payload: bytes, data_offset_words: int = 5) -> bytes:
    tcp_header = struct.pack(
        ">HHIIHHHH",
        44321,  # src port
        443,  # dst port
        0,  # seq
        0,  # ack
        (data_offset_words << 12) | 0x018,  # data offset + flags (PSH, ACK)
        8192,  # window
        0,  # checksum
        0,  # urgent pointer
    )
    ip = ipv4_header(
        protocol=6, payload_len=len(tcp_header) + len(payload), src="10.1.2.3", dst="1.2.3.4"
    )
    return ip + tcp_header + payload


def tls_client_hello_ip_packet() -> bytes:
    return tcp_ip_packet(client_hello_record(sni_extension(b"f-droid.org")))


def hostile_ip_packets() -> list[bytes]:
    """Packets no honest stack sends: each is a length field or structure an
    app under review could put on the wire to try to walk the parser off the
    end of a buffer, keep it looping, or make it report a bogus endpoint.
    None of them may yield an event.
    """
    return [
        # DNS label length above 63: a compression pointer, where a question
        # section's QNAME is never compressed.
        dns_ip_packet(b"\xc0\x0c"),
        dns_ip_packet(b"\x40" + b"a" * 64 + b"\x00"),
        # Label length running off the end of the captured payload.
        dns_ip_packet(b"\x3f" + b"ab"),
        # Name far longer than the protocol's own 255-byte limit.
        dns_ip_packet(b"".join(b"\x3f" + b"a" * 63 for _ in range(8)) + b"\x00"),
        # SNI claiming 65535 bytes of hostname in a 16-byte extension body.
        tcp_ip_packet(client_hello_record(sni_extension(b"f-droid.org", name_len=0xFFFF))),
        # Cipher suite list claiming to be longer than the whole handshake.
        tcp_ip_packet(client_hello_record(sni_extension(b"f-droid.org"), cipher_suites_len=0xFFFF)),
        # An extension claiming 65535 bytes of body, inside an extension list
        # claiming 65535 bytes of extensions.
        tcp_ip_packet(
            client_hello_record(struct.pack(">HH", 0x0015, 0xFFFF), extensions_len=0xFFFF)
        ),
        # IPv4 header length field below the 20-byte minimum.
        dns_ip_packet(b"\x07f-droid\x03org\x00", version_ihl=0x40),
        # TCP data offset below the 20-byte minimum.
        tcp_ip_packet(client_hello_record(sni_extension(b"f-droid.org")), data_offset_words=0),
    ]


def pcap_global_header(linktype: int) -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)


def pcap_record(packet: bytes, ts_sec: int) -> bytes:
    header = struct.pack("<IIII", ts_sec, 0, len(packet), len(packet))
    return header + packet


def build_pcap(
    linktype: int, frame: Callable[[bytes], bytes], ip_packets: list[bytes] | None = None
) -> bytes:
    if ip_packets is None:
        ip_packets = [dns_query_ip_packet(), tls_client_hello_ip_packet()]
    out = pcap_global_header(linktype)
    for i, ip_packet in enumerate(ip_packets):
        out += pcap_record(frame(ip_packet), ts_sec=1_700_000_000 + i)
    return out


def main() -> None:
    ethernet_pcap = build_pcap(linktype=1, frame=ethernet_frame)
    Path(__file__).with_name("sample.pcap").write_bytes(ethernet_pcap)

    # Covers the "tcpdump -i any" path (see scripts/quick_review.py and
    # netpolicy/parser.py's module docstring): always Linux cooked v2
    # framing, never Ethernet, regardless of the real underlying interface.
    sll2_pcap = build_pcap(linktype=276, frame=linux_sll2_frame)
    Path(__file__).with_name("sample_sll2.pcap").write_bytes(sll2_pcap)

    hostile_pcap = build_pcap(linktype=1, frame=ethernet_frame, ip_packets=hostile_ip_packets())
    Path(__file__).with_name("sample_hostile.pcap").write_bytes(hostile_pcap)


if __name__ == "__main__":
    main()
