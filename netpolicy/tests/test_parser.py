import struct
import sys
from pathlib import Path

import pytest
from netpolicy.parser import DnsQueryEvent, PcapParseError, TlsSniEvent, iter_pcap_events

SAMPLE_PCAP = Path(__file__).parent / "fixtures" / "sample.pcap"
SAMPLE_SLL2_PCAP = Path(__file__).parent / "fixtures" / "sample_sll2.pcap"
SAMPLE_HOSTILE_PCAP = Path(__file__).parent / "fixtures" / "sample_hostile.pcap"

# The exact ts_sec values generate_sample_pcap.py bakes into both fixtures
# (ts_usec=0 in each record), so equality checks below can pin them exactly.
_DNS_EVENT_TIMESTAMP = 1_700_000_000.0
_TLS_EVENT_TIMESTAMP = 1_700_000_001.0


def test_parses_dns_query_and_tls_sni_from_canned_pcap() -> None:
    events = list(iter_pcap_events(SAMPLE_PCAP))
    assert DnsQueryEvent(query_name="f-droid.org", timestamp=_DNS_EVENT_TIMESTAMP) in events
    assert TlsSniEvent(sni="f-droid.org", timestamp=_TLS_EVENT_TIMESTAMP, port=443) in events


def test_parses_the_same_events_from_a_linux_cooked_v2_capture() -> None:
    """`tcpdump -i any` (see scripts/quick_review.py) always frames packets
    this way, never as Ethernet, regardless of the real underlying
    interface. Confirmed against a real `-i any` capture that this was
    silently parsed as zero events under the Ethernet-only assumption.
    """
    events = list(iter_pcap_events(SAMPLE_SLL2_PCAP))
    assert DnsQueryEvent(query_name="f-droid.org", timestamp=_DNS_EVENT_TIMESTAMP) in events
    assert TlsSniEvent(sni="f-droid.org", timestamp=_TLS_EVENT_TIMESTAMP, port=443) in events


def test_rejects_non_pcap_file(tmp_path: Path) -> None:
    bogus = tmp_path / "not-a-pcap"
    bogus.write_bytes(b"definitely not a pcap file")
    with pytest.raises(PcapParseError):
        list(iter_pcap_events(bogus))


def test_crafted_malformed_packets_yield_no_events() -> None:
    """The packets this parser reads come from the app under review, which
    is assumed hostile. See `generate_sample_pcap.hostile_ip_packets` for
    what each record claims about its own lengths; none of them may produce
    an event, and none may raise.
    """
    assert list(iter_pcap_events(SAMPLE_HOSTILE_PCAP)) == []


def test_tolerates_a_record_truncated_mid_packet(tmp_path: Path) -> None:
    """`tcpdump -U` flushes per packet, so the last record of a capture
    being read while it is still running is routinely half-written.
    """
    truncated = tmp_path / "truncated.pcap"
    truncated.write_bytes(SAMPLE_PCAP.read_bytes()[:-20])
    events = list(iter_pcap_events(truncated))
    assert [event.query_name for event in events if isinstance(event, DnsQueryEvent)] == [
        "f-droid.org"
    ]


def test_skips_a_record_claiming_an_implausible_length(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.pcap"
    header = SAMPLE_PCAP.read_bytes()[:24]
    oversized.write_bytes(header + struct.pack("<IIII", 1_700_000_000, 0, 1 << 30, 1 << 30))
    assert list(iter_pcap_events(oversized)) == []


def _fixture_builders():  # type: ignore[no-untyped-def]
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "generate_sample_pcap", Path(__file__).parent / "fixtures" / "generate_sample_pcap.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["generate_sample_pcap"] = module
    spec.loader.exec_module(module)
    return module


def test_raw_ip_pcaps_are_read(tmp_path: Path) -> None:
    """What PCAPdroid's VPN capture writes (link type 101): bare IP packets, no link header."""
    builders = _fixture_builders()
    pcap = tmp_path / "raw.pcap"
    pcap.write_bytes(builders.build_pcap(linktype=101, frame=lambda ip: ip))
    events = list(iter_pcap_events(pcap))
    assert any(isinstance(e, DnsQueryEvent) and e.query_name == "f-droid.org" for e in events)
    assert any(isinstance(e, TlsSniEvent) and e.sni == "f-droid.org" for e in events)


def test_an_unsupported_link_type_is_an_error_not_an_empty_result(tmp_path: Path) -> None:
    builders = _fixture_builders()
    pcap = tmp_path / "odd.pcap"
    pcap.write_bytes(builders.build_pcap(linktype=147, frame=lambda ip: ip))
    with pytest.raises(PcapParseError, match="unsupported pcap link type 147"):
        list(iter_pcap_events(pcap))
    from netpolicy.logger import write_network_log

    assert write_network_log(pcap, tmp_path / "log.jsonl") is None
