"""Turn a captured pcap into the JSONL network log that becomes part of a
session's evidence bundle. Degrades gracefully: a missing or unparsable
pcap yields `None`, never an exception.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from netpolicy.parser import (
    DnsQueryEvent,
    NetworkEvent,
    PcapParseError,
    TlsSniEvent,
    iter_pcap_events,
)


def event_to_record(event: NetworkEvent) -> dict[str, str]:
    """The JSON-compatible shape a network event takes everywhere it's
    exposed: the JSONL evidence log, and a runtime's live `network_events()`
    (see `runtime.base.RuntimeSession`), so consumers never need to
    special-case which produced it.
    """
    if isinstance(event, DnsQueryEvent):
        return {"type": "dns", **asdict(event)}
    if isinstance(event, TlsSniEvent):
        return {"type": "tls_sni", **asdict(event)}
    raise AssertionError(f"unhandled event type: {event!r}")  # pragma: no cover


def write_network_log(
    pcap_path: Path,
    output_path: Path,
    *,
    window: tuple[float, float] | None = None,
) -> Path | None:
    """`window` is an inclusive (start, end) range of the capturing host's
    clock, in seconds since the epoch; events outside it are left out. For a
    pcap that covers more than the span of interest, such as an emulator's
    whole session, boot included.
    """
    if not pcap_path.exists():
        return None
    try:
        events = list(iter_pcap_events(pcap_path))
    except PcapParseError:
        return None
    if window is not None:
        start, end = window
        events = [event for event in events if start <= event.timestamp <= end]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event_to_record(event)) + "\n")
    return output_path
