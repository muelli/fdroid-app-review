"""Per-session egress policy configuration.

Defaults implement the architecture's stated policy: default-allow outbound
with carve-outs for RFC1918, link-local, configured host ranges and
TCP/25, plus a hard rate cap.
"""

from __future__ import annotations

from dataclasses import dataclass

RFC1918_RANGES: tuple[str, ...] = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
LINK_LOCAL_RANGE = "169.254.0.0/16"


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    session_id: str
    netns_name: str
    deny_rfc1918: bool = True
    deny_link_local: bool = True
    deny_host_ranges: tuple[str, ...] = ()
    deny_tcp_ports: tuple[int, ...] = (25,)
    bandwidth_limit_mbytes_per_second: int = 5
    pps_limit: int = 2000

    @property
    def table_name(self) -> str:
        return f"fdroid_s_{self.session_id}"
