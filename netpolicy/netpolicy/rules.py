"""Generate an nftables ruleset, and the apply/remove script pair that loads
and unloads it inside a session's network namespace.

Pure text generation: nothing here touches the network or requires
privileges, which is what makes it possible to golden-test exactly.
Applying the generated ruleset is exercised only in
`docs/manual-testing.md`.
"""

from __future__ import annotations

from netpolicy.config import LINK_LOCAL_RANGE, RFC1918_RANGES, PolicyConfig


def generate_ruleset(config: PolicyConfig) -> str:
    lines = [
        f"table inet {config.table_name} {{",
        "    chain egress {",
        "        type filter hook output priority 0; policy accept;",
        "",
    ]

    if config.deny_rfc1918:
        addrs = ", ".join(RFC1918_RANGES)
        lines.append(f"        ip daddr {{ {addrs} }} drop comment \"deny RFC1918\"")

    if config.deny_link_local:
        lines.append(f'        ip daddr {LINK_LOCAL_RANGE} drop comment "deny link-local"')

    if config.deny_host_ranges:
        addrs = ", ".join(config.deny_host_ranges)
        lines.append(
            f'        ip daddr {{ {addrs} }} drop comment "deny configured host ranges"'
        )

    if config.deny_tcp_ports:
        ports = ", ".join(str(p) for p in config.deny_tcp_ports)
        lines.append(f'        tcp dport {{ {ports} }} drop comment "deny configured TCP ports"')

    lines.append(
        f"        limit rate over {config.pps_limit}/second "
        f'drop comment "per-session packet rate cap"'
    )
    lines.append(
        f"        limit rate over {config.bandwidth_limit_mbytes_per_second} mbytes/second "
        f'drop comment "per-session bandwidth cap"'
    )

    lines.append("    }")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def generate_apply_script(config: PolicyConfig) -> str:
    return (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "\n"
        f'NETNS="{config.netns_name}"\n'
        f'RULESET="$(dirname "$0")/{config.session_id}.nft"\n'
        "\n"
        'ip netns exec "$NETNS" nft -f "$RULESET"\n'
    )


def generate_remove_script(config: PolicyConfig) -> str:
    return (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "\n"
        f'NETNS="{config.netns_name}"\n'
        f'ip netns exec "$NETNS" nft delete table inet {config.table_name} 2>/dev/null || true\n'
    )
