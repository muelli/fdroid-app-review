#!/usr/bin/env bash
set -euo pipefail

NETNS="fdroid-sess-abc123deadbeef"
ip netns exec "$NETNS" nft delete table inet fdroid_s_abc123deadbeef 2>/dev/null || true
