#!/usr/bin/env bash
set -euo pipefail

NETNS="fdroid-sess-abc123deadbeef"
RULESET="$(dirname "$0")/abc123deadbeef.nft"

ip netns exec "$NETNS" nft -f "$RULESET"
