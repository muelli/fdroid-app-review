# netpolicy

Per-session network egress policy and passive evidence capture for hosted review
sessions. Two independent pieces:

- `netpolicy.rules`: turns a `PolicyConfig` into an nftables ruleset (default-allow
  outbound, with carve-outs for RFC1918, link-local, configured host ranges and
  TCP/25, plus bandwidth/pps caps) and a matching apply/remove shell script pair,
  keyed by session id and network namespace. Pure text generation, no privileges
  needed; golden-tested (`tests/test_rules.py`).
- `netpolicy.capture` / `netpolicy.parser`: a thin wrapper over the `tcpdump` binary
  (invoked as a subprocess, never linked in-process, so its own licence never touches
  this AGPL codebase) to produce a pcap file, and a dependency-free pure-Python pcap
  parser that extracts DNS queries and TLS SNI values into a JSONL evidence log. The
  parser does no TCP reassembly, so a ClientHello split across TCP segments will be
  missed; single-packet ClientHellos (the overwhelming majority in practice) are
  captured. It understands standard Ethernet framing and both Linux cooked-capture
  link types (`SLL`/`SLL2` — what `tcpdump -i any` always produces, regardless of
  the real underlying interface). Capture degrades gracefully: if `tcpdump` is
  missing, unprivileged, or fails for any reason, the session's evidence bundle
  simply has no network log rather than failing the session — and "fails" now
  includes the case where `tcpdump` launches but exits almost immediately (a
  permissions error, an unknown interface), not just a launch failure, confirmed
  the hard way when that case silently reported success with no packets ever
  captured (see `DECISIONS.md`).

  `PassiveCapture.start()` can scope capture into a specific network namespace
  two different ways, and which one applies depends on how that namespace came
  to exist: `netns=` joins a *named* namespace (`ip netns add ...`, the shape a
  manually-provisioned Cuttlefish-style namespace takes); `target_pid=` joins
  the namespace of an already-running process via `nsenter`, which is what a
  plain Docker container's namespace looks like from the outside — nothing to
  name or provision, since `docker run` already creates one per container.
  The latter is what makes `-i any` actually safe to use: capturing inside a
  container's own namespace sees *only* that namespace's traffic, confirmed
  for real by generating unrelated host traffic during a container-scoped
  capture and confirming none of it leaked into the resulting pcap (see
  `DECISIONS.md` and `scripts/quick_review.py --capture-container`). Capturing
  `any` from the *host's* own namespace has no such guarantee — confirmed the
  other way too, the same host traffic showed up right alongside the reviewed
  device's.

  **Confirmed against real traffic, not just theory:** run against an actual
  Android session (`local-image`, `--log-network`, see `DECISIONS.md`), the
  network log came back empty despite the device making real network calls.
  This was not a bug: the device's DNS resolution went out as DNS-over-TLS to
  `8.8.8.8:853` (Android's default "Private DNS" behaviour), invisible to a
  plaintext-UDP/53 DNS parser by construction and correctly so (decrypting it
  would be the TLS interception this project deliberately doesn't do), and
  the DoT connection's own ClientHello — captured whole, not fragmented —
  turned out to genuinely carry no SNI extension at all, since it connects
  directly to a literal IP with no virtual-hosting reason to send one. **A
  real session can produce an empty or sparse network log while making real,
  identifiable network requests.** Treat "no network log entries" as "nothing
  observable with this passive technique", not as "no network activity
  occurred" — this matters when using the log as review evidence
  (`docs/SECURITY.md`).

Real `tcpdump` capture (both host-interface and container-namespace-scoped, via
`scripts/quick_review.py`) has been exercised for real against a real `redroid`
container and real network traffic — see `DECISIONS.md`. `netpolicy.rules`'
nftables application still hasn't (no privileged network namespace provisioning
anywhere in this codebase yet, only unit tests against generated text and the
manual steps in `docs/manual-testing.md`).
