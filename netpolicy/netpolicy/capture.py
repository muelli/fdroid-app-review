"""A thin subprocess wrapper over `tcpdump`.

Deliberately a subprocess, not a library import: `tcpdump` (BSD licence)
is invoked as an external binary and never linked into this AGPL-3.0
codebase, sidestepping any licence question entirely. Degrades gracefully
throughout: a missing binary, missing capabilities, or a launch failure
all just mean no capture happened, not a session failure.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

# tcpdump fails fast (permission denied, unknown interface, ...): this is
# long enough to catch that class of failure reliably without meaningfully
# slowing down the success path.
_STARTUP_CHECK_SECONDS = 0.3


class PassiveCapture:
    def __init__(self, tcpdump_binary: str = "tcpdump") -> None:
        self._tcpdump_binary = tcpdump_binary
        self._process: subprocess.Popen[bytes] | None = None
        self.last_error: str | None = None

    def available(self) -> bool:
        return shutil.which(self._tcpdump_binary) is not None

    def start(
        self,
        interface: str,
        pcap_path: Path,
        *,
        netns: str | None = None,
        target_pid: int | None = None,
    ) -> bool:
        """`netns` and `target_pid` are two different, non-interchangeable
        ways to scope capture into a specific network namespace rather than
        the caller's own, and only one applies to a given guest:

        - `netns`: a *named* namespace registered under `/var/run/netns/`
          (`ip netns add ...`), the shape a manually-provisioned namespace
          takes — see `netpolicy/rules.py` and `docs/manual-testing.md`.
        - `target_pid`: the PID of a process already running inside the
          namespace to join — what a plain container runtime's network
          namespace looks like from the outside (Docker creates one per
          container automatically; there is nothing to name or provision).
          Capturing this way sees *only* that namespace's interfaces, which
          is what makes `-i any` finally safe to use: confirmed the hard
          way that `-i any` run in the *host's* namespace against a plain
          redroid container captured this host's own unrelated traffic
          right alongside the container's, indistinguishable from each
          other after the fact (see `DECISIONS.md`). Requires the same
          privilege raw capture always does, plus the ability to enter
          another process's namespace (`nsenter`, typically root).
        """
        self.last_error = None
        if netns is not None and target_pid is not None:
            raise ValueError("netns and target_pid are mutually exclusive")
        if not self.available():
            self.last_error = f"{self._tcpdump_binary!r} not found on PATH"
            return False
        pcap_path.parent.mkdir(parents=True, exist_ok=True)
        # -U flushes each packet to disk as it's captured instead of tcpdump's
        # default several-hundred-KB write buffer, so a reader can tail the
        # file while capture is still running (see `netpolicy.parser`, whose
        # pcap parser already tolerates a partially-written trailing record
        # for exactly this reason) rather than only ever seeing whatever was
        # last flushed.
        command = [self._tcpdump_binary, "-U", "-i", interface, "-w", str(pcap_path)]
        if netns is not None:
            command = ["ip", "netns", "exec", netns, *command]
        elif target_pid is not None:
            command = ["nsenter", "--target", str(target_pid), "--net", "--", *command]
        # A pipe would risk deadlocking a long-running, successfully-started
        # capture if tcpdump ever wrote enough to stderr to fill the pipe
        # buffer with nothing reading it afterwards; a file has no such
        # limit and still lets a failed start's error be read back.
        stderr_path = pcap_path.with_suffix(".stderr.log")
        try:
            with stderr_path.open("wb") as stderr_file:
                process = subprocess.Popen(  # noqa: S603
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=stderr_file,
                )
        except OSError as exc:
            self.last_error = str(exc)
            return False

        # A `Popen` that launches successfully still doesn't mean tcpdump is
        # actually capturing: confirmed the hard way that it exits almost
        # immediately on "permission denied, CAP_NET_RAW may be required"
        # and on an unknown interface name, with no packets ever written —
        # `Popen` succeeding only means the process started, not that it
        # stayed running. Give it a moment and check it's still alive
        # before reporting success.
        time.sleep(_STARTUP_CHECK_SECONDS)
        if process.poll() is not None:
            stderr_text = stderr_path.read_text(errors="replace").strip()
            self.last_error = stderr_text or (
                f"tcpdump exited immediately with code {process.returncode}"
            )
            return False

        self._process = process
        return True

    def stop(self) -> None:
        if self._process is None:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
        self._process = None
