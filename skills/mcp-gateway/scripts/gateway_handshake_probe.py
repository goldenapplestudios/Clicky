#!/usr/bin/env python3
"""Drive the Clicky gateway through a real MCP stdio session and report health.

Used by gateway-doctor.sh. Deliberately dependency-free and run with the SYSTEM
python, not the gateway's own venv: a health check must not import the thing it
is checking, or a broken venv makes the check unavailable exactly when needed.

Written against the MCP specification rather than from memory
(https://modelcontextprotocol.io/specification/), which dictates four things
an ad-hoc probe tends to get wrong:

  * Transport framing. stdio messages are newline-delimited JSON-RPC and
    "MUST NOT contain embedded newlines" - json.dumps escapes them, so one
    dump per line is correct.

  * stdout purity. "The server MUST NOT write anything to its stdout that is
    not a valid MCP message", while stderr MAY carry logs. Non-JSON on stdout
    is therefore a real defect that breaks strict clients, so it is REPORTED
    here rather than silently skipped.

  * Version negotiation. The current revision (2026-07-28) declares versions
    per-request and offers `server/discover`, a mandatory RPC returning
    supported versions, capabilities and identity in one call. Servers built
    on handshake-based revisions (2025-11-25 and earlier) answer -32601 to it
    and negotiate through `initialize` instead. Both paths are tried, newest
    first, and the outcome is reported so a stale server is visible rather
    than merely "working".

  * Shutdown. The spec's stdio shutdown is: close the server's stdin, wait for
    exit, then SIGTERM, then SIGKILL. Going straight to SIGKILL denies the
    server any chance to clean up.

Prints one machine-readable line, then optional NOTE:/WARN: lines:
  TOOLS <names>         success; comma-separated tool names
  NO_INITIALIZE_RESPONSE / NO_TOOLS_LIST / INITIALIZE_ERROR <json>

Usage: gateway_handshake_probe.py /path/to/launch.sh [--timeout SECONDS]
"""
import json
import selectors
import subprocess
import sys
import threading
import time

# The latest revision this probe knows how to speak. Per the spec a client
# "MUST send a protocol version it supports [and] SHOULD be the latest".
LATEST_PROTOCOL_VERSION = "2026-07-28"
DEFAULT_TIMEOUT = 60.0


class Probe:
    def __init__(self, launcher, timeout):
        self.deadline = time.monotonic() + timeout
        self.notes = []
        self.stderr_lines = []
        self.proc = subprocess.Popen(
            ["bash", launcher],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, start_new_session=True,
        )
        # Drain stderr so a chatty launcher cannot fill its pipe and deadlock.
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.proc.stdout, selectors.EVENT_READ)

    def _drain_stderr(self):
        try:
            for line in self.proc.stderr:
                self.stderr_lines.append(line.rstrip())
        except Exception:
            pass

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def _readline(self):
        """Read one line, bounded by the overall deadline, so the probe itself
        can never hang waiting on a silent server."""
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return None
        if not self.sel.select(timeout=remaining):
            return None
        return self.proc.stdout.readline() or None

    def await_id(self, want):
        while True:
            line = self._readline()
            if line is None:
                return None
            stripped = line.strip()
            if not stripped:
                continue
            try:
                msg = json.loads(stripped)
            except ValueError:
                # Spec: the server MUST NOT write non-MCP data to stdout.
                self.notes.append(
                    "WARN: server wrote non-MCP data to stdout, which violates the "
                    "stdio transport contract and breaks strict clients: "
                    + stripped[:120]
                )
                continue
            if msg.get("id") == want:
                return msg

    def shutdown(self):
        # Spec stdio shutdown: close stdin, wait, SIGTERM, then SIGKILL.
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=3)
            return
        except Exception:
            pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass

    def err_tail(self):
        return (" | stderr: " + " ".join(self.stderr_lines[-3:])) if self.stderr_lines else ""


def main() -> int:
    if len(sys.argv) < 2:
        print("NO_INITIALIZE_RESPONSE missing launcher argument")
        return 1
    launcher = sys.argv[1]
    timeout = DEFAULT_TIMEOUT
    if "--timeout" in sys.argv:
        try:
            timeout = float(sys.argv[sys.argv.index("--timeout") + 1])
        except (IndexError, ValueError):
            pass

    try:
        p = Probe(launcher, timeout)
    except OSError as exc:
        print(f"NO_INITIALIZE_RESPONSE could not start launcher: {exc}")
        return 1

    try:
        # --- newest path first: server/discover (mandatory in 2026-07-28) ---
        p.send({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}})
        discover = p.await_id(1)
        supports_discover = bool(discover and "result" in discover)
        if supports_discover:
            versions = discover["result"].get("protocolVersions") or discover["result"].get("versions")
            p.notes.append(f"NOTE: server/discover supported (versions: {versions})")
        else:
            code = (discover or {}).get("error", {}).get("code")
            if code == -32601:
                p.notes.append(
                    "NOTE: server/discover not implemented (-32601); server speaks a "
                    "handshake-based revision (2025-11-25 or earlier). This is a "
                    "supported backward-compatibility path, not a fault."
                )
            elif discover is None:
                print("NO_INITIALIZE_RESPONSE server did not answer server/discover" + p.err_tail())
                for n in p.notes:
                    print(n)
                return 1

        # --- handshake path --------------------------------------------------
        p.send({"jsonrpc": "2.0", "id": 2, "method": "initialize",
                "params": {"protocolVersion": LATEST_PROTOCOL_VERSION,
                           "capabilities": {},
                           "clientInfo": {"name": "clicky-gateway-doctor", "version": "1"}}})
        init = p.await_id(2)
        if init is None:
            print("NO_INITIALIZE_RESPONSE" + p.err_tail())
            for n in p.notes:
                print(n)
            return 1
        if "error" in init:
            print("INITIALIZE_ERROR " + json.dumps(init["error"])[:200])
            for n in p.notes:
                print(n)
            return 1

        negotiated = init.get("result", {}).get("protocolVersion")
        if negotiated and negotiated != LATEST_PROTOCOL_VERSION:
            # Spec: if the server does not support the requested version it MUST
            # answer with one it does support.
            p.notes.append(
                f"NOTE: negotiated protocol version {negotiated} "
                f"(probe offered {LATEST_PROTOCOL_VERSION})"
            )
        elif negotiated:
            p.notes.append(f"NOTE: negotiated protocol version {negotiated}")

        # Spec: after a successful initialize the client MUST send this.
        p.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        p.send({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}})
        tools = p.await_id(3)
        if tools is None or "result" not in tools:
            print("NO_TOOLS_LIST" + p.err_tail())
            for n in p.notes:
                print(n)
            return 1

        names = sorted(t.get("name", "") for t in tools["result"].get("tools", []))
        print("TOOLS " + ",".join(n for n in names if n))
        for n in p.notes:
            print(n)
        return 0
    except (BrokenPipeError, OSError) as exc:
        print(f"NO_INITIALIZE_RESPONSE transport error: {exc}{p.err_tail()}")
        return 1
    finally:
        p.shutdown()


if __name__ == "__main__":
    sys.exit(main())
