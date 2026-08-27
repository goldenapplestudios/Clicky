#!/usr/bin/env python3
"""Live check for the credential-attack technique gate in server.py.

Backs the countermeasure to the most-documented failure of LLM pentest agents:
defaulting to brute force. PentestGPT (USENIX Security '24, Table 3) measured
it as the #1 unnecessary operation - 235 instances, ~3x the next category,
worst in the strongest model. Because that is a learned prior rather than an
instruction-following gap, the gate is enforced at execution time here, not
merely requested in an agent prompt.

Asserts:
  1. Credential-attack tooling is BLOCKED when unauthorized.
  2. The refusal explains the three required preconditions.
  3. Ordinary commands that merely MENTION a tool are not blocked.
  4. `--help`-style invocations are not blocked.
  5. Once technique-gate.sh grants authorization, the same command runs.
  6. The block is recorded in the session trace.

Usage: test_technique_gate.py /path/to/server.py
"""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from mcp import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession

SERVER_PATH = sys.argv[1]
REPO_ROOT = Path(SERVER_PATH).resolve().parents[2]
GATE_SH = REPO_ROOT / "skills" / "engagement-state" / "scripts" / "technique-gate.sh"
FAILED = 0


def check(label, condition, detail=""):
    global FAILED
    if condition:
        print(f"PASS: {label}")
    else:
        FAILED = 1
        print(f"FAIL: {label}" + (f" - {detail}" if detail else ""))


def tool_text(result):
    return "\n".join(
        t for t in (getattr(b, "text", None) for b in result.content) if t is not None
    )


async def main():
    tmp_dir = tempfile.mkdtemp(prefix="clicky-technique-gate-check-")
    try:
        session_dir = Path(tmp_dir) / "session"
        session_dir.mkdir()
        (session_dir / "session.json").write_text(
            json.dumps({"session_id": "gate-fixture", "target": "fixture"})
        )
        (session_dir / "scope.json").write_text(
            json.dumps({"targets": {"in_scope": ["203.0.113.10"], "out_of_scope": []}})
        )

        params = StdioServerParameters(
            command=sys.executable,
            args=[SERVER_PATH],
            env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")},
        )

        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                async def run(cmd, timeout_s=20):
                    return tool_text(await session.call_tool("execute_command", {
                        "command": cmd, "session_dir": str(session_dir),
                        "timeout_s": timeout_s, "caller": "gate-test"}))

                # --- 1/2: blocked while unauthorized -----------------------
                out = await run("hydra -l root -P /tmp/pw.txt ssh://203.0.113.10")
                check("hydra is blocked when credential_attack is unauthorized",
                      "BLOCKED BY TECHNIQUE GATE" in out, out[:200])
                check("refusal names the auth-surface precondition",
                      "--auth-surface" in out, out[:400])
                check("refusal names the username-link precondition",
                      "--username-link" in out, out[:400])
                check("refusal names the operator-approval precondition",
                      "--operator-approval" in out, out[:400])
                check("refusal cites why brute force is deprioritised",
                      "WSTG" in out or "unnecessary operation" in out, out[:400])

                for cmd, label in [
                    ("medusa -h 203.0.113.10 -u root -P pw.txt -M ssh", "medusa"),
                    ("ncrack -p 22 --user root -P pw.txt 203.0.113.10", "ncrack"),
                    ("python3 /opt/tools/ssh-spray.py -t 203.0.113.10 -U u.txt -W p.txt", "ssh-spray.py"),
                    ("nxc smb 203.0.113.10 -u users.txt -p passwords.txt", "netexec spray"),
                ]:
                    out = await run(cmd)
                    check(f"{label} is blocked when unauthorized",
                          "BLOCKED BY TECHNIQUE GATE" in out, out[:150])

                # --- 3: no false positives on ordinary commands ------------
                for cmd, label in [
                    ("echo 'notes about hydra and medusa' > /dev/null; echo SAFE_OK", "echo mentioning tool names"),
                    ("grep -c hydra /etc/hostname 2>/dev/null; echo SAFE_OK", "grep for a tool name"),
                    ("command -v hydra >/dev/null; echo SAFE_OK", "checking whether a tool exists"),
                ]:
                    out = await run(cmd)
                    check(f"not blocked: {label}",
                          "BLOCKED BY TECHNIQUE GATE" not in out and "SAFE_OK" in out, out[:150])

                out = await run("hydra --help >/dev/null 2>&1; echo HELP_OK")
                check("not blocked: hydra --help", "BLOCKED BY TECHNIQUE GATE" not in out, out[:150])

                # --- 6: the block is traced --------------------------------
                trace = (session_dir / "logs" / "trace.jsonl")
                check("block is recorded in the session trace",
                      trace.exists() and "BLOCKED BY TECHNIQUE GATE" in trace.read_text(),
                      "no trace entry found")

                # --- 5: authorization unblocks it --------------------------
                res = subprocess.run([
                    "bash", str(GATE_SH), "request", str(session_dir),
                    "--technique", "credential_attack", "--service", "ssh", "--port", "22",
                    "--auth-surface", "ssh banner offers password auth (observed)",
                    "--username-link", "usernames recovered from /etc/passwd on this host",
                    "--operator-approval", "operator approved spray in session transcript",
                ], capture_output=True, text=True)
                check("technique-gate.sh grants with full evidence",
                      res.returncode == 0 and "GRANTED" in res.stdout, res.stdout + res.stderr)

                out = await run("hydra --version >/dev/null 2>&1; echo AUTHORIZED_RUN")
                check("authorized session no longer blocks the tool",
                      "BLOCKED BY TECHNIQUE GATE" not in out, out[:150])

                # and a real (non-help) invocation now passes the gate
                out = await run("echo would-run-hydra; hydra 2>/dev/null; echo AFTER", 15)
                check("authorized session runs a real credential-attack command",
                      "BLOCKED BY TECHNIQUE GATE" not in out, out[:150])

                # --- denial path of the gate script ------------------------
                res = subprocess.run([
                    "bash", str(GATE_SH), "request", str(session_dir),
                    "--technique", "credential_attack", "--service", "ftp",
                ], capture_output=True, text=True)
                check("technique-gate.sh DENIES a request with no evidence",
                      res.returncode == 3 and "DENIED" in res.stderr, res.stdout + res.stderr)

        return FAILED
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
