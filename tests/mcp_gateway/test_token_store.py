#!/usr/bin/env python3
"""Unit tests for skills/mcp-gateway/token_store.py.

Plain manual assertions (no framework), matching this repo's existing test
style (see tests/README.md / tests/schema_validation/test_schema_validation.py).
Exercises the real TokenStore class against real temp session directories -
not tautological: every check asserts a specific expected value, not just
"it didn't crash".
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(REPO_ROOT / "skills" / "mcp-gateway"))

from token_store import TokenStore  # noqa: E402

FAILED = 0


def check(label: str, actual, expected) -> None:
    global FAILED
    if actual == expected:
        print(f"PASS: {label}")
    else:
        FAILED = 1
        print(f"FAIL: {label} - expected {expected!r}, got {actual!r}")


def check_true(label: str, condition: bool, detail: str = "") -> None:
    global FAILED
    if condition:
        print(f"PASS: {label}")
    else:
        FAILED = 1
        print(f"FAIL: {label}" + (f" - {detail}" if detail else ""))


def with_tmp_store():
    tmp = tempfile.mkdtemp(prefix="clicky-token-store-test-")
    return tmp, TokenStore(tmp)


def test_register_dedup_and_sequential_numbering():
    tmp, store = with_tmp_store()
    try:
        t1 = store.register("10.10.10.5", "target")
        check("first target registers as TARGET_1", t1, "TARGET_1")

        t1_again = store.register("10.10.10.5", "target")
        check("re-registering the same value returns the same token", t1_again, "TARGET_1")

        t2 = store.register("10.10.10.6", "target")
        check("second distinct target registers as TARGET_2", t2, "TARGET_2")

        # Different kind gets its own independent counter, not sharing
        # TARGET's sequence.
        h1 = store.register("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", "cred_hash")
        check("first cred_hash registers as CRED_HASH_1 (independent counter)", h1, "CRED_HASH_1")

        t3 = store.register("10.10.10.7", "target")
        check(
            "target counter keeps incrementing regardless of cred_hash registrations",
            t3,
            "TARGET_3",
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_register_unknown_kind_raises():
    tmp, store = with_tmp_store()
    try:
        raised = False
        try:
            store.register("x", "not_a_real_kind")
        except ValueError:
            raised = True
        check_true("register() with an unknown kind raises ValueError", raised)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_resolve_round_trip_and_no_op():
    tmp, store = with_tmp_store()
    try:
        store.register("10.10.10.5", "target")
        store.register("10.10.10.6", "target")

        resolved = store.resolve("nmap -p- TARGET_1 and also TARGET_2")
        check(
            "resolve() substitutes every known token with its real value",
            resolved,
            "nmap -p- 10.10.10.5 and also 10.10.10.6",
        )

        plain = "just a plain sentence with no tokens in it at all"
        check("resolve() is a no-op on text with no tokens", store.resolve(plain), plain)

        check("resolve() is a no-op on empty string", store.resolve(""), "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_resolve_does_not_corrupt_on_prefix_collision():
    tmp, store = with_tmp_store()
    try:
        # Register 10 targets so TARGET_1 and TARGET_10 both exist - a naive
        # substring replace of "TARGET_1" would corrupt "TARGET_10".
        for i in range(1, 11):
            store.register(f"10.0.0.{i}", "target")
        resolved = store.resolve("hosts: TARGET_1 TARGET_10")
        check(
            "resolve() doesn't let TARGET_1 corrupt TARGET_10 (word-boundary safe)",
            resolved,
            "hosts: 10.0.0.1 10.0.0.10",
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_redact_known_value_and_no_op():
    tmp, store = with_tmp_store()
    try:
        store.register("10.10.10.5", "target")
        redacted = store.redact("connection refused from 10.10.10.5")
        check(
            "redact() replaces an already-known real value with its token",
            redacted,
            "connection refused from TARGET_1",
        )

        clean = "The quick brown fox jumps over the lazy dog"
        check(
            "redact() is a no-op on text with no known values and nothing discoverable",
            store.redact(clean),
            clean,
        )

        check("redact() is a no-op on empty string", store.redact(""), "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_redact_auto_discovers_new_target():
    tmp, store = with_tmp_store()
    try:
        redacted = store.redact("nmap scan against 10.10.10.99 found 3 open ports")
        check(
            "redact() auto-discovers and tokenizes a brand-new target-shaped value",
            redacted,
            "nmap scan against TARGET_1 found 3 open ports",
        )
        # Confirm it was actually persisted, not just substituted in-memory.
        with open(store.path) as f:
            data = json.load(f)
        check_true(
            "the newly-discovered target was actually persisted to .token-map.json",
            data["tokens"].get("TARGET_1", {}).get("value") == "10.10.10.99"
            and data["tokens"]["TARGET_1"]["kind"] == "target",
            f"tokens={data['tokens']}",
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_redact_auto_discovers_credential_shapes():
    tmp, store = with_tmp_store()
    try:
        # api_key= assignment (adapted from report-generator.sh's sanitize())
        redacted = store.redact('config: api_key="sk_test_ABCDEFGHIJ1234567890"')
        check_true(
            "redact() tokenizes an api_key=... secret as CRED_APIKEY_1, keeping the prefix",
            redacted == 'config: api_key="CRED_APIKEY_1"',
            f"got {redacted!r}",
        )

        # Bare 40-hex-char hash (adapted from hash-identifier.py's PATTERNS)
        redacted2 = store.redact(
            "found hash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 for user admin"
        )
        check_true(
            "redact() tokenizes a 40-hex-char hash as CRED_HASH_1",
            redacted2 == "found hash: CRED_HASH_1 for user admin",
            f"got {redacted2!r}",
        )

        # Private key block (verbatim pattern from report-generator.sh's sanitize())
        key_block = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpQIBAAKCAQEAtest1234567890abcdefTESTKEYDATA==\n"
            "-----END RSA PRIVATE KEY-----"
        )
        redacted3 = store.redact(f"leaked id_rsa:\n{key_block}\ndone")
        check_true(
            "redact() tokenizes a PEM private key block as CRED_KEY_1",
            redacted3 == "leaked id_rsa:\nCRED_KEY_1\ndone",
            f"got {redacted3!r}",
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_redact_then_resolve_round_trip():
    tmp, store = with_tmp_store()
    try:
        original = "connecting to 10.20.30.40 now"
        redacted = store.redact(original)
        check_true("redact() tokenized the fresh target", "TARGET_1" in redacted)
        restored = store.resolve(redacted)
        check("redact() then resolve() round-trips back to the original text", restored, original)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_file_permissions_are_0600():
    tmp, store = with_tmp_store()
    try:
        store.register("10.10.10.5", "target")
        mode = stat.S_IMODE(os.stat(store.path).st_mode)
        check_true(
            ".token-map.json is created with mode 0600",
            mode == 0o600,
            f"got {oct(mode)}",
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_concurrent_registration_is_safe():
    tmp, store = with_tmp_store()
    try:
        n = 20
        values = [f"10.99.0.{i}" for i in range(n)]

        def do_register(v):
            # Each thread uses the SAME TokenStore instance's session_dir but
            # a fresh flock acquisition per call (see _with_lock), so this
            # genuinely exercises the locking path, not just Python's GIL.
            return TokenStore(tmp).register(v, "target")

        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
            tokens = list(pool.map(do_register, values))

        check_true(
            "concurrent register() calls all succeeded",
            len(tokens) == n,
            f"got {len(tokens)} results",
        )
        check_true(
            "concurrent register() calls minted N distinct tokens (no lost updates)",
            len(set(tokens)) == n,
            f"got {sorted(set(tokens))}",
        )
        with open(store.path) as f:
            data = json.load(f)
        check(
            "final token-map.json has exactly N target entries persisted",
            sum(1 for e in data["tokens"].values() if e["kind"] == "target"),
            n,
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    test_register_dedup_and_sequential_numbering()
    test_register_unknown_kind_raises()
    test_resolve_round_trip_and_no_op()
    test_resolve_does_not_corrupt_on_prefix_collision()
    test_redact_known_value_and_no_op()
    test_redact_auto_discovers_new_target()
    test_redact_auto_discovers_credential_shapes()
    test_redact_then_resolve_round_trip()
    test_file_permissions_are_0600()
    test_concurrent_registration_is_safe()

    print()
    print("=== SUMMARY ===")
    print("ALL PASS" if FAILED == 0 else "SOME FAILED")
    return FAILED


if __name__ == "__main__":
    sys.exit(main())
