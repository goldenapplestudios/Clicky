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


def test_redact_does_not_tokenize_output_noise():
    """redact() must not mint tokens for text that merely LOOKS target-shaped.

    Regression for a real corruption. extract-targets.py is deliberately
    permissive because its original caller scope-checks shell commands, where
    a false positive costs one wasted check. redact() is a second caller with
    the opposite cost model: a false positive mints a PERMANENT token and then
    rewrites that string in every later result, client-facing reports included.

    Observed live before the fix: a single-target engagement minted 337 tokens.
    257 were two-character fragments of /nix/store hashes matched as bare
    hostnames; version strings that parse as valid dotted quads
    ("net-snmp-5.9.5.2") were tokenized as addresses; and "[exit 0]" became
    "[exit TARGET_307]". Rendered output read "OpenSSH 9.TARGET_84".
    """
    noise = [
        ("[exit 0]", "a bare exit code"),
        ("/nix/store/s4qk35irdiqna4h2mkhgg2q6b3fx1wz5-net-snmp-5.9.5.2-bin/bin/snmpwalk",
         "nix store path with a version that parses as IPv4"),
        ("OpenSSH_9.6p1 Ubuntu-3ubuntu13.16", "an ssh version banner"),
        ('counts: {"exhausted":1,"open":3,"untested":2}', "json counts"),
        ("total 44 drwxrwxr-x 2 howzor howzor 4096", "ls -l output"),
    ]
    for text, label in noise:
        tmp, store = with_tmp_store()
        try:
            out = store.redact(text)
            check(f"redact leaves {label} untouched", out, text)
            minted = len(store._load()["tokens"])
            check_true(f"no token minted from {label}", minted == 0, f"minted {minted}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def test_redact_still_tokenizes_real_targets():
    """The inverse: tightening discovery must not stop it catching real hosts.

    A newly-seen host in scan output still has to become a token - that is the
    whole point of auto-discovery, and it is what keeps a pivot target from
    leaking into the model as a raw value.
    """
    real = [
        ("Nmap scan report for 10.129.55.61", "10.129.55.61", "a bare IPv4"),
        ("Host: 10.129.55.61:3000 open", "10.129.55.61", "IPv4 followed by a port"),
        ("fetching https://api.example.com/v1", "api.example.com", "a dotted hostname"),
        ("neighbour 2001:db8::1 reachable", "2001:db8::1", "an IPv6 address"),
    ]
    for text, value, label in real:
        tmp, store = with_tmp_store()
        try:
            out = store.redact(text)
            check_true(f"{label} is still tokenized", value not in out, f"got: {out}")
            check_true(f"{label} produced a TARGET_ token", "TARGET_" in out, f"got: {out}")
            check_true(f"{label} round-trips back", store.resolve(out) == text,
                       f"resolve gave: {store.resolve(out)}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def test_redact_does_not_over_tokenize_technical_strings():
    """Non-secret technical strings that merely LOOK hash- or IP-shaped must
    not be minted as tokens - the over-tokenization the operator hit on a real
    engagement (GPG fingerprint -> CRED_HASH, 'FreePBX 16.0.40.7' -> TARGET).
    Bare-hex hashes tokenize only in a credential context; dotted-quad version
    strings are not treated as addresses.
    """
    leave_alone = [
        ("Key fingerprint = 0BDE0BFA09946D732091E26E1588A7366BD35B34", "a GPG fingerprint"),
        ("[GNUPG:] VALIDSIG " + "A" * 40 + " 2026", "a gpg VALIDSIG hex"),
        ("signedwith=1588A7366BD35B34", "a 16-hex key id"),
        ("sha256sum: " + "d" * 64 + "  release.tar.gz", "a sha256 checksum"),
        ("hash=sha256 /usr/local/asterisk/pwn = " + "e" * 64, "a sig-file digest"),
        ("FreePBX 16.0.40.7 is licensed under the", "a 4-part version string"),
        ("running OpenSSH_9.6p1 on the host", "an OpenSSH version"),
        ("root.txt: 5f6238f293a69bc1b1963b6c167ecdea", "a bare flag (no cred context)"),
    ]
    for text, label in leave_alone:
        tmp, store = with_tmp_store()
        try:
            out = store.redact(text)
            check_true(f"{label} is left untokenized", out == text, f"got: {out!r}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ...but real credential material and real targets STILL tokenize.
    still_tokenize = [
        ("shadow line root:$6$abc$" + "x" * 60 + ":19000:", "CRED_HASH", "a sha512crypt hash"),
        ("found hash: " + "a1b2c3d4" * 5 + " for admin", "CRED_HASH", "a hash in credential context"),
        ("password_hash: " + "f" * 32 + " stored", "CRED_HASH", "an MD5 in a password context"),
        ("Nmap scan report for 10.129.245.100", "TARGET_", "a real target IP"),
    ]
    for text, prefix, label in still_tokenize:
        tmp, store = with_tmp_store()
        try:
            out = store.redact(text)
            check_true(f"{label} still tokenizes", prefix in out, f"got: {out!r}")
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
    test_redact_does_not_tokenize_output_noise()
    test_redact_still_tokenizes_real_targets()
    test_redact_does_not_over_tokenize_technical_strings()

    print()
    print("=== SUMMARY ===")
    print("ALL PASS" if FAILED == 0 else "SOME FAILED")
    return FAILED


if __name__ == "__main__":
    sys.exit(main())
