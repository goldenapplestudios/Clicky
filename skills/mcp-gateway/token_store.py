#!/usr/bin/env python3
"""Token Store - session-scoped real-value <-> token mapping for the MCP
gateway (skills/mcp-gateway). See SKILL.md for the full token scheme.

Storage: `$SESSION_DIR/.token-map.json`, mode 0600, created fresh per
session (a caller that wants a clean slate simply points at a fresh
SESSION_DIR - this module never deletes an existing map itself). Writes
are atomic (write-to-tempfile + os.replace) and serialized with an
advisory flock on a sidecar `.token-map.json.lock` file, so overlapping
tool calls within or across agent turns can't corrupt the map or lose an
update to a lost race.

Token naming is deterministic and sequential per kind:
  - "target"       -> TARGET_1, TARGET_2, ...
  - "cred_key"      -> CRED_KEY_1, ...       (PEM private key blocks)
  - "cred_apikey"   -> CRED_APIKEY_1, ...    (api_key=... style secrets;
                                                also GitHub/GitLab/Terraform
                                                Cloud PATs, see below)
  - "cred_hash"     -> CRED_HASH_1, ...      (password/NTLM/etc. hashes)
  - "cred_user"     -> CRED_USER_1, ...      (explicit registration only -
  - "cred_pass"     -> CRED_PASS_1, ...       see note below)

We split the CRED_ family by shape (CRED_KEY/CRED_APIKEY/CRED_HASH) rather
than minting a single generic CRED_n, since the patterns we reuse for
auto-discovery (see `_discover()` below) already distinguish these shapes
and a differentiated token reads more usefully in a transcript than an
opaque "CRED_3". CRED_USER_n/CRED_PASS_n exist as registerable kinds for a
caller that already knows a value is specifically a username or password
(e.g. a future credential-harvesting integration calling `register()`
directly) but - unlike the other four kinds - `redact()`'s automatic
discovery never mints these two on its own: a bare "word: word" shape in
free-text output is too ambiguous to safely auto-tag as a credential pair
without real false-positive cost, so that judgment call is left to an
explicit caller instead of a regex.

Auto-discovery in `redact()` reuses, rather than reinvents, this repo's
existing pattern-matching:
  - target shapes (IPv4/CIDR, coarse IPv6, dotted hostnames, bare
    letter+digit hostnames like "dc01") come directly from
    skills/target-validation/scripts/extract-targets.py's own
    `extract_from_text()`, loaded dynamically since that script's filename
    isn't a valid Python module name.
  - credential shapes are adapted from two existing scripts' own regexes:
    the private-key-block and api_key=... patterns in
    skills/report-generation/scripts/report-generator.sh's `sanitize()`
    function, and the hash-length/format patterns in
    skills/credential-harvesting/scripts/hash-identifier.py's `PATTERNS`
    list (bcrypt/$1$/$5$/$6$ prefixes plus bare 32/40/64/128 hex-char
    runs). Both are known best-effort/over-matching trade-offs, same as
    extract-targets.py documents about itself - a hex checksum that isn't
    actually a password hash costs one spurious token, not a correctness
    bug.
"""
from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_EXTRACT_TARGETS_PATH = _HERE.parent / "target-validation" / "scripts" / "extract-targets.py"

TOKEN_MAP_FILENAME = ".token-map.json"


def _load_extract_from_text():
    """Dynamically load extract_from_text() from extract-targets.py.

    That script's filename has a hyphen, so it can't be imported with a
    plain `import` statement; this loads it as a standalone module by
    path instead of duplicating its regexes here. Guarded so a missing/
    broken source file degrades to "no target auto-discovery" rather than
    breaking every other token_store operation.
    """
    if not _EXTRACT_TARGETS_PATH.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "clicky_extract_targets", _EXTRACT_TARGETS_PATH
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.extract_from_text
    except Exception:
        return None


_extract_from_text = _load_extract_from_text()

# --- Credential-shape patterns, adapted from
# skills/report-generation/scripts/report-generator.sh's sanitize()
# function (private key blocks, api_key=... assignments) and
# skills/credential-harvesting/scripts/hash-identifier.py's PATTERNS list
# (hash formats), both read in full before writing these. ---

# Same as report-generator.sh's sanitize(), verbatim.
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)

# Adapted from report-generator.sh's
#   (?i)\b(api[ _-]?key[^:=]*[:=][ "']*)[A-Za-z0-9_-]{16,}
# That pattern's capture group is the "api_key=" prefix, since
# sanitize()'s job is to replace the whole match with "[REDACTED]". Here
# we need the *value* on its own (group 1) so it can become the token's
# real-value, while the "api_key=" prefix stays as literal surrounding
# text.
_API_KEY_RE = re.compile(
    r"(?i)\bapi[ _-]?key[^:=\n]*[:=]\s*[\"']?([A-Za-z0-9_-]{16,})[\"']?"
)

# IaC/CI-CD platform token shapes (GitHub personal access token, GitLab
# personal access token, Terraform Cloud/Enterprise API token) - added
# alongside _API_KEY_RE for the same reason it exists: these are exactly
# the credential shapes cloud-detection.sh's new
# check_cicd_config_exposure()/check_terraform_state_exposure() checks
# surface, and skills/source-code-analysis/scripts/source_taint_scan.py
# now scans .tf/.tfvars/.tfstate/.yml/.yaml/Jenkinsfile/Dockerfile for the
# same shapes - all three need to come back through the gateway already
# tokenized, not raw. Whole-match tokens (no prefix/value split like
# _API_KEY_RE), each self-describing enough that no separate literal
# prefix needs preserving in the surrounding text.
_GITHUB_PAT_RE = re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{22,}\b")
_GITLAB_PAT_RE = re.compile(r"\bglpat-[A-Za-z0-9_-]{20}\b")
_TF_CLOUD_TOKEN_RE = re.compile(r"\batlasv1\.[A-Za-z0-9_-]{40,}\b")

# Adapted from hash-identifier.py's PATTERNS (bcrypt / glibc crypt / bare
# hex hash lengths). Order matters: more specific ($-prefixed) patterns
# are tried first so a bare-hex pattern doesn't grab a substring of one.
_HASH_RES = [
    re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"),  # bcrypt
    re.compile(r"\$6\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{1,86}"),  # sha512crypt
    re.compile(r"\$5\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{1,43}"),  # sha256crypt
    re.compile(r"\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}"),  # md5crypt
    re.compile(r"\by\$[./A-Za-z0-9]+"),  # yescrypt tail, sans literal '$' start ambiguity
    re.compile(r"\b[A-Fa-f0-9]{128}\b"),  # SHA-512
    re.compile(r"\b[A-Fa-f0-9]{64}\b"),  # SHA-256
    re.compile(r"\b[A-Fa-f0-9]{40}\b"),  # SHA-1
    re.compile(r"\b[A-Fa-f0-9]{32}\b"),  # MD5 or NTLM
]

# Our own minted token names (e.g. "TARGET_1", "CRED_HASH_3") must never be
# treated as newly-discovered values by _discover() - without this guard,
# redact() would try to re-register an already-redacted token as if it
# were fresh loot the moment it saw its own output again.
_OWN_TOKEN_RE = re.compile(r"^(?:TARGET|CRED_[A-Z]+)_\d+$")

KIND_PREFIX = {
    "target": "TARGET",
    "cred_key": "CRED_KEY",
    "cred_apikey": "CRED_APIKEY",
    "cred_hash": "CRED_HASH",
    "cred_user": "CRED_USER",
    "cred_pass": "CRED_PASS",
}

def _prefix_for(kind: str) -> str:
    try:
        return KIND_PREFIX[kind]
    except KeyError:
        raise ValueError(f"Unknown token kind: {kind!r} (valid: {sorted(KIND_PREFIX)})") from None


class TokenStore:
    """Real-value <-> token mapping, scoped to one session directory."""

    def __init__(self, session_dir: str | os.PathLike):
        self.session_dir = Path(session_dir)
        self.path = self.session_dir / TOKEN_MAP_FILENAME
        self.lock_path = self.session_dir / (TOKEN_MAP_FILENAME + ".lock")

    # --- storage ---

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"counters": {}, "tokens": {}}
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return {"counters": {}, "tokens": {}}
        data.setdefault("counters", {})
        data.setdefault("tokens", {})
        return data

    def _save(self, data: dict[str, Any]) -> None:
        self.session_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self.session_dir), prefix=".token-map.", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self.path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _with_lock(self, fn):
        """Run fn(data) under an exclusive flock, persisting any mutation.

        fn may mutate `data` in place and/or return a value; the (possibly
        mutated) data is always re-saved after fn returns, so callers don't
        need to remember to persist themselves.
        """
        self.session_dir.mkdir(parents=True, exist_ok=True)
        with open(self.lock_path, "a+") as lockf:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
            try:
                data = self._load()
                result = fn(data)
                self._save(data)
                return result
            finally:
                fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)

    # --- public API ---

    def register(self, real_value: str, kind: str) -> str:
        """Return the existing token for real_value, or mint+persist a new one.

        Lookup is by value alone (not value+kind): a given real value maps
        to exactly one token for the life of the session, regardless of
        which kind first registered it.
        """
        prefix = _prefix_for(kind)  # validate kind up front, before taking the lock

        def op(data: dict[str, Any]) -> str:
            tokens = data["tokens"]
            for token, entry in tokens.items():
                if entry["value"] == real_value:
                    return token
            counters = data["counters"]
            n = counters.get(kind, 0) + 1
            counters[kind] = n
            token = f"{prefix}_{n}"
            tokens[token] = {"value": real_value, "kind": kind}
            return token

        return self._with_lock(op)

    def resolve(self, text: str) -> str:
        """Replace every known token in `text` with its real value."""
        if not text:
            return text
        data = self._load()
        tokens = data["tokens"]
        if not tokens:
            return text
        pattern = re.compile(r"\b(" + "|".join(re.escape(t) for t in tokens) + r")\b")
        return pattern.sub(lambda m: tokens[m.group(1)]["value"], text)

    def redact(self, text: str) -> str:
        """Replace known real values with tokens, and auto-register+
        tokenize any newly-discovered target/credential-shaped value.
        """
        if not text:
            return text

        data = self._load()
        tokens = data["tokens"]

        # Step 1: redact already-known real values. Longest-first so one
        # value that happens to be a substring of another (e.g. a bare IP
        # inside a longer URL string already registered separately)
        # doesn't get corrupted by a shorter match firing first.
        if tokens:
            value_to_token = {entry["value"]: tok for tok, entry in tokens.items()}
            values_sorted = sorted(value_to_token, key=len, reverse=True)
            if values_sorted:
                known_pattern = re.compile("|".join(re.escape(v) for v in values_sorted))
                text = known_pattern.sub(lambda m: value_to_token[m.group(0)], text)

        # Step 2: discover new target/credential values and tokenize those too.
        discovered = self._discover(text)
        # Longest value first, same reasoning as step 1.
        for value, kind in sorted(discovered, key=lambda pair: len(pair[0]), reverse=True):
            token = self.register(value, kind)
            text = text.replace(value, token)

        return text

    # --- discovery ---

    def _discover(self, text: str) -> list[tuple[str, str]]:
        """Find target/credential-shaped values in `text` not yet known.

        Returns a list of (value, kind) pairs, deduplicated, in priority
        order (private key blocks > api keys > hashes > targets) with
        overlapping spans resolved in that same priority order so e.g. a
        hash pattern can't match a substring already claimed as part of a
        private key block.
        """
        found: list[tuple[str, str]] = []
        seen: set[str] = set()
        occupied: list[tuple[int, int]] = []

        def overlaps(span: tuple[int, int]) -> bool:
            return any(span[0] < e and span[1] > s for s, e in occupied)

        def add(value: str, kind: str, span: tuple[int, int]) -> None:
            occupied.append(span)
            if not value or value in seen or _OWN_TOKEN_RE.match(value):
                return
            seen.add(value)
            found.append((value, kind))

        for m in _PRIVATE_KEY_RE.finditer(text):
            add(m.group(0), "cred_key", m.span())

        for m in _API_KEY_RE.finditer(text):
            span = m.span(1)
            if overlaps(span):
                continue
            add(m.group(1), "cred_apikey", span)

        for pat in (_GITHUB_PAT_RE, _GITLAB_PAT_RE, _TF_CLOUD_TOKEN_RE):
            for m in pat.finditer(text):
                span = m.span()
                if overlaps(span):
                    continue
                add(m.group(0), "cred_apikey", span)

        for pat in _HASH_RES:
            for m in pat.finditer(text):
                span = m.span()
                if overlaps(span):
                    continue
                add(m.group(0), "cred_hash", span)

        if _extract_from_text is not None:
            # mode="output": this is command OUTPUT, not a command. A false
            # positive here is not one wasted scope check - it mints a
            # permanent token and rewrites that string in every later result,
            # reports included. See extract_from_text's docstring.
            for value in _extract_from_text(text, mode="output"):
                if value in seen or _OWN_TOKEN_RE.match(value):
                    continue
                seen.add(value)
                found.append((value, "target"))

        return found


__all__ = ["TokenStore", "KIND_PREFIX", "TOKEN_MAP_FILENAME"]
