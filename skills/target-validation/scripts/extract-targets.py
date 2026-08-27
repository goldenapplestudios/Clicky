#!/usr/bin/env python3
"""Extract Targets - pull candidate scan targets (IPv4/CIDR, coarse IPv6,
hostnames) out of a shell command or URL, so callers can check each one
against scope.json via scope-validator.sh.

Two real callers today:
  - skills/mcp-gateway/token_store.py dynamically loads this module's
    extract_from_text() (this filename has a hyphen, so it can't be
    `import`ed normally) for its redact() auto-discovery step.
  - This script's own CLI (below), for ad hoc / manual checks.
(Before Phase 2 of the MCP-gateway plan, the now-retired
skills/target-validation/scripts/scope-enforcement-hook.sh PreToolUse hook
was also a caller, invoking the CLI below for every Bash/WebFetch call;
that hook has been replaced by skills/mcp-gateway's register_target tool,
which does its own scope check via scope_gate.py without going through
this script.)

Usage:
  extract-targets.py --command "nmap -p- 10.10.10.10"
  extract-targets.py --url "https://api.example.com/v1"
  extract-targets.py --command "..." --url "..."

Prints one candidate target per line (deduplicated, sorted), or nothing if
no candidates were found. Deliberately best-effort / regex-based: a false
positive (a version string that happens to look like an IP) just costs one
extra scope-validator.sh check; false negatives (an obfuscated or
indirectly-referenced target, e.g. via a shell variable) are a known blind
spot, not something this script tries to defeat - see the plan's Risks
section. Extraction here is a safety net on top of normal engagement
discipline, not a guarantee against a deliberately evasive command.
"""
import argparse
import ipaddress
import re

IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/\d{1,2})?\b'
)
# Coarse IPv6: 2+ colon-separated hex groups. This over-matches (e.g. a
# HH:MM:SS timestamp is technically hex-valid), which is an accepted
# trade-off - see module docstring.
IPV6_RE = re.compile(r'\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:/\d{1,3})?\b')
# Dotted hostnames: label(.label)+ with a final alphabetic TLD-shaped label,
# so plain IPs (already caught above) and dotted version numbers (e.g.
# "3.0.3") don't also match here.
HOSTNAME_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b'
)
# Bare (no-dot) single-label hostnames, e.g. "dc01" - an ordinary internal
# AD hostname. Unlike HOSTNAME_RE above this has no dot to anchor on, so it
# is deliberately much more conservative than plain free-text matching
# would be, to avoid flagging ordinary flag values/usernames/subcommands
# (which is exactly what most bare alnum tokens in a pentest command are):
#   - must contain BOTH a letter and a digit (rules out English words like
#     "admin"/"pass"/"smb" and tool/subcommand names like "crackmapexec",
#     while matching common internal-host naming like "dc01"/"web01");
#   - must not be glued to an immediately preceding "-" or "=" (rules out
#     flag names/values fused to their dash, e.g. the "p1"/"1000" fragments
#     inside an nmap "-p1-1000" port range, and "--flag=value" / URL query
#     "key=value" values, e.g. the "admin01" in "?user=admin01").
# The caller (extract_from_text) additionally skips the leading whitespace-
# delimited token of --command text, i.e. the binary/tool name itself,
# which is otherwise a common false positive when it has a trailing
# version digit (e.g. "ping6", "python3").
# Known residual blind spot, accepted: a single-label hostname with no
# digit in it at all (e.g. "attackbox") still isn't caught by this - see
# module docstring on the false-negative trade-off generally.
BARE_HOSTNAME_RE = re.compile(
    r'(?<![-=])\b(?=[a-zA-Z0-9-]*[a-zA-Z])(?=[a-zA-Z0-9-]*[0-9])'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\b'
)
# Small denylist of common letter+digit tokens that are hostname-shaped but
# almost never actual scan targets in pentest commands (hash/algorithm/
# encoding names, common arch/protocol tags) - keeps BARE_HOSTNAME_RE's
# extra "ask" prompts down without weakening the digit+letter requirement.
BARE_NOISE = {
    "md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "ntlmv1", "ntlmv2", "smb1", "smb2", "smb3", "http2", "tls1", "ssl2",
    "ssl3", "oauth2", "utf8", "ipv4", "ipv6", "x86", "x64", "base64", "b64",
    "socks4", "socks5", "top1", "top10", "top100", "top1000",
}
# host directly after a URL scheme: either a bracketed IPv6 literal
# ([::1], [2001:db8::1]) or a normal host up to the next '/', ':', quote,
# or whitespace. Trusted as a real host regardless of what its final label
# looks like.
URL_HOST_RE = re.compile(r'(?:https?|ftp)://(\[[0-9a-fA-F:]+\]|[^\s/:\'"\[]+)')

NOISE = {"example.com", "example.org", "example.net", "localhost.localdomain"}

# A bare (no-scheme) dotted token whose final label is one of these is
# almost always a filename in a path or argument (login.php, dump.sql,
# shell.jsp, backup.tar.gz), not a hostname - URL paths are extremely
# common in pentest commands (curl/sqlmap/wget/webshells), so without this
# filter nearly every web-testing command would spuriously flag its own
# request path as an unscoped target. Doesn't apply to hosts already
# confirmed via URL_HOST_RE, which are trusted outright.
EXT_BLOCKLIST = {
    "php", "php3", "php4", "php5", "phtml", "html", "htm", "js", "mjs", "json",
    "py", "pyc", "sh", "bash", "txt", "xml", "asp", "aspx", "jsp", "jspx",
    "css", "scss", "png", "jpg", "jpeg", "gif", "svg", "ico", "bmp", "pdf",
    "zip", "tar", "gz", "bz2", "7z", "rar", "log", "conf", "cfg", "yml",
    "yaml", "md", "sql", "bak", "env", "ini", "csv", "tsv", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "exe", "dll", "so", "dylib", "class",
    "jar", "war", "ear", "rb", "go", "rs", "c", "cpp", "h", "hpp", "java",
    "ts", "tsx", "jsx", "vue", "lock", "toml", "swp", "tmp", "cache", "map",
    "woff", "woff2", "ttf", "eot", "mp3", "mp4", "avi", "mov", "wav", "pem",
    "key", "crt", "cer", "pub",
}


# IPv4 glued to letters/hyphens is a version string, not an address:
# "net-snmp-5.9.5.2-bin" is syntactically a valid dotted quad, and
# ipaddress.ip_address() happily accepts it. A real address in output text is
# delimited by whitespace or punctuation like ':' '(' ',' - never welded to a
# word. Used by output mode only; command mode keeps the permissive match.
_IPV4_GLUE_BEFORE = re.compile(r'[A-Za-z_-]$')
_IPV4_GLUE_AFTER = re.compile(r'^[A-Za-z_-]')

# IPv6 shapes that are never a scan target but do match the coarse regex.
_IPV6_NOISE = {"::", ":::", "::0", "0::"}

# Version-string vs IPv4 disambiguation (output mode only). A dotted quad
# like "16.0.40.7" is a valid address by shape, so "FreePBX 16.0.40.7" got
# minted as a target ("FreePBX TARGET_10") - the exact usability failure the
# operator hit. Real addresses in output are introduced by punctuation or by
# an IP-context word (host/target/for/inet/...); a product/name word
# ("FreePBX", "Apache") before the quad marks a version instead. Kept
# conservative so a real in-scope IP is never suppressed: only a name NOT in
# _IP_INTRODUCER, or an explicit version keyword, or a 5th dotted component,
# counts as a version.
_VERSION_KEYWORD_RE = re.compile(r"(?:version|ver|rev|release|build|\bv)\s*$", re.IGNORECASE)
_NAME_BEFORE_RE = re.compile(r"([A-Za-z][A-Za-z0-9+]*[A-Za-z])[/ ]$")
_IP_INTRODUCER = {
    "host", "hosts", "target", "targets", "server", "gateway", "address", "addr",
    "ip", "inet", "inet6", "from", "to", "via", "peer", "router", "dns", "ns",
    "nameserver", "for", "at", "on", "src", "dst", "source", "dest", "destination",
    "proxy", "bind", "listening", "connect", "connected", "ping", "scan", "reach",
}


def _looks_like_version(text: str, start: int, end: int) -> bool:
    """True when the dotted quad at [start:end] reads as a software version
    rather than an address (output-mode heuristic - conservative on purpose:
    suppressing a real target IP is a privacy failure, so this only fires on
    an unambiguous version shape)."""
    if text[end:end + 1] == "." and text[end + 1:end + 2].isdigit():
        return True  # a 5th component -> not an IPv4 at all
    before = text[:start]
    if _VERSION_KEYWORD_RE.search(before[-16:]):
        return True
    m = _NAME_BEFORE_RE.search(before[-40:])
    if not m:
        return False
    name = m.group(1)
    # Only a PRODUCT identifier marks a version. A plain lowercase English
    # word before a dotted quad ("against 10.10.10.99", "found 10.0.0.5") is
    # prose around a real address - do NOT suppress it. A product name is
    # mixed-case or digit-bearing ("FreePBX", "OpenSSH2"); IP-introducer words
    # (host/target/for/...) are excluded even when capitalized.
    if name.isalpha() and name.islower():
        return False
    return name.lower() not in _IP_INTRODUCER


def extract_from_text(text: str, mode: str = "command") -> set:
    """Pull candidate targets out of `text`.

    `mode` selects the policy, because the two callers have opposite cost
    models for a false positive:

      "command" (default) - scanning a shell command before running it, to
        scope-check what it touches. A false positive costs one extra
        scope-validator.sh call, so over-matching is the safe direction and
        this stays deliberately permissive (see the module docstring).

      "output" - scanning command OUTPUT for values to tokenize
        (token_store.redact()). Here a false positive is NOT cheap: it mints
        a permanent token and then rewrites that string everywhere it appears
        for the rest of the engagement, including in client-facing reports.
        Observed live: one engagement minted 337 tokens for a single-target
        scan - 257 of them two-character fragments of /nix/store hashes
        matched as "hostnames", plus version strings that parse as IPv4
        ("net-snmp-5.9.5.2") and a bare "0" from "[exit 0]". Output that read
        "OpenSSH 9.6p1" came back as "OpenSSH 9.TARGET_84".

    So output mode drops the single-label bare-hostname pass entirely (a
    no-dot word in arbitrary output is not identifiable as a host), requires
    IPv4 not to be welded to surrounding word characters, and rejects IPv6
    noise shapes. Dotted hostnames and well-delimited IPs - the values that
    actually matter for privacy - are still caught.
    """
    if mode not in ("command", "output"):
        raise ValueError(f"extract_from_text: unknown mode {mode!r}")
    candidates = set()
    # Spans already claimed by a higher-confidence pattern (URL host, IPv4/
    # IPv6, dotted hostname) below, so the bare-hostname pass at the end
    # doesn't re-match fragments of them (e.g. the "db8" group inside IPv6
    # "2001:db8::1", or the numeric octets of a plain IP).
    occupied = []

    url_hosts = set()
    for m in URL_HOST_RE.finditer(text):
        occupied.append(m.span(1))
        host = m.group(1).rstrip("/").lower()
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        if host:
            url_hosts.add(host)
    candidates |= url_hosts

    for m in IPV4_RE.finditer(text):
        occupied.append(m.span())
        val = m.group(0)
        if mode == "output":
            start, end = m.span()
            if _IPV4_GLUE_BEFORE.search(text[:start][-1:]) or _IPV4_GLUE_AFTER.match(text[end:end + 1]):
                continue
            if _looks_like_version(text, start, end):
                continue
        try:
            if "/" in val:
                ipaddress.ip_network(val, strict=False)
            else:
                ipaddress.ip_address(val)
            candidates.add(val)
        except ValueError:
            continue

    for m in IPV6_RE.finditer(text):
        occupied.append(m.span())
        val = m.group(0)
        if val.count(":") < 2:
            continue
        if mode == "output" and (val in _IPV6_NOISE or not any(c in "0123456789abcdefABCDEF" for c in val)):
            continue
        try:
            ipaddress.ip_address(val.split("/")[0])
            candidates.add(val)
        except ValueError:
            continue

    for m in HOSTNAME_RE.finditer(text):
        occupied.append(m.span())
        val = m.group(0)
        low = val.lower()
        if low in NOISE:
            continue
        if low not in url_hosts:
            final_label = low.rsplit(".", 1)[-1]
            if final_label in EXT_BLOCKLIST:
                continue
        candidates.add(val)

    # The leading whitespace-delimited token is the binary/tool name for
    # --command text (e.g. "ping6", "python3", "crackmapexec") - never a
    # scan target, so bare-hostname matches fully inside it are excluded.
    leading = re.match(r'\s*\S+', text)
    leading_end = leading.end() if leading else 0

    # Single-label bare hostnames are command-mode only. In a shell command
    # "dc01" is plausibly a target; in arbitrary output it is indistinguishable
    # from a hash fragment, a filename, or a column header - and this pass is
    # what minted 257 junk tokens from /nix/store paths in one session.
    bare_iter = () if mode == "output" else BARE_HOSTNAME_RE.finditer(text)
    for m in bare_iter:
        span = m.span()
        if span[0] < leading_end:
            continue
        if any(span[0] < e and span[1] > s for s, e in occupied):
            continue
        val = m.group(0)
        if val.lower() in BARE_NOISE:
            continue
        candidates.add(val)

    return candidates


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--command", default=None, help="A Bash command string to scan")
    parser.add_argument("--url", default=None, help="A URL (WebFetch tool_input.url) to scan")
    args = parser.parse_args()

    candidates = set()
    if args.command:
        candidates |= extract_from_text(args.command)
    if args.url:
        candidates |= extract_from_text(args.url)

    for c in sorted(candidates):
        print(c)


if __name__ == "__main__":
    main()
