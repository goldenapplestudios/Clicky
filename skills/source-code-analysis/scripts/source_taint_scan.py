#!/usr/bin/env python3
"""Source Taint Scan - heuristic source-to-sink and hardcoded-secret
scanner for application source code.

Usage: source_taint_scan.py <directory>

Prints a JSON object matching agents/source-analyzer-agent.md's output
schema to stdout: {"source_location": ..., "findings": [...]}.

This is the fallback path run when Semgrep isn't installed (see
source-scanner.sh's `scan()`, which prefers Semgrep's real AST-based
analysis when available). This scanner itself is regex/proximity-based,
not real dataflow or AST analysis: a "tainted sink" finding means a
dangerous sink pattern and an untrusted-input pattern both appear within a
few lines of each other in the same file, not that data provably flows
from one to the other. Treat every finding as a lead worth manually
confirming, not a proven vulnerability - see agents/source-analyzer-agent.md.

Secret patterns are extended from (not duplicated line-for-line out of)
skills/report-generation/scripts/report-generator.sh's `sanitize`
redaction patterns and the broad terms in
skills/credential-harvesting/SKILL.md, adding source-code-specific ones
(AWS keys, Slack tokens, DB connection strings) those two don't need.
"""
import json
import os
import re
import sys

EXCLUDED_DIRS = {
    ".git", "node_modules", "vendor", "venv", ".venv", "__pycache__",
    "dist", "build", "target", ".tox", "coverage", ".next", ".nuxt",
}

SCANNABLE_EXTENSIONS = {
    ".php", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".py", ".rb", ".java",
    ".go", ".aspx", ".asp", ".jsp",
}

# Untrusted-input source patterns, by language/framework family. All are
# matched as substrings via regex search, not full-line matches.
SOURCE_PATTERNS = [
    re.compile(p) for p in [
        r"\$_GET\b", r"\$_POST\b", r"\$_REQUEST\b", r"\$_COOKIE\b",
        r"\$_SERVER\[['\"]HTTP_",
        r"req\.query\b", r"req\.body\b", r"req\.params\b", r"req\.headers\b", r"req\.cookies\b",
        r"request\.args\b", r"request\.form\b", r"request\.GET\b", r"request\.POST\b",
        r"request\.data\b", r"request\.json\b", r"request\.cookies\b",
        r"params\[", r"request\.getParameter",
        r"r\.URL\.Query\(\)", r"r\.FormValue\(",
    ]
]

# (type, sink_regex) pairs. Order matters only for which "type" wins when
# a line matches more than one - first match takes it.
SINK_PATTERNS = [
    ("command_injection", re.compile(r"\bos\.system\s*\(")),
    ("command_injection", re.compile(r"subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True")),
    ("command_injection", re.compile(r"\bshell_exec\s*\(")),
    ("command_injection", re.compile(r"\bpopen\s*\(")),
    ("command_injection", re.compile(r"Runtime\.getRuntime\(\)\.exec")),
    ("command_injection", re.compile(r"child_process\.(exec|execSync)\s*\(")),
    ("code_injection", re.compile(r"\beval\s*\(")),
    ("code_injection", re.compile(r"\bexec\s*\(")),
    ("code_injection", re.compile(r"new\s+Function\s*\(")),
    ("code_injection", re.compile(r"pickle\.loads?\s*\(")),
    ("code_injection", re.compile(r"yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)")),
    ("code_injection", re.compile(r"\bunserialize\s*\(")),
    ("xss", re.compile(r"\.innerHTML\s*=")),
    ("xss", re.compile(r"dangerouslySetInnerHTML")),
    ("xss", re.compile(r"document\.write\s*\(")),
    ("xss", re.compile(r"\bv-html\s*=")),
    ("path_traversal", re.compile(r"\bopen\s*\([^)]*\b(request|req\.)")),
    ("path_traversal", re.compile(r"\binclude(_once)?\s*\([^)]*\$_")),
    ("path_traversal", re.compile(r"\brequire(_once)?\s*\([^)]*\$_")),
    ("path_traversal", re.compile(r"readFileSync\s*\([^)]*req\.")),
    ("ssrf", re.compile(r"requests\.(get|post)\s*\([^)]*\b(request|req\.)")),
    ("ssrf", re.compile(r"fetch\s*\([^)]*\breq\.")),
    ("ssrf", re.compile(r"curl_exec\s*\(")),
]

# Heuristic SQL-injection check is separate: needs both a SQL keyword AND
# a sign of raw string-building (concatenation/format/f-string), since
# `SELECT ... WHERE id = %s` alone (a parameterized placeholder) is fine.
SQL_KEYWORD_RE = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)
SQL_CONCAT_RE = re.compile(r"""
    \+\s*["'$]                 # string concatenation with + into a quote/var (JS/Java/Python)
    | ["']\s*\.\s*\$\w+        # PHP: '...' . $var
    | \$\w+\s*\.\s*["']        # PHP: $var . '...'
    | \.format\s*\(            # .format( call
    | f["']                    # python f-string
    | `\s*\$\{                 # JS template literal interpolation
    | %\s*\(                   # old-style % formatting
""", re.VERBOSE)

SECRET_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("api_key", re.compile(r"(?i)(api[_-]?key|secret|token)[^=:\n]{0,10}[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]")),
    ("hardcoded_password", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]")),
    ("db_connection_string", re.compile(r"(?i)(mysql|postgres(?:ql)?|mongodb)://[^:\s'\"]+:[^@\s'\"]+@")),
]

TAINT_WINDOW_LINES = 5

MITRE_BY_TYPE = {
    "command_injection": ["T1190"],
    "code_injection": ["T1190"],
    "sql_injection": ["T1190"],
    "xss": ["T1189"],
    "path_traversal": ["T1083"],
    "ssrf": ["T1190"],
}


def iter_source_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS and not d.startswith(".")]
        for fn in filenames:
            if os.path.splitext(fn)[1] in SCANNABLE_EXTENSIONS:
                yield os.path.join(dirpath, fn)


def read_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except OSError:
        return []


def nearest_source(lines, idx):
    """Look backward from idx (0-based) within TAINT_WINDOW_LINES for a
    source pattern; also checks the sink line itself."""
    start = max(0, idx - TAINT_WINDOW_LINES)
    for i in range(idx, start - 1, -1):
        for pat in SOURCE_PATTERNS:
            m = pat.search(lines[i])
            if m:
                return m.group(0), i + 1  # 1-indexed line number
    return None, None


def scan_file(path, rel_path, findings, next_id):
    lines = read_lines(path)
    for idx, line in enumerate(lines):
        # Sink patterns (non-SQL)
        matched_type = None
        matched_sink_text = None
        for vuln_type, pat in SINK_PATTERNS:
            m = pat.search(line)
            if m:
                matched_type = vuln_type
                matched_sink_text = m.group(0)
                break

        # SQL injection heuristic
        if not matched_type and SQL_KEYWORD_RE.search(line) and SQL_CONCAT_RE.search(line):
            matched_type = "sql_injection"
            matched_sink_text = SQL_KEYWORD_RE.search(line).group(0)

        if matched_type:
            source_text, source_line = nearest_source(lines, idx)
            confidence = "high" if source_text else "low"
            findings.append({
                "id": f"src-{next_id[0]}",
                "type": matched_type,
                "file": rel_path,
                "line": idx + 1,
                "sink": matched_sink_text.strip(),
                "source_of_taint": source_text or "no untrusted-input pattern found nearby - sink alone, confirm data origin manually",
                "confidence": confidence,
                "suggested_attack_vector": {
                    "technique": matched_type,
                },
                "mitre_attack": MITRE_BY_TYPE.get(matched_type, []),
            })
            next_id[0] += 1

        # Secrets - independent of source/sink proximity
        for secret_type, pat in SECRET_PATTERNS:
            m = pat.search(line)
            if m:
                findings.append({
                    "id": f"src-{next_id[0]}",
                    "type": "hardcoded_secret",
                    "file": rel_path,
                    "line": idx + 1,
                    "secret_type": secret_type,
                    "confidence": "high",
                })
                next_id[0] += 1


def main():
    if len(sys.argv) != 2:
        print("Usage: source_taint_scan.py <directory>", file=sys.stderr)
        sys.exit(1)

    root = sys.argv[1]
    findings = []
    next_id = [1]
    files_scanned = 0

    for path in iter_source_files(root):
        rel_path = os.path.relpath(path, root)
        scan_file(path, rel_path, findings, next_id)
        files_scanned += 1

    print(json.dumps({
        "source_location": os.path.abspath(root),
        "files_scanned": files_scanned,
        "scanner": "regex_taint_scan",
        "findings": findings,
    }, indent=2))


if __name__ == "__main__":
    main()
