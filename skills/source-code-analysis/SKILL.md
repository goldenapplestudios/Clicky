---
name: source-code-analysis
description: White-box source-code acquisition and analysis - taint-style source-to-sink scanning, hardcoded secret detection, and dependency vulnerability scanning
allowed-tools: Bash, Read, Grep
---

# Source Code Analysis Skill

## Purpose

Gives Clicky a white-box capability alongside its normal black-box recon/exploitation flow: acquire application source (a local checkout, a git URL, or reconstruction from a misconfigured server's exposed `.git` directory), then scan it for likely vulnerabilities instead of only probing the live target blind. Used by `agents/source-analyzer-agent.md` - see that file for when/how it gets invoked during a `/pentest` run.

This complements, not replaces, `credential-harvesting` (live credential attacks) and `web-vulnerability-testing` (live black-box web testing) - this skill is specifically about reading source before or alongside testing the running target.

## Acquiring Source

```bash
# Local directory - used in place, no copy
${CLAUDE_PLUGIN_ROOT}/skills/source-code-analysis/scripts/source-scanner.sh acquire \
  --source "/path/to/checkout" --output-dir "$SESSION_DIR/recon/source"

# Git hosting URL - shallow clone
${CLAUDE_PLUGIN_ROOT}/skills/source-code-analysis/scripts/source-scanner.sh acquire \
  --source "https://github.com/org/repo.git" --output-dir "$SESSION_DIR/recon/source"

# Exposed .git on a live target - tries a direct `git clone .../.git` first
# (works against many misconfigured servers even without smart-HTTP
# support), then falls back to git-dumper or GitTools' gitdumper.sh if
# either is installed
${CLAUDE_PLUGIN_ROOT}/skills/source-code-analysis/scripts/source-scanner.sh acquire \
  --source "http://10.10.10.10/" --output-dir "$SESSION_DIR/recon/source"
```

If none of these work, the script fails loudly rather than silently proceeding with no source - do not fabricate findings when acquisition fails.

## Scanning Source: Taint-Style Analysis

```bash
${CLAUDE_PLUGIN_ROOT}/skills/source-code-analysis/scripts/source-scanner.sh scan \
  --dir "$SESSION_DIR/recon/source" --output "$SESSION_DIR/recon/source_findings.json"
```

**Prefers Semgrep (real AST-based static analysis) when installed**, via a bundled offline ruleset at `references/semgrep-ruleset.yml` - deliberately not `--config auto`, which would pull from the Semgrep Registry over the network on every run. Falls back to this repo's own regex/proximity heuristic scanner (`source_taint_scan.py`) when Semgrep isn't installed, or produces no usable output. Check the output's `scanner` field (`"semgrep"` or `"regex_taint_scan"`) to see which path actually ran - the two aren't equally rigorous.

The regex/proximity fallback flags a dangerous sink pattern (e.g. `eval(`, raw SQL string concatenation, `os.system(`) that has an untrusted-input source pattern (e.g. `$_POST`, `req.body`, `request.args`) within 5 lines of it in the same file, and reports the pair with a `confidence` of `high` (source found nearby) or `low` (sink only, no source pattern in range - a lead, not a confirmed vulnerability). It does not track data flow across variables, functions, or files.

The bundled Semgrep ruleset is mostly real pattern-based static analysis (`mode: search`, the default), which likewise has no separately-tracked taint-source line - see each finding's `source_of_taint` for the honest caveat when `scanner` is `"semgrep"` and the matched rule isn't taint-mode. 7 of the bundled rules (id ending `-taint`: SQL injection and command injection in Python/JS/PHP, plus PHP `unserialize` code injection) are `mode: taint` instead - genuine intraprocedural dataflow analysis, a free capability of the OSS Semgrep engine this project uses (no Pro license needed for the matching itself). A taint-mode finding means semgrep confirmed a real source (an HTTP request parameter or PHP superglobal) actually reaches the matched sink through the function's data flow, including through an intermediate reassignment - not just two patterns co-occurring nearby. Those findings carry `"taint_traced": true` and `confidence: "high"` unconditionally. What Semgrep Pro gates is only the granular `extra.dataflow_trace` field (a separately-tracked intermediate-variable file:line) - confirmed absent from this project's OSS-engine output during verification, with or without the `--dataflow-traces` flag `source-scanner.sh` passes defensively; `source_of_taint` says so honestly rather than fabricating a location, without walking back the fact that the flow itself was genuinely traced.

Either way, treat every finding as a strong hint worth manually confirming, never as gospel - the plan-level risk note for this whole capability is that source can also be stale relative to what's actually deployed.

Covered vulnerability classes (both scanners cover the same set, so ruleset choice doesn't change scope): command injection, code injection (`eval`, `pickle.loads`, insecure `yaml.load`, `unserialize`), SQL injection (SQL keyword + string-concatenation heuristic - covers both `+`-style and PHP's `.` concatenation operator), XSS, path traversal/LFI, SSRF, and hardcoded secrets (private keys, AWS access keys, Slack tokens, generic API keys, hardcoded passwords, DB connection strings with embedded credentials - these patterns extend, not duplicate, `skills/report-generation/scripts/report-generator.sh`'s `sanitize` redaction patterns and the broad terms in `skills/credential-harvesting/SKILL.md`).

### Output Shape

```json
{
  "source_location": "/absolute/path",
  "files_scanned": 42,
  "scanner": "semgrep",
  "findings": [
    {
      "id": "src-1",
      "type": "sql_injection",
      "file": "src/login.php",
      "line": 4,
      "sink": "SELECT",
      "source_of_taint": "$_POST",
      "confidence": "high",
      "suggested_attack_vector": {"technique": "sql_injection"},
      "mitre_attack": ["T1190"]
    }
  ]
}
```

(`scanner` is `"regex_taint_scan"` when the fallback ran instead. A `type: "unmapped"` finding with a `raw_rule_id` field can appear from the Semgrep path if a rule doesn't match the known type table - never guessed, always flagged as unmapped.)

`hardcoded_secret` findings have `secret_type` instead of `sink`/`source_of_taint`/`suggested_attack_vector`.

## Scanning Dependencies

```bash
${CLAUDE_PLUGIN_ROOT}/skills/source-code-analysis/scripts/dependency-scanner.sh \
  --dir "$SESSION_DIR/recon/source" --output "$SESSION_DIR/recon/dependency_findings.json"
```

Prefers `trivy fs` if installed (covers npm/pip/gem/go from one pass over whatever lockfiles are present). Falls back to per-ecosystem native tools for whichever manifest is found: `npm audit` (package.json), `pip-audit` (requirements.txt/Pipfile.lock/pyproject.toml), `bundler-audit` (Gemfile.lock), `govulncheck` (go.mod). The fallback also runs if `trivy` is installed but fails or produces no output, not only when it's entirely absent - a broken trivy install shouldn't silently read as "zero vulnerabilities." A manifest found with no matching tool installed is reported in the result's `skipped` array, never silently dropped.

After normalization, every CVE-shaped `vulnerability_id` (GHSA/OSV-only IDs from npm-audit/govulncheck can't be enriched - EPSS and CISA KEV are both CVE-only feeds) is enriched with an **EPSS score** (exploit prediction) and **CISA KEV listed** (known-exploited-in-the-wild) status - the same "known-exploited beats a guess" signal `decision-agent` already uses for source-derived findings with a populated `maps_to_service`. This is the first network-dependent step in this skill; any failure (timeout, DNS, non-200) is caught and recorded in `enrichment_skipped` rather than failing the scan - the vulnerability list is still returned, just unenriched.

### Output Shape

```json
{
  "scanners_run": ["trivy"],
  "skipped": [],
  "vulnerabilities": [
    {
      "package": "lodash",
      "installed_version": "4.17.4",
      "fixed_version": "4.17.12",
      "vulnerability_id": "CVE-2019-10744",
      "severity": "CRITICAL",
      "description": "...",
      "source": "trivy",
      "epss_score": 0.05006,
      "epss_percentile": 0.91371,
      "cisa_kev_listed": false
    }
  ],
  "enrichment_skipped": []
}
```

`epss_score`/`epss_percentile`/`cisa_kev_listed` are absent (not zeroed/faked) on any entry whose `vulnerability_id` isn't CVE-shaped, or if the network call that would have supplied them failed - check `enrichment_skipped` for the latter case.

This is the concrete implementation behind `skills/web-vulnerability-testing/SKILL.md`'s OWASP A03:2025 (software/data integrity, including vulnerable-components) checklist item.

## Integration with the Rest of the Pipeline

- **Trigger conditions**: see `agents/source-analyzer-agent.md` for the two ways this gets invoked (explicit context flag, or opportunistic `.git`-exposure trigger from `recon-agent`).
- **Findings validation**: source-derived findings get logged with `--confidence "likely"` (never `confirmed`) via `session-manager.sh log`, and flow through the same Tier 1/Tier 2 validation pipeline as every other finding (`docs/workflow.md`) once something confirms them against the live target.
- **Decision-agent hand-off**: `decision-agent.md` reads this skill's output as a parallel input alongside `recon-agent`'s `services[]`, and promotes any finding with a populated `suggested_attack_vector.maps_to_service` to the top of its recommended sequence - a known sink beats a black-box guess.

## Notes

- Excludes `.git`, `node_modules`, `vendor`, `venv`/`.venv`, `__pycache__`, `dist`, `build`, `target`, `.tox`, `coverage`, `.next`, `.nuxt`, and any dotdir from scanning.
- Scans `.php`, `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.py`, `.rb`, `.java`, `.go`, `.asp`, `.aspx`, `.jsp` files.
- A finding with no `suggested_attack_vector.maps_to_service` is still worth reporting - it just doesn't get the priority boost.
