---
name: fuzzing
description: Directory/vhost/parameter fuzzing with a tool-preference cascade (ffuf, feroxbuster, gobuster, dirb, wfuzz, curl fallback) and authenticated-target support via skills/web-auth-capture
allowed-tools: Bash, Read
---

# Fuzzing Skill

## Purpose

Consolidates what used to be three scattered mentions of the same idea - a 9-line gobuster/dirb/ffuf blurb in `web-vulnerability-testing`, a 24-line ffuf parameter snippet in `api-security-testing`, and an inline tool cascade in `agents/recon-agent.md` - into one script both `recon-agent` (directory/vhost discovery) and `exploit-agent` (authenticated parameter fuzzing) call into, with real response filtering, recursive fuzzing, and wordlist strategy instead of a single hardcoded wordlist path.

## Tool Cascade

Same "prefer, track what ran, fall back on absence/failure" idiom as `dependency-scanner.sh`: **ffuf -> feroxbuster -> gobuster -> dirb -> wfuzz -> a plain `curl` loop** that always works as the last resort. Check the output's `tool_used` field - ffuf/feroxbuster results come from their own native JSON output modes; gobuster/dirb/wfuzz's structured-output support varies across versions, so those three are parsed from default text output via regex (best-effort - confirm against your installed version if a result looks off).

Prefer autocalibration (`ffuf -ac`) over hand-tuned filters where the running tool supports it - too permissive a filter produces thousands of false positives, too aggressive silently swallows real hits.

## Usage

```bash
# Directory/file discovery
${CLAUDE_PLUGIN_ROOT}/skills/fuzzing/scripts/fuzz.sh dir \
  --url "http://10.10.10.10" [--recursive] [--filter-code 404] [--auth-file "$AUTH_FILE"] \
  --output "$SESSION_DIR/recon/fuzz_dir.json"

# Virtual host / subdomain discovery
${CLAUDE_PLUGIN_ROOT}/skills/fuzzing/scripts/fuzz.sh vhost \
  --url "http://10.10.10.10" --domain "example.com" \
  --output "$SESSION_DIR/recon/fuzz_vhost.json"

# Parameter discovery (compares each candidate param's response against an
# unrelated-nonsense-param baseline, since a genuinely new param usually
# produces a response that differs in size/status from "param not recognized")
${CLAUDE_PLUGIN_ROOT}/skills/fuzzing/scripts/fuzz.sh param \
  --url "http://10.10.10.10/api/endpoint?x=1" --auth-file "$AUTH_FILE" \
  --output "$SESSION_DIR/recon/fuzz_param.json"
```

`--auth-file` (a `skills/web-auth-capture` output file) makes fuzzing/discovery work against endpoints behind a login wall - without it, everything behind auth just looks like a wall of 401/403s.

## Wordlists

Resolution order when `--wordlist` isn't given: the `default_web_wordlist_dir` plugin option (if set and it has a matching file for the mode) -> this skill's own small bundled wordlist in `assets/wordlists/` -> (dir mode only) the legacy `/usr/share/wordlists/dirb/common.txt`, for behavior parity with the old inline cascade on an unmodified Kali box. `default_web_wordlist_dir` is deliberately separate from the plugin's existing `default_password_wordlist`/`default_username_wordlist` - those are hydra/hashcat credential lists, not web-content wordlists.

The bundled wordlists (`dir-common-small.txt`, `vhost-subdomains-small.txt`, `api-params-small.txt`) are intentionally small and curated, not exhaustive - point `default_web_wordlist_dir` at a real SecLists checkout for serious coverage.

## Output Shape

```json
{
  "mode": "dir",
  "target": "http://10.10.10.10",
  "tool_used": "ffuf",
  "wordlist_used": "/path/to/wordlist.txt",
  "hits": [
    {"value": "/admin", "status": 200, "size": 4523}
  ]
}
```
`value` is the discovered path (`dir`), hostname (`vhost`), or parameter name (`param`) depending on mode. `tool_used` is `"curl_loop"` when nothing else was installed - still functional, just slower and without the preferred tools' extra filtering/calibration logic.

## Integration

`agents/recon-agent.md` uses `dir`/`vhost` (it already ran the old inline cascade, this replaces it 1:1 plus adds vhost as a first-class step). `agents/exploit-agent.md` uses `param` for authenticated parameter discovery. Both list `fuzzing` in their `skills:` frontmatter.
