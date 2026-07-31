---
name: web-auth-capture
description: Capture an authenticated web-app session (cookies, bearer token, CSRF token) via manual paste, a curl-driven login POST, or HAR import, for reuse by fuzzing/crawling/exploitation against endpoints behind a login wall
allowed-tools: Bash, Read, Write
---

# Web Auth Capture Skill

## Purpose

Most of Clicky's web-testing capability (`web-vulnerability-testing`, `api-security-testing`, `skills/fuzzing`, `skills/web-crawling`) assumes an unauthenticated or already-authorized target. This skill closes that gap: it captures a real authenticated session once, in a uniform on-disk shape, so every other skill's tooling can reuse it via a single `--auth-file` flag instead of each reinventing login handling.

**Naming note:** this is deliberately not called anything with "session" in it. `$SESSION_ID`/`$SESSION_DIR` already mean "the current pentest engagement" throughout this codebase - a captured web-app auth context is a different, narrower thing, stored at `$SESSION_DIR/context/auth/<label>.json` (a namespaced subdirectory of the existing per-engagement session, not a competing concept).

## Three Capture Paths

Claude Code's Bash tool is one-shot and foreground - there's no way for Clicky to orchestrate a live intercepting proxy the way a dedicated red-team platform might. Given that constraint, this skill ships three practical alternatives instead, in order of how much they can capture:

1. **`manual`** - paste a raw `Cookie:` value and/or headers you already have from your own browser's devtools. Zero dependencies, always works, but requires you to have done the login yourself first.
2. **`curl-login`** - POST a login form directly. Best-effort auto-discovers a CSRF hidden field from the login page first (checks `csrf_token`, `_token`, `authenticity_token`, `csrfmiddlewaretoken`, `__RequestVerificationToken`) and merges it into the POST automatically if your `--data` doesn't already include it. **Only works against classic server-rendered forms** - it cannot execute JavaScript, so a client-side-rendered login form's dynamically-injected CSRF field won't be found.
3. **`from-har`** - import a HAR file (browser devtools' Network tab -> "Save all as HAR", or a manually-run mitmproxy session's own HAR export). This is the richest option and the only one that reliably covers JS-rendered SPA logins, since it's capturing what a real browser actually did.

```bash
# Manual
${CLAUDE_PLUGIN_ROOT}/skills/web-auth-capture/scripts/auth-capture.sh manual \
  --target "http://10.10.10.10" --cookie "PHPSESSID=abc123; other=xyz" \
  --header "Authorization: Bearer eyJ..." \
  --output "$SESSION_DIR/context/auth/10.10.10.10.json"

# curl-driven login
${CLAUDE_PLUGIN_ROOT}/skills/web-auth-capture/scripts/auth-capture.sh curl-login \
  --url "http://10.10.10.10/login" --data "user=admin&pass=Summer2024!" \
  --output "$SESSION_DIR/context/auth/10.10.10.10.json"

# HAR import
${CLAUDE_PLUGIN_ROOT}/skills/web-auth-capture/scripts/auth-capture.sh from-har \
  --har-file /path/to/exported.har --login-url-hint "http://10.10.10.10" \
  --output "$SESSION_DIR/context/auth/10.10.10.10.json"
```

Store the output under `$SESSION_DIR/context/auth/<label>.json` (pick `<label>` as the target hostname, sanitized, unless multiple auth contexts are needed for the same engagement) - the script itself doesn't compute this path, callers pass `--output` explicitly, same convention as every other script in this codebase.

## Output Schema

```json
{
  "target": "http://10.10.10.10",
  "captured_at": "2026-07-31T14:32:04Z",
  "method": "manual|curl_login|har_import",
  "cookies": {"PHPSESSID": "abc123"},
  "headers": {"Authorization": "Bearer ..."},
  "csrf_token": {"field": "csrf_token", "value": "..."},
  "expires_hint": ""
}
```
`csrf_token` is `null` when none was found/applicable. `expires_hint` is recorded when known but nothing actively re-checks it - if a long fuzzing run starts failing partway through, a stale/expired auth context is a real possibility worth checking manually (`status` below), not something this skill detects automatically.

## Consuming a Captured Auth Context

```bash
${CLAUDE_PLUGIN_ROOT}/skills/web-auth-capture/scripts/auth-capture.sh to-header-args \
  --auth-file "$SESSION_DIR/context/auth/10.10.10.10.json"
# -> prints one raw header per line, e.g.:
#      Cookie: PHPSESSID=abc123; other=xyz
#      Authorization: Bearer eyJ...
```

No `-H` prefix is baked into the output (a header value containing spaces makes naive word-splitting of pre-quoted `-H "..."` tokens fragile) - build an array instead:

```bash
mapfile -t auth_headers < <(${CLAUDE_PLUGIN_ROOT}/skills/web-auth-capture/scripts/auth-capture.sh to-header-args --auth-file "$AUTH_FILE")
args=()
for h in "${auth_headers[@]}"; do args+=(-H "$h"); done
curl "${args[@]}" http://10.10.10.10/admin
```

This is exactly what `skills/fuzzing/scripts/fuzz.sh --auth-file` and `skills/web-crawling/scripts/crawl.sh --auth-file` do internally.

```bash
${CLAUDE_PLUGIN_ROOT}/skills/web-auth-capture/scripts/auth-capture.sh status \
  --auth-file "$SESSION_DIR/context/auth/10.10.10.10.json"
```
Prints a quick human-readable summary (target, method, cookie count, whether an auth header/CSRF token is present) - useful before trusting a captured context in a new step, especially one carried over from earlier in a long session.

## Known Limitations

- **No live proxy interception.** This is the biggest gap versus a dedicated platform's mitmproxy-based capture - it doesn't fit Claude Code's one-shot foreground Bash model. If a target's login flow is JS-heavy and no HAR is available, `manual` (after logging in yourself) is the fallback.
- **`curl-login`'s CSRF discovery is regex-based against static HTML** - it will not find a field injected by client-side JavaScript after page load.
- **Captured tokens are not currently covered by `report-generator.sh`'s `sanitize` redaction patterns** (which cover private keys, API-key-shaped strings, and internal IPs, but not `Cookie:`/`Authorization: Bearer` values). If a captured value ends up quoted in a finding's description, it won't be auto-redacted from a generated report - a real, open gap, not something this skill silently protects against yet.
- **No active expiry detection.** A 401 partway through a long run on a stale auth context is possible; `expires_hint` is recorded when known but nothing polls it.

## Integration

- `agents/recon-agent.md` and `agents/exploit-agent.md` both list this skill, for authenticated crawling/enumeration and authenticated exploitation/fuzzing respectively.
- `skills/fuzzing` and `skills/web-crawling` both accept `--auth-file` and consume it via `to-header-args`.
