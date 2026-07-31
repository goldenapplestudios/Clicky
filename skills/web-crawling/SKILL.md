---
name: web-crawling
description: JS-aware endpoint discovery for modern SPA targets via a katana/hakrawler/static-HTML tool cascade, closing the gap left by recon-agent's fixed-endpoint-probe approach
allowed-tools: Bash, Read
---

# Web Crawling Skill

## Purpose

`agents/recon-agent.md`'s existing API discovery (`curl http://target/api/`, `/v1/`, `/graphql`, ...) and `api-security-testing/scripts/api-testing.sh`'s `test_rest_api()` both probe a fixed list of common endpoint paths - real coverage for a conventional REST API, but blind to anything a modern single-page app only exposes via client-side routing or an XHR/fetch call the server never renders into static HTML. This skill closes that gap with an actual crawler.

## Tool Cascade

**katana (preferred) -> hakrawler (partial fallback) -> stdlib-only static HTML link extraction (weakest tier)**, same tracked-fallback idiom as `dependency-scanner.sh`/`skills/fuzzing`. Check `crawler_used` before trusting completeness:

- **katana** - real JS parsing, XHR/fetch detection, form discovery. The only tier that reliably finds JS-rendered routes.
- **hakrawler** - link/form extraction without JS execution. A real but materially weaker fallback - it will miss anything only reachable via client-side JavaScript.
- **static-fallback** - a stdlib-only Python regex extractor (`href=`/`src=`/`action=` attributes, resolved against the page's base URL, `javascript:`/`mailto:`/`data:` pseudo-links skipped). Finds nothing JS-rendered at all. This is what runs when neither tool is installed - it's genuinely the weakest tier, not a silent approximation of the others.

## Usage

```bash
${CLAUDE_PLUGIN_ROOT}/skills/web-crawling/scripts/crawl.sh crawl \
  --url "http://10.10.10.10" [--auth-file "$AUTH_FILE"] [--depth 2] \
  --output "$SESSION_DIR/recon/crawl_results.json"
```

`--auth-file` (a `skills/web-auth-capture` output file) lets the crawler reach pages behind a login wall - all three tiers accept it via the same header-injection mechanism `skills/fuzzing` uses.

## Output Shape

```json
{
  "target": "http://10.10.10.10",
  "crawler_used": "katana",
  "skipped_reason": "",
  "endpoints": [
    {"url": "http://10.10.10.10/api/users", "method": "GET", "source": "xhr"}
  ]
}
```
`source` is `"js_parse"`/`"xhr"`/`"form"` from katana, `"link"` from hakrawler (which doesn't categorize further), or `"static_href"` from the fallback tier. `skipped_reason` explains why a weaker tier ran (e.g. `"katana not installed"`) - never silently absent when it should be populated.

## Integration

`agents/recon-agent.md` runs this per discovered HTTP/HTTPS service and adds a `crawled_endpoints` field to its own output. `skills/api-security-testing/scripts/api-testing.sh`'s `test_rest_api()` accepts the resulting file as an optional 3rd argument, testing crawled endpoints alongside its existing fixed list rather than instead of it.
