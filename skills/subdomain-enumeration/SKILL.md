---
name: subdomain-enumeration
description: DNS attack-surface mapping - subdomain discovery via certificate transparency logs and passive/active enumeration tools, resolution, and subdomain takeover fingerprinting
allowed-tools: Bash, Read, Write
---

# Subdomain Enumeration Skill

## Purpose

Maps a domain's DNS attack surface before anything else happens against it -
the foundational first step of Jason Haddix's Bug Hunter's Methodology
recon flow. This is a distinct technique domain from `skills/osint-gathering`
(people/org/breach-data OSINT): here the target is DNS assets themselves,
matching Clicky's existing one-skill-per-technique convention (`web-crawling`,
`fuzzing`, `service-enumeration` are each separate skills too). Discovers
subdomains, resolves them, and flags any that look claimable via a
subdomain-takeover fingerprint check.

## Methodology

### Source Cascade

`scripts/subdomain-enum.sh` runs three discovery sources in order, each
degrading gracefully - a missing tool, or an empty/failed response from a
source, is a normal result for that source, not a script failure:

1. **crt.sh Certificate Transparency search** - always runs, free, no API
   key. Queries `https://crt.sh/?q=%.<domain>&output=json`, a JSON array of
   cert log entries; each entry's `name_value` field is a newline-separated
   list of every SAN on that certificate. crt.sh is a small, sometimes
   rate-limited/flaky free community service - a 502 or non-JSON body from
   it means zero names from this source, not an error.
2. **subfinder**, if installed (`command -v subfinder`) - `subfinder -d
   <domain> -silent -oJ`. Its baseline passive sources work with no API key
   configured. Skipped entirely, not a failure, if subfinder isn't on PATH.
3. **amass**, if installed (`command -v amass`) - passive by default
   (`amass enum -passive -d <domain> -json`); `--active` on this skill's
   own script adds amass's own active/brute-force techniques instead.
   Amass had a significant CLI restructuring in a v5.0.0 release, so the
   script does not hardcode flags from memory - it runs the installed
   binary's own `amass enum -h` first and only passes flags that binary's
   help output actually advertises, so it adapts to whichever amass
   version is actually present. Skipped entirely if amass isn't on PATH.

All names found across whichever sources ran are merged, deduped, and
stripped of a leading `*.` wildcard.

### Resolution

Every merged candidate is resolved (CNAME and A records, via `dig` if
present else `host`, each with a short per-lookup timeout). A candidate
that returns no CNAME and no A record - never deployed, or a long-expired
cert entry for a name that was never actually provisioned - is dropped from
the `resolved` list; it's still present in the raw `subdomains` list.

### Subdomain Takeover Fingerprinting

`scripts/takeover-fingerprints.json` is a curated 15-25 entry subset of the
community-maintained
[`EdOverflow/can-i-take-over-xyz`](https://github.com/EdOverflow/can-i-take-over-xyz)
reference list - refresh it from that live list periodically, it is
deliberately not a full mirror. Each entry is `{"provider", "cname_suffix",
"fingerprint"}`. For every resolved subdomain whose CNAME suffix matches a
known provider, the script fetches the subdomain (HTTPS first, HTTP
fallback) and greps the response body for that provider's fingerprint
string - only a confirmed string match is reported in `possible_takeovers`,
not a bare CNAME-suffix match on its own (a suffix match alone just means
"points at this provider," which is completely normal for a live,
non-takeoverable resource too).

### Usage

```bash
${CLAUDE_PLUGIN_ROOT}/skills/subdomain-enumeration/scripts/subdomain-enum.sh \
  --domain {domain} \
  --output "$SESSION_DIR/recon/subdomain_enum_{domain}.json"

# Only with the engagement's rules of engagement explicitly permitting
# active brute-force subdomain discovery:
${CLAUDE_PLUGIN_ROOT}/skills/subdomain-enumeration/scripts/subdomain-enum.sh \
  --domain {domain} --active \
  --output "$SESSION_DIR/recon/subdomain_enum_{domain}.json"
```

## Output Format

```json
{
  "domain": "example.com",
  "sources": {
    "crtsh": true,
    "subfinder": true,
    "amass": false
  },
  "subdomains": [
    "api.example.com",
    "mail.example.com",
    "www.example.com"
  ],
  "resolved": [
    {
      "subdomain": "www.example.com",
      "cnames": [],
      "a_records": ["93.184.216.34"]
    },
    {
      "subdomain": "old-campaign.example.com",
      "cnames": ["old-campaign.example.com.s3.amazonaws.com"],
      "a_records": []
    }
  ],
  "possible_takeovers": [
    {
      "subdomain": "old-campaign.example.com",
      "provider": "AWS S3",
      "cname": "old-campaign.example.com.s3.amazonaws.com",
      "fingerprint_matched": true
    }
  ]
}
```

`sources.crtsh`/`sources.subfinder`/`sources.amass` mean "this source ran"
(tool present, or crt.sh attempted), not "this source returned data" - a
tool that's absent from PATH reports `false` and is simply skipped; that's
graceful degradation, not a partial failure.

## Integration with Other Skills

### Session Management

`$SESSION_ID` is set earlier in the workflow (`commands/pentest.md` Step 1
exports it) - use the value already in the environment.

```bash
# Store each discovered subdomain as a discovery, not an attempt outcome -
# same distinction service-enumeration/SKILL.md's Integration section
# documents: `record` is for attack-attempt success/failure,
# `store` is for a plain discovery. See skills/session-management/SKILL.md.
${CLAUDE_PLUGIN_ROOT}/skills/session-management/scripts/state-persistence.sh store \
  "subdomains" '{"domain":"{domain}","subdomain":"{subdomain}","cnames":[...],"a_records":[...]}' "$SESSION_ID"

# A confirmed possible-takeover is itself a vulnerability discovery, not
# just an inventory entry - store it under "vulnerabilities" too so it
# surfaces alongside every other finding of that kind.
${CLAUDE_PLUGIN_ROOT}/skills/session-management/scripts/state-persistence.sh store \
  "vulnerabilities" '{"type":"subdomain_takeover","subdomain":"{subdomain}","provider":"{provider}","cname":"{cname}"}' "$SESSION_ID"
```

### Recon Agent

`agents/recon-agent.md` runs this skill as its Phase 0 (Attack Surface
Mapping), ahead of port/service discovery, whenever the target it was given
is a domain name rather than a bare IP/range/CIDR. Newly discovered
subdomains become pivot targets the same way any other newly-seen host
does - see that file's Gateway Calling Convention section for the
auto-tokenization mechanism, not repeated here. A non-empty
`possible_takeovers` sets `takeover_candidate_detected: true` in
recon-agent's report, the same opportunistic-handoff pattern as its
`git_exposure_detected`/`llm_endpoint_detected` fields, so `exploit-agent`
can act on a confirmed takeover opportunity.

## Notes

- This is passive/read-only reconnaissance by default (crt.sh, passive
  subfinder/amass, plain DNS resolution) - nothing here touches the target
  beyond ordinary DNS queries and a single HTTP(S) fetch per takeover
  candidate. `--active` is the one flag that changes that (amass's own
  active/brute-force techniques) - only pass it when scope/rules of
  engagement explicitly allow it.
- crt.sh is a free, community-run service with known reliability limits;
  treat an empty result from it as "try again later," not as proof the
  domain has no certificate history.
- The bundled fingerprint list is intentionally small and curated, not
  exhaustive - a subdomain that doesn't match any entry in it may still be
  vulnerable to a takeover technique this list doesn't cover yet.
