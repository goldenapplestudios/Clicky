---
name: engagement-state
description: Externalized engagement state - a persistent attack tree, an OWASP WSTG/PTES coverage ledger, technique preconditions gating brute-force attacks, and objective binding, all kept on disk outside any model's context window
allowed-tools: Bash, Read, Write
---

# Engagement State Skill

## Purpose

Keeps the three things an automated pentest most reliably loses - **what is left
to try**, **what was never tested**, and **what the operator actually asked
for** - in files on disk rather than in a conversation that gets compacted.

## Why this exists

The failure modes here are measured, not hypothetical:

- **Loss of engagement context is the #1 cause of failed testing trials.** The
  PentestGPT evaluation (USENIX Security '24, Table 4) attributes more failures
  to "session context lost" (74) than to any other cause, ahead of false
  command generation (55) and deadlock operations (45).
- **Externalizing the plan is what fixes it.** PentestGPT's own Pentesting Task
  Tree improved subtask completion 58.6% over raw GPT-4; the follow-up
  structured-attack-tree work (COLM '25) showed that making the model *follow*
  an externally maintained tree, instead of regenerating its plan each turn,
  raised subtask completion from 35.2% to 74.4% using 55.9% fewer queries.
- **Brute force is the #1 unnecessary operation LLMs prescribe** (PentestGPT
  Table 3: 235 instances, ~3x the next category, worst in the strongest model).
  That is a learned prior, so it is gated at execution time, not merely
  discouraged in a prompt.
- **End-state-only evaluation misses method.** PentestJudge (arXiv 2508.02921)
  judges an agent's *trajectory* against hierarchical rubrics precisely because
  "models may find alternative routes to the success condition that bypass the
  intended behavior" - i.e. quietly solving an easier problem than the one
  asked.

## Scripts

All three state files live under `$SESSION_DIR/state/` and are created
automatically by the gateway's `create_session`.

### `scripts/attack-tree.sh` - what is left to try

`$SESSION_DIR/state/attack-tree.json`. Nodes carry a status, a hypothesis, and
evidence. Statuses: `open`, `in_progress`, `exhausted`, `confirmed`, `blocked`,
`untested`.

`exhausted` (investigated, nothing found) and `untested` (never investigated)
are deliberately separate words, and `exhausted` **requires `--evidence`** -
you cannot close a branch by asserting you looked at it.

```bash
attack-tree.sh add "$SESSION_DIR" --title "SSH :22" --tactic TA0006 --priority 30
attack-tree.sh set "$SESSION_DIR" n2 exhausted --evidence "<what you actually ran>"
attack-tree.sh next "$SESSION_DIR"     # highest-priority open node
attack-tree.sh render "$SESSION_DIR"   # human-readable tree
```

### `scripts/coverage-ledger.sh` - what was never tested

`$SESSION_DIR/state/coverage.json`. **120 checks: all 109 from the official
OWASP WSTG checklist plus 11 Clicky-local ones.**

The WSTG ids and test names are generated verbatim from a vendored copy of the
upstream checklist (`data/wstg-checklist.md`, CC BY-SA 4.0) by
`tools/generate-coverage-catalog.py` - they are never typed by hand. An earlier
revision did hand-write them and got 25 of 36 names wrong, including labelling
`WSTG-APIT-01` "Test GraphQL" when its official name is "API Reconnaissance"
(GraphQL is actually `WSTG-APIT-99`). A client-facing report citing a WSTG id
against the wrong test name is worse than one citing no id at all, so
`tests/run_all.sh` fails if the generated catalog drifts from the vendored
checklist, and the engagement-state suite fails if any title differs from the
official one.

`NET-*`, `SRC-*`, `ART-*`, and `PTES-*` are Clicky's own additions for
network-service and methodology coverage WSTG does not address; they
deliberately avoid the `WSTG-` prefix so nothing invented can be mistaken for
an OWASP identifier.

To refresh after an upstream WSTG release: re-fetch `data/wstg-checklist.md`
from the OWASP repo, re-run `python3 tools/generate-coverage-catalog.py`, and
commit both.

`done` requires `--evidence`; `skipped`/`partial`/`not_applicable` require
`--why`. Neither can be claimed by default.

```bash
coverage-ledger.sh mark "$SESSION_DIR" WSTG-INFO-04 done --evidence "7 Host values, byte-identical"
coverage-ledger.sh mark "$SESSION_DIR" NET-02 skipped --why "needs root; no passwordless sudo"
coverage-ledger.sh gaps "$SESSION_DIR"     # report-agent MUST print this
```

### `scripts/technique-gate.sh` - preconditions before low-yield attacks

`$SESSION_DIR/state/technique-authorizations.json`. A `credential_attack`
requires **all three** of `--auth-surface`, `--username-link`, and
`--operator-approval`.

This is enforced by the MCP gateway, which refuses to execute credential-attack
tooling (hydra, medusa, ncrack, patator, crowbar, netexec/crackmapexec sprays,
`ssh-spray.py`, Metasploit `*_login` modules) without an authorization on file.
The refusal is not advisory - the command does not run.

```bash
technique-gate.sh request "$SESSION_DIR" --technique credential_attack \
    --service ssh --port 22 \
    --auth-surface "<evidence the service takes credential auth>" \
    --username-link "<evidence these usernames belong to THIS service>" \
    --operator-approval "<what the operator actually said>"
```

`--username-link` is the precondition that most often cannot be met, and that
is the point: names displayed on a web page are **not** evidence that those
people hold accounts on SSH.

## Objective binding

`session.json` carries the operator's stated `objective` verbatim plus an
`objective_status` (`not_assessed` | `addressed` | `partially_addressed` |
`substituted` | `not_addressed`). `report-agent` must set it and say so
explicitly. An engagement that pursued an easier goal than the one asked for is
a failed engagement even if it produced findings.
