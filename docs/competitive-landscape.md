# Competitive Landscape

Where Clicky sits relative to real prior art in AI-driven penetration testing - open-source/academic frameworks and published benchmarks, not just funded commercial startups. Researched 2026-07-31; **this space moves fast, re-verify star counts/last-commit dates/benchmark scores before citing them externally.**

## Why this doc exists

An earlier comparison covered only two commercial startups (XBOW, RunSybil). That undersold the actual technical landscape - there's a substantial body of open-source and academic work in this exact category, plus recognized benchmarks that give a real, reproducible bar for "how good is this," which vendor marketing pages don't. This doc grounds Clicky's positioning against that wider field.

## Commercial platforms

| | XBOW | RunSybil (Sybil) |
|---|---|---|
| Model | Hosted SaaS, "Pentest On-Demand" (~$6K, ~5 business days) | Hosted SaaS, continuous re-testing on every deploy |
| Architecture | Coordinator + sandbox + validation agents, Docker-isolated; discovery and validation are separate systems | Single agent reasoning across app/infra layers |
| Track record | **#1 on HackerOne's US leaderboard** (Aug 2025); disclosed CVE-2026-32194/32191 (Bing RCE, CVSS 9.8); 1,100+ vulns found; 80/104 on the public XBOW Benchmark | Founded by OpenAI's first security hire + ex-Meta red-team lead; clients incl. Cursor, Turbopuffer, Baseten, Fortune 500 (per public claims) |
| Funding | $120M Series C, >$1B valuation (DFJ Growth, Northzone, Sequoia et al.) | $40M raise (Khosla Ventures, Anthropic's Anthology Fund, Menlo) |

Sources: [XBOW Series C](https://xbow.com/news/xbow-raises-120m-to-scale), [XBOW HackerOne #1](https://xbow.com/blog/top-1-how-xbow-did-it), [XBOW Bing RCE](https://tech-insider.org/xbow-ai-hacker-bing-rce-2026/), [XBOW Pentest On-Demand](https://www.businesswire.com/news/home/20251112470912/en/Announcing-XBOW-Pentest-On-Demand-for-Security-at-Machine-Speed), [XBOW Benchmark repo](https://github.com/xbow-engineering/validation-benchmarks), [RunSybil $40M raise](https://siliconangle.com/2026/03/18/runsybil-raises-40m-automate-offensive-security-ai-agents/), [RunSybil site](https://www.runsybil.com/).

## Open-source and academic frameworks

Methodology note: figures marked "verified" were cross-checked directly against the GitHub API or arXiv/USENIX/ICML primary sources during this research pass; figures marked "self-reported" come only from the project's own materials with no independent reproduction found.

### Higher-traction (real GitHub activity, but mostly no published third-party benchmark scores)

| Project | Stars (verified) | Last push (verified) | Architecture | Notes |
|---|---|---|---|---|
| [Strix](https://github.com/usestrix/strix) | 46,154 | 2026-07-31 | Multi-agent, Manager + specialized Workers | Docker-isolated, telemetry sanitizer redacts secrets in logs, ships a dedicated skill defining scope rules/validation/reporting bar baked into the tool (not just a README disclaimer). By far the most-starred open-source pentest agent found. |
| [Shannon](https://github.com/KeygraphHQ/shannon) | 46,312 | 2026-07-31 | Multi-agent, 5-phase pipeline | White-box: combines static source analysis with live exploitation. **"No Exploit, No Report" policy** - only reports vulnerabilities with a working, reproducible PoC, a concrete anti-hallucination gate comparable to Clicky's Tier 1/Tier 2 validation pipeline. Self-reports 96.15% (100/104) on a "cleaned" XBOW benchmark subset - self-reported, unverified, and the "cleaned" qualifier suggests a curated subset rather than the full untouched benchmark. |
| [PentAGI](https://github.com/vxcontrol/pentagi) | 21,413 | 2026-07-31 | 13 specialized agents | Neo4j/Graphiti temporal knowledge graph for semantic memory (external memory beyond the context window), Docker sandboxing, 20+ integrated tools (nmap, Metasploit, sqlmap). MIT licensed, self-hostable via Ollama. |
| [CAI (Cybersecurity AI)](https://github.com/aliasrobotics/cai), Alias Robotics | 9,611 | 2026-07-14 | ReACT framework, 300+ model backends | Commercially backed (straddles open-source/startup like XBOW/RunSybil). Claims to lead Cybench (pass@3) on a vendor-run, not independently-reproduced, benchmark. Markets explicit prompt-injection/dangerous-command defenses. |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) | 14,635 | 2026-07-14 | Single LLM session, 3 cooperating modules (Reasoning/Generation/Parsing) | **Published at USENIX Security 2024 with a Distinguished Artifact Award** - the strongest independent academic validation found in this space. 228.6% task-completion improvement vs. GPT-3.5 baseline on a 182-subtask HTB/VulnHub benchmark. Maintains an XBOW-benchmark validation companion. |

### Academic / narrower scope

| Project | Status | Notes |
|---|---|---|
| [hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT) (TU Wien) | 1,193★, active | Deliberately minimal single-agent ReAct loop ("~50 lines"). Source paper reported GPT-4 autonomously escalating Linux privileges in ~73% of test scenarios. Same research lineage as `cochise` below - arguably the most safety-conscious academic group in this space (see Ethics section). |
| [VulnBot](https://github.com/KHenryAegis/VulnBot) | 182★, **dormant since 2025-04** | Genuine multi-agent (Planner/Generator/Executor/Summarizer + Memory Retriever, "Penetration Task Graph"). 30.3% on AutoPenBench vs 9.09% stock Llama3.1-405B. A follow-on paper (xOffense) found it "designed for CTF competitions, failed to cope with real-world pentesting" - <10% real-world host compromise, a concrete lab-vs-reality gap. |
| [ARACNE](https://arxiv.org/abs/2502.18528) | Paper only | Autonomous SSH-shell agent, multi-LLM (separate planner/interpreter/summarizer). 60% vs. the ShelLM defender, 57.58% on OverTheWire Bandit. |
| [xOffense](https://arxiv.org/abs/2509.13021) | Paper only | Built on fine-tuned Qwen3-32B (not a frontier closed model) - 79.17% sub-task completion, beating VulnBot and PentestGPT on the same measure. Notable: a domain-adapted mid-size open model can outperform larger general ones on this task class. |
| [cochise](https://github.com/andreashappe/cochise) (TU Wien) | Paper only | First fully autonomous "assumed breach" **Active Directory** pentester, tested against the GOAD testbed. The only credible open-source/academic entry covering AD/enterprise lateral movement - none of the higher-traction tools above address it. |
| [RapidPen](https://arxiv.org/abs/2502.16730) | Paper only | Single-agent + retrieval-augmented "success-case" knowledge base. Explicitly scoped "IP-to-Shell" only - **does not attempt privilege escalation**, a deliberate stated safety boundary rare in this literature. Self-reported 60% success (small-N, single target, unverified). |
| [PentestAgent](https://arxiv.org/abs/2411.05185) | Paper only | Multi-agent, RAG-augmented. No independent benchmark scores found; trails PentestGPT/VulnBot in the PentestEval study below. |
| [DeepExploit](https://github.com/13o-bbr-bbq/machine_learning_security) | Legacy, abandoned (2022) | **Not LLM-based** - A3C deep-RL wrapped around Metasploit RPC, 2018-era. Pre-LLM historical baseline only. |
| [AutoAttacker](https://arxiv.org/abs/2403.01038) | Paper only, **code never released** ("for security reasons") | Post-breach/"hands-on-keyboard" stage only (14 techniques). Unreproducible by design - a meaningful negative data point since most comparable papers do release artifacts. |
| Villager (Cyberspike) | Product, no canonical repo | **Cautionary tale, not a credible comparable**: MCP client wrapping Kali tools + LangChain + DeepSeek, 11,000+ PyPI downloads in two months with essentially no scope/authorization gating. Distributor previously linked to repackaged commodity malware (AsyncRAT, Mimikatz). [Straiker's analysis](https://www.straiker.ai/blog/cyberspike-villager-cobalt-strike-ai-native-successor) frames it as following "the Cobalt Strike trajectory." |

Sources for this section: see the per-project links inline above, plus [hackingBuddyGPT Linux privesc paper](https://arxiv.org/html/2310.11409), [CAI paper](https://arxiv.org/html/2504.06017v1), [VulnBot paper](https://arxiv.org/abs/2501.13411).

## Benchmarks

| Benchmark | Measures | Scale | Key result |
|---|---|---|---|
| [XBOW Validation Benchmarks](https://github.com/xbow-engineering/validation-benchmarks) | End-to-end exploit proof, Docker web-vuln challenges | 104 challenges | XBOW: 80/104 |
| [AutoPenBench](https://github.com/lucagioacchini/auto-pen-bench) | 22 in-vitro + 11 real-CVE tasks | 33 tasks | **Assisted 64% vs. fully autonomous 21%** - human-in-the-loop roughly triples success over full autonomy |
| [Cybench](https://github.com/andyzorigin/cybench) | 40 professional CTF tasks, pass@k, capped budget | 40 | CAI claims pass@3 lead (self-reported) |
| [CVE-Bench](https://github.com/uiuc-kang-lab/cve-bench) (ICML'25 Spotlight) | Real exploitation of 40 critical CVEs, realistic deployments | 40 CVEs | Best agent framework: **13%** success |
| [CyberGym](https://arxiv.org/abs/2506.02548) (UC Berkeley) | Reproduce real vulnerabilities from description + codebase | 1,507 vulns, 188 projects | Best combos ~20% success; running the benchmark itself found 34 new zero-days |
| [PentestEval](https://arxiv.org/abs/2512.14233) | Stage-decomposed (PTES/NIST-aligned), expert-annotated | 346 tasks, 12 scenarios | **31% end-to-end success; "autonomous agents fail almost entirely" on full pipelines** even though individual stages score better in isolation - PentestGPT, PentestAgent, VulnBot all show the same pattern |
| [Fang et al.](https://arxiv.org/abs/2402.06664) "LLM Agents can Autonomously Hack Websites" | GPT-4 exploiting known CVEs, with/without advisory text | - | **87% with advisory text, 7% without** - the clearest evidence of pattern-matching known writeups rather than novel reasoning |
| NYU CTF Bench, InterCode-CTF | CSAW/picoCTF challenges | 200 / 100 | Used as comparison baselines in several studies; InterCode-CTF's repo is stale (last push 2024-05) |

**Pattern across every credible, independently-run benchmark**: a steep "lab vs. reality" cliff (64%→21%, 87%→7%, 31% end-to-end, 13% on CVE-Bench, ~20% on CyberGym). Treat any vendor claiming near-100% on a named benchmark as a claim to verify, not accept - check whether it's the full untouched benchmark or a "cleaned"/curated subset (see Shannon above).

## What "feature-complete" means in this category

Synthesized from two field-wide meta-analyses (not single-project marketing):
- ["Hackers or Hallucinators?"](https://arxiv.org/abs/2604.05719) - systematic review of 13 open-source + 2 baseline AutoPT frameworks, >10B tokens, ~1,500 execution logs.
- ["SoK: Measuring What Matters for Closed-Loop Security Agents"](https://arxiv.org/pdf/2510.01654) - proposes evaluation dimensions: cost-aware planning, **confidence calibration**, **grounding/anti-hallucination** (not fabricating tool output or false confidence - the "soliloquizing" failure mode where an agent pretends a command succeeded and builds on the imagined result), **scope/constraint enforcement**, **transparency/provenance**.

A genuinely complete framework in this category consistently needs:
- Multi-agent role specialization with a real planner/executor split (monolithic single-agent loops "fail almost entirely" end-to-end per PentestEval; hierarchical teams beat monolithic agents by up to 4.3x per other cited work)
- External memory beyond the context window (vector DB, knowledge graph, or explicit task-dependency graph)
- **Anti-hallucination / proof-of-exploitation gating** - Shannon's "No Exploit, No Report" is the clearest concrete example found
- Execution sandboxing (Docker isolation is table stakes among the serious projects, not a differentiator)
- **Explicit scope/authorization enforcement baked into the tool**, not just a README disclaimer - rare; most academic papers rely entirely on operator trust (see Ethics below), and Villager is the clearest cautionary counter-example
- Secrets/telemetry hygiene (Strix's auto-redacting log sanitizer)
- Broad, realistic tool coverage (20-150+ integrated real tools, not reimplemented exploit logic)
- Standardized reporting mapped to a recognized methodology (PTES/NIST stages, OWASP mapping)
- **Published, reproducible scores against a recognized third-party benchmark, run unmodified** - the single biggest differentiator between "credible" and "marketing" in this space. Most popular open-source tools, including Strix/Shannon/PentAGI despite real tens-of-thousands-of-stars traction, have **not** done this.
- Coverage beyond web apps - nearly the entire open-source/academic field is web-app/API-focused; only `cochise` (AD/lateral movement), ARACNE (SSH/Linux shell), and hackingBuddyGPT (Linux privesc) address other technique classes.

## Ethics and safety posture in this field

A third meta-analysis, ["Recognition Without Mitigation"](https://arxiv.org/abs/2506.08693) (Happe & Cito, TU Wien - same lab as hackingBuddyGPT/cochise), audited ethics practices across offensive-LLM-agent papers: only **39%** even acknowledge dual-use risk, only **7%** propose concrete mitigations, only **2%** underwent institutional review, only **6%** describe responsible-disclosure processes, and **17%** actively document defeating model safety guardrails without proposing countermeasures. 94% have research-integrity safeguards (sandboxes, human-in-the-loop) that protect the experiment, not the public, from misuse.

Clicky's `scope-enforcement-hook.sh` (a real, fail-closed-within-session PreToolUse hook checked against every Bash/WebFetch call, with `commands/pentest.md` auto-generating a `scope.json` if the operator doesn't supply one) is already ahead of most of this field on that specific axis - worth stating plainly rather than just disclaiming.

## Honest positioning for Clicky

**Where Clicky genuinely differentiates:**
- Source-available and fully inspectable - every agent is a readable markdown file, not a black box, unlike XBOW/RunSybil
- Runs entirely inside the operator's own Claude Code session - no engagement data leaves to a third-party hosted platform
- Broadest single-framework technique coverage on paper among everything surveyed here: traditional infra, web/API, Active Directory, cloud (AWS/Azure/GCP), containers/Kubernetes, and AI/LLM app security together - most competitors (commercial and open-source) cover a subset of this
- Real Tier 1 (mechanical trace cross-check) + Tier 2 (independent LLM re-check) finding validation - the same category of anti-hallucination mechanism as Shannon's "No Exploit, No Report" gate
- Real self-calibration from the operator's own session history (`skills/htb-decision-tree`) - genuinely novel; nothing surveyed here does this
- CI/tooling-consumable exports (SARIF, CycloneDX SBOM, CycloneDX AIBOM) alongside the narrative report
- A real, re-runnable test suite (`tests/`) backing its own internal correctness claims, not just prose assertions

**Where Clicky is honestly behind:**
- No continuous/CI-triggered monitoring mode - both major commercial competitors' core pitch, and Clicky's session-based engagement model doesn't cover that use case
- No independent, published, reproducible score against any recognized third-party benchmark (XBOW-104, AutoPenBench, Cybench, CVE-Bench, CyberGym, PentestEval) - per the analysis above, this is the single biggest "credible vs. marketing" differentiator in the entire field, and it's the clearest, highest-leverage next step for genuine external credibility
- No dedicated infra for large-scale parallel sandboxed execution
- No external memory beyond individual session context + decision-agent's informal Claude memory (PentAGI's knowledge-graph approach is more sophisticated here)
- Solo/small-scale project with no independent validation, vs. commercial competitors' external track record (XBOW's HackerOne #1, disclosed CVEs) or academic competitors' peer review (PentestGPT's USENIX Distinguished Artifact Award)

**Recommended next step**: run Clicky against a public benchmark (AutoPenBench and the XBOW-104 set are both openly available) to get a real, comparable, reproducible number instead of relying entirely on architecture comparisons like this document.
