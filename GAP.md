# Gap Analysis: ai-vuln-harness vs. Project Glasswing / Claude Mythos / GPT-5.5-Cyber

**Last updated:** 2026-05-21
**Baseline:** v1 scaffold (`src/ai_vuln_harness/`)
**Benchmarks:** Project Glasswing (Anthropic), Claude Mythos Preview, OpenAI GPT-5.5 / GPT-5.5-Cyber (CyberGym score: 81.9%)

---

## What the v1 Harness Does Today

The v1 scaffold implements a **Hunt → Validate → Dedupe → Trace → PoC** pipeline with:

- AST-based C/C++ ingestor via tree-sitter ≥ 0.25, KL-divergence hallucination filtering, cosine-sim dedup
- Multi-provider model routing, resumable state DB, AddressSanitizer PoC compilation
- 11 security domains, cross-run regression auditing, schema-validated stage contracts
- Run modes: `full`, `max-run`, `validate-only`, `resume`, `poc-only`

---

## Gaps by Capability Area

### 1. Autonomous Zero-Day Discovery at Scale

**Reference systems:** Project Glasswing (found a 27-year-old OpenBSD bug; thousands of high-severity CVEs in a single campaign), Claude Mythos Preview.

| Gap | Details |
|---|---|
| **Multi-language ingestor** | The harness supports C/C++ only. Non-C code falls back to 200-line windows, creating silent coverage gaps. Tree-sitter grammars exist for Rust, Go, Python, Java, and TypeScript — all are needed for supply-chain sweeps. |
| **Cross-repository / dependency graph scanning** | Glasswing targets the software supply chain (crypto libs, OS kernels, browsers) across multiple repos. The harness is scoped to a single repo today. |
| **Historical CVE corpus integration** | Past CVEs are not fed as negative examples. Without them the Hunt stage rediscovers known patterns instead of biasing toward novel bug classes. |

---

### 2. Exploit Chaining

**Reference system:** Project Glasswing — chains renderer bug + sandbox bypass + privilege escalation into full exploit scenarios.

| Gap | Details |
|---|---|
| **Inter-component chain graph** | The existing BFS chainer operates intra-repo only. Glasswing-level chaining requires edges across library and OS boundaries (e.g., buffer overflow in a parser library → privilege escalation in the calling application). |
| **Exploit narrative generation** | From a confirmed chain of findings, the harness should synthesize a prose attack scenario with CVSS scoring, CWE mapping, and proposed mitigations. A dedicated "chain synthesis" stage is absent. |
| **Sandbox simulation for PoC** | PoCs run under AddressSanitizer on the host. Privilege-escalation and sandbox-escape chains require execution inside an isolated VM or container (e.g., gVisor, Firecracker) to validate safely. |

---

### 3. Trusted-Access / Role-Tiered Permissioning

**Reference system:** GPT-5.5 Trusted Access for Cyber (TAC) — vetted researchers get progressively more permissive models.

| Gap | Details |
|---|---|
| **Researcher identity + authorization layer** | No access-control config exists. A simple role config (`defensive`, `red-team`, `full-cyber`) should gate prompt permissiveness and PoC generation depth. Without it, the harness either over-restricts (misses exploitable chains) or under-restricts (produces raw weaponizable PoCs with no audit trail). |
| **Audit log with attribution** | Every finding, PoC, and chain output should be signed and attributed to the requesting operator for accountability. |

---

### 4. Continuous / DevSecOps-Integrated Discovery

**Reference systems:** Both Glasswing and GPT-5.5-Cyber are designed for continuous embedding in CI/CD pipelines, not one-off audits.

| Gap | Details |
|---|---|
| **Incremental / diff-driven scanning** | `full` mode re-ingests the entire repo on every run. A git-blame-aware ingestor should re-scan only changed functions between commits, making per-PR runs feasible. |
| **CI integration hooks** | No ready-made GitHub Actions / GitLab CI step. A CI step running `poc-only` on pull requests and blocking merges when `poc_verdict = confirmed` is missing. |
| **Exposure-window tracking** | Glasswing's primary KPI is *exposure window* (time from first-seen commit to patch). The harness records findings but does not track first-seen commit or time-to-fix. |

---

### 5. Remediation Co-Pilot

**Reference system:** GPT-5.5-Cyber not only finds bugs — it generates patch candidates and re-validates via re-run.

| Gap | Details |
|---|---|
| ~~**Patch generation stage**~~ | ~~The harness stops at a `fix_now` annotation. A patch generation stage should call a model to produce a minimal, correct patch (diff format), then re-run the PoC against the patched binary to verify the fix.~~ **Implemented**: `stages/patch.py` provides a deterministic PATCH stage that builds structured `PatchCandidate` records with a class-driven fix strategy, CWE mapping, and PoC-based verification plan. Enable with `--run-patch`. |
| **Regression gate on patches** | Generated patches should be validated against the existing test suite before being recommended, with regressions flagged. |

---

### 6. Business Logic, Auth, and Cloud/SaaS Vulnerability Classes

**Context:** Analysts note that memory-safety bugs are increasingly "solved" territory; the frontier is business logic, auth flows, and cloud misconfiguration — areas the harness's 11 domains only partially cover.

| Gap | Details |
|---|---|
| **Auth and IAM domain depth** | The `auth` domain needs expansion: OAuth/OIDC flow analysis, JWT claim inspection, SSRF pattern detection. |
| **Cloud-native targets** | IaC scanning (Terraform, CloudFormation) for misconfigured IAM roles, public S3 buckets, overly permissive security groups is absent. |
| **LLM-specific vulnerability classes** | For harnesses targeting AI-integrated codebases: prompt injection, insecure tool-call routing, and data exfiltration via model output are not covered. |

---

### 7. Benchmark-Driven Quality Signal

**Reference system:** GPT-5.5-Cyber is publicly benchmarked at 81.9% on CyberGym (1,500+ known CVEs).

| Gap | Details |
|---|---|
| **CyberGym / NVD CVE replay mode** | A `--benchmark` run mode that replays known CVEs through the full pipeline and reports precision/recall against ground truth is missing. Without it there is no externally comparable quality score. |
| **Competitive leaderboard integration** | No mechanism exists to publish benchmark results and track regression or improvement across model/prompt updates over time. |

---

### 8. Mythos System Card — New Findings (May 2026)

**Reference:** Claude Mythos Preview System Card — Anthropic (April 2026)

| Gap | Details | Status |
|---|---|---|
| **Reward-hack / grind detection in VALIDATE** | Models re-run structurally identical experiments to fish for high-confidence scores (§4.2.2). `detect_reward_hack` in `validate.py` flags call histories where ≥3 attempts are near-identical and the finding flipped from rejected→confirmed. | ✅ Implemented |
| **Confabulation cascade guard** | Models produce mutually contradictory confident assessments without surfacing the contradiction (§4.3.3). `build_negation_probe_prompt` and `confabulation_risk` in `validate.py` detect when a model agrees with both a finding and its negation. | ✅ Implemented |
| **Egress audit + scope violation enforcement in POC** | Agentic models issued out-of-scope shell commands including posting exploit details to public websites (§4.2.4). `EgressAuditContext` in `poc.py` intercepts every subprocess call during PoC execution and raises `ScopeViolationError` on network or out-of-scope path access. | ✅ Implemented |

---

## Priority Matrix

| Priority | Gap | Estimated Effort |
|---|---|---|
| 🔴 Critical | Multi-language ingestor (Rust, Go, Python) | Medium |
| 🔴 Critical | Diff-driven incremental scanning + CI hooks | Medium |
| 🔴 Critical | VM-isolated sandbox (gVisor / Firecracker PoC) | High |
| ~~🔴 Critical~~ | ~~Patch generation + re-validation stage~~ | ~~Medium~~ |
| ✅ Done | Reward-hack / grind detection in VALIDATE | Low |
| ✅ Done | Confabulation cascade guard | Low |
| ✅ Done | Egress audit + scope violation enforcement in POC | Low |
| 🟠 High | Inter-component exploit chain graph | High |
| 🟠 High | CyberGym / CVE benchmark mode | Low–Medium |
| 🟠 High | Exposure-window tracking | Low |
| 🟡 Medium | Role-tiered access layer + audit log | Low–Medium |
| 🟡 Medium | Auth/IAM + cloud-native domain expansion | Medium |
| 🟢 Stretch | LLM-specific vuln classes (prompt injection, etc.) | High |

---

## References

- [Claude Mythos Preview System Card — Anthropic (April 2026)](https://www.anthropic.com/research/claude-mythos-preview)
- [Project Glasswing — Anthropic](https://www.anthropic.com/project/glasswing)
- [Anthropic Glasswing and the Future of Vulnerability Research — GetCybr](https://getcybr.com/insights/anthropic-glasswing-future-vulnerability-research/)
- [Project Glasswing Proved AI Can Find the Bugs. Who's Going to Fix Them? — The Hacker News](https://thehackernews.com/2026/04/project-glasswing-proved-ai-can-find.html)
- [Project Glasswing Shows That AI Will Break The Vulnerability Management Playbook — Forrester](https://www.forrester.com/blogs/project-glasswing-shows-that-ai-will-break-the-vulnerability-management-playbook/)
- [Scaling Trusted Access for Cyber with GPT-5.5 and GPT-5.5-Cyber — OpenAI](https://openai.com/index/gpt-5-5-with-trusted-access-for-cyber/)
- [OpenAI introduces GPT-5.5-Cyber for high-impact cybersecurity research — SiliconAngle](https://siliconangle.com/2026/05/08/openai-introduces-gpt%E2%80%915-5%E2%80%91cyber-high-impact-cybersecurity-research/)
- [Claude Mythos & Project Glasswing: AI Breakthroughs, Not Real-World Readiness — Novee Security](https://novee.security/blog/claude-mythos-project-glasswing-ai-security-research-vs-continuous-testing/)
- [The "AI Vulnerability Storm": Building a "Mythos-ready" Security Program — Cloud Security Alliance Labs](https://labs.cloudsecurityalliance.org/research/ai-vulnerability-storm-mythos-ready-security-program/)
