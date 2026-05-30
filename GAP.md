# Gap Analysis: ai-vuln-harness vs. Project Glasswing / Claude Mythos / GPT-5.5-Cyber

**Last updated:** 2026-05-30
**Baseline:** v1 scaffold (`src/ai_vuln_harness/`)
**Benchmarks:** Project Glasswing (Anthropic), Claude Mythos Preview, OpenAI GPT-5.5 / GPT-5.5-Cyber (CyberGym score: 81.9%)
**Reference corpus:** [red.anthropic.com](https://red.anthropic.com) — Anthropic Frontier Red Team blog (Jun 2025 – May 2026)

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

### 9. Exploit Depth — Full ACE vs. ASan Crash

**Reference:** [ExploitBench](https://exploitbench.ai) / [ExploitGym](https://rdi.berkeley.edu/blog/exploitgym/) results (May 2026), [CVE-2026-2796 reverse engineering](https://red.anthropic.com/2026/exploit/) (Mar 2026), [Firefox collaboration](https://red.anthropic.com/2026/firefox/) (Mar 2026).

The harness's POC stage confirms bugs via AddressSanitizer crash detection — this maps to ExploitBench Tier T4 (Reproduction). Mythos Preview achieves T1 (Full Control / ACE) on 21/41 V8 CVEs. The gap spans three full capability tiers:

| Gap | Details |
|---|---|
| **V8 sandbox primitives (T3)** | Creating address/capacity confusion inside the V8 heap sandbox. Requires JIT object layout knowledge, inlining heuristics, and the V8 d8 shell as a target — none present. |
| **Sandbox escape / generic primitives (T2)** | Breaking the V8 heap sandbox to gain arbitrary read/write across the process. Requires challenge-response heap layout verification (randomized across trials to prevent hardcoded addresses). ExploitBench replays exploits across multiple heap layouts. |
| **Control flow hijack / ACE (T1)** | Shellcode generation, ROP chain construction, stack pivot, or JIT spray to redirect execution. The CVE-2026-2796 Firefox exploit required combining a JavaScript type confusion with a write primitive into full ACE — the harness has no equivalent capability. |
| **Kernel exploit primitives** | ExploitGym shows Mythos is one of only two models able to frequently develop Linux kernel exploits. Requires KASLR bypass, SMAP/SMEP awareness, heap spray / slab allocator manipulation — none present. |
| **ASLR / mitigation bypass** | ExploitGym supports toggleable ASLR/KASLR. The harness's ASan-only approach doesn't attempt any mitigation bypass. |

The gap is structural, not incremental: bridging it requires a new **exploit synthesis stage** that takes confirmed bugs + crash telemetry and generates working shellcode/ROP chains.

---

### 10. Property-Based Testing

**Reference:** [Finding Bugs with Claude and Property-based Testing](https://red.anthropic.com/2026/property-based-testing/) (Jan 2026).

The blog describes a separate agent that infers program invariants (properties that should always hold) and then applies property-based testing to falsify them. This discovered real bugs in top Python packages.

| Gap | Details |
|---|---|
| **PBT agent missing from pipeline** | The harness's HUNT stage uses static analysis (AST snippet inspection + LLM reasoning). It has no mechanism to infer runtime invariants or generate fuzz/test harnesses that probe edge cases dynamically. |
| **Complementary bug classes** | Static analysis finds buffer overflows, use-after-frees, format strings. PBT finds logic bugs, invariant violations, edge-case state corruption — classes the current pipeline systematically misses. |
| **Multi-language invariant inference** | The blog's PBT works on Python (hypothesis/property-based). Extending to C/C++ would require integrating a coverage-guided fuzzer (libFuzzer, AFL) with LLM-generated seed corpora and invariant oracles. |

**Recommendation:** Add an optional PBT stage that runs after LOCALIZATION but before VALIDATE. For each finding, generate a property-based test harness that probes the vulnerable function with bounded-random inputs and checks the finding's preconditions/hazards.

---

### 11. Coordinated Vulnerability Disclosure Workflow

**Reference:** [CVD Dashboard](https://red.anthropic.com/2026/cvd/) (May 2026).

Anthropic maintains a regularly updated public record of vulnerabilities found and disclosed, with cryptographic commitments (hashes) at disclosure time.

| Gap | Details |
|---|---|
| **Cryptographic attestation per finding** | No disclosure receipt or signed commitment is generated for any finding. Without this, the harness cannot prove *when* it discovered a finding (priority for bug bounty / CVD credibility). |
| **Maintainer notification tracking** | No workflow for generating disclosure emails, tracking maintainer response, or logging patch availability. Findings sit in the report until manually handled. |
| **Embargo timer / disclosure timeline** | CVD requires tracking embargo dates, 90/120-day disclosure deadlines, and patch availability milestones. No such state machine exists. |
| **CVD feed export** | The blog's dashboard is a public webpage. No structured feed (JSON/RSS) output from the harness to power a similar dashboard. |

---

### 12. Browser / Kernel Target Specialization

**Reference:** [Firefox collaboration](https://red.anthropic.com/2026/firefox/) (Mar 2026), [ExploitBench V8 results](https://red.anthropic.com/2026/exploit-evals/) (May 2026), [ExploitGym kernel tasks](https://rdi.berkeley.edu/blog/exploitgym/) (May 2026).

The blog's most impressive results target V8 (Chrome/Node.js), SpiderMonkey (Firefox), and the Linux kernel. These require specialized infrastructure the harness lacks:

| Gap | Details |
|---|---|
| **Build harness per target** | V8 requires `d8` shell builds with debug symbols. Firefox requires a mozconfig with ASan + debug. Linux kernel requires a bootable image + QEMU + debug initramfs. None are configured. |
| **CVE reproduction environment** | For 41 V8 CVEs, ExploitBench provides patched/unpatched build pairs. The harness has no mechanism to check out specific revisions, apply/remove patches, or build targeted test binaries. |
| **Sandbox simulation** | Kernel exploit validation requires a VM (Firecracker, QEMU). V8 sandbox validation requires the V8 sandbox testing framework (challenge-response functions). Neither is integrated. |
| **Target-specific debug symbols** | Reliable PoC verification for kernel/V8 bugs requires full debug symbols + source-line mapping. The harness assumes generic `-fsanitize=address -g -O0`. |

---

### 13. Red Team / Cyber Operations (Scope Boundary)

**Reference:** [Cyber Toolkits for LLMs](https://red.anthropic.com/2025/cyber-toolkits/) (Jun 2025), [AI Models on Realistic Cyber Ranges](https://red.anthropic.com/2026/cyber-toolkits-update/) (Jan 2026), [Claude Does Cyber Competitions](https://red.anthropic.com/2025/cyber-competitions/) (Aug 2025), [Project Vend](https://red.anthropic.com/2025/project-vend/) / [Project Fetch](https://red.anthropic.com/2025/project-fetch/).

These areas are **explicitly out of scope** for a vulnerability discovery harness. Documented here for completeness:

| Area | Blog post(s) | Why out of scope |
|---|---|---|
| **Multi-stage network attacks** | Cyber toolkits, Cyber ranges | Requires network simulation (hosts, services, pivot paths). The harness is source-code-only. |
| **CTF / wargame challenges** | Claude Does Cyber Competitions | CTF requires diverse challenge types (crypto, forensics, web, reverse engineering) — source code audit is only one. |
| **Autonomous real-world agents** | Project Vend, Project Fetch | Physical-world operation (storefront, robot dog) is a completely different evaluation axis. |
| **Biorisk assessment** | LLMs and Biorisk (Sep 2025) | Biology domain knowledge + wet-lab protocol evaluation. No overlap with code audit. |
| **Nuclear safeguards** | Nuclear Safeguards (Aug 2025) | Classifier-based content moderation for nuclear conversations. No overlap. |

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
| 🟠 High | Exploit depth — ACE beyond ASan crash (T3→T1) | High |
| 🟠 High | Property-based testing stage (invariant inference + fuzz) | Medium–High |
| 🟠 High | Inter-component exploit chain graph | High |
| 🟠 High | CyberGym / CVE benchmark mode | Low–Medium |
| 🟠 High | Exposure-window tracking | Low |
| 🟠 High | CVD disclosure workflow + cryptographic attestation | Low–Medium |
| 🟡 Medium | Browser / kernel target specialization (V8, Firefox, Linux) | High |
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

### red.anthropic.com Posts (by date)

- [Cyber Toolkits for LLMs](https://red.anthropic.com/2025/cyber-toolkits/) — Jun 2025
- [Cyber Evaluations of Claude 4](https://red.anthropic.com/2025/claude-4-cyber/) — Jul 2025
- [Claude Does Cyber Competitions](https://red.anthropic.com/2025/cyber-competitions/) — Aug 2025
- [Developing Nuclear Safeguards for AI](https://red.anthropic.com/2025/nuclear-safeguards/) — Aug 2025
- [Building AI for Cyber Defenders](https://red.anthropic.com/2025/ai-for-cyber-defenders/) — Sep 2025
- [LLMs and Biorisk](https://red.anthropic.com/2025/biorisk/) — Sep 2025
- [Project Fetch](https://red.anthropic.com/2025/project-fetch/) — Nov 2025
- [AI Agents Find Smart Contract Exploits](https://red.anthropic.com/2025/smart-contracts/) — Dec 2025
- [Project Vend: Phase Two](https://red.anthropic.com/2025/project-vend-2/) — Dec 2025
- [Finding Bugs with Claude and Property-based Testing](https://red.anthropic.com/2026/property-based-testing/) — Jan 2026
- [AI Models on Realistic Cyber Ranges](https://red.anthropic.com/2026/cyber-toolkits-update/) — Jan 2026
- [Experimenting with AI to Defend Critical Infrastructure](https://red.anthropic.com/2026/critical-infrastructure-defense/) — Jan 2026
- [LLM-discovered 0-days](https://red.anthropic.com/2026/zero-days/) — Feb 2026
- [Partnering with Mozilla to Improve Firefox's Security](https://red.anthropic.com/2026/firefox/) — Mar 2026
- [Reverse Engineering Claude's CVE-2026-2796 Exploit](https://red.anthropic.com/2026/exploit/) — Mar 2026
- [Assessing Claude Mythos Preview's Cybersecurity Capabilities](https://red.anthropic.com/2026/mythos-preview/) — Apr 2026
- [Measuring LLMs' Ability to Develop Exploits](https://red.anthropic.com/2026/exploit-evals/) — May 2026
- [Coordinated Vulnerability Disclosure Dashboard](https://red.anthropic.com/2026/cvd/) — May 2026
