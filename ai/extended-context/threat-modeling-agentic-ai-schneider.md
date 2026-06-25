# Threat Modeling and Verifying Controls for Agentic AI

Summary of Christian Schneider's two-part series on securing agentic AI systems.

- [Threat Modeling Agentic AI: A Scenario-Driven Approach](https://christian-schneider.net/blog/threat-modeling-agentic-ai/) (5 Feb 2026)
- [Verifying Agentic AI Controls with Attack Tree Micro Simulations](https://christian-schneider.net/blog/verifying-agentic-ai-controls-attack-tree-micro-simulations/) (8 Apr 2026)

---

## Part 1: Threat Modeling Agentic AI

### Why traditional threat modeling falls short

STRIDE applied per-component produces incomplete results for agentic AI. Attacks like EchoLeak (CVE-2025-32711) in Microsoft Copilot move through legitimate system states — no spoofing, no broken auth, no tampering at any individual component. Three patterns STRIDE misses:

1. **Semantic state accumulation** — latent attacker intent persists across reasoning turns and contexts. STRIDE has no category for this.
2. **Cross-zone causality** — attacks chain across components: input injection biases retrieval, which shifts planning goals, which triggers tool invocations, which exfiltrates data. STRIDE evaluates these as separate assessments; attackers treat them as one chain.
3. **Abuse of legitimate functionality** — every step works as designed. STRIDE handles individual misuse but struggles with *composed* misuse and emergent behavior across components.

> "If you STRIDE each *component*, an EchoLeak-style attack looks compliant. If you STRIDE the *attack path*, it doesn't."

### The five-zone lens

These zones are a discovery lens for tracing attack propagation, not a new taxonomy. They are meant to be overlaid on concrete architectures alongside existing threat libraries (particularly OWASP's agentic AI threat taxonomy).

| Zone | Scope |
|------|-------|
| **1. Input Surfaces** | All channels through which data enters the agent's context: user prompts, RAG-retrieved documents, emails, API responses, MCP tool descriptions |
| **2. Planning & Reasoning** | Where the agent interprets goals, decomposes subtasks, and selects tools. Target for goal hijacking |
| **3. Tool Execution** | Invocation of external capabilities: database queries, API calls, file operations, code execution |
| **4. Memory & State** | Short-term context, working memory, long-term persistence. Memory poisoning creates attack persistence across sessions |
| **5. Inter-Agent Communication** | Messages between agents in multi-agent architectures. A single poisoned agent can cascade through the collaboration network |

Attacks rarely stay within a single zone. Injection enters through Zone 1, manipulates planning in Zone 2, triggers unauthorized actions in Zone 3, and potentially persists via Zone 4 or spreads via Zone 5.

### How the five zones integrate with other frameworks

| Phase | Framework(s) | Primary Question | Output |
|-------|-------------|-----------------|--------|
| 1. Discovery | Five-zone lens + scenarios | How does the attack propagate? | Attack paths and scenarios |
| 2. Formalization | Attack trees | What are the AND/OR steps and control points? | Attack trees with controls |
| 3. Validation | MAESTRO | Did we cover the full architecture stack? | Coverage gaps identified |
| 4. Classification & remediation | OWASP Top 10 + ATFAA/SHIELD | Which risk applies and what mitigations? | Categorized findings with mitigations |

Related frameworks:

- **MAESTRO** (Cloud Security Alliance) — seven-layer model for technology stack decomposition. Serves as a coverage checklist.
- **ATFAA** — five threat domains: cognitive architecture vulnerabilities, temporal persistence threats, operational execution vulnerabilities, trust boundary violations, governance circumvention. Companion SHIELD framework provides six defensive strategy categories.
- **OWASP Agentic Threat Work** — Threat Taxonomy Navigator, Threat Decision Path, and the OWASP Top 10 for Agentic Applications (ASI01-ASI10).

### Methodology: seven steps

1. **Map architecture to threat zones** — diagram which components belong to each zone, data flows, and trust boundaries.
2. **Identify entry points per zone** — every channel for malicious content introduction, including tool responses, RAG retrievals, inter-agent messages.
3. **Walk through attack scenarios** — for each entry point, trace a concrete scenario through all five zones. What could go wrong? What controls would prevent it? What happens if controls fail?
4. **Build attack trees for critical paths** — formalize highest-risk scenarios into trees showing logical attack structure, blocking controls, and residual risk.
5. **Challenge controls with what-if analysis** — for each control, ask what happens if it's bypassed, misconfigured, or the attacker adapts.
6. **Validate coverage and classify findings** — verify completeness against MAESTRO layers. Classify via ATFAA taxonomy. Map to OWASP playbooks for remediation.
7. **Validate against four agentic factors** — per the OWASP Multi-Agentic System Threat Modeling Guide: (1) non-determinism, (2) autonomy, (3) agent identity management, (4) agent-to-agent communication.

### Worked scenarios

#### RAG pipeline poisoning

Attacker uploads a document with legitimate content plus hidden instructions. User query triggers retrieval of the poisoned chunk. LLM incorporates malicious instructions into its reasoning. Crosses Zones 1 -> 2 -> 3. Based on PoisonedRAG research (USENIX Security 2025) showing high success rates.

Controls: content scanning at ingestion, provenance metadata tagging, prompt design separating data from control, output validation.

What-if highlights: Unicode homoglyphs and base64 bypasses; trusted employees uploading poisoned documents; factually correct content with subtly manipulated recommendations.

#### MCP tool chain exploitation

Malicious instructions hidden in tool descriptions, or legitimate tools compromised post-approval ("rug pull"). Developer installs an MCP server for a package manager; its tool description contains hidden exfiltration instructions. Based on Palo Alto Unit 42 research.

Controls: pin tool definitions by hashing schema+description at approval time and verify on each invocation; isolate MCP servers with minimal privileges; monitor for behavioral anomalies; human approval for credential access and external network calls.

What-if highlights: post-approval supply chain compromise; side-channel exfiltration via DNS; multiple tools colluding.

#### Multi-agent goal cascade

Hidden instructions in a customer request propagate through triage -> knowledge -> transaction agents via normal inter-agent protocols. Every agent performs its designated function correctly. The supervisor logs it as legitimate since all protocols were followed. Detection requires correlating the entire sequence.

Controls: message sanitization at agent boundaries; separate trust domains (high-exposure agents cannot directly instruct high-privilege agents); human approval for sensitive operations with full reasoning chain context; cross-network anomaly detection.

What-if highlights: malicious context persisting in supervisor memory; triage agent silently exfiltrating; approval fatigue (>95% approval rate triggers automatic scrutiny increase).

### Attack tree formalization

Scenarios are formalized into attack trees (AND/OR decompositions). Each node is annotated with:

- **Zone** — where this step happens
- **OWASP threat family** — categorizing the threat
- **OWASP Agentic Top 10** — categorizing the vulnerability
- **MAESTRO layer(s)** — architectural stack location
- **ATFAA/SHIELD classification** (optional) — for reporting

Example tree for MCP tool chain attack:

```
GOAL: Exfiltrate developer credentials to deploy backdoored code (AND)
├── Developer installs benign-looking but malicious MCP server
├── Malicious instructions reach the agent (OR)
│   ├── Tool description contains hidden exfiltration instructions
│   └── Legitimate tool compromised via rug pull
├── MCP server has access to credential stores
└── Agent can make outbound network calls to attacker-controlled endpoints
```

Attack trees reveal single points of failure that prose descriptions miss, enable assigning probabilities and costs for risk calculation, and allow simulating the effect of adding/removing controls.

---

## Part 2: Verifying Controls with Attack Tree Micro Simulations

### The verification gap

Teams build attack trees, brief stakeholders, then file them away. The controls on those trees are assumptions, not evidence.

Common failure modes:

- Controls that looked solid on whiteboards fail during testing with unexpected bypass rates
- "Defense-in-depth" where multiple controls all fail against the same payload class
- Trees claiming five barriers when testing reveals two don't function as designed

> "An unverified attack tree is a diagram of assumptions."

### Test locally, reason globally

There is a tension: STRIDE per-component is insufficient for agentic AI (as argued in Part 1), yet micro simulations test individual controls in isolation. The distinction:

- **STRIDE isolates the *selection*** of what to test — examining threats per component with no awareness of upstream/downstream effects
- **Micro simulations isolate the *execution*** — a focused probe at a specific tree node — but *selection* comes from the attack tree, which maintains full path awareness

Analogy: a surgeon operates on one specific point, but the diagnosis considered the whole body.

Caveat: local node verification does not replace end-to-end path checks for highest-impact branches. Direct-access tests validate a control under assumed preconditions but don't prove upstream reachability, downstream composition, latent memory effects, tool sequencing, or orchestration timing.

### Workflow: six steps

#### Step 1: Start from the attack tree

Take a tree produced through five-zone discovery. Nodes should have zone annotations, OWASP mappings, and control points.

#### Step 2: Select critical nodes for verification

Not every node warrants a simulation. Highest-leverage targets:

- **AND-nodes** — all children must succeed for the attack to progress. Test the weakest child; if it holds, the AND-gate blocks the path.
- **Convergence points** — multiple attack paths flow through one control. One simulation covers multiple paths.
- **Single points of failure** — one control is the only barrier. Must verify.
- **Probabilistic controls** — LLM guardrails, intent classifiers, content filters. Not binary pass/fail. Need repeated probing to establish bypass rates.
- **Defense-in-depth claims** — verify the backup catches what the primary *misses*, not just the same attack category.
- **Privilege-amplification and trust-boundary nodes** — cross-agent handoffs, tool brokers, MCP/plugin boundaries, impersonation paths.

#### Step 3: Design micro simulations

For each selected node, define: the specific control assertion being tested, the direct-access setup, and clear success/failure criteria.

#### Step 4: Execute at direct access

Isolate the control's decision point while holding assumed preconditions constant. Bypass upstream controls to test the target control directly. For a goal-lock classifier, call the classifier API directly with test payloads. For an egress allowlist, send requests directly to the network filtering layer.

#### Step 5: Feed results back into the tree

If a control at node X fails, mark it compromised and trace forward through all dependent paths. For each affected path, check whether remaining downstream controls compensate. If combined bypass probability exceeds risk tolerance, remediate.

Where two controls both fail to the same payload category: defense-in-depth was "defense-in-hope."

#### Step 6: Update the risk posture

Tag each node with an evidence level:

| Level | Meaning |
|-------|---------|
| **Assumed** | No testing yet |
| **Design-reviewed** | Architecture analysis only |
| **Lab-validated** | Passed micro simulation under controlled conditions |
| **End-to-end validated** | Confirmed in a path-level drill |
| **Regression-tested** | Verified across multiple system versions |

Re-run verification after major system changes: model updates, new tool integrations, prompt template modifications.

### Worked example

An enterprise AI assistant that processes emails, retrieves internal documents via RAG, and can draft responses and schedule meetings.

Attack path crosses three zones:

1. Indirect prompt injection (Zone 1) -> 2. Reasoning manipulation (Zone 2) -> 3. Unauthorized tool invocation (Zone 3)

Five nodes with controls:

| Node | Control |
|------|---------|
| 1. Injection payload survives email ingestion | Content scanning for instruction-like patterns |
| 2. Payload retrieved into agent context | Provenance tagging and trust-level filtering |
| 3. Agent planning shifts to attacker goal | Goal-lock mechanism with deviation detection |
| 4. Agent selects file-access tool | Tool scope restriction |
| 5. Agent sends data externally | Egress allowlist + HITL approval |

Three selected for simulation:

- **Node 2 (convergence point):** Provenance tagging sits where multiple injection vectors converge (emails, RAG docs, API responses). Test: provide inputs of varying trust levels and injection payloads, verify classification and filtering.
- **Node 3 (probabilistic control):** Goal-lock mechanism likely relies on an LLM classifier. Test: run goal-hijacking prompts varying in subtlety, encoding, and indirection. Establish bypass rate with statistical confidence.
- **Node 5 (defense-in-depth claim):** Egress allowlist and HITL supposedly back each other up. Test: does the allowlist catch data encoded in legitimate-looking requests? Does the HITL screen show enough context to spot a hijacked email, or just a minimal action summary?

Results: if the goal-lock classifier shows a 15% bypass rate and the HITL screen shows minimal context, the tree reveals a viable end-to-end path. The two remaining controls are insufficient to compensate. Defense-in-depth on this path is weaker than assumed.

### The probabilistic problem

LLM-based guardrails are not binary. Key considerations:

- Micro simulations for probabilistic controls need **multiple runs** — a single pass/fail is meaningless for probability-distribution controls
- Sample size depends on confidence level and underlying bypass rate. Low-impact leaf nodes: 30-50 probes. High-impact convergence nodes: proper sample-size calculations.
- **Correlated failures** — the same payload family can defeat multiple controls on a path, so naive probability multiplication overstates defense-in-depth
- **Test oracle reliability** — measured bypass rates are only as reliable as the automated judges used. Human review of sampled subsets calibrates false positives and negatives.
- Bypass rates without confidence intervals give a "false sense of precision"

### Tooling

Four open-source tools for execution (selection of *what* to test still requires human judgment via the attack tree):

| Tool | Strength |
|------|----------|
| **DeepTeam** | 50+ vulnerability types including agentic-specific (system override, permission escalation, objective reframing, context poisoning). 20+ attack methods. |
| **Microsoft PyRIT** | Modular architecture with prompt converters, scorers, targets. Well suited for automated probing campaigns needing hundreds of payload variations. |
| **NVIDIA Garak** | LLM vulnerability scanner with iterative probes and auto-red-team features that adapt based on prior responses. |
| **Promptfoo** | CI/CD integration with OWASP and MITRE ATLAS compliance mapping. Natural fit for regression testing once baseline bypass rates are established. |

MITRE ATLAS v5.0.0 (October 2025) introduced Technique Maturity levels (Feasible, Demonstrated, Realized) and 14 agent-focused techniques. Nodes mapping to Realized techniques deserve higher verification priority.

### Urgency: autonomous exploit development

Schneider references Anthropic's assessment of Claude Mythos Preview, which autonomously discovered zero-day vulnerabilities and chained them into a browser sandbox escape. Controls whose security value comes primarily from *friction* rather than *hard barriers* weaken against model-assisted adversaries that probe systematically at machine speed. A 15% bypass rate acceptable against a human attacker spending hours per attempt changes drastically when thousands of variations run overnight.

> "Attackers don't read your threat model — they test it."

---

## How the two parts connect

Part 1 answers **"what could go wrong?"** — discovering and formalizing attack paths through the five-zone lens and attack trees.

Part 2 answers **"do our defenses actually work?"** — systematically verifying controls through targeted micro simulations, then feeding results back into the tree.

Together they form a cycle: **model -> verify -> remediate -> re-model**.
