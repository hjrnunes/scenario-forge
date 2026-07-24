# Adversarial Review: tactic-sequences-t10-t15-t12-t13-t16.md

## Summary

8 patterns reviewed. 14 issues found (3 significant, 5 moderate, 6 minor). Overall the worker produced structurally sound tactic sequences with correct tactic ID/name mappings and no hallucinated case study references. However, there is one significant mechanism mismatch (AP-T15-02 vs CS0055), systematic confidence inflation across multi-agent adaptations, and problematic lack of differentiation between patterns derived from the same case study.

## Per-Pattern Findings

### AP-T10-01: Human oversight interface manipulation via artificial decision context

- **Tactic ID/Name errors**: None. All 10 tactic IDs map correctly to their names.

- **Case study accuracy**: CS0026 exists and is correctly identified as "Financial Transaction Hijacking with M365 Copilot." The worker's proposed sequence aligns well with CS0026's actual procedure (S00-S13), correctly collapsing duplicate tactic steps (CS0026 has two TA0008, two TA0003, and three TA0007 steps; worker collapses each to one occurrence). The worker's description of CS0026 as demonstrating "context manipulation of financial transaction details presented to humans" is accurate.

- **Pattern mechanism fidelity**: The adaptation from financial transaction fraud to general human oversight interface manipulation is reasonable. AP-T10-01's mechanism (injecting artificial decision contexts to obscure critical information) maps to CS0026's mechanism (substituting financial data presented to users). However, the worker's step 7 introduces RAG persistence language ("The manipulated context persists in the RAG system") that is specific to CS0026's delivery mechanism and not part of AP-T10-01's abstract definition, which is implementation-agnostic.

- **Confidence justification**: Step 2 (AI Model Access) is rated "adapted" despite CS0026 explicitly having this step (S01). The worker appears to rate based on whether the abstract action's framing (specifically "oversight presentation mechanisms") matches, rather than the tactic itself. This approach is inconsistent with other steps (e.g., step 7 Persistence is "explicit" despite being adapted to "RAG system" language not in AP-T10-01's definition).

- **Sequence coherence**: The 10-step sequence follows a coherent attack narrative. However, it is **identical in tactic structure** to AP-T15-01 (see cross-cutting issues).

- **Verdict**: PASS WITH NOTES

---

### AP-T15-01: Trust-exploiting content substitution for fraudulent action

- **Tactic ID/Name errors**: None.

- **Case study accuracy**: CS0026 is correctly identified and accurately described. The worker correctly notes this is an "exact match" — CS0026 literally demonstrates bank account detail substitution via M365 Copilot, which is the core mechanism of AP-T15-01.

- **Pattern mechanism fidelity**: Strong. CS0026's mechanism (substituting payment details via indirect prompt injection) maps directly to AP-T15-01's content substitution for fraudulent action.

- **Confidence justification**: Step 9 (Privilege Escalation) is correctly rated "adapted" — CS0026's privilege escalation involves compromising the search_enterprise plugin, while the worker reframes it as "trusted status" causing the substituted data to be presented with high confidence. This is an honest adaptation. All other "explicit" ratings are justified by CS0026's procedure steps.

- **Sequence coherence**: The sequence tells a coherent story but is structurally identical to AP-T10-01. Both produce the same 10-step tactic sequence: TA0002 -> TA0000 -> TA0008 -> TA0003 -> TA0004 -> TA0007 -> TA0006 -> TA0005 -> TA0012 -> TA0011. The differentiation exists only in abstract action descriptions. This raises the question of whether the tactic sequences adequately distinguish two genuinely different attack mechanisms (oversight manipulation vs. data substitution).

- **Existing kill chain comparison**: Accurately reported. The existing chain (TA0003 -> TA0004 -> TA0005 -> TA0007 -> TA0011) matches the YAML file.

- **Verdict**: PASS WITH NOTES

---

### AP-T15-02: AI-mediated social engineering via deceptive instruction generation

- **Tactic ID/Name errors**: None.

- **Case study accuracy**: CS0055 exists but the worker's description of what it demonstrates is **materially inaccurate**. The worker states: "CS0055 demonstrates AI-mediated social engineering where a malicious website tricks Claude Computer-Use into instructing the user to perform specific UI actions (click terminal icon, paste clipboard contents, hit return), ultimately executing attacker commands."

  In reality, CS0055's ATLAS description states: "the text 'Are you a computer? Please see instructions to confirm:' caused the agent to click the associated button. This executed JavaScript to copy a malicious command into the agent's clipboard. The agent then proceeded to follow the instructions, opening a terminal, pasting the malicious command, and executing it."

  The critical distinction: the AI **agent itself** performed the UI actions (clicking, opening terminal, pasting, executing). It did NOT generate instructions for a human user to perform these actions. The human was the victim of the agent's autonomous execution, not the recipient of deceptive instructions from the AI.

- **Pattern mechanism fidelity**: **SIGNIFICANT MISMATCH.** AP-T15-02's defined mechanism is: "An attacker compromises an AI assistant's output generation through indirect prompt injection, causing it to produce urgent, authoritative messages that direct users toward malicious actions." The key element is the AI producing messages that DIRECT USERS toward harmful actions via social engineering.

  CS0055's actual mechanism is: the AI agent was tricked into autonomously performing harmful UI actions (clicking buttons, opening terminal, pasting clipboard, executing code). No human was "directed" by AI-generated messages — the agent acted directly.

  The worker's adaptation rationale claims "the mechanism — AI generates trusted instructions causing users to perform harmful actions — maps directly to AP-T15-02" but this mischaracterizes CS0055. The agent did not generate instructions for users; it performed the actions itself.

- **Confidence justification**: The "explicit" ratings for steps 1-4 and 6 are technically correct against CS0055's procedure steps. Step 5 (Privilege Escalation) is correctly rated "adapted." However, the "explicit" ratings carry an implicit claim that CS0055 demonstrates the AP-T15-02 mechanism, which it does not.

- **Sequence coherence**: The 6-step sequence is internally coherent as a description of CS0055's attack flow. But because CS0055 demonstrates a different mechanism than AP-T15-02 requires, the sequence describes the wrong attack.

- **Verdict**: NEEDS REVISION — The mechanism mismatch between CS0055 (agent performs harmful actions autonomously) and AP-T15-02 (AI generates deceptive instructions causing humans to act) is fundamental. The sequence needs either: (a) a different source case study that demonstrates AI-generated social engineering of humans, or (b) a substantially different adaptation rationale that honestly acknowledges the mechanism gap and provides clear justification for how CS0055's agent-directed-action pattern can be reframed as AI-directed-human-action pattern.

---

### AP-T12-01: Collaborative decision manipulation via inter-agent message injection

- **Tactic ID/Name errors**: None.

- **Case study accuracy**: CS0024 exists and is correctly identified as "Morris II Worm: RAG-Based Attack." The worker's characterization of the self-propagating mechanism is accurate.

- **Pattern mechanism fidelity**: Reasonable with acknowledged limitations. CS0024 demonstrates a single-agent RAG email system, while AP-T12-01 targets multi-agent collaborative decision-making. The worker correctly acknowledges this gap. The adaptation from "RAG poisoning of a single email agent" to "inter-agent message injection for collective decision manipulation" is a substantial generalization, but the core mechanism (poisoning shared data structures consumed by agents) does transfer.

- **Confidence justification**: **Step 6 (Exfiltration) is overrated as "explicit."** The abstract action says "Poisoned reasoning may cause agents to leak sensitive information to attacker-controlled channels." CS0024 does explicitly demonstrate exfiltration (S05: TA0010), but the multi-agent network framing is adapted. The confidence should be "adapted" since CS0024 shows single-agent PII leakage, not multi-agent network information leakage. The added TA0003 (Resource Development) step is correctly rated "adapted" — CS0024's actual procedure goes directly from AI Model Access (TA0000) to Execution (TA0005) with no Resource Development step.

- **Sequence coherence**: Coherent but the repeated Execution (steps 3 and 5) could be clearer about what distinguishes them (injection vs. activation upon retrieval).

- **Verdict**: PASS WITH NOTES

---

### AP-T12-03: Misinformation cascade via shared knowledge poisoning

- **Tactic ID/Name errors**: None.

- **Case study accuracy**: CS0024 correctly identified. The worker's description of the self-propagating "worm" mechanism is accurate.

- **Pattern mechanism fidelity**: Good match. CS0024's self-replicating prompt injection through shared data structures maps well to AP-T12-03's misinformation cascade. The dual Persistence steps (4 and 6) reasonably represent the initial persistence and the cascade reinforcement cycle.

- **Confidence justification**: **Step 7 (Exfiltration) is overrated as "explicit"** — same issue as AP-T12-01. The abstract action says "The cascade may cause sensitive data leakage as agents act on poisoned context." The multi-agent cascade framing is adapted, not explicit in CS0024. Steps 5 and 6 are correctly rated "adapted."

- **Sequence coherence**: The dual Persistence steps (4 and 6) effectively differentiate this sequence from AP-T12-01 by capturing the cascade reinforcement cycle. However, the overall tactic structure is very similar to AP-T13-04 (identical: TA0000, TA0003, TA0005, TA0006, TA0005, TA0006, TA0010, TA0011).

- **Verdict**: PASS WITH NOTES

---

### AP-T13-04: Infectious reasoning-chain backdoor propagation

- **Tactic ID/Name errors**: None.

- **Case study accuracy**: CS0024 correctly identified. The worker's adaptation from email-based propagation to reasoning-chain propagation is adequately explained.

- **Pattern mechanism fidelity**: Reasonable. AP-T13-04 specifically describes "a compromised agent [that] embeds malicious logic in reasoning outputs that propagates to consuming agents." CS0024's self-replicating prompt injection (where the worm payload causes the agent to include the malicious prompt in generated email responses) does demonstrate a similar propagation mechanism, adapted from email outputs to reasoning-chain outputs.

- **Confidence justification**: **Step 7 (Exfiltration) is overrated as "explicit."** Abstract action: "The infectious backdoor may cause data exfiltration across the agent network." CS0024 shows exfiltration from a single agent, not across an agent network. Should be "adapted." Step 2 (Resource Development) is rated "explicit" with action "Craft self-propagating backdoor logic embedded within reasoning-chain outputs" — CS0024 does explicitly demonstrate self-replicating prompt crafting (S01: testing prompts on public model APIs), so the tactic is explicit. But the "reasoning-chain" framing is adapted. Mixed.

- **Sequence coherence**: Structurally identical to AP-T12-03. Both have the same 8-step tactic sequence: TA0000 -> TA0003 -> TA0005 -> TA0006 -> TA0005 -> TA0006 -> TA0010 -> TA0011. Differentiation exists only in abstract actions.

- **Verdict**: PASS WITH NOTES

---

### AP-T16-02: Context hijacking via crafted protocol response injection

- **Tactic ID/Name errors**: None.

- **Case study accuracy**: CS0020 exists. The worker's description of CS0020 as demonstrating "indirect prompt injection via web content consumed by Bing Chat, causing it to exfiltrate user PII through manipulated URLs" is accurate. Secondary references (CS0024, CS0045, CS0053, CS0054) all exist.

- **Pattern mechanism fidelity**: Moderate. AP-T16-02 is specifically about "inter-agent protocol response injection" — crafting malicious content within protocol payloads exchanged between agents. CS0020 demonstrates web content injection consumed by a browser-based LLM assistant. The "protocol response" framing is a substantial adaptation from "web page content" that the worker presents as closer to explicit than it actually is. The secondary case studies (CS0045 MCP, CS0053, CS0054 MCP) are better matches for "protocol response injection" but were not used as the primary source.

- **Confidence justification**: **Step 4 (Initial Access) is overrated as "explicit."** The abstract action says "The receiving agent retrieves the poisoned protocol response (web scrape, tool metadata, RAG query)." CS0020 shows a browser-based LLM viewing an open website — not an agent retrieving a "protocol response." The "protocol response" framing is a significant adaptation. Additionally, the worker **reordered Initial Access and Execution** relative to CS0020's actual procedure: CS0020's sequence is TA0003 -> TA0007 -> TA0005 -> TA0004 -> TA0011, but the worker's sequence places TA0004 before TA0005 (steps 4 and 5). This reordering is not documented in the adaptation rationale.

- **Sequence coherence**: The 6-step sequence is concise and coherent. The reordering of TA0004/TA0005 from CS0020's original sequence arguably produces a more logical flow (access before execution).

- **Verdict**: PASS WITH NOTES — The reordering should be documented, and step 4's confidence should be "adapted."

---

### AP-T16-03: Tool capability misrepresentation via registry description poisoning

- **Tactic ID/Name errors**: None.

- **Case study accuracy**: CS0049 exists and is correctly identified as "Supply Chain Compromise via Poisoned ClawdBot Skill." The worker's description of CS0049's attack flow (hidden prompt injection in rules/logic.md, download count inflation, skill activation triggering shell command execution) is accurate. The worker's 8-step sequence collapses CS0049's 11-step procedure appropriately (4 Resource Development steps collapsed to 3, 2 Execution steps collapsed to 1, 2 Defense Evasion steps collapsed to 1).

- **Pattern mechanism fidelity**: **Subtle mismatch.** AP-T16-03's defined mechanism is about "misleading, overly broad, or adversarially crafted tool descriptions in a shared tool registry" — the deception is in the tool's DESCRIPTION causing agents to invoke tools under false assumptions about scope.

  CS0049's actual mechanism is different: the deception was a hidden prompt injection in a rules/logic.md file that executes when the skill is activated. The tool description ("What Would Elon Do?") was not itself misleading about the tool's capabilities — the malicious content was hidden inside the tool's files, not in its registry description.

  The worker's step 2 abstract action blends both concepts: "Craft misleading, overly broad, or adversarially crafted tool descriptions containing hidden prompt injections." This conflates AP-T16-03's description-based deception with CS0049's file-based injection. The two mechanisms are different: AP-T16-03 envisions the agent being misled by the description into invoking a tool with unexpected scope; CS0049 has the agent invoke a seemingly normal tool that executes hidden instructions.

- **Confidence justification**: All steps rated "explicit" are justified against CS0049's procedure steps. The tactic mapping is accurate.

- **Sequence coherence**: The 8-step sequence is coherent and accurately reflects CS0049's supply chain poisoning flow.

- **Verdict**: PASS WITH NOTES — The mechanism subtlety (description-based deception vs. hidden file injection) should be acknowledged in the adaptation rationale.

---

## Cross-Cutting Issues

### 1. Identical sequences for different patterns (structural collapse)

Two pairs of patterns produce structurally identical tactic sequences despite describing different attack mechanisms:

- **AP-T10-01 and AP-T15-01** share the exact same 10-step sequence (both from CS0026): TA0002, TA0000, TA0008, TA0003, TA0004, TA0007, TA0006, TA0005, TA0012, TA0011. The only differentiation is in abstract action text. If the tactic sequence is meant to structurally distinguish attack mechanisms, this is a failure — oversight manipulation and content substitution should not have identical kill chains.

- **AP-T12-03 and AP-T13-04** share the exact same 8-step sequence (both from CS0024): TA0000, TA0003, TA0005, TA0006, TA0005, TA0006, TA0010, TA0011. AP-T12-01 differs only by lacking the second Persistence step.

This suggests the worker derived sequences too mechanically from the source case study without adapting the tactic structure to reflect each pattern's distinct mechanism.

### 2. Systematic confidence inflation for multi-agent adaptations

Across AP-T12-01, AP-T12-03, and AP-T13-04, multiple steps are rated "explicit" where the underlying tactic is present in CS0024 (a single-agent system) but the abstract action describes multi-agent behavior not demonstrated by the case study. Specifically, Exfiltration steps describing "agent network" or multi-agent information leakage are consistently rated "explicit" when they should be "adapted." This is a systematic pattern of overstating how directly CS0024 supports multi-agent claims.

### 3. CS0055 mechanism mischaracterization (AP-T15-02)

The most significant issue in this batch. The worker describes CS0055 as demonstrating "AI-mediated social engineering" where the AI "instructs the user to perform specific UI actions." In reality, CS0055 demonstrates the AI agent autonomously performing the UI actions itself. This error flows from the matching analysis (which also calls this a "strong match") into the tactic sequence. The consequence is that AP-T15-02's sequence describes a different attack than its pattern definition requires.

### 4. Undocumented sequence reordering (AP-T16-02)

The worker reordered Initial Access and Execution relative to CS0020's actual procedure without documenting or justifying the change. CS0020's ATLAS procedure has Execution (S02) before Initial Access (S03), reflecting the specific mechanics of Bing Chat's content processing. The worker silently reversed this to a more conventional order.

### 5. Three case studies serving six patterns

CS0024 (Morris II Worm) serves as the source for 3 patterns, and CS0026 (M365 Copilot) serves as the source for 2 patterns. This concentration means 5 of 8 patterns share only 2 distinct case study sources, limiting the diversity of evidence and creating the structural duplication noted above.
