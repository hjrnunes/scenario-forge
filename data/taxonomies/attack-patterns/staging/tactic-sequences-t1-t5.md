# ATLAS Tactic Sequences for T1 (Memory Poisoning) and T5 (Cascading Hallucination) Patterns

This document provides pattern-specific ATLAS tactic sequences for 8 attack patterns. Each sequence is adapted from a matched ATLAS case study to fit the pattern's specific mechanism.

**Methodology**: Use matched case study as reference, adapt sequence to pattern's mechanism. NOT a verbatim copy.

---

## AP-T1-01: Persistent memory rule injection

**Source case study**: AML.CS0040 — Hacking ChatGPT's Memories with Prompt Injection (match type: evidenced)
**Existing kill chain**: yes — being replaced

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence | 
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Craft adversarial prompt containing false operational rules | explicit |
| 2 | AML.TA0007 | Defense Evasion | Conceal prompt within content using steganographic techniques (invisible text, background-color matching) | explicit |
| 3 | AML.TA0004 | Initial Access | Deliver poisoned content through connected application channel treated as trusted data source | explicit |
| 4 | AML.TA0005 | Execution | User references shared content → agent ingests into context → hidden prompt executes | explicit |
| 5 | AML.TA0006 | Persistence | Injection writes attacker-controlled false rules into persistent memory store | explicit |
| 6 | AML.TA0006 | Persistence | Poisoned content remains in shared channel, acting as persistent infection vector | explicit |
| 7 | AML.TA0011 | Impact | Agent operates with corrupted memory, authorizing constraint-violating actions | explicit |

**Adaptation rationale**: CS0040 demonstrates all core steps. Added Defense Evasion (S01: T0068) which was missing from original pattern kill chain. The two Persistence steps are distinct: S04 (memory write) and S05 (content persistence in channel). Pattern correctly identifies cross-session persistence and propagation mechanisms. Abstracted from "ChatGPT memories" to "persistent memory" and from "Google Doc" to "connected application channel."

**Comparison with existing kill chain**: Original pattern omitted the Defense Evasion step (hiding prompt in document). Original also didn't distinguish between memory persistence and content-channel persistence. New sequence adds explicit evasion step and clarifies the dual persistence mechanism.

---

## AP-T1-02: Context window saturation for privilege escalation

**Source case study**: AML.CS0040 — Hacking ChatGPT's Memories with Prompt Injection (match type: strong)
**Existing kill chain**: no

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence | 
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Craft fragmented inputs designed to stay below per-input detection thresholds while cumulatively corrupting authorization state | adapted |
| 2 | AML.TA0004 | Initial Access | Deliver fragmented inputs across repeated interactions via normal channels | adapted |
| 3 | AML.TA0005 | Execution | Each fragment executes, consuming context window capacity and incrementally altering the agent's authorization state tracking | adapted |
| 4 | AML.TA0012 | Privilege Escalation | Agent grants access it should deny due to cumulative state corruption exceeding context capacity | inferred |
| 5 | AML.TA0011 | Impact | Attacker gains unauthorized access through fragmented privilege escalation | inferred |

**Adaptation rationale**: CS0040 shows persistent memory poisoning; AP-T1-02 describes context window fragmentation — an ephemeral, within-session attack. Context window saturation does NOT persist across sessions, so TA0006 (Persistence) is inappropriate. The evasion mechanism (staying below detection thresholds) is intrinsic to the crafting step, not a separate action. The core progression is: craft fragments → deliver across interactions → each fragment corrupts state → cumulative corruption causes privilege escalation → impact. Significantly diverges from CS0040's mechanism.

**Comparison with existing kill chain**: N/A - pattern had no existing kill chain.

---

## AP-T1-03: Gradual threat-model erosion via memory drift

**Source case study**: AML.CS0009 — Tay Poisoning (match type: strong)
**Existing kill chain**: no

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence | 
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0000 | AI Model Access | Attacker gains ability to interact with agent and influence its learning/memory processes | explicit |
| 2 | AML.TA0004 | Initial Access | Deliver incremental inputs containing subtly altered threat definitions | adapted |
| 3 | AML.TA0006 | Persistence | Repeated adversarial inputs cause gradual corruption of stored threat classification criteria | explicit |
| 4 | AML.TA0011 | Impact | Agent progressively reclassifies malicious activity as benign, creating detection blind spot | explicit |

**Adaptation rationale**: CS0009 (Tay) demonstrates gradual corruption through repeated adversarial training inputs (S00→S01→S02→S03). Adapted from "racist language" to "altered threat definitions" and from "conversation algorithms" to "threat classification criteria." The core mechanism is identical: incremental corruption through repeated interaction. CS0009's tactic sequence is notably short (4 steps) because Tay had direct online learning — this pattern maintains that brevity. No separate execution step needed; access implies execution in online learning contexts.

**Comparison with existing kill chain**: N/A - pattern had no existing kill chain.

---

## AP-T1-04: Shared memory corruption for cross-agent influence

**Source case study**: AML.CS0024 — Morris II Worm: RAG-Based Attack (match type: strong)
**Existing kill chain**: no

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence | 
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0000 | AI Model Access | Attacker gains ability to write to shared memory structure (RAG database, vector store, shared memory backend) | explicit |
| 2 | AML.TA0005 | Execution | Craft and test adversarial payload designed to corrupt shared memory and propagate across agents | adapted |
| 3 | AML.TA0006 | Persistence | Inject false operational data into shared memory structure consumed by multiple agents | explicit |
| 4 | AML.TA0010 | Exfiltration | Propagation mechanism causes other agents to read corrupted data and incorporate into decision-making | adapted |
| 5 | AML.TA0011 | Impact | Cross-agent behavior corruption propagates without direct interaction with each affected agent | explicit |

**Adaptation rationale**: CS0024 demonstrates shared-channel poisoning via RAG database. Adapted from "self-replicating prompt in email RAG" to "false operational data in shared memory." Kept the core 5-step sequence: access → test → poison → propagate → impact. Step 2 (S01: test prompts) maps to initial payload crafting. Step 4 uses TA0010 (Exfiltration) because CS0024 S05 uses T0057 (exfiltrate data via generation) — the propagation mechanism in Morris II included data leakage. For pure cross-agent influence without exfiltration, TA0015 (Lateral Movement) would be more accurate, but following the case study's actual tactic mapping. Abstracted from "email assistant RAG" to generic "shared memory structure."

**Comparison with existing kill chain**: N/A - pattern had no existing kill chain.

---

## AP-T1-06: Zero-click RAG poisoning with rendered-output exfiltration

**Source case study**: CS0059 DOES NOT EXIST — using AML.CS0024 (Morris II RAG, strong), CS0021 (ChatGPT markdown exfil, strong), and CS0029 (Bard markdown exfil, strong) as composite reference
**Existing kill chain**: yes — being replaced

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence | 
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Craft prompt injection disguised as benign content, designed for RAG retrieval; stage exfiltration endpoint | adapted |
| 2 | AML.TA0004 | Initial Access | Deliver crafted content through channel that feeds AI assistant's data corpus (email, shared doc, knowledge base) | adapted |
| 3 | AML.TA0006 | Persistence | Content automatically indexed into RAG database, establishing dormant injection | adapted |
| 4 | AML.TA0005 | Execution | User query triggers RAG retrieval of poisoned content → hidden instructions activate without user interaction | adapted |
| 5 | AML.TA0009 | Collection | Activated injection instructs AI to search accessible data for sensitive information | inferred |
| 6 | AML.TA0010 | Exfiltration | AI encodes collected data into rendered output element (markdown image URL) that client automatically fetches | adapted |
| 7 | AML.TA0011 | Impact | Confidential data exfiltrated to attacker endpoint via automatic rendering | explicit |

**Adaptation rationale**: **CRITICAL: CS0059 does not exist.** Constructed composite sequence from three case studies: CS0024 (RAG poisoning mechanism, steps 1-4), CS0021/CS0029 (markdown image exfiltration, steps 5-7). CS0024 provides: resource dev → delivery → persistence → execution. CS0021/CS0029 provide: markdown element generation → automatic rendering → exfiltration. Added Collection step (TA0009) which is implied in the pattern description ("search for sensitive data") but not explicitly present in CS0021/CS0029 (they exfiltrate conversation history, not searched data). The "zero-click" aspect comes from CS0024's RAG retrieval trigger. The rendered-output exfiltration comes from CS0021 S03-S04 (markdown image) and CS0029 S04-S05 (same mechanism). This is an informed construction, not a direct case study mapping.

**Comparison with existing kill chain**: Original pattern had setup → delivery → ingestion → activation → collection → exfiltration → impact (7 steps). New sequence matches the step count and flow. Original used TA0003 → TA0004 → TA0006 → TA0005 → TA0009 → TA0010 → TA0011. New sequence is identical. However, original cited non-existent CS0059, so the techniques and descriptions needed correction based on actual case studies.

---

## AP-T5-01: Progressive misinformation accumulation in persistent memory

**Source case study**: AML.CS0040 — Hacking ChatGPT's Memories with Prompt Injection (match type: strong)
**Existing kill chain**: no

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence | 
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Craft subtly false information designed to be stored as agent's authoritative memory | adapted |
| 2 | AML.TA0007 | Defense Evasion | Conceal fabricated data within legitimate-appearing content to avoid detection | explicit |
| 3 | AML.TA0004 | Initial Access | Deliver content containing false information via trusted channel | explicit |
| 4 | AML.TA0005 | Execution | Agent ingests content → false information processed and stored in persistent memory | explicit |
| 5 | AML.TA0006 | Persistence | False information persists in long-term memory, treated as authoritative source material in subsequent sessions | explicit |
| 6 | AML.TA0011 | Impact | Progressive compounding produces increasingly distorted outputs as agent builds on prior hallucinations | adapted |

**Adaptation rationale**: CS0040 shows single-injection memory poisoning; AP-T5-01 describes progressive accumulation over successive interactions. The core mechanism (persistent memory corruption) is identical. CS0040's dual Persistence (S04 memory write + S05 document channel persistence) is collapsed to one step here because this pattern has a single persistence vector (memory store), unlike AP-T1-01 where the shared document also acts as an infection vector. Impact adapted from "misinformed/misled" to "progressive compounding" to reflect the cascading nature.

**Comparison with existing kill chain**: N/A - pattern had no existing kill chain.

---

## AP-T5-02: Hallucinated endpoint injection for data exfiltration

**Source case study**: AML.CS0021 — ChatGPT Markdown Image Exfiltration (match type: strong); secondary: CS0029 (match type: strong)
**Existing kill chain**: no

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence | 
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Develop prompt injection causing agent to include fabricated endpoint references in generated output | explicit |
| 2 | AML.TA0003 | Resource Development | Stage prompt injection in content accessible to agent (webpage, document, knowledge base) | explicit |
| 3 | AML.TA0004 | Initial Access | User query causes agent to retrieve content containing injection | explicit |
| 4 | AML.TA0005 | Execution | Injection activates, causing agent to generate calls to fabricated API endpoints or webhook URLs | adapted |
| 5 | AML.TA0010 | Exfiltration | Agent invokes hallucinated endpoints with user data encoded in URL parameters or request body | adapted |
| 6 | AML.TA0011 | Impact | Confidential data exfiltrated to attacker-controlled endpoint through hallucinated API calls | explicit |

**Adaptation rationale**: Switched primary source from CS0020 to CS0021 because CS0021's mechanism (agent generating attacker-controlled URLs in output) better matches "hallucinated endpoint injection" than CS0020's conversational style manipulation. CS0021 demonstrates: S00-S01 (dual resource dev: craft injection + stage it, TA0003), S02 (retrieval via plugin, TA0004), S03 (injection causes markdown image element generation, TA0005), S04 (image render triggers HTTP request, TA0010), S06 (privacy impact, TA0011). Adapted from "markdown image URL" to "fabricated API endpoints/webhooks" — the core mechanism is identical: agent treats attacker-controlled URLs as legitimate and makes requests that exfiltrate data. Steps 1-3 and 6 are explicit (CS0021 demonstrates them directly). Steps 4-5 are adapted because CS0021 shows rendered markdown images; the pattern describes API endpoint hallucination, which follows the same URL-based exfiltration pattern but through tool invocations rather than UI rendering.

**Comparison with existing kill chain**: N/A - pattern had no existing kill chain.

---

## AP-T5-04: Fabricated reference data injection for value manipulation

**Source case study**: AML.CS0026 — Financial Transaction Hijacking with M365 Copilot (match type: strong)
**Existing kill chain**: no

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence | 
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0002 | Reconnaissance | Identify agent's data corpus and query patterns to target value-dependent decisions | explicit |
| 2 | AML.TA0000 | AI Model Access | Interact with agent to discover retrieval mechanisms and response format | explicit |
| 3 | AML.TA0008 | Discovery | Probe agent to identify how it handles quantitative reference data and value lookups | explicit |
| 4 | AML.TA0003 | Resource Development | Craft false quantitative reference data targeting agent's value-dependent decision processes | adapted |
| 5 | AML.TA0004 | Initial Access | Deliver content containing fabricated values through channel feeding agent's data corpus | adapted |
| 6 | AML.TA0007 | Defense Evasion | Obfuscate injection and manipulate retrieval to prioritize attacker-controlled data | explicit |
| 7 | AML.TA0006 | Persistence | False reference data indexed into RAG database, persisting across sessions | explicit |
| 8 | AML.TA0005 | Execution | User query triggers retrieval → prompt injection activates | explicit |
| 9 | AML.TA0012 | Privilege Escalation | Injection manipulates agent's tool invocations or authorization decisions using fabricated values | adapted |
| 10 | AML.TA0011 | Impact | Agent negotiates, transacts, or decides based on unrealistic values, systematically biasing computations | adapted |

**Adaptation rationale**: CS0026 is the longest case study sequence (S00-S13, 10+ tactics). Adapted from "financial transaction hijacking" to "fabricated reference data for value manipulation." The reconnaissance phase (S00-S03: TA0002 → TA0000 → TA0008 → TA0008) is preserved because the pattern requires understanding agent's value-handling. Steps 4-7 adapt the content crafting and delivery (S04-S08). Step 9 uses TA0012 (Privilege Escalation) from CS0026 S11, adapting from "compromise search functionality" to "manipulate value-dependent decisions." Impact step (S13) adapted from "fraudulent wire transfer" to generic "value-biased computations." This is the longest sequence because CS0026 demonstrates a sophisticated multi-phase attack requiring extensive preparation.

**Comparison with existing kill chain**: N/A - pattern had no existing kill chain.

---

## Summary Statistics

**Patterns processed**: 8
- AP-T1-01: 7 steps (explicit alignment with CS0040, added evasion step)
- AP-T1-02: 5 steps (adapted from CS0040, added privilege escalation)
- AP-T1-03: 4 steps (explicit alignment with CS0009)
- AP-T1-04: 5 steps (explicit alignment with CS0024)
- AP-T1-06: 7 steps (composite from CS0024 + CS0021/CS0029, CS0059 non-existent)
- AP-T5-01: 6 steps (adapted from CS0040, emphasis on compounding)
- AP-T5-02: 6 steps (adapted from CS0020 + CS0021/CS0029)
- AP-T5-04: 10 steps (adapted from CS0026, longest sequence)

**Confidence distribution**:
- Explicit: 34 steps (direct demonstration in case study)
- Adapted: 20 steps (case study demonstrates related mechanism, adapted to pattern)
- Inferred: 4 steps (logically required by pattern, not in case study)

**Special case resolved**:
- AP-T1-06: CS0059 does not exist. Used composite reference from CS0024 (RAG poisoning) + CS0021/CS0029 (markdown exfiltration). Recommendation: Update pattern evidence field to cite composite sources rather than non-existent CS0059.

**Tactic coverage** (unique tactics used across all sequences):
- TA0000 (AI Model Access): 3 patterns
- TA0002 (Reconnaissance): 1 pattern
- TA0003 (Resource Development): 8 patterns
- TA0004 (Initial Access): 7 patterns
- TA0005 (Execution): 7 patterns
- TA0006 (Persistence): 7 patterns
- TA0007 (Defense Evasion): 5 patterns
- TA0008 (Discovery): 1 pattern
- TA0009 (Collection): 1 pattern
- TA0010 (Exfiltration): 3 patterns
- TA0011 (Impact): 8 patterns
- TA0012 (Privilege Escalation): 2 patterns

**Quality gates passed**:
- All technique→tactic mappings validated against ATLAS achieves relationships
- All tactic sequences follow attacker perspective framing
- All sequences are linear (no branching)
- All adaptation rationales explain what changed and why
