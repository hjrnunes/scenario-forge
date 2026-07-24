# ATLAS Tactic Sequences for T2 (Tool Misuse) Patterns

This document provides pattern-specific ATLAS tactic sequences for T2 attack patterns, adapted from matched case study procedures.

## Methodology

- **Source case studies**: Matched via mechanism analysis in `owasp-atlas-matching.md`
- **Adaptation**: Each sequence is tailored to the pattern's specific mechanism, not copied verbatim from case studies
- **Confidence levels**:
  - **explicit**: Tactic directly demonstrated in source case study
  - **adapted**: Case study demonstrates related mechanism; adapted to pattern context
  - **inferred**: Not in case study but logically required by pattern mechanism
- **Perspective**: All sequences use attacker perspective (agent actions are effects of attacker actions)

---

## Pattern Sequences

### AP-T2-01: Parameter pollution via function-call manipulation

**Source case study**: AML.CS0037 — Data Exfiltration via Agent Tools in Copilot Studio (strong)  
**Existing kill chain**: YES — being replaced

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0002 | Reconnaissance | Study the agent's tool definitions and parameter schemas to identify validation gaps, boundary conditions, or parameters that accept open-ended values | explicit |
| 2 | AML.TA0003 | Resource Development | Craft input designed to cause the agent to populate tool parameters with inflated, malformed, or boundary-violating values while staying within the tool's granted permissions | adapted |
| 3 | AML.TA0004 | Initial Access | Submit the crafted input through an accessible channel (direct input or indirect via document/email) | adapted |
| 4 | AML.TA0005 | Execution | The agent processes the input, and the prompt injection causes it to resolve attacker-influenced values into tool call parameter slots | adapted |
| 5 | AML.TA0005 | Execution | The agent invokes the tool with polluted parameters; the call passes permission checks because the tool itself is authorized, but parameter values produce an outcome far outside intended operational bounds | adapted |
| 6 | AML.TA0011 | Impact | The tool executes with attacker-influenced parameters, producing amplified quantities, modified recipients, or other outcomes that violate the system's operational intent | adapted |

**Adaptation rationale**: CS0037 demonstrates the full reconnaissance-to-impact flow for tool misuse via parameter manipulation. The sequence adapts CS0037's email-based discovery and exfiltration flow to the more general parameter pollution pattern. The key difference is that AP-T2-01 focuses on boundary-violating parameter values (amplified quantities, malformed inputs) rather than the specific exfiltration chain in CS0037. The tactic progression is preserved: recon → craft → deliver → execute tool → impact.

**Comparison with existing kill chain**: The existing kill chain had five steps (reconnaissance, setup, execution, tool_invocation, impact). The new sequence expands this to six steps by splitting Initial Access (step 3) from the execution phases, making the attack flow clearer. It also consolidates the two execution steps (steps 4-5) under AML.TA0005 since both represent different phases of the same execution tactic.

---

### AP-T2-02: Multi-tool chain exploitation for data exfiltration

**Source case study**: AML.CS0037 — Data Exfiltration via Agent Tools in Copilot Studio (strong), also CS0021/CS0035/CS0045  
**Existing kill chain**: YES — being replaced

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0002 | Reconnaissance | Discover the agent's available tools and their call chain relationships, identifying combinations where one tool retrieves sensitive data and another can transmit externally | explicit |
| 2 | AML.TA0003 | Resource Development | Craft a prompt that induces the agent to plan a multi-step tool sequence, framing the retrieval-then-exfiltration chain as a legitimate composite operation | explicit |
| 3 | AML.TA0004 | Initial Access | Submit the crafted prompt through an accessible input channel | explicit |
| 4 | AML.TA0005 | Execution | The agent processes the prompt and commits to the multi-tool chain without recognizing the composite intent as malicious | explicit |
| 5 | AML.TA0008 | Discovery | The agent discovers or accesses the data sources containing sensitive information through the first tool in the chain | explicit |
| 6 | AML.TA0009 | Collection | The first tool retrieves sensitive data from an authorized source, producing output that appears to be a normal intermediate result | explicit |
| 7 | AML.TA0010 | Exfiltration | A subsequent tool call transmits the retrieved data to an external destination (attacker-controlled email, URL, API endpoint) | explicit |
| 8 | AML.TA0011 | Impact | Organization suffers data breach through a composite tool chain that bypasses per-call authorization controls | explicit |

**Adaptation rationale**: CS0037 is an exact match for this pattern — it demonstrates multi-tool chaining (discovery tools → collection tools → email exfiltration tool) to achieve data exfiltration. The sequence directly follows CS0037's step progression (S00-S11), which shows: reconnaissance for tools (S00-S05), discovery of data sources (S08-S09), crafting the composite attack (S10), and execution of the chain (S11). The adapted sequence generalizes the specific tools (Salesforce get-records, email send) to any retrieval-and-transmit tool pair. Secondary matches (CS0021, CS0035, CS0045) also demonstrate exfiltration but through simpler single-tool paths rather than the explicit multi-tool chaining that AP-T2-02 emphasizes.

**Comparison with existing kill chain**: The existing kill chain had six steps; the new sequence expands to eight by explicitly separating Discovery (step 5) and Collection (step 6), which better reflects how multi-tool chains operate. This aligns with ATLAS's model where Discovery and Collection are distinct phases in the attack lifecycle.

---

### AP-T2-04: Tool misuse via poisoned persistent memory

**Source case study**: AML.CS0040 — Hacking ChatGPT's Memories with Prompt Injection (strong)  
**Existing kill chain**: NO

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Craft adversarial prompt containing false directives designed to be written into the agent's persistent memory store | explicit |
| 2 | AML.TA0007 | Defense Evasion | Conceal the prompt injection within content that appears benign or legitimate (hidden in document formatting, embedded in innocuous text) | explicit |
| 3 | AML.TA0004 | Initial Access | Deliver the poisoned content through a channel the agent consumes as a trusted source (shared document, API response, data feed) | explicit |
| 4 | AML.TA0005 | Execution | When the agent ingests the content into its context, the hidden prompt injection executes | explicit |
| 5 | AML.TA0006 | Persistence | The injection writes attacker-controlled false directives into the agent's persistent memory store, establishing cross-session persistence | explicit |
| 6 | AML.TA0006 | Persistence | The poisoned content remains in the shared channel or data source, acting as a persistent infection vector that can compromise additional users or sessions | explicit |
| 7 | AML.TA0005 | Execution | In a subsequent session, the agent retrieves the poisoned memory and treats it as legitimate operational context, causing it to invoke tools with unauthorized parameters or targets | adapted |
| 8 | AML.TA0011 | Impact | The agent performs tool invocations driven by attacker-controlled memory content, bypassing session-level security checks that would have caught the malicious directive if presented directly | adapted |

**Adaptation rationale**: CS0040 demonstrates the memory poisoning mechanism perfectly (steps S00-S05), but it focuses on misinformation impact rather than tool misuse. AP-T2-04 requires adapting the final steps to show how poisoned memory drives unauthorized tool invocations in future sessions. The first six steps (resource development → persistence) are explicit from CS0040. Steps 7-8 are adapted: CS0040 ends with misinformation impact (S06), while AP-T2-04 extends this to tool execution driven by the poisoned memory. The core innovation is that the memory pollution in session N causes tool misuse in session N+1, bypassing the input validation that would catch direct prompt injection.

**Comparison with existing kill chain**: No existing kill chain to compare.

---

### AP-T2-05: Tool misuse via adversarial retrieval content

**Source case study**: AML.CS0024 — Morris II Worm: RAG-Based Attack (strong)  
**Existing kill chain**: NO

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0000 | AI Model Access | Gain access to the vector store or RAG system that the agent queries (either through write access or by injecting content into a data source the system indexes) | explicit |
| 2 | AML.TA0005 | Execution | Craft and insert adversarial content into the vector store; the content contains embedded directives designed to manipulate the agent's tool invocation decisions | explicit |
| 3 | AML.TA0006 | Persistence | The poisoned content is indexed and persists in the retrieval system, where it can be activated by future queries | explicit |
| 4 | AML.TA0005 | Execution | When the agent queries the RAG system, it retrieves the poisoned content and invokes tools based on the manipulated directives, executing unsafe or unauthorized operations | adapted |
| 5 | AML.TA0011 | Impact | The agent performs unauthorized tool actions driven by poisoned retrieval content, with each query to the compromised vector store potentially triggering malicious behavior | adapted |

**Adaptation rationale**: CS0024 (Morris II Worm) demonstrates RAG poisoning with self-propagating prompts that cause data exfiltration. AP-T2-05 adapts this to emphasize tool misuse rather than self-replication. CS0024's retrieval-triggers-execution (S03) and propagation (S04) are collapsed to one step since the pattern's mechanism is tool invocation, not worm propagation. CS0024's Exfiltration step (S05) is dropped — this pattern is about tool misuse generally, not specifically data exfiltration. If the attacker's goal is exfiltration, that is the Impact, not a separate step. The sequence generalizes from email-based RAG injection to any vector store poisoning mechanism.

**Comparison with existing kill chain**: No existing kill chain to compare.

---

### AP-T2-06: Tool hijacking via prompt injection

**Source case study**: AML.CS0016 — Achieving Code Execution in MathGPT via Prompt Injection (strong), also CS0037/CS0039/CS0045/CS0046/CS0051  
**Existing kill chain**: YES — being replaced

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0002 | Reconnaissance | Study the agent's interaction model and tool access to understand which tools can execute attacker commands (shell, code interpreter, API client, file operations) | explicit |
| 2 | AML.TA0000 | AI Model Access | Gain ability to interact with the agent's LLM, either directly or through data sources it consumes | explicit |
| 3 | AML.TA0003 | Resource Development | Craft adversarial instructions designed to override the agent's operational goal and direct it to invoke a specific tool with attacker-chosen commands; stage any required external payloads or receiving infrastructure | adapted |
| 4 | AML.TA0001 | AI Attack Staging | Verify that the prompt injection is effective and the tool invocation will execute attacker commands (through benign test payloads before escalating to malicious ones) | explicit |
| 5 | AML.TA0004 | Initial Access | Inject the crafted prompt into the agent's input channel or embed it within an external data source the agent consumes (document, web page, API response, email) | explicit |
| 6 | AML.TA0005 | Execution | The injected prompt activates within the agent's context, overriding or supplementing its original goal with the attacker's directive to invoke a tool | explicit |
| 7 | AML.TA0005 | Execution | The agent invokes a tool — such as a shell, API client, or code interpreter — executing an attacker-chosen command through the agent's legitimate tool access | explicit |
| 8 | AML.TA0013 | Credential Access | If the goal is credential theft, the tool execution accesses environment variables, configuration files, or memory to extract secrets | explicit |
| 9 | AML.TA0011 | Impact | The attacker achieves arbitrary tool execution through the hijacked agent, potentially gaining host-level access, exfiltrating data, or performing destructive actions | explicit |

**Adaptation rationale**: CS0016 (MathGPT) demonstrates the complete tool hijacking flow: reconnaissance (S00), model access (S01), craft prompt (S02), staging/testing (S03), initial access via injection (S04), tool execution (S05), credential access via environment variables (S06), impact via API abuse (S07), and optional DoS (S08). AP-T2-06 generalizes this from code interpreters to any tool with execution capability. The sequence preserves CS0016's testing phase (S03 → step 6, AI Attack Staging) which is a characteristic feature of tool hijacking attacks. Step 8 (credential access) is optional but shown because CS0016 demonstrates it as a common secondary objective. The existing kill chain in attack-patterns-memory-tool.yaml had five steps and didn't include the staging phase or the optional credential access step, making the new sequence more detailed and realistic.

**Comparison with existing kill chain**: The existing kill chain had five steps (setup, delivery, execution, tool_hijack, impact). The new sequence expands to nine steps by: (1) splitting reconnaissance as a distinct phase, (2) adding AI Model Access to reflect the access prerequisite, (3) adding AI Attack Staging to capture the testing/verification phase that CS0016 demonstrates, (4) adding optional Credential Access to reflect common secondary objectives, and (5) separating the two execution phases (prompt activation vs. tool invocation). This makes the attack progression much more granular and aligned with observed real-world behavior.

---

## Summary

All five T2 patterns now have ATLAS tactic sequences derived from strong case study matches:
- **AP-T2-01**: 6 steps, based on CS0037 parameter manipulation flow
- **AP-T2-02**: 8 steps, based on CS0037 multi-tool chaining (also informed by CS0021/CS0035/CS0045)
- **AP-T2-04**: 8 steps, based on CS0040 memory poisoning extended to tool misuse
- **AP-T2-05**: 5 steps, based on CS0024 RAG poisoning adapted to tool invocation
- **AP-T2-06**: 9 steps, based on CS0016 code execution via prompt injection (also informed by CS0037/CS0039/CS0045/CS0046/CS0051)

Each sequence is tailored to the pattern's specific mechanism while preserving the tactic progressions demonstrated in the source case studies. Where case studies demonstrate related but not identical mechanisms, adaptations are clearly marked and justified.
