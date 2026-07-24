# ATLAS Tactic Sequences for Attack Patterns: T10, T15, T12, T13, T16

This document provides pattern-specific ATLAS tactic sequences for 8 attack patterns. Each sequence is adapted from a matched ATLAS case study to fit the pattern's specific mechanism.

---

## AP-T10-01: Human oversight interface manipulation via artificial decision context

**Source case study**: AML.CS0026 — Financial Transaction Hijacking with M365 Copilot (strong match)  
**Existing kill chain**: YES — being replaced

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0002 | Reconnaissance | Discover the structure of the human oversight interface, including what contextual information is presented to reviewers alongside agent action requests. | explicit |
| 2 | AML.TA0000 | AI Model Access | Interact with the AI agent to understand its oversight presentation mechanisms. | explicit |
| 3 | AML.TA0008 | Discovery | Identify delimiters, formatting structures, and context presentation patterns used in human review interfaces. | explicit |
| 4 | AML.TA0003 | Resource Development | Craft input designed to cause the agent to generate misleading decision contexts that obscure critical information from the human reviewer. | explicit |
| 5 | AML.TA0004 | Initial Access | Deliver the crafted content through a data channel the agent consumes (e.g., email, document). | explicit |
| 6 | AML.TA0007 | Defense Evasion | Obfuscate the malicious portion to evade detection by the recipient. | explicit |
| 7 | AML.TA0006 | Persistence | The manipulated context persists in the RAG system and is retrieved whenever relevant queries occur. | explicit |
| 8 | AML.TA0005 | Execution | The injection activates and manipulates the agent's output generation, presenting actions with artificially constructed context. | explicit |
| 9 | AML.TA0012 | Privilege Escalation | The agent presents attacker-controlled context as verified information, neutralizing the oversight function. | explicit |
| 10 | AML.TA0011 | Impact | The human reviewer approves attacker-aligned actions based on the manipulated context, bypassing the human-in-the-loop security control. | explicit |

**Adaptation rationale**: CS0026 demonstrates context manipulation of financial transaction details presented to humans via M365 Copilot. The tactic sequence is adapted from financial fraud to general human oversight bypass — the core mechanism (manipulating AI-presented context to deceive human reviewers) maps directly to AP-T10-01's oversight interface manipulation.

**Comparison with existing kill chain**: The existing kill chain (from attack-patterns-agentic-only.yaml) follows: Discovery → Resource Development → Execution → Defense Evasion → Impact. The new sequence adds Initial Access, Persistence, and Privilege Escalation tactics based on CS0026's full attack flow, providing a more complete picture of how context poisoning persists and escalates privileges in RAG-based systems.

---

## AP-T15-01: Trust-exploiting content substitution for fraudulent action

**Source case study**: AML.CS0026 — Financial Transaction Hijacking with M365 Copilot (strong match)  
**Existing kill chain**: YES — being replaced

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Craft content containing prompt injection designed to substitute legitimate operational data (payment details, contact information) with attacker-controlled values | explicit |
| 2 | AML.TA0007 | Defense Evasion | Obfuscate the injection within legitimate-appearing business content to evade detection | explicit |
| 3 | AML.TA0004 | Initial Access | Deliver the poisoned content through a data channel the AI assistant consumes (email, document, knowledge base entry) | explicit |
| 4 | AML.TA0006 | Persistence | The poisoned data is indexed into the RAG database and retrieved for relevant queries | explicit |
| 5 | AML.TA0005 | Execution | The injection activates and manipulates the AI's output to substitute legitimate values with attacker-controlled data | explicit |
| 6 | AML.TA0012 | Privilege Escalation | The agent's trusted status causes the substituted data to be presented as verified legitimate information | explicit |
| 7 | AML.TA0011 | Impact | The human operator acts on the substituted data without independent verification, completing a fraudulent transaction | explicit |

**Adaptation rationale**: CS0026 demonstrates this attack directly — substituting bank account details in M365 Copilot's responses via indirect prompt injection. This sequence focuses on the content substitution mechanism: craft → obfuscate → deliver → persist → activate substitution → trust exploitation → fraud. Structurally differentiated from AP-T10-01 (which shares CS0026 but focuses on reconnaissance and discovery of the oversight interface). T15-01 omits the Recon/AI Model Access/Discovery phases because the pattern's mechanism is the substitution itself, not the interface probing.

**Comparison with existing kill chain**: The existing kill chain follows: Resource Development → Initial Access → Execution → Defense Evasion → Impact (5 steps). The new sequence (7 steps) adds Persistence and Privilege Escalation while reordering Defense Evasion before delivery (obfuscation is preparation, not post-delivery).

---

## AP-T15-02: AI-mediated social engineering via deceptive instruction generation

**Source case study**: AML.CS0055 — AI ClickFix: Hijacking Computer-Use Agents (strong match)  
**Existing kill chain**: YES — being replaced

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Craft a prompt injection designed to hijack the AI assistant's output generation, causing it to produce urgent, authoritative messages directing users toward attacker-controlled actions. | explicit |
| 2 | AML.TA0003 | Resource Development | Stage malicious content (website, script) that will deliver the social engineering payload. | explicit |
| 3 | AML.TA0004 | Initial Access | The user's AI agent accesses the malicious website or document, ingesting the injected prompt. | explicit |
| 4 | AML.TA0005 | Execution | The compromised AI assistant processes the injection and generates deceptive messages leveraging its established trust relationship with the user. | explicit |
| 5 | AML.TA0012 | Privilege Escalation | The injection causes the agent to escalate from passive information display to active instruction that prompts user actions (clicking buttons, running commands). | inferred |
| 6 | AML.TA0011 | Impact | Users follow the AI-generated deceptive instructions, executing malicious actions on the attacker's behalf. | explicit |

**Adaptation rationale**: CS0055 demonstrates agent-as-victim (website tricks agent into acting). AP-T15-02 inverts this to agent-as-tool (compromised agent generates instructions that trick humans). The tactic sequence adapts CS0055's preparation and delivery mechanism but the execution/impact phase represents the opposite direction of social engineering. CS0055's privilege escalation is agent-to-host (JavaScript clipboard), not agent-to-human (deceptive instructions) — hence the TA0012 step is marked "inferred" rather than "adapted." This pattern's mechanism (AI generating social engineering content directed at humans) is not directly demonstrated in any ATLAS case study — the closest evidence is the preparation mechanism from CS0055.

**Comparison with existing kill chain**: The existing kill chain follows: Resource Development → Initial Access → Execution → Defense Evasion → Impact. The new sequence removes Defense Evasion (not present in CS0055's primary attack flow) and adds Privilege Escalation to capture the critical transition where the agent moves from passive display to actively instructing the user to perform actions, which is central to the social engineering mechanism.

---

## AP-T12-01: Collaborative decision manipulation via inter-agent message injection

**Source case study**: AML.CS0024 — Morris II Worm: RAG-Based Attack (strong match)  
**Existing kill chain**: NO

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0000 | AI Model Access | Access the shared communication channel or RAG system used by multiple agents | explicit |
| 2 | AML.TA0003 | Resource Development | Craft messages containing prompt injections designed to shift collective decision-making when consumed by peer agents | adapted |
| 3 | AML.TA0005 | Execution | Inject the crafted messages into the inter-agent communication channel (shared RAG, message bus, knowledge store) | explicit |
| 4 | AML.TA0006 | Persistence | The injected messages persist in the shared data structure, affecting future agent queries and reasoning | explicit |
| 5 | AML.TA0005 | Execution | When other agents consume the poisoned messages, the injections activate and influence their reasoning processes | explicit |
| 6 | AML.TA0011 | Impact | The collective decision-making of the multi-agent system gradually shifts toward attacker-chosen objectives | explicit |

**Adaptation rationale**: CS0024 demonstrates injection into a shared RAG database used by an email assistant, with prompts that propagate when retrieved by the agent. While CS0024 targets a single-agent RAG system, the mechanism — poisoning a shared data structure that multiple consumers query — maps directly to multi-agent message injection. The "worm" aspect (self-propagating prompts re-emitted by the agent) demonstrates how poisoned content spreads through agent-to-agent data flow, which is the core of AP-T12-01's collaborative decision manipulation.

---

## AP-T12-03: Misinformation cascade via shared knowledge poisoning

**Source case study**: AML.CS0024 — Morris II Worm: RAG-Based Attack (strong match)  
**Existing kill chain**: NO

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0000 | AI Model Access | Access the shared knowledge store or retrieval system consumed by multiple agents | explicit |
| 2 | AML.TA0003 | Resource Development | Craft false data designed to be consumed, reasoned over, and re-emitted by agents | adapted |
| 3 | AML.TA0005 | Execution | Plant the poisoned data into the shared knowledge store (RAG database, vector store, shared memory) | explicit |
| 4 | AML.TA0006 | Persistence | The false data persists in the retrieval system, activated when agents query on relevant topics | explicit |
| 5 | AML.TA0005 | Execution | Each agent retrieval triggers the injection, causing the agent to incorporate false information into its reasoning | explicit |
| 6 | AML.TA0006 | Persistence | Agents re-emit the poisoned information through normal outputs, creating a self-reinforcing cascade | adapted |
| 7 | AML.TA0011 | Impact | Misinformation spreads through the agent network, degrading collective decision-making quality | explicit |

**Adaptation rationale**: CS0024's "Morris II Worm" demonstrates self-propagating prompt injection in a RAG system, where poisoned emails cause the agent to generate outputs containing the malicious prompt, enabling worm-like spread. This maps to AP-T12-03's misinformation cascade — the key difference is that AP-T12-03 generalizes to any shared knowledge poisoning (not just self-replicating prompts), and emphasizes the cascade effect across multiple agents. The tactic sequence reflects both the initial poisoning and the propagation/reinforcement cycle.

---

## AP-T13-04: Infectious reasoning-chain backdoor propagation

**Source case study**: AML.CS0024 — Morris II Worm: RAG-Based Attack (strong match)  
**Existing kill chain**: NO

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Craft self-propagating prompt injection designed so that any agent processing it will include the payload in its own outputs | adapted |
| 2 | AML.TA0005 | Execution | Inject the self-propagating payload into a single agent's input or a shared data structure | adapted |
| 3 | AML.TA0006 | Persistence | The infected agent's outputs contain the backdoor payload, which becomes input for peer agents through normal inter-agent communication | explicit |
| 4 | AML.TA0015 | Lateral Movement | Peer agents process the infected output, incorporate the backdoor logic, and propagate it further through their own outputs | adapted |
| 5 | AML.TA0011 | Impact | The backdoor spreads across the multi-agent system through normal communication, persisting even if the original infection point is removed | explicit |

**Adaptation rationale**: CS0024 demonstrates self-propagating prompt injection where the worm payload causes the agent to include the malicious prompt in its generated outputs, enabling spread to other agents. Structurally differentiated from AP-T12-03 (misinformation cascade): T12-03 involves false *data* that agents passively re-emit; T13-04 involves executable *backdoor logic* that actively replicates through reasoning chains. This distinction is reflected in the use of Lateral Movement (TA0015) for the agent-to-agent infection chain — the payload moves laterally through the network rather than persisting in a shared store. Sequence is shorter than T12-03 because the self-propagating payload collapses the craft/inject/persist/propagate cycle into fewer steps — the payload IS the propagation mechanism.

---

## AP-T16-02: Context hijacking via crafted protocol response injection

**Source case study**: AML.CS0020 — Indirect Prompt Injection: Bing Chat Data Pirate (strong match), also CS0024/CS0045/CS0053/CS0054  
**Existing kill chain**: NO

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Craft malicious context or tool metadata designed to be injected into an inter-agent protocol response payload. | explicit |
| 2 | AML.TA0007 | Defense Evasion | Obfuscate the malicious prompt within the response content to evade human detection. | explicit |
| 3 | AML.TA0003 | Resource Development | Stage the malicious content on external infrastructure (website, MCP server, tool registry). | adapted |
| 4 | AML.TA0004 | Initial Access | The receiving agent retrieves the poisoned protocol response (web scrape, tool metadata, RAG query). | explicit |
| 5 | AML.TA0005 | Execution | The agent interprets the injected content as trusted protocol context and executes unintended operations. | explicit |
| 6 | AML.TA0011 | Impact | The agent performs attacker-specified actions due to context hijacking, such as data exfiltration or unauthorized tool invocations. | explicit |

**Adaptation rationale**: CS0020 demonstrates indirect prompt injection via web content consumed by Bing Chat, causing it to exfiltrate user PII through manipulated URLs. CS0024 (RAG), CS0045 (MCP web scrape), CS0053 (poisoned MCP package), and CS0054 (remote MCP tool) all show variations of poisoning protocol responses or data channels consumed by agents. The common mechanism — crafting server-side or external responses containing malicious context that the agent treats as trusted protocol data — maps to AP-T16-02's context hijacking via protocol response injection. The sequence is adapted from single-source injection (CS0020) to general inter-agent protocol response poisoning.

---

## AP-T16-03: Tool capability misrepresentation via registry description poisoning

**Source case study**: AML.CS0049 — Supply Chain Compromise via Poisoned ClawdBot Skill (strong match), also CS0045/CS0053/CS0054  
**Existing kill chain**: NO

**Proposed tactic sequence:**

| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Stage external infrastructure to host the poisoned tool or skill. | explicit |
| 2 | AML.TA0003 | Resource Development | Craft misleading, overly broad, or adversarially crafted tool descriptions containing hidden prompt injections. | explicit |
| 3 | AML.TA0003 | Resource Development | Develop a poisoned tool/skill/extension containing malicious logic in metadata files (e.g., docstrings, rules files). | explicit |
| 4 | AML.TA0007 | Defense Evasion | Inflate download counts or adoption metrics to increase perceived trustworthiness in the registry. | explicit |
| 5 | AML.TA0004 | Initial Access | Users download the poisoned extension from the registry through normal dependency management. | explicit |
| 6 | AML.TA0005 | Execution | When the agent activates the poisoned extension, it reads all skill files, executing the hidden prompt injection. | explicit |
| 7 | AML.TA0012 | Privilege Escalation | The injected instructions cause the agent to invoke privileged tools (e.g., command execution) based on the misleading tool description. | explicit |
| 8 | AML.TA0011 | Impact | The agent operates under false assumptions about the tool's scope, inadvertently leaking sensitive data or triggering privileged operations. | explicit |

**Adaptation rationale**: CS0049 demonstrates poisoning a ClawdBot skill registry — the attacker publishes a skill with a hidden prompt injection in `rules/logic.md`, which Claude Code reads when activating the skill, causing it to execute attacker commands. CS0045 (MCP web scrape), CS0053 (poisoned npm package), and CS0054 (remote MCP with poisoned docstring) show similar tool/protocol metadata poisoning. The mechanism — embedding malicious instructions in tool descriptions or metadata that agents consume when selecting/invoking tools — maps directly to AP-T16-03's tool capability misrepresentation. The tactic sequence captures the full supply chain poisoning flow from staging through execution.

---

## Summary

All 8 patterns now have evidence-based tactic sequences derived from ATLAS case studies:

- **AP-T10-01, AP-T15-01**: CS0026 (M365 Copilot) — context/data manipulation via RAG poisoning
- **AP-T15-02**: CS0055 (AI ClickFix) — AI-mediated social engineering via deceptive instructions
- **AP-T12-01, AP-T12-03, AP-T13-04**: CS0024 (Morris II Worm) — shared knowledge poisoning and propagation
- **AP-T16-02**: CS0020 (Bing Chat) + CS0024/CS0045/CS0053/CS0054 — protocol response injection
- **AP-T16-03**: CS0049 (ClawdBot Skill) + CS0045/CS0053/CS0054 — tool registry poisoning

Multi-agent patterns (T12, T13, T16) are adapted from single-agent case studies by generalizing the shared-data or protocol-based propagation mechanisms to multi-agent contexts.
