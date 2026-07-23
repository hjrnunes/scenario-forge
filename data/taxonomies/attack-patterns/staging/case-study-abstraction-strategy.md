# ATLAS Case Study Abstraction Strategy

Comprehensive analysis for extracting abstract attack patterns from MITRE ATLAS
agentic case studies (CS0040-CS0062), with kill chain integration.

---

## 1. Abstraction Methodology

### 1.1 Principles

Transforming a concrete ATLAS case study into a scenario-forge abstract attack
pattern requires moving from Level 4 (incident) to Level 3.5 (mechanism). The
process follows four operations:

**Strip** (remove domain-specific anchors):
- Named actors (APT28, Embrace the Red, Pillar Security)
- Named targets (ChatGPT, Cursor, Claude Computer Use, Amazon Q)
- Specific delivery mechanisms (Google Docs, npm, ClawdHub)
- CVE numbers, dates, reporter attributions
- Technology-specific details (base64 encoding, rot13, zero-width Unicode)

**Keep** (preserve the attack mechanism):
- The tactical progression (which ATLAS tactics, in which order)
- The technique chain (which ATLAS techniques are employed, and their relationships)
- The fundamental exploit primitive (what trust boundary is violated, what capability is abused)
- The causal logic (why step N enables step N+1)

**Abstract** (generalize the descriptions):
- Replace specific systems with generic roles (e.g., "AI coding assistant" -> "AI agent with tool execution capability")
- Replace specific delivery channels with abstract categories (e.g., "Google Doc" -> "content from a connected application")
- Replace specific credentials with generic types (e.g., ".openapi.apiKey" -> "agent service credentials")
- Write abstract_action descriptions that are domain-agnostic but mechanistically precise

**Add** (supply scenario-forge-specific fields):
- `id`: Following AP-T{N}-{NN} convention
- `threat_id`: Map to T1-T17 (primary) and optionally ASI01-10
- `prerequisite_capabilities`: Infer `min_zones` and `kc_requires` from the kill chain
- `nist_classification`: Assign attacker_goal, attacker_knowledge, learning_stage
- `kill_chain`: Structured scaffold from the case study's relationship graph
- `evidence`: Link back to the source case study

### 1.2 Kill Chain Abstraction Rules

Each step in an ATLAS case study relationship becomes a kill chain step in the
pattern, following these rules:

1. **Preserve the tactic ID** (AML.TA0000-TA0015) exactly.
2. **Preserve the technique ID(s)** (AML.T0xxx) exactly.
3. **Replace the description** with a domain-agnostic abstract_action.
4. **Collapse purely concrete steps** that are domain-specific delivery details
   into a single abstract step (e.g., CS0040's S00 "crafted a basic prompt" and
   S01 "placed it in a Google Doc header" become one "setup" step).
5. **Name each step** with a phase label (setup, delivery, execution, persistence,
   impact, etc.) for human readability.
6. **Keep the tactic ordering** faithful to the case study -- do not re-order
   steps even if the tactic sequence seems unusual.

### 1.3 Full Transformation Examples

#### Example 1: CS0040 (Memory Poisoning via Connected App)

**Source: ATLAS CS0040 raw relationship data** (7 steps, 5 tactics):

```
S00: AML.T0065 (Resource Development) -> S01
S01: AML.T0068 (Defense Evasion) -> S02
S02: AML.T0093 (Initial Access) -> S03
S03: AML.T0051.001 (Execution) -> S04
S04: AML.T0080.000 (Persistence) -> S05
S05: AML.T0093 (Persistence) -> S06
S06: AML.T0048.003 (Impact) -> end
```

**Transformed: Abstract Attack Pattern**

```yaml
AP-T1-05:
  id: "AP-T1-05"
  threat_id: "T1"
  name: "Memory poisoning via connected application injection"
  description: >
    An attacker embeds a hidden prompt injection in content shared through
    an application connected to the AI agent. When the agent ingests the
    content, the injection executes and writes attacker-controlled false
    facts into the agent's persistent memory store. The poisoned memory
    persists across sessions, and the shared content remains a persistent
    infection vector that can compromise additional users who access it.

  prerequisite_capabilities:
    min_zones: ["input", "memory"]
    kc_requires:
      all: [KCX-PMEM]
      any: [KC4.3, KC4.4, KC4.5, KC4.6]

  nist_classification:
    attacker_goal: "integrity"
    attacker_knowledge: "black_box"
    learning_stage: "deployment"
    attack_class: "poisoning.targeted_poisoning"

  kill_chain:
    - step: setup
      tactic: AML.TA0003          # Resource Development
      techniques: [AML.T0065, AML.T0068]
      abstract_action: >
        Craft an adversarial prompt injection and conceal it within
        shareable content that the agent's connected application will
        ingest (e.g., hidden in document metadata, styling, or
        non-visible elements).
    - step: delivery
      tactic: AML.TA0004          # Initial Access
      techniques: [AML.T0093]
      abstract_action: >
        Deliver the poisoned content through a connected application
        channel that the agent treats as a trusted data source.
    - step: execution
      tactic: AML.TA0005          # Execution
      techniques: [AML.T0051.001]
      abstract_action: >
        When a user references the shared content, the agent ingests
        it into its context and the hidden prompt injection executes.
    - step: persistence
      tactic: AML.TA0006          # Persistence
      techniques: [AML.T0080.000]
      abstract_action: >
        The injection writes attacker-controlled false facts into the
        agent's persistent memory store, establishing cross-session
        persistence.
    - step: propagation
      tactic: AML.TA0006          # Persistence
      techniques: [AML.T0093]
      abstract_action: >
        The poisoned content remains in the shared channel, acting as
        a persistent infection vector that compromises additional
        users who access it.
    - step: impact
      tactic: AML.TA0011          # Impact
      techniques: [AML.T0048.003]
      abstract_action: >
        The agent operates with corrupted memory, producing outputs
        influenced by attacker-controlled false facts, potentially
        causing user harm through misinformation or manipulated decisions.

  evidence:
    - source: "AML.CS0040"
      type: "direct_demonstration"
      note: "ChatGPT memory poisoning via Google Docs (Embrace the Red, 2024-02)"
```

#### Example 2: CS0045 (MCP-Mediated Data Exfiltration)

**Source: ATLAS CS0045 raw relationship data** (11 steps, 7 tactics):

```
S00: AML.T0065 (Resource Development) -> S01
S01: AML.T0079 (Resource Development) -> S02
S02: AML.T0068 (Defense Evasion) -> S03
S03: AML.T0079 (Resource Development) -> S04
S04: AML.T0078 (Initial Access) -> S05
S05: AML.T0051.001 (Execution) -> S06
S06: AML.T0053 (Privilege Escalation) -> S07
S07: AML.T0068 (Defense Evasion) -> S08
S08: AML.T0083 (Credential Access) -> S09
S09: AML.T0086 (Exfiltration) -> S10
S10: AML.T0048.000 (Impact) -> end
```

**Transformed: Abstract Attack Pattern**

```yaml
AP-T2-07:
  id: "AP-T2-07"
  threat_id: "T2"
  name: "Credential exfiltration via tool-mediated prompt injection"
  description: >
    An attacker plants a hidden prompt injection on an external resource.
    When the agent fetches this resource through a tool (MCP server, web
    scraper, or similar data retrieval tool), the injection enters the
    agent's context and instructs it to locate sensitive credential files,
    then exfiltrate them to an attacker-controlled endpoint by invoking
    the agent's own command execution tools.

  prerequisite_capabilities:
    min_zones: ["input", "reasoning", "tool_execution"]
    kc_requires:
      any: [KC6.1.1, KC6.1.2, KC6.2.1, KC6.2.2, KC6.3.1, KC6.3.2, KC6.4, KC6.5, KC6.6, KC6.7]

  nist_classification:
    attacker_goal: "abuse"
    attacker_knowledge: "black_box"
    learning_stage: "deployment"
    attack_class: "genai.indirect_prompt_injection.abuse_violations"

  kill_chain:
    - step: setup
      tactic: AML.TA0003          # Resource Development
      techniques: [AML.T0065, AML.T0079, AML.T0068]
      abstract_action: >
        Craft a prompt injection payload, stage it on an external
        resource the agent may fetch, and obfuscate the payload to
        evade human review if the agent presents a confirmation prompt.
    - step: delivery
      tactic: AML.TA0004          # Initial Access
      techniques: [AML.T0078]
      abstract_action: >
        The agent fetches the poisoned external resource through a
        data retrieval tool, ingesting the hidden injection into its
        context.
    - step: execution
      tactic: AML.TA0005          # Execution
      techniques: [AML.T0051.001]
      abstract_action: >
        The ingested prompt injection activates, instructing the agent
        to perform unauthorized actions on the local system.
    - step: privilege_escalation
      tactic: AML.TA0012          # Privilege Escalation
      techniques: [AML.T0053]
      abstract_action: >
        The injected instructions invoke the agent's command execution
        tools, escalating from data retrieval context to local system
        access.
    - step: credential_access
      tactic: AML.TA0013          # Credential Access
      techniques: [AML.T0083]
      abstract_action: >
        The agent locates and reads sensitive credential files from
        the local filesystem (API keys, service tokens, configuration
        files containing secrets).
    - step: exfiltration
      tactic: AML.TA0010          # Exfiltration
      techniques: [AML.T0086]
      abstract_action: >
        The agent exfiltrates the harvested credentials to an
        attacker-controlled endpoint by invoking its own network
        or command execution tools.
    - step: impact
      tactic: AML.TA0011          # Impact
      techniques: [AML.T0048.000]
      abstract_action: >
        The stolen credentials enable further attacks: unauthorized
        API access, financial damage, or lateral movement into
        connected services.

  evidence:
    - source: "AML.CS0045"
      type: "direct_demonstration"
      note: "MCP-mediated credential exfiltration from Cursor (Backslash Security, 2025-06)"
```

#### Example 3: CS0055 (Computer-Use Agent Social Engineering)

**Source: ATLAS CS0055 raw relationship data** (8 steps, 5 tactics):

```
S00: AML.T0016.002 (Resource Development) -> S01
S01: AML.T0017 (Resource Development) -> S02
S02: AML.T0079 (Resource Development) -> S03
S03: AML.T0078 (Initial Access) -> S04
S04: AML.T0100 (Execution) -> S05
S05: AML.T0051.001 (Execution) -> S06
S06: AML.T0053 (Privilege Escalation) -> S07
S07: AML.T0112.000 (Impact) -> end
```

**Transformed: Abstract Attack Pattern**

```yaml
AP-T11-05:
  id: "AP-T11-05"
  threat_id: "T11"
  name: "Computer-use agent exploitation via adversarial web content"
  description: >
    An attacker crafts web content containing elements designed to
    attract and manipulate a computer-use AI agent. The content
    includes agent-targeted clickbait that triggers interaction,
    client-side scripts that load malicious commands into the
    clipboard, and embedded instructions that direct the agent to
    open a terminal and execute the clipboard contents. The agent's
    ability to control keyboard, mouse, and clipboard bridges the
    gap from web content to arbitrary code execution on the host.

  prerequisite_capabilities:
    min_zones: ["input", "reasoning", "tool_execution"]
    kc_requires:
      any: [KC6.1.1, KC6.1.2, KC6.2.1, KC6.2.2, KC6.4, KC6.5]

  nist_classification:
    attacker_goal: "abuse"
    attacker_knowledge: "black_box"
    learning_stage: "deployment"
    attack_class: "genai.indirect_prompt_injection.abuse_violations"

  kill_chain:
    - step: setup
      tactic: AML.TA0003          # Resource Development
      techniques: [AML.T0017, AML.T0079]
      abstract_action: >
        Create adversarial web content designed to manipulate
        computer-use agents, including agent-targeted interactive
        elements and scripts that load commands into the clipboard.
        Stage the content on a web-accessible location.
    - step: delivery
      tactic: AML.TA0004          # Initial Access
      techniques: [AML.T0078]
      abstract_action: >
        The computer-use agent navigates to or is directed to the
        adversarial web content, ingesting it into its visual and
        textual context.
    - step: engagement
      tactic: AML.TA0005          # Execution
      techniques: [AML.T0100]
      abstract_action: >
        Agent-targeted clickbait content (e.g., identity-probing
        text, verification prompts) causes the agent to interact
        with the page, triggering client-side scripts.
    - step: injection
      tactic: AML.TA0005          # Execution
      techniques: [AML.T0051.001]
      abstract_action: >
        Embedded instructions direct the agent to perform a
        sequence of GUI actions: open a terminal, paste clipboard
        contents, and execute.
    - step: execution
      tactic: AML.TA0012          # Privilege Escalation
      techniques: [AML.T0053]
      abstract_action: >
        The agent uses its computer-use capabilities to execute
        the attacker's command on the host system, bridging from
        web context to OS-level code execution.
    - step: impact
      tactic: AML.TA0011          # Impact
      techniques: [AML.T0112.000]
      abstract_action: >
        Arbitrary code executes on the host with the agent's
        privileges, achieving full machine compromise.

  evidence:
    - source: "AML.CS0055"
      type: "direct_demonstration"
      note: "AI ClickFix against Claude Computer Use (Embrace the Red, 2025-05)"
```

---

## 2. Coverage Analysis

### 2.1 Case Study to Existing Pattern Mapping

| Case Study | Core Mechanism | Existing Pattern(s) | Coverage Status |
|---|---|---|---|
| CS0040 | Memory poisoning via connected app injection | AP-T1-01 (partial) | **ENRICHMENT** -- AP-T1-01 covers memory rule injection but not the connected-app delivery or self-propagation aspects. CS0040's kill chain adds value. |
| CS0041 | Rules file backdoor supply chain attack | AP-T17-01, AP-T17-02 (partial) | **ENRICHMENT** -- Supply chain patterns exist but lack the AI-assistant-specific configuration poisoning mechanism and the invisible Unicode obfuscation vector. |
| CS0042 | AI service API as C2 channel | None | **NEW** -- No existing pattern covers the use of AI service APIs as covert C2 infrastructure. This is not an attack ON an AI agent; it is an attack USING an AI service. |
| CS0043 | Prompt injection in malware to evade AI detectors | None | **NEW** -- No existing pattern covers adversarial prompt injection targeting AI-based security tools. This inverts the typical attack direction. |
| CS0044 | LLM-generated polymorphic commands in malware | None | **NEW** -- No existing pattern covers AI-augmented malware that uses LLM APIs at runtime for command generation. |
| CS0045 | MCP tool-mediated credential exfiltration | AP-T2-02, AP-T2-06 (partial) | **NEW VARIANT** -- Existing tool misuse patterns describe the mechanism abstractly but not the MCP-specific data retrieval tool as injection vector, nor the credential-targeting kill chain. |
| CS0046 | Computer-use agent data destruction via PDF injection | AP-T2-06 (partial) | **NEW VARIANT** -- Tool hijacking via prompt injection is covered, but the computer-use context (GUI control, bash tool) and the document-as-weapon vector are distinct. |
| CS0047 | Supply chain deploy of destructive AI agent | AP-T17-01 (partial) | **NEW** -- The deployment of an AI agent as a destructive payload (with `--trust-all-tools --no-interactive`) via CI/CD compromise is a distinct mechanism from generic supply chain. |
| CS0048 | Exposed AI agent control interface exploitation | None | **NEW** -- No existing pattern covers exposed AI agent management interfaces as an attack surface. This is an infrastructure security pattern unique to deployed AI agents. |
| CS0049 | Poisoned skill/plugin supply chain attack | AP-T17-01, AP-T17-02 (partial) | **ENRICHMENT** -- Supply chain patterns exist but lack the skill registry specifics (download inflation, typosquatting, hidden rules files). Kill chain adds the registry-specific progression. |
| CS0050 | 1-click RCE via AI agent configuration API | None | **NEW** -- Attack targets the agent's configuration API to disable safety controls, not the LLM itself. No prompt injection involved. |
| CS0051 | AI agent as persistent C2 implant via prompt injection | None | **NEW** -- Transforming an AI agent into a persistent C2 node via control sequence spoofing and system prompt file modification is a novel mechanism. |
| CS0052 | Prompt-to-RCE via framework code execution sinks | AP-T11-01, AP-T11-02 (partial) | **ENRICHMENT** -- RCE patterns exist but lack the framework-specific code sink mechanism (eval() on tool parameters) and sandbox escape chain. Kill chain adds the tool-invocation-to-code-execution pathway. |
| CS0053 | MCP supply chain poisoning via namesquatting + rug pull | AP-T17-01 (partial) | **NEW** -- The namesquatting + rug pull + passive exfiltration pattern (BCC injection) is a distinct supply chain attack specific to the MCP ecosystem. First real-world malicious MCP incident. |
| CS0054 | Tool docstring prompt injection for credential theft | AP-T16-03, AP-T2-06 (partial) | **NEW VARIANT** -- Tool description poisoning is related to AP-T16-03 but the kill chain (docstring injection -> agent reads local secrets -> parameter smuggling for exfiltration) is distinct enough to warrant its own pattern. |
| CS0055 | Computer-use agent ClickFix social engineering | None | **NEW** -- Social engineering adapted for AI computer-use agents (agent clickbait, clipboard manipulation, GUI-instructed code execution) is a novel mechanism with no existing pattern. |
| CS0056 | Large-scale model distillation/IP theft | None | **OUT OF SCOPE** -- Model distillation is an attack on the AI service provider, not on an agentic system. Does not fit scenario-forge's threat model (agentic AI threats). |
| CS0057 | Jailbreak-as-a-service operation | None | **OUT OF SCOPE** -- Industrialized jailbreak services are an ecosystem threat, not an attack pattern against a specific agentic system. |
| CS0058 | On-device model extraction from mobile app | None | **OUT OF SCOPE** -- Mobile APK model extraction is a traditional ML security concern, not agentic-specific. |
| CS0059 | Zero-click RAG poisoning with Markdown exfiltration | AP-T2-05, AP-T5-02 (partial) | **NEW** -- Zero-click triggered prompt injection via RAG, combined with Markdown image rendering as exfiltration channel, is a distinct and novel mechanism. |
| CS0060 | LLM-generated stored XSS for session hijacking | None | **NEW** -- Using an LLM to generate XSS payloads that persist in chat history and execute in a different security context (support agent browser) is novel. |
| CS0061 | AI service web interface as C2 relay | None | **NEW** -- Related to CS0042 but distinct: uses the AI service's web-fetch capability bidirectionally (not API-level), requires no authentication, and the AI is infrastructure, not target. |
| CS0062 | Prompt injection to eval() code sink | AP-T11-01 (partial) | **ENRICHMENT** -- Existing RCE patterns are more abstract; CS0062's specific eval() code sink via tool parameter is a well-defined, CVE-assigned variant. |

### 2.2 Coverage Summary

| Status | Count | Case Studies |
|---|---|---|
| **NEW** (genuinely new mechanism) | 10 | CS0042, CS0043, CS0044, CS0048, CS0050, CS0051, CS0053, CS0055, CS0059, CS0060 |
| **NEW VARIANT** (distinct variant of existing) | 3 | CS0045, CS0046, CS0054 |
| **ENRICHMENT** (kill chain enriches existing) | 5 | CS0040, CS0041, CS0049, CS0052, CS0062 |
| **OUT OF SCOPE** (not agentic system threat) | 3 | CS0056, CS0057, CS0058 |
| **AI-as-infrastructure** (new category) | 2 | CS0042, CS0061 |

### 2.3 Extraction Candidate Clusters

**Cluster A: MCP/Tool Ecosystem Attacks** (4 patterns)
- CS0045: Tool-mediated prompt injection for credential exfiltration
- CS0053: MCP supply chain poisoning via namesquatting + rug pull
- CS0054: Tool docstring prompt injection for credential theft
- (CS0049 enriches existing AP-T17-01/02 rather than creating new)

**Cluster B: Computer-Use Agent Exploitation** (2 patterns)
- CS0046: Document-based injection targeting computer-use agent for data destruction
- CS0055: Adversarial web content targeting computer-use agent for code execution

**Cluster C: AI Agent as C2 Infrastructure** (2 patterns)
- CS0042: AI service API as covert C2 channel (for traditional malware)
- CS0051: AI agent transformed into persistent C2 implant (via prompt injection)
- CS0061: AI service web interface as bidirectional C2 relay

**Cluster D: AI-Augmented Malware** (2 patterns)
- CS0043: Prompt injection embedded in malware targeting AI security tools
- CS0044: LLM-generated polymorphic commands in deployed malware

**Cluster E: Agent Infrastructure Attacks** (2 patterns)
- CS0048: Exposed AI agent control interface exploitation
- CS0050: Agent configuration API manipulation for safety control disablement

**Cluster F: AI Output Weaponization** (2 patterns)
- CS0059: Zero-click RAG poisoning with rendered-output exfiltration
- CS0060: LLM-generated stored XSS via chat handoff

---

## 3. Threat ID Assignment

### 3.1 Assignment Table

| Case Study | Primary threat_id | Secondary | ASI mapping | Rationale |
|---|---|---|---|---|
| CS0042 | T11 | -- | ASI05 | AI service API used for code execution/C2; closest to "Unexpected Code Attacks" as the AI service enables command execution. However, this is a stretch -- see note below. |
| CS0043 | T6 | T11 | ASI01 | Prompt injection targeting an AI system's goal (detect malware -> report benign). Goal hijacking of the AI detector. |
| CS0044 | T11 | -- | ASI05 | LLM generates executable commands at runtime; the code execution is the core mechanism. |
| CS0045 | T2 | T3 | ASI02 | Tool misuse (MCP tool as injection vector) leading to credential theft (privilege). Primary mechanism is tool misuse for data exfiltration. |
| CS0046 | T2 | T11 | ASI02, ASI05 | Tool hijacking (bash tool) via prompt injection for data destruction. Tool misuse is primary; the destructive impact is via code execution. |
| CS0048 | T3 | T9 | ASI03 | Exposed control interface -> credential access -> privilege escalation. Identity/privilege abuse is the core. |
| CS0050 | T3 | -- | ASI03 | Configuration API manipulation to disable safety controls; privilege escalation without prompt injection. |
| CS0051 | T6 | T1 | ASI01, ASI06 | Goal hijacking (via control sequence spoofing) + memory poisoning (HEARTBEAT.md system prompt persistence). Primary is goal hijacking. |
| CS0053 | T17 | T2 | ASI04, ASI02 | Supply chain compromise is the primary mechanism; the tool misuse (BCC injection) is the payload. |
| CS0054 | T16 | T2 | ASI07, ASI02 | Tool description poisoning exploits insecure inter-agent protocol (MCP tool metadata); the credential theft is via tool misuse. |
| CS0055 | T11 | T2 | ASI05, ASI02 | Computer-use capabilities enable code execution on host; tool invocation (GUI control) is the mechanism. |
| CS0059 | T1 | T2 | ASI06, ASI02 | RAG poisoning (memory/context poisoning) with exfiltration via tool output rendering. Primary is context poisoning. |
| CS0060 | T15 | T11 | ASI09, ASI05 | LLM generates content that manipulates a human (support agent) + enables code execution (XSS). Human manipulation is primary. |
| CS0061 | T11 | -- | ASI05 | AI service enables command execution via its web-fetch capability; same stretch as CS0042 but the AI is infrastructure not target. |

### 3.2 Classification Challenges

**CS0042 and CS0061 (AI-as-Infrastructure)**: These case studies do not cleanly
map to any T-threat because the AI system is not the target -- it is unwitting
infrastructure. The T1-T17 taxonomy assumes the AI agent IS the thing being
attacked. Options:
- Map to T11 (Unexpected Code Execution) because the AI service enables
  command execution as a side effect. This is a weak but defensible mapping.
- Flag as candidates for a future T18 ("AI Infrastructure Abuse") threat category.
- **Recommendation**: Map to T11 with a `mapping_note: "AI service is
  infrastructure, not target"` annotation. Accept the imperfect fit.

**CS0043 and CS0044 (AI-Augmented Traditional Malware)**: These describe
traditional malware enhanced with AI capabilities. The AI is a component of the
malware, not the target. Similar classification challenge.
- CS0043 maps better: it IS an attack on an AI system (the malware detector).
- CS0044 maps poorly: the LLM is a tool used by the malware. The target is a
  traditional endpoint.
- **Recommendation**: Include CS0043 (maps to T6 -- attacking an AI detector's
  goal). Exclude CS0044 unless we want to represent AI-augmented malware as an
  attack that could target an AI-based security monitoring agent. Include with
  a caveat note.

---

## 4. Prerequisite Inference

### 4.1 Zone and KC Requirements

| Pattern (from CS) | min_zones | kc_requires.all | kc_requires.any | Rationale |
|---|---|---|---|---|
| CS0042 -> AP-T11-04 | [input, tool_execution] | -- | [KC6.1.1, KC6.1.2, KC6.2.1, KC6.2.2] | Needs API access capability for C2 channel |
| CS0043 -> AP-T6-06 | [input, reasoning] | -- | [KC1.1, KC1.2, KC1.3, KC1.4] | Only needs the AI system to process input and reason (malware detector) |
| CS0045 -> AP-T2-07 | [input, reasoning, tool_execution] | -- | [KC6.1.1, KC6.1.2, KC6.2.1, KC6.2.2, KC6.3.1, KC6.3.2, KC6.4, KC6.5, KC6.6, KC6.7] | Needs tool execution (both data retrieval tool and command execution tool) |
| CS0046 -> AP-T2-08 | [input, reasoning, tool_execution] | -- | [KC6.1.1, KC6.1.2, KC6.2.1, KC6.2.2, KC6.4, KC6.5] | Needs tool execution (bash/shell tool for destruction) |
| CS0048 -> AP-T3-04 | [input, tool_execution] | -- | [KC6.1.1, KC6.1.2, KC6.2.1, KC6.2.2, KC6.4, KC6.5] | Needs exposed management interface + tool execution |
| CS0050 -> AP-T3-05 | [input, tool_execution] | -- | [KC6.1.1, KC6.1.2, KC6.2.1, KC6.2.2, KC6.4, KC6.5] | Needs configurable agent with tool execution |
| CS0051 -> AP-T6-06 | [input, reasoning, tool_execution, memory] | [KCX-PMEM] | [KC6.1.1, KC6.1.2, KC6.4, KC6.5] | Needs persistent memory (system prompt file) + tool execution (bash) |
| CS0053 -> AP-T17-03 | [input, tool_execution] | -- | [KC6.1.1, KC6.1.2, KC6.2.1, KC6.2.2, KC6.3.1, KC6.3.2] | Needs tool execution (MCP tool invocation) |
| CS0054 -> AP-T16-04 | [input, reasoning, tool_execution] | -- | [KC6.1.1, KC6.1.2, KC6.2.1, KC6.2.2, KC6.3.1, KC6.3.2, KC6.4, KC6.5] | Needs tool execution (file read + tool invocation for exfiltration) |
| CS0055 -> AP-T11-05 | [input, reasoning, tool_execution] | -- | [KC6.1.1, KC6.1.2, KC6.2.1, KC6.2.2, KC6.4, KC6.5] | Needs computer-use (GUI tool execution) |
| CS0059 -> AP-T1-05 | [input, reasoning, memory] | [KCX-VSTORE] | [KC4.3, KC4.4, KC4.5, KC4.6] | Needs RAG/vector store (email auto-ingestion) |
| CS0060 -> AP-T15-03 | [input, reasoning, tool_execution] | -- | [KC6.1.1, KC6.1.2, KC6.2.1, KC6.2.2] | Needs output generation capability + tool-like chat interface |
| CS0061 -> AP-T11-06 | [input, tool_execution] | -- | [KC6.1.1, KC6.1.2, KC6.2.1, KC6.2.2] | Needs web-fetch/URL retrieval capability |

### 4.2 Consistency Check Against Existing Patterns

The prerequisite schemes above are consistent with existing patterns:
- **T1 patterns** (AP-T1-01 through AP-T1-04) all require `min_zones: [input, memory]` and memory-related KC codes. New CS0059 pattern follows this with KCX-VSTORE.
- **T2 patterns** (AP-T2-01 through AP-T2-06) require `tool_execution` zone and KC6.x codes. New CS0045, CS0046 patterns follow this convention.
- **T3 patterns** (AP-T3-01 through AP-T3-03) require `tool_execution` zone. New CS0048, CS0050 patterns follow this.
- **T11 patterns** would require `tool_execution` for code execution paths. New CS0055 pattern follows this.
- **T17 patterns** require `tool_execution` for supply chain tool invocation. New CS0053 pattern follows this.

---

## 5. Kill Chain Template Design

### 5.1 Templates for Each Extraction Candidate

#### AP-T2-07: Credential exfiltration via tool-mediated injection (CS0045)

Full YAML shown in Section 1.3 Example 2 above. Key tactic progression:
Resource Development -> Initial Access -> Execution -> Privilege Escalation ->
Credential Access -> Exfiltration -> Impact.

#### AP-T2-08: Computer-use agent data destruction via document injection (CS0046)

```yaml
kill_chain:
  - step: setup
    tactic: AML.TA0003          # Resource Development
    techniques: [AML.T0065]
    abstract_action: >
      Craft a prompt injection targeting a computer-use agent's
      capabilities, combining guardrail bypass techniques with
      an obfuscated destructive command.
  - step: delivery
    tactic: AML.TA0004          # Initial Access
    techniques: [AML.T0093]
    abstract_action: >
      Embed the injection in a document or file that the agent
      will process when a user requests interaction with it.
  - step: execution
    tactic: AML.TA0005          # Execution
    techniques: [AML.T0051.001]
    abstract_action: >
      When the agent processes the document, the hidden injection
      enters its context and executes.
  - step: guardrail_bypass
    tactic: AML.TA0007          # Defense Evasion
    techniques: [AML.T0054, AML.T0068]
    abstract_action: >
      The injection employs jailbreak techniques (environmental
      framing, authority spoofing) and command obfuscation
      (encoding, steganography) to bypass safety guardrails.
  - step: tool_invocation
    tactic: AML.TA0005          # Execution
    techniques: [AML.T0053]
    abstract_action: >
      The agent invokes its command execution tool (bash, shell,
      or equivalent) to run the decoded destructive command.
  - step: impact
    tactic: AML.TA0011          # Impact
    techniques: [AML.T0101]
    abstract_action: >
      The command executes with the agent's privileges, destroying
      data on the local filesystem or connected resources.
```

#### AP-T17-03: MCP tool supply chain poisoning via namesquatting (CS0053)

```yaml
kill_chain:
  - step: setup
    tactic: AML.TA0007          # Defense Evasion
    techniques: [AML.T0073]
    abstract_action: >
      Impersonate a legitimate service by registering a matching
      package name on a public tool registry before the official
      maintainer claims it.
  - step: trust_building
    tactic: AML.TA0003          # Resource Development
    techniques: [AML.T0017]
    abstract_action: >
      Publish a legitimate, functional version of the tool to
      build trust and user adoption over time.
  - step: poisoning
    tactic: AML.TA0003          # Resource Development
    techniques: [AML.T0104]
    abstract_action: >
      After sufficient adoption, publish a malicious update that
      subtly modifies tool behavior to include an exfiltration
      side-channel (e.g., hidden data forwarding).
  - step: evasion
    tactic: AML.TA0007          # Defense Evasion
    techniques: [AML.T0109]
    abstract_action: >
      The rug-pull timing evades scrutiny applied to new tools;
      updates from already-trusted packages receive minimal review.
  - step: distribution
    tactic: AML.TA0004          # Initial Access
    techniques: [AML.T0010.005]
    abstract_action: >
      Users upgrade to the poisoned version through normal
      dependency management, receiving the malicious tool via
      the compromised supply chain.
  - step: persistence
    tactic: AML.TA0006          # Persistence
    techniques: [AML.T0110]
    abstract_action: >
      The poisoned tool persists in agent configurations as a
      set-and-forget dependency, maintaining compromise until
      explicitly detected and removed.
  - step: exfiltration
    tactic: AML.TA0010          # Exfiltration
    techniques: [AML.T0086]
    abstract_action: >
      Every normal invocation of the poisoned tool exfiltrates
      data through its built-in side-channel, piggybacking on
      legitimate tool operation.
  - step: impact
    tactic: AML.TA0011          # Impact
    techniques: [AML.T0048]
    abstract_action: >
      Sensitive data is continuously leaked to the attacker
      through the tool's normal operation, potentially exposing
      user data, business communications, or credentials.
```

#### AP-T16-04: Tool docstring injection for credential theft (CS0054)

```yaml
kill_chain:
  - step: setup
    tactic: AML.TA0003          # Resource Development
    techniques: [AML.T0065, AML.T0104]
    abstract_action: >
      Craft a prompt injection and embed it in a tool's description
      or docstring. Publish or host the poisoned tool so that agents
      can discover and load it.
  - step: delivery
    tactic: AML.TA0004          # Initial Access
    techniques: [AML.T0010.005]
    abstract_action: >
      An agent loads the poisoned tool, ingesting the tool's
      description (including the hidden injection) into its context
      as part of normal tool discovery.
  - step: execution
    tactic: AML.TA0005          # Execution
    techniques: [AML.T0051.000]
    abstract_action: >
      The injection in the tool description activates when the
      agent processes the tool metadata, instructing the agent to
      perform unauthorized actions before invoking the tool.
  - step: lateral_tool_use
    tactic: AML.TA0005          # Execution
    techniques: [AML.T0053]
    abstract_action: >
      The injected instructions cause the agent to invoke other
      tools (filesystem access, configuration readers) to locate
      and read sensitive files.
  - step: credential_access
    tactic: AML.TA0013          # Credential Access
    techniques: [AML.T0055, AML.T0098]
    abstract_action: >
      The agent reads credential files (SSH keys, API tokens,
      tool configuration files containing secrets for other
      services).
  - step: exfiltration
    tactic: AML.TA0010          # Exfiltration
    techniques: [AML.T0086]
    abstract_action: >
      The agent encodes stolen credentials into a tool input
      parameter and invokes the poisoned tool, exfiltrating the
      data to the attacker's server through the normal tool call.
  - step: impact
    tactic: AML.TA0011          # Impact
    techniques: [AML.T0048.003]
    abstract_action: >
      The attacker obtains credentials enabling further compromise
      of the user's services, including potential cascading
      access through harvested tool configuration credentials.
```

#### AP-T11-05: Computer-use agent exploitation via adversarial web content (CS0055)

Full YAML shown in Section 1.3 Example 3 above.

#### AP-T6-06: AI agent as persistent C2 implant (CS0051)

```yaml
kill_chain:
  - step: reconnaissance
    tactic: AML.TA0002          # Reconnaissance
    techniques: [AML.T0095.000]
    abstract_action: >
      Study the target agent's open-source configuration to
      identify control sequences, system prompt structure, and
      configuration file locations.
  - step: discovery
    tactic: AML.TA0008          # Discovery
    techniques: [AML.T0069.000, AML.T0069.001]
    abstract_action: >
      Identify special characters and control sequences used
      by the agent's runtime to delimit user messages, tool
      results, and internal reasoning.
  - step: setup
    tactic: AML.TA0003          # Resource Development
    techniques: [AML.T0065, AML.T0079]
    abstract_action: >
      Craft a multi-stage prompt injection that spoofs the
      agent's internal control sequences to fabricate a fake
      interaction history showing user approval. Stage the
      injection and a C2 polling script on external infrastructure.
  - step: delivery
    tactic: AML.TA0004          # Initial Access
    techniques: [AML.T0078]
    abstract_action: >
      Lure or direct the agent to fetch content from the
      attacker-controlled resource, ingesting the injection.
  - step: execution
    tactic: AML.TA0005          # Execution
    techniques: [AML.T0051.001, AML.T0054]
    abstract_action: >
      The injection activates, spoofing internal control flow
      to bypass safety alignment and induce the agent to
      download and execute an external script.
  - step: persistence
    tactic: AML.TA0006          # Persistence
    techniques: [AML.T0081, AML.T0080.001]
    abstract_action: >
      The script modifies a configuration file that is appended
      to every system prompt, persistently injecting C2 polling
      instructions into all future sessions.
  - step: c2_activation
    tactic: AML.TA0014          # Command and Control
    techniques: [AML.T0108]
    abstract_action: >
      On a trigger (user greeting, scheduled interval), the
      compromised agent fetches a task list from the attacker's
      server and executes the listed commands, acting as a
      persistent C2 node.
  - step: impact
    tactic: AML.TA0011          # Impact
    techniques: [AML.T0112.000]
    abstract_action: >
      The agent's behavior is permanently hijacked; it executes
      attacker commands while continuing to appear normal to
      the user. Full machine compromise via the agent's tool
      capabilities.
```

#### AP-T3-04: Exposed agent control interface exploitation (CS0048)

```yaml
kill_chain:
  - step: reconnaissance
    tactic: AML.TA0002          # Reconnaissance
    techniques: [AML.T0000]
    abstract_action: >
      Scan for exposed AI agent control interfaces on the
      public internet using search engines, port scanners, or
      specialized databases.
  - step: initial_access
    tactic: AML.TA0004          # Initial Access
    techniques: [AML.T0049]
    abstract_action: >
      Access the exposed control interface, exploiting weak
      or absent authentication, proxy misconfigurations, or
      default credentials.
  - step: credential_harvest
    tactic: AML.TA0013          # Credential Access
    techniques: [AML.T0083]
    abstract_action: >
      Access the agent's configuration through the control
      interface, harvesting plaintext credentials for connected
      services (API keys, messaging tokens, OAuth credentials).
  - step: agent_exploitation
    tactic: AML.TA0005          # Execution
    techniques: [AML.T0051.001]
    abstract_action: >
      Use the control interface to send arbitrary prompts to
      the agent, exploiting its instruction-following behavior.
  - step: privilege_escalation
    tactic: AML.TA0012          # Privilege Escalation
    techniques: [AML.T0053]
    abstract_action: >
      Prompt the agent to invoke its tool capabilities (bash,
      system commands) to achieve elevated access on the host.
  - step: lateral_movement
    tactic: AML.TA0010          # Exfiltration
    techniques: [AML.T0025]
    abstract_action: >
      Use harvested credentials to access connected services
      (messaging platforms, cloud APIs), exfiltrating data
      across the agent's entire connected service ecosystem.
  - step: impact
    tactic: AML.TA0011          # Impact
    techniques: [AML.T0048.003]
    abstract_action: >
      The attacker gains access to the user's entire digital
      footprint through the agent's connected services,
      enabling impersonation, data theft, and chat manipulation.
```

#### AP-T3-05: Agent safety control disablement via configuration API (CS0050)

```yaml
kill_chain:
  - step: setup
    tactic: AML.TA0003          # Resource Development
    techniques: [AML.T0017, AML.T0079]
    abstract_action: >
      Develop an exploit script and stage it on a web-accessible
      location that will be visited by the target.
  - step: credential_theft
    tactic: AML.TA0013          # Credential Access
    techniques: [AML.T0106]
    abstract_action: >
      Steal the agent's authentication token by exploiting
      weaknesses in the control interface (e.g., unvalidated
      URL parameters, cross-origin vulnerabilities).
  - step: defense_bypass
    tactic: AML.TA0007          # Defense Evasion
    techniques: [AML.T0107]
    abstract_action: >
      Bypass network restrictions on the agent's local API
      using cross-origin techniques (WebSocket hijacking, CORS
      bypass) to reach localhost-bound services.
  - step: authentication
    tactic: AML.TA0012          # Privilege Escalation
    techniques: [AML.T0012]
    abstract_action: >
      Authenticate to the agent's configuration API using the
      stolen token.
  - step: safety_disablement
    tactic: AML.TA0007          # Defense Evasion
    techniques: [AML.T0081]
    abstract_action: >
      Modify the agent's configuration to disable safety
      controls: turn off user confirmation prompts, disable
      sandboxing, escalate tool permissions.
  - step: execution
    tactic: AML.TA0005          # Execution
    techniques: [AML.T0050]
    abstract_action: >
      Execute arbitrary commands through the agent's now-
      unrestricted execution interface, achieving full host
      access.
```

#### AP-T1-06: Zero-click RAG poisoning with rendered-output exfiltration (CS0059)

```yaml
kill_chain:
  - step: setup
    tactic: AML.TA0003          # Resource Development
    techniques: [AML.T0065, AML.T0066, AML.T0079]
    abstract_action: >
      Craft a prompt injection disguised as benign business
      content, designed to be retrieved by the target AI's
      RAG pipeline. Stage an exfiltration endpoint to receive
      data encoded in URL parameters.
  - step: delivery
    tactic: AML.TA0004          # Initial Access
    techniques: [AML.T0093]
    abstract_action: >
      Deliver the crafted content through a channel that feeds
      into the AI assistant's data corpus (email, shared
      document, knowledge base entry).
  - step: ingestion
    tactic: AML.TA0006          # Persistence
    techniques: [AML.T0070]
    abstract_action: >
      The content is automatically indexed into the RAG
      database, establishing a dormant injection that activates
      when semantically relevant queries trigger retrieval.
  - step: activation
    tactic: AML.TA0005          # Execution
    techniques: [AML.T0051.002]
    abstract_action: >
      When a user invokes the AI assistant with a query that
      triggers retrieval of the poisoned content, the hidden
      instructions activate without any user interaction with
      the malicious content itself.
  - step: collection
    tactic: AML.TA0009          # Collection
    techniques: [AML.T0085.000]
    abstract_action: >
      The activated injection instructs the AI to search the
      user's accessible data corpus for sensitive information
      matching attacker-specified criteria.
  - step: exfiltration
    tactic: AML.TA0010          # Exfiltration
    techniques: [AML.T0077, AML.T0025]
    abstract_action: >
      The AI encodes the collected sensitive data into a
      rendered output element (e.g., Markdown image URL) that
      the client automatically fetches, exfiltrating data
      to the attacker's endpoint without user action.
  - step: impact
    tactic: AML.TA0011          # Impact
    techniques: [AML.T0048]
    abstract_action: >
      Confidential enterprise data is exfiltrated to the
      attacker, potentially including business communications,
      project details, and personal information.
```

#### AP-T15-03: LLM-generated stored XSS via cross-context chat handoff (CS0060)

```yaml
kill_chain:
  - step: setup
    tactic: AML.TA0003          # Resource Development
    techniques: [AML.T0008, AML.T0065]
    abstract_action: >
      Set up an exfiltration endpoint and craft a prompt that
      causes a customer-facing AI chatbot to generate an HTML
      response containing a JavaScript payload targeting the
      support agent's browser.
  - step: delivery
    tactic: AML.TA0004          # Initial Access
    techniques: [AML.T0093]
    abstract_action: >
      Submit the crafted prompt through the chatbot's public
      interface, causing the AI to generate and store the
      malicious HTML in the chat transcript.
  - step: payload_generation
    tactic: AML.TA0005          # Execution
    techniques: [AML.T0051.000]
    abstract_action: >
      The chatbot follows the formatting instructions and
      generates an HTML response containing the attacker's
      JavaScript payload. The response persists in the chat
      history.
  - step: trigger
    tactic: AML.TA0005          # Execution
    techniques: [AML.T0011]
    abstract_action: >
      The attacker requests transfer to a human agent. When
      the agent opens the chat transcript, the stored XSS
      payload executes in their browser.
  - step: credential_theft
    tactic: AML.TA0013          # Credential Access
    techniques: [AML.T0113]
    abstract_action: >
      The JavaScript reads session cookies from the support
      agent's browser and exfiltrates them to the attacker.
  - step: exfiltration
    tactic: AML.TA0010          # Exfiltration
    techniques: [AML.T0077]
    abstract_action: >
      The session cookie is encoded in a rendered element
      (image tag) that automatically sends a request to the
      attacker's server.
  - step: lateral_movement
    tactic: AML.TA0015          # Lateral Movement
    techniques: [AML.T0091.001]
    abstract_action: >
      The attacker replays the stolen session cookie to
      hijack the support agent's authenticated session,
      gaining access to the internal support platform.
  - step: impact
    tactic: AML.TA0011          # Impact
    techniques: [AML.T0048]
    abstract_action: >
      The attacker accesses internal support infrastructure
      as the agent, potentially viewing customer data,
      performing unauthorized actions, or pivoting further.
```

#### AP-T11-04: AI service API as covert C2 channel (CS0042)

```yaml
kill_chain:
  - step: c2_operation
    tactic: AML.TA0014          # Command and Control
    techniques: [AML.T0096]
    abstract_action: >
      Malware on a compromised host uses a legitimate AI
      service API as a bidirectional command-and-control
      channel. Commands and results are encrypted and relayed
      through the API's CRUD operations (create/read/delete
      message objects). After each exchange, the malware
      deletes the API objects to destroy forensic evidence.
      The traffic blends with legitimate AI service usage,
      evading network-level detection.
```

Note: CS0042 has a minimal ATLAS kill chain (1 step) because the broader
intrusion uses conventional ATT&CK TTPs. The pattern captures only the
AI-specific C2 mechanism.

#### AP-T11-06: AI service web interface as bidirectional C2 relay (CS0061)

```yaml
kill_chain:
  - step: reconnaissance
    tactic: AML.TA0002          # Reconnaissance
    techniques: [AML.T0095]
    abstract_action: >
      Identify public AI services with unauthenticated web-
      browsing or URL-fetch capabilities that can retrieve
      arbitrary attacker-controlled URLs.
  - step: setup
    tactic: AML.TA0003          # Resource Development
    techniques: [AML.T0008.002, AML.T0079]
    abstract_action: >
      Register a domain and deploy an endpoint that serves
      C2 commands in responses while logging inbound requests
      containing exfiltrated data.
  - step: c2_channel
    tactic: AML.TA0014          # Command and Control
    techniques: [AML.T0114]
    abstract_action: >
      Malware on the compromised host uses the AI service's
      public web interface to establish a bidirectional C2
      channel: crafted prompts instruct the AI to fetch
      attacker URLs with victim data encoded in query
      parameters (exfiltration); the AI summarizes the
      response, which the implant parses as commands.
  - step: collection
    tactic: AML.TA0009          # Collection
    techniques: [AML.T0037]
    abstract_action: >
      The implant collects system information, credentials,
      or other data from the local host.
  - step: exfiltration
    tactic: AML.TA0010          # Exfiltration
    techniques: [AML.T0086]
    abstract_action: >
      Collected data is exfiltrated when the AI service
      fetches the attacker URL with encoded data in
      query parameters.
  - step: execution
    tactic: AML.TA0005          # Execution
    techniques: [AML.T0050]
    abstract_action: >
      The implant extracts commands from the AI's summarized
      response and executes them on the local system.
```

#### AP-T6-07: Prompt injection targeting AI security tool (CS0043)

```yaml
kill_chain:
  - step: setup
    tactic: AML.TA0003          # Resource Development
    techniques: [AML.T0065, AML.T0017]
    abstract_action: >
      Craft a prompt injection designed to hijack an AI-based
      security analysis tool and embed it within a payload
      (malware binary, document, data artifact) that the AI
      tool will process.
  - step: delivery
    tactic: AML.TA0005          # Execution
    techniques: [AML.T0051.000]
    abstract_action: >
      When the AI-based security tool processes the payload
      for analysis or classification, the embedded prompt
      injection enters the tool's context and executes.
  - step: evasion
    tactic: AML.TA0007          # Defense Evasion
    techniques: [AML.T0015]
    abstract_action: >
      The injection hijacks the AI tool's classification
      goal, causing it to report the malicious payload as
      benign, effectively evading AI-based detection.
  - step: impact
    tactic: AML.TA0011          # Impact
    techniques: [AML.T0048]
    abstract_action: >
      The malicious payload evades detection and proceeds
      to execute its intended actions (data theft, system
      compromise) unimpeded by AI security controls.
```

### 5.2 Shared Kill Chain Templates

Several extraction candidates share tactical progressions that can be
represented as reusable kill chain template archetypes:

**Template Alpha: Tool-Mediated Injection Chain**
Used by: AP-T2-07 (CS0045), AP-T2-08 (CS0046), AP-T11-05 (CS0055)

```
Resource Development -> Initial Access (via content fetch) ->
Execution (prompt injection) -> Privilege Escalation (tool invocation) ->
[Credential Access | Exfiltration | Destruction] -> Impact
```

Distinguishing factor: the final objective (credential theft vs. data
destruction vs. code execution).

**Template Beta: Supply Chain Poisoning Chain**
Used by: AP-T17-03 (CS0053), AP-T16-04 (CS0054)

```
Resource Development (craft + publish poisoned tool) ->
Initial Access (via tool installation) -> Persistence (tool config) ->
Execution (tool invocation) -> Exfiltration -> Impact
```

Distinguishing factor: the poisoning vector (package registry vs. docstring).

**Template Gamma: Agent Infrastructure Exploitation Chain**
Used by: AP-T3-04 (CS0048), AP-T3-05 (CS0050)

```
Reconnaissance -> Initial Access (exposed interface) ->
Credential Access -> [Privilege Escalation | Defense Evasion (config modification)] ->
Execution -> Impact
```

Distinguishing factor: whether the attack uses prompt injection (CS0048) or
configuration API manipulation (CS0050).

**Template Delta: C2 via AI Service Chain**
Used by: AP-T11-04 (CS0042), AP-T11-06 (CS0061)

```
[Reconnaissance ->] Resource Development (stage infrastructure) ->
Command and Control (AI service as relay) ->
Collection -> Exfiltration -> Execution
```

Distinguishing factor: API-level (CS0042) vs. web-interface-level (CS0061).

---

## 6. Dedup Considerations

### 6.1 Variant Analysis

**MCP/Tool cluster (CS0045, CS0053, CS0054)**: Three distinct patterns, NOT
variants of the same mechanism:

| Case Study | Attack Vector | Mechanism | Verdict |
|---|---|---|---|
| CS0045 | External content fetched BY a tool | Indirect prompt injection via tool output | **Distinct** -- the tool is the delivery channel for external content |
| CS0053 | The tool itself is poisoned at source | Supply chain rug pull of an MCP package | **Distinct** -- the tool's CODE is malicious, not its input |
| CS0054 | The tool's DESCRIPTION is poisoned | Prompt injection via tool metadata | **Distinct** -- the tool's METADATA is the injection vector |

Recommendation: **Three separate patterns.** These represent three fundamentally
different trust boundary violations: data ingested by a tool (CS0045), code
inside a tool (CS0053), metadata describing a tool (CS0054).

**Computer-use agent attacks (CS0046, CS0055)**: Two distinct patterns:

| Case Study | Delivery | Mechanism | Verdict |
|---|---|---|---|
| CS0046 | Document (PDF) | Indirect injection + jailbreak -> bash tool -> data destruction | **Distinct** -- any agent with tool execution |
| CS0055 | Adversarial web content | Agent clickbait + clipboard manipulation -> GUI terminal execution | **Distinct** -- requires computer-use (GUI control) |

Recommendation: **Two separate patterns.** CS0046 targets any agent with bash
access via document injection; CS0055 targets specifically computer-use agents
via GUI interaction manipulation. Different prerequisite capabilities and
different kill chains.

**C2 channel patterns (CS0042, CS0051, CS0061)**: Three distinct patterns:

| Case Study | AI Role | Mechanism | Verdict |
|---|---|---|---|
| CS0042 | AI API as communication relay | Malware uses API CRUD operations for C2 | **Distinct** -- AI is passive relay |
| CS0051 | AI agent as active C2 implant | Agent is compromised and polls for commands | **Distinct** -- AI is active participant |
| CS0061 | AI web UI as fetch proxy | Malware instructs AI to fetch URLs (bidirectional) | **Distinct** -- AI's URL-fetch is the mechanism |

Recommendation: **Three separate patterns.** The AI plays fundamentally
different roles in each: passive API relay, active compromised agent, and
unwitting URL-fetching proxy. Different threat models and different
prerequisites.

**Agent infrastructure (CS0048, CS0050)**: Two distinct patterns:

| Case Study | Vector | Mechanism | Verdict |
|---|---|---|---|
| CS0048 | Exposed web control interface | Direct access to agent config + prompt interface | **Distinct** -- exploits deployment misconfiguration |
| CS0050 | 1-click exploit via browser | WebSocket hijacking -> config API -> safety disable | **Distinct** -- exploits agent API vulnerabilities |

Recommendation: **Two separate patterns.** Different initial access vectors
and different exploit chains, even though both target agent configuration.

### 6.2 Granularity Recommendation

**One pattern per mechanism, NOT one pattern per case study.** The 13
extraction candidates above represent 13 distinct mechanisms. No further
dedup is warranted because:

1. Each has a distinct kill chain template (different tactic progression)
2. Each violates a different trust boundary
3. Each has different prerequisite capabilities
4. Merging would lose mechanistic precision that drives scenario quality

The existing 66 patterns average 3.9 patterns per threat category. Adding 13
new patterns (distributed across T1, T2, T3, T6, T11, T15, T16, T17) maintains
this density without inflation.

---

## 7. Concrete Extraction Plan

### 7.1 Ordered Extraction List

Priority: novel mechanisms first, then variants, then enrichments.

| Priority | Pattern ID | Name | Source CS | Threat | Template | Est. Effort |
|---|---|---|---|---|---|---|
| **P1** | AP-T6-06 | AI agent as persistent C2 implant | CS0051 | T6 | Unique (longest chain) | High |
| **P1** | AP-T11-05 | Computer-use agent exploitation via adversarial web content | CS0055 | T11 | Alpha | Medium |
| **P1** | AP-T17-03 | MCP tool supply chain poisoning via namesquatting | CS0053 | T17 | Beta | Medium |
| **P1** | AP-T1-06 | Zero-click RAG poisoning with rendered-output exfiltration | CS0059 | T1 | Unique | Medium |
| **P1** | AP-T3-04 | Exposed agent control interface exploitation | CS0048 | T3 | Gamma | Medium |
| **P2** | AP-T2-07 | Credential exfiltration via tool-mediated injection | CS0045 | T2 | Alpha | Medium |
| **P2** | AP-T16-04 | Tool docstring injection for credential theft | CS0054 | T16 | Beta | Medium |
| **P2** | AP-T15-03 | LLM-generated stored XSS via cross-context chat handoff | CS0060 | T15 | Unique | Medium |
| **P2** | AP-T3-05 | Agent safety control disablement via configuration API | CS0050 | T3 | Gamma | Medium |
| **P3** | AP-T2-08 | Computer-use agent data destruction via document injection | CS0046 | T2 | Alpha | Low |
| **P3** | AP-T11-04 | AI service API as covert C2 channel | CS0042 | T11 | Delta | Low |
| **P3** | AP-T11-06 | AI service web interface as bidirectional C2 relay | CS0061 | T11 | Delta | Low |
| **P3** | AP-T6-07 | Prompt injection targeting AI security tool | CS0043 | T6 | Unique | Low |

### 7.2 Enrichment-Only Items (no new pattern, add kill chain to existing)

| Existing Pattern | Source CS | Action |
|---|---|---|
| AP-T1-01 | CS0040 | Add kill chain scaffold + evidence link |
| AP-T17-01 / AP-T17-02 | CS0041, CS0049 | Add kill chain scaffold + evidence link |
| AP-T11-01 / AP-T11-02 | CS0052, CS0062 | Add kill chain scaffold + evidence link |

### 7.3 Excluded Items

| Case Study | Reason |
|---|---|
| CS0044 (LAMEHUG) | AI-augmented traditional malware; AI is a tool used by malware, not the target. Low relevance for agentic threat scenarios. |
| CS0047 (Amazon Q) | Mechanism is supply chain + destructive agent deployment. The supply chain part is covered by enriching AP-T17-01; the destructive agent part overlaps with CS0046/CS0047 patterns. Consider including as evidence link on AP-T17-01 rather than separate pattern. |
| CS0056 (Model distillation) | Not an agentic system threat; IP theft from AI service provider. |
| CS0057 (Storm-2139) | Ecosystem threat (jailbreak-as-a-service), not a pattern against a specific agent. |
| CS0058 (Google Photos) | Traditional ML model extraction from mobile app; not agentic. |

### 7.4 Summary Metrics

| Metric | Value |
|---|---|
| Total new patterns to extract | **13** |
| P1 (novel, high value) | 5 |
| P2 (variants/distinct mechanisms) | 4 |
| P3 (AI-as-infrastructure, niche) | 4 |
| Existing patterns to enrich with kill chains | 5 |
| Case studies excluded | 5 |
| Shared kill chain templates | 4 (Alpha, Beta, Gamma, Delta) |
| New threat categories covered | T1 (+1), T2 (+2), T3 (+2), T6 (+2), T11 (+3), T15 (+1), T16 (+1), T17 (+1) |
| Post-extraction total patterns | **79** (66 existing + 13 new) |

### 7.5 SSSOM Provenance Requirements

Each new pattern requires companion SSSOM entries mapping to ATLAS technique
IDs. The kill chain already embeds these references; the SSSOM entries should
be generated from the kill chain technique lists:

```
# Example for AP-T2-07 (CS0045-derived)
AP-T2-07  scenario-forge  skos:relatedMatch  AML.T0051.001  mitre-atlas  semapv:ManualMappingCuration
AP-T2-07  scenario-forge  skos:relatedMatch  AML.T0053      mitre-atlas  semapv:ManualMappingCuration
AP-T2-07  scenario-forge  skos:relatedMatch  AML.T0083      mitre-atlas  semapv:ManualMappingCuration
AP-T2-07  scenario-forge  skos:relatedMatch  AML.T0086      mitre-atlas  semapv:ManualMappingCuration
```

Select the 2-4 most distinctive techniques from the kill chain for SSSOM
(not the generic ones like AML.T0065 Prompt Crafting that appear in every
case study).

### 7.6 File Placement

New patterns should go into one of the existing attack pattern YAML files
based on their threat_id:
- T1, T2, T3 -> `attack-patterns-memory-tool.yaml`
- T6, T11 -> `attack-patterns-halluc-intent.yaml`
- T15, T16, T17 -> `attack-patterns-comms-human-supply.yaml`

Alternatively, create a new file `attack-patterns-atlas-derived.yaml` to keep
ATLAS-sourced patterns distinct from OWASP-derived patterns for provenance
clarity. The glob pattern `attack-patterns*.yaml` will pick it up automatically.

### 7.7 Implementation Order

1. **Extract P1 patterns** (5 patterns) -- novel mechanisms with highest scenario generation value
2. **Write SSSOM entries** for P1 patterns
3. **Run pipeline** with new patterns to validate they produce coherent scenarios
4. **Enrich existing patterns** (5 patterns) with kill chain scaffolds from case studies
5. **Extract P2 patterns** (4 patterns) -- distinct variants
6. **Extract P3 patterns** (4 patterns) -- AI-as-infrastructure niche
7. **Validate kill chain templates** in Stage 4 Call 2 integration (when the pipeline adds kill chain support)
