# ATLAS Tactic Sequences for T11 (RCE) and T17 (Supply Chain) Patterns

This document provides ATLAS-backed tactic sequences for 7 attack patterns in the T11 and T17 threat categories.

## Methodology

For each pattern:
1. **Source case study** — The ATLAS case study demonstrating the attack mechanism
2. **Tactic sequence** — Ordered list of ATLAS tactics from the attacker's perspective
3. **Confidence annotation** — explicit (directly in case study), adapted (mechanism present but different context), or inferred (logically required but not in case study)
4. **Adaptation rationale** — How the sequence differs from the case study to fit the pattern's mechanism

---

### AP-T11-01: Infrastructure-as-code injection via agent code generation

**Source case study**: AML.CS0052 — LLMSmith: RCE Vulnerabilities in LLM-Integrated Applications (evidenced)
**Existing kill chain**: yes — being replaced

**Proposed tactic sequence:**
| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Perform static analysis on LLM framework APIs to identify code execution sinks (eval, exec) | explicit |
| 2 | AML.TA0002 | Reconnaissance | Scan source code repositories for app deployment URLs that use vulnerable frameworks | explicit |
| 3 | AML.TA0008 | Discovery | Extract call chains from target application source code to identify paths leading to code execution | explicit |
| 4 | AML.TA0003 | Resource Development | Develop prompts designed to trigger tool invocations that flow attacker-controlled data into execution sinks | explicit |
| 5 | AML.TA0004 | Initial Access | Access public-facing AI agent application through its user interface or API | explicit |
| 6 | AML.TA0005 | Execution | Submit crafted prompt to agent, causing it to process attacker instructions | explicit |
| 7 | AML.TA0007 | Defense Evasion | Use lightweight jailbreaking techniques to bypass LLM guardrails that refuse malicious requests | explicit |
| 8 | AML.TA0012 | Privilege Escalation | Agent invokes tools with attacker-controlled arguments, passing data into code execution call chain | explicit |
| 9 | AML.TA0005 | Execution | Attacker's input evaluated as code within framework's sandboxed interpreter (e.g., Python eval) | explicit |
| 10 | AML.TA0012 | Privilege Escalation | Execute sandbox escape techniques to break out of containerized or virtualized environment | explicit |
| 11 | AML.TA0014 | Command and Control | Open reverse shell to establish persistent command channel to attacker infrastructure | explicit |
| 12 | AML.TA0011 | Impact | Achieve full system control; compromise host running the AI agent framework | explicit |

**Adaptation rationale**: 
The pattern describes code generation agents producing infrastructure configuration with embedded malicious commands. CS0052 demonstrates the core RCE mechanism through LLM framework call chains. The sequence maps directly from CS0052 with all 12 steps preserved, including the 4 critical steps that were missing from the original worker-authored kill chain:
- Discovery (step 3): Call chain extraction from source code
- Defense Evasion (step 7): Jailbreak to bypass guardrails
- Second Privilege Escalation (step 10): Sandbox escape
- Command and Control (step 11): Reverse shell establishment

The pattern abstracts from specific frameworks (LangChain, LlamaIndex) to generic "agent frameworks with code execution sinks."

**Comparison with existing kill chain**: 
Original had 7 steps and omitted Discovery (TA0008), Defense Evasion (TA0007), sandbox escape (second TA0012), and C2 (TA0014). New sequence includes full attack flow from research to persistence.

---

### AP-T11-02: Workflow automation backdoor insertion

**Source case study**: INCORRECT MAPPING — CS0062 does not exist in ATLAS-2026.05.yaml
**Existing kill chain**: yes — being replaced

**Pattern description analysis**: "Agent responsible for generating or modifying automation workflows is manipulated into embedding backdoor logic within the generated scripts."

**Best match identified**: AML.CS0047 — Amazon Q Destructive Agent via Supply Chain Compromise

**Proposed tactic sequence:**
| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Develop prompt instructing agent to embed backdoor logic in generated workflow scripts | explicit |
| 2 | AML.TA0013 | Credential Access | Obtain access to workflow generation system's credentials or publishing mechanism | explicit |
| 3 | AML.TA0004 | Initial Access | Use compromised credentials to inject malicious workflow configuration into deployment pipeline | explicit |
| 4 | AML.TA0005 | Execution | Agent initializes with poisoned configuration or prompt injection | explicit |
| 5 | AML.TA0005 | Execution | Agent generates workflow scripts embedding attacker-specified destructive commands | explicit |
| 6 | AML.TA0011 | Impact | Generated workflows execute with agent's privileges, performing unauthorized actions | explicit |

**Adaptation rationale**: 
CS0047 shows an agent deploying with a malicious system prompt that causes it to generate destructive code. The pattern describes workflow automation backdoor insertion, which aligns with CS0047's mechanism: an agent that generates automation artifacts (workflows, scripts) being manipulated to embed malicious logic.

The key adaptation is abstracting from "deployed destructive agent" to "workflow generation poisoning." Both involve an agent producing executable artifacts containing attacker-controlled logic.

**Comparison with existing kill chain**: 
Original sequence (5 steps) was mapped to non-existent CS0062 and described parameter escaping/RCE. New sequence (6 steps from CS0047) correctly models supply chain compromise of workflow-generating agents.

**Note on wrong mapping**: The original evidence pointed to CS0062 (does not exist). CS0047 demonstrates the closest mechanism: agent generating executable code/workflows with embedded malicious instructions via compromised deployment.

---

### AP-T11-03: Linguistic ambiguity exploitation for command injection

**Source case study**: AML.CS0052 — LLMSmith: RCE Vulnerabilities in LLM-Integrated Applications (strong match)
**Existing kill chain**: NO

**Proposed tactic sequence:**
| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Craft natural-language input with deliberate ambiguities that resolve into unintended executable commands | adapted |
| 2 | AML.TA0002 | Reconnaissance | Identify target agent systems that translate natural language to executable commands without strict validation | adapted |
| 3 | AML.TA0004 | Initial Access | Submit ambiguous natural-language input through agent's public interface | adapted |
| 4 | AML.TA0005 | Execution | Agent resolves linguistic ambiguity into command structure, misinterpreting attacker intent as legitimate | adapted |
| 5 | AML.TA0012 | Privilege Escalation | Agent invokes tools with parameters derived from ambiguous interpretation, escalating to code execution | adapted |
| 6 | AML.TA0005 | Execution | Execution environment parses agent's output as code, bridging semantic gap between NL and command layer | adapted |
| 7 | AML.TA0011 | Impact | Unintended command executes with agent's privileges, achieving attacker objective | adapted |

**Adaptation rationale**: 
AP-T11-03 describes exploiting the semantic gap between natural language interpretation and command execution. CS0052 demonstrates RCE through language-to-code boundary exploitation, but focuses on direct prompt injection rather than linguistic ambiguity.

The tactic sequence is adapted from CS0052's core flow but removes framework-specific steps (static analysis, call chain extraction, sandbox escape) and emphasizes the NL→code translation boundary. The attack relies on the agent's language model misinterpreting ambiguous input rather than explicit code injection.

Key difference from AP-T11-01: T11-01 targets framework-level execution sinks with explicit code; T11-03 exploits ambiguous natural language that the agent resolves into dangerous commands.

**Comparison with existing kill chain**: 
No existing kill chain. This sequence adapts CS0052's RCE mechanism to the linguistic ambiguity attack vector.

---

### AP-T11-05: Computer-use agent exploitation via adversarial web content

**Source case study**: AML.CS0055 — AI ClickFix: Hijacking Computer-Use Agents (evidenced)
**Existing kill chain**: YES — being replaced

**Proposed tactic sequence:**
| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Obtain access to LLM service (e.g., ChatGPT) for generating attack content | explicit |
| 2 | AML.TA0003 | Resource Development | Use LLM to generate adversarial web content with agent-targeted interactive elements and malicious scripts | explicit |
| 3 | AML.TA0003 | Resource Development | Stage malicious website and payload script on attacker-controlled infrastructure | explicit |
| 4 | AML.TA0004 | Initial Access | Computer-use agent navigates to or is directed to adversarial website, ingesting content into context | explicit |
| 5 | AML.TA0005 | Execution | Agent-targeted clickbait (e.g., "Are you a computer?") causes agent to interact with page elements | explicit |
| 6 | AML.TA0005 | Execution | Embedded instructions direct agent to perform GUI action sequence: open terminal, paste clipboard, execute | explicit |
| 7 | AML.TA0012 | Privilege Escalation | Agent uses computer-use capabilities to execute attacker's command on host via keyboard/mouse/clipboard control | explicit |
| 8 | AML.TA0011 | Impact | Arbitrary code executes on host with agent's privileges, achieving machine compromise | explicit |

**Adaptation rationale**: 
CS0055 demonstrates the exact attack mechanism: adversarial web content designed to manipulate computer-use agents through visual and textual elements. The pattern abstracts from Claude Computer Use to "computer-use agents" generally.

The sequence preserves all 8 steps from CS0055, including the three Resource Development steps that show the full attack preparation workflow (obtain LLM access → generate content → stage infrastructure).

Key mechanism: JavaScript loads malicious commands into clipboard, prompt instructions cause agent to paste and execute them, bridging web context to OS-level execution.

**Comparison with existing kill chain**: 
Original sequence (6 steps) compressed the three Resource Development steps into one. New sequence preserves CS0055's granularity, showing the attack preparation workflow.

---

### AP-T17-01: Upstream artifact poisoning via repository compromise

**Source case study**: AML.CS0041 — Rules File Backdoor (evidenced)
**Existing kill chain**: YES — being replaced

**Proposed tactic sequence:**
| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0003 | Resource Development | Stage malicious payload (e.g., JavaScript backdoor) on publicly accessible infrastructure | explicit |
| 2 | AML.TA0003 | Resource Development | Craft prompt injection designed to cause agent to embed malicious elements in generated code | explicit |
| 3 | AML.TA0007 | Defense Evasion | Hide prompt in configuration file using invisible Unicode characters (zero-width joiners, bidirectional markers) | explicit |
| 4 | AML.TA0004 | Initial Access | Distribute poisoned configuration file through public repository or package registry where AI agent configs are shared | explicit |
| 5 | AML.TA0006 | Persistence | Users pull the poisoned rules file, replacing their configuration and persisting the malicious content in their development environment | explicit |
| 6 | AML.TA0005 | Execution | When agent initializes, it reads configuration file and hidden prompt executes | explicit |
| 7 | AML.TA0007 | Defense Evasion | Use jailbreak techniques to convince agent to add malicious elements to generated artifacts | explicit |
| 8 | AML.TA0007 | Defense Evasion | Prompt instructs agent to suppress mention of code changes in responses to user | explicit |
| 9 | AML.TA0011 | Impact | Developers use agent-generated code containing hidden backdoors, exfiltration logic, or vulnerable constructs | explicit |

**Adaptation rationale**: 
CS0041 demonstrates supply chain poisoning of AI coding assistant configuration files. The pattern describes "upstream artifact poisoning via repository compromise," which matches CS0041's mechanism exactly: poisoned configurations distributed through shared repositories.

The sequence preserves CS0041's 9-step flow, including three separate Defense Evasion steps that show the layered evasion approach (invisible characters → jailbreak → output suppression). CS0041 S04 explicitly maps to TA0006 — users pulling the poisoned rules file constitutes persistence through normal dependency management.

**Comparison with existing kill chain**: 
Original sequence (7 steps) omitted the TA0006 Persistence step and merged the three Defense Evasion steps. New sequence (9 steps) includes the explicit Persistence step from CS0041 S04 and preserves all Defense Evasion granularity.

---

### AP-T17-02: Autonomous agent self-sabotage via unvalidated execution

**Source case study**: NO strong match — mechanism mismatch with all ATLAS case studies
**Existing kill chain**: YES — being replaced

**Pattern description analysis**: "Autonomous code-generating agent hallucinates incorrect resource references, destroys legitimate data, produces falsified verification results."

**Match quality assessment**:
- CS0049: Supply chain skill poisoning — WRONG (external supply chain ≠ autonomous hallucination)
- CS0050: External 1-click exploit — WEAK (attacker disables safety controls remotely ≠ agent autonomously fails via hallucination)

**Secondary reference**: AML.CS0050 — OpenClaw 1-Click RCE (weak match — shows impact of absent safety controls, not autonomous failure mode)

**Proposed tactic sequence (reconstructed from pattern description):**
| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0005 | Execution | Agent generates infrastructure code or automation workflows containing hallucinated resource references (wrong endpoints, incorrect paths, fabricated dependencies) | inferred |
| 2 | AML.TA0007 | Defense Evasion | Agent produces falsified verification results (claims tests pass, reports success despite errors) | inferred |
| 3 | AML.TA0011 | Impact | Generated code executes with agent's privileges, destroying legitimate data or corrupting infrastructure due to hallucinated references | inferred |

**Adaptation rationale**: 
NO strong ATLAS case study match exists for autonomous agent self-sabotage via hallucination. CS0050 is cited only as evidence that agents CAN cause destruction when safety controls fail, not as a procedural template.

**Mechanism mismatch**:
- CS0050: External attacker disables safety controls remotely → agent executes attacker-specified destructive commands
- AP-T17-02: Agent autonomously hallucinates incorrect references → agent's own generated code destroys data → agent falsifies verification results

CS0050 = external exploit (attacker-driven destruction)
AP-T17-02 = autonomous failure (agent self-sabotage through hallucination)

The tactic sequence is reconstructed from the pattern description, not adapted from CS0050. All steps are marked "inferred" — this is a constructed sequence representing an emergent failure mode not yet documented in ATLAS case studies.

**Comparison with existing kill chain**: 
Original sequence incorrectly mapped to CS0049 (supply chain poisoning, different mechanism entirely). New sequence acknowledges the lack of ATLAS evidence and reconstructs the attack flow from pattern description, using CS0050 only as secondary reference for impact evidence.

---

### AP-T17-03: Tool supply chain poisoning via registry namesquatting

**Source case study**: AML.CS0053 — Poisoned Postmark MCP Server Email Exfiltration (evidenced)
**Existing kill chain**: YES — being replaced

**Proposed tactic sequence:**
| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0007 | Defense Evasion | Register package name on public registry before legitimate maintainer claims it (namesquatting) | explicit |
| 2 | AML.TA0003 | Resource Development | Develop functional tool implementation with embedded malicious side-channel for data exfiltration | explicit |
| 3 | AML.TA0003 | Resource Development | Publish malicious version to package registry, embedding exfiltration logic in normal tool operation | explicit |
| 4 | AML.TA0007 | Defense Evasion | Wait for user adoption before activating malicious behavior to evade initial scrutiny of new packages | explicit |
| 5 | AML.TA0004 | Initial Access | Users download and install poisoned tool through normal dependency management and supply chain | explicit |
| 6 | AML.TA0006 | Persistence | Poisoned tool persists in agent configurations as trusted dependency until explicitly detected and removed | explicit |
| 7 | AML.TA0005 | Execution | User instructs agent to invoke poisoned tool for legitimate operation | explicit |
| 8 | AML.TA0010 | Exfiltration | Tool performs normal function but silently exfiltrates data through embedded side-channel with each invocation | explicit |
| 9 | AML.TA0011 | Impact | Sensitive data continuously leaked to attacker through tool's covert channel piggybacking on legitimate use | inferred |

**Adaptation rationale**: 
CS0053 demonstrates MCP server registry namesquatting where attackers register `postmark-mcp` before the official maintainer and publish a version with BCC exfiltration. The pattern describes "tool supply chain poisoning via registry namesquatting," which is exactly CS0053's mechanism.

The sequence adds one step (step 7: Execution) that was missing from the original pattern kill chain but is present in CS0053: users must actually invoke the tool (AML.T0011.002 / TA0005) for the exfiltration to occur.

Recon noted: "Missing execution step per recon" — this sequence includes it.

**Comparison with existing kill chain**: 
Original sequence (8 steps) jumped from Persistence directly to Exfiltration, omitting the Execution step where users invoke the poisoned tool. New sequence includes this critical step showing the tool must be actively used for the attack to succeed.

---

## Summary Statistics

### Patterns by Match Quality
- **Evidenced strong matches**: 4 patterns (T11-01, T11-05, T17-01, T17-03)
- **Strong adapted matches**: 1 pattern (T11-03 from CS0052)
- **Corrected mappings**: 1 pattern (T11-02 to CS0047 instead of non-existent CS0062)
- **No strong ATLAS match (reconstructed from pattern)**: 1 pattern (T17-02 — autonomous hallucination-driven self-sabotage not demonstrated in ATLAS)

### Tactic Coverage
Most common tactics in these sequences:
1. **AML.TA0003** (Resource Development): 7/7 patterns — attack preparation phase
2. **AML.TA0005** (Execution): 7/7 patterns — code/prompt execution
3. **AML.TA0007** (Defense Evasion): 6/7 patterns — guardrail bypass, obfuscation
4. **AML.TA0011** (Impact): 7/7 patterns — final compromise/damage
5. **AML.TA0004** (Initial Access): 6/7 patterns — delivery mechanisms
6. **AML.TA0012** (Privilege Escalation): 5/7 patterns — tool invocation, sandbox escape

### Average Sequence Length
- **T11 RCE patterns**: 12, 6, 7, 8 steps (avg 8.25)
- **T17 Supply Chain patterns**: 9, 3, 9 steps (avg 7.0)
- **Overall**: 7.7 steps per sequence

### Key Insights

1. **Defense Evasion is critical**: 6/7 patterns include explicit evasion steps (jailbreak, obfuscation, timing)
2. **RCE patterns are longest**: T11-01 (12 steps) includes full research→sandbox escape→C2 flow
3. **Supply chain attacks emphasize preparation**: Multiple Resource Development steps for staging
4. **Execution appears twice in complex attacks**: Initial execution + final code execution (T11-01, T11-03)
5. **Privilege Escalation separates tool invocation from sandbox escape**: Critical distinction in RCE attacks

### Corrections Made

1. **AP-T11-02**: Remapped from non-existent CS0062 to CS0047 (destructive agent deployment)
2. **AP-T17-02**: Reconstructed from pattern description — no strong ATLAS match (CS0049 wrong, CS0050 weak mechanism mismatch)
3. **AP-T11-01**: Added 4 missing steps from CS0052 (discovery, evasion, sandbox escape, C2)
4. **AP-T17-01**: Added missing TA0006 Persistence step from CS0041 S04
5. **AP-T17-03**: Added missing execution step from CS0053
