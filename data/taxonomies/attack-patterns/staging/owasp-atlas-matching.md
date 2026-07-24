# OWASP Pattern → ATLAS Case Study Matching Analysis

This document maps 61 OWASP attack patterns (those without evidence fields) to ATLAS case studies based on attack mechanism similarity.

## Matching Methodology

- **Strong match**: Same core attack mechanism - the case study demonstrates the same fundamental technique
- **Partial match**: Related mechanism with key differences - overlapping approach but different execution vectors or contexts
- **No match**: No case study demonstrates a sufficiently similar mechanism

For each match, I analyze:
1. Mechanism overlap - how the attack techniques align
2. Tactic sequence from ATLAS case study
3. Adaptation notes - what would change to apply the case study to the OWASP pattern

---

## Analysis by Pattern


### Memory Poisoning Patterns (T1)

#### AP-T1-02: Context window saturation for privilege escalation
**Mechanism**: Fragments privilege escalation across sessions to exploit finite context window, causing agent to lose track of authorization state.

**Strongest match**: AML.CS0040 - Hacking ChatGPT's Memories with Prompt Injection
- **Match type**: Strong
- **Mechanism overlap**: Both exploit persistent memory mechanisms to embed false rules that persist across sessions. AML.CS0040 uses prompt injection to write attacker-controlled instructions into ChatGPT's persistent memory, similar to how AP-T1-02 fragments attacks across the context window/memory boundary.
- **CS tactic sequence**: AML.TA0003 → AML.TA0007 → AML.TA0004 → AML.TA0005 → AML.TA0006 → AML.TA0011
- **Adaptation**: CS0040 uses persistent memory injection; AP-T1-02 focuses on context window fragmentation, but both exploit memory to bypass authorization.

#### AP-T1-03: Gradual threat-model erosion via memory drift
**Mechanism**: Incrementally alters stored threat definitions over successive interactions, causing agent to reclassify malicious activity as benign.

**Strongest match**: AML.CS0009 - Tay Poisoning
- **Match type**: Strong  
- **Mechanism overlap**: Both involve gradual corruption of the agent's learning/memory through repeated adversarial inputs. Tay's online learning incorporated toxic content over time; AP-T1-03 describes erosion of threat classification through memory drift.
- **CS tactic sequence**: AML.TA0000 → AML.TA0004 → AML.TA0006 → AML.TA0011
- **Adaptation**: Tay used feedback loops; AP-T1-03 targets threat definitions specifically, but the gradual corruption mechanism is shared.

**Secondary match**: AML.CS0040 - Hacking ChatGPT's Memories
- **Match type**: Partial
- **Mechanism overlap**: Persistent memory poisoning, but CS0040 is about single injection rather than gradual drift.

#### AP-T1-04: Shared memory corruption for cross-agent influence
**Mechanism**: Writes false data into shared memory structure, propagating incorrect behavior across multiple agents without direct interaction.

**Strongest match**: AML.CS0024 - Morris II Worm: RAG-Based Attack
- **Match type**: Strong
- **Mechanism overlap**: Both involve poisoning a shared data structure (RAG/vector store) that multiple agents consume. Morris II injects self-propagating prompts into retrieval systems; AP-T1-04 describes shared memory corruption affecting multiple agents.
- **CS tactic sequence**: AML.TA0000 → AML.TA0005 → AML.TA0006 → AML.TA0010 → AML.TA0011
- **Adaptation**: Morris II uses RAG retrieval; AP-T1-04 is more general shared memory, but the cross-agent propagation mechanism is identical.

**Secondary match**: AML.CS0025 - Web-Scale Data Poisoning: Split-View Attack
- **Match type**: Partial
- **Mechanism overlap**: Poisons shared training/retrieval data affecting multiple systems, but at pre-deployment rather than runtime.

### Tool Misuse Patterns (T2)

#### AP-T2-01: Parameter pollution via function-call manipulation
**Mechanism**: Crafts input causing agent to invoke tool with inflated/malformed parameter values producing outcomes outside intended bounds.

**Strongest match**: AML.CS0037 - Data Exfiltration via Agent Tools in Copilot Studio
- **Match type**: Strong
- **Mechanism overlap**: Both manipulate tool parameters through prompt injection to achieve unintended tool behavior. CS0037 uses prompt injection to cause data exfiltration via tool misuse; AP-T2-01 describes parameter pollution for boundary violations.
- **CS tactic sequence**: AML.TA0002 → AML.TA0003 → AML.TA0004 → AML.TA0005 → AML.TA0008 → AML.TA0000 → AML.TA0009 → AML.TA0010
- **Adaptation**: CS0037 targets data exfiltration specifically; AP-T2-01 is more general parameter manipulation, but core mechanism (tool misuse via input crafting) is shared.

**Secondary match**: AML.CS0039 - Living Off AI: Prompt Injection via Jira
- **Match type**: Strong
- **Mechanism overlap**: Uses prompt injection to manipulate tool invocations for unauthorized actions.

#### AP-T2-02: Multi-tool chain exploitation for data exfiltration
**Mechanism**: Manipulates agent into chaining authorized tools in unanticipated sequence (retrieve-then-transmit) for data exfiltration.

**Strongest match**: AML.CS0037 - Data Exfiltration via Agent Tools in Copilot Studio
- **Match type**: Strong
- **Mechanism overlap**: Demonstrates multi-step tool chain for data exfiltration. CS0037 chains discovery, collection, and exfiltration tools; AP-T2-02 describes the retrieve-then-transmit chain pattern.
- **CS tactic sequence**: AML.TA0002 → AML.TA0003 → AML.TA0004 → AML.TA0005 → AML.TA0008 → AML.TA0000 → AML.TA0009 → AML.TA0010
- **Adaptation**: Direct match - both use tool chaining for exfiltration.

**Secondary matches**:
- AML.CS0021 - ChatGPT Conversation Exfiltration (strong)
- AML.CS0029 - Google Bard Conversation Exfiltration (strong)
- AML.CS0035 - Data Exfiltration from Slack AI (strong)
- AML.CS0045 - Data Exfiltration via MCP Server (strong)

#### AP-T2-03: Automated mass-action abuse via tool amplification
**Mechanism**: Tricks agent into using batch-processing tools to perform high-volume malicious operations from single deceptive input.

**Strongest match**: AML.CS0009 - Tay Poisoning
- **Match type**: Partial
- **Mechanism overlap**: While Tay doesn't show batch tool abuse, it demonstrates amplification - coordinated inputs producing disproportionate system-wide impact through the agent's broadcasting capabilities.
- **CS tactic sequence**: AML.TA0000 → AML.TA0004 → AML.TA0006 → AML.TA0011
- **Adaptation**: Tay amplifies through social broadcast; AP-T2-03 describes batch processing tools, but both show input-to-impact amplification.

**No strong match**: No case study demonstrates mass-action abuse through batch processing/distribution tools.

#### AP-T2-04: Tool misuse via poisoned persistent memory
**Mechanism**: Injects false directives into persistent memory in prior session, causing future tool invocations with unauthorized parameters.

**Strongest match**: AML.CS0040 - Hacking ChatGPT's Memories with Prompt Injection
- **Match type**: Strong
- **Mechanism overlap**: Direct match - both use persistent memory injection to influence future tool behavior. CS0040 injects instructions into memory that affect later sessions.
- **CS tactic sequence**: AML.TA0003 → AML.TA0007 → AML.TA0004 → AML.TA0005 → AML.TA0006 → AML.TA0011
- **Adaptation**: Exactly the pattern described - persistent memory poisoning leading to cross-session tool misuse.

#### AP-T2-05: Tool misuse via adversarial retrieval content
**Mechanism**: Inserts crafted content into vector store that agent queries, leading to unsafe tool invocations from poisoned retrieval results.

**Strongest match**: AML.CS0024 - Morris II Worm: RAG-Based Attack
- **Match type**: Strong
- **Mechanism overlap**: Direct match - both poison RAG/retrieval systems to inject instructions that cause unauthorized tool invocations.
- **CS tactic sequence**: AML.TA0000 → AML.TA0005 → AML.TA0006 → AML.TA0010 → AML.TA0011
- **Adaptation**: CS0024 demonstrates self-propagating RAG poisoning; AP-T2-05 describes the same retrieval-based injection mechanism.

**Secondary match**: AML.CS0025 - Web-Scale Data Poisoning
- **Match type**: Partial
- **Mechanism overlap**: Poisons retrieval data but at training time rather than query time.

#### AP-T2-06: Tool hijacking via prompt injection
**Mechanism**: Injects adversarial instructions causing agent to invoke tools (shell, API, code interpreter) with attacker-chosen commands.

**Strongest match**: AML.CS0016 - Achieving Code Execution in MathGPT via Prompt Injection
- **Match type**: Strong
- **Mechanism overlap**: Direct match - uses prompt injection to hijack tool invocation (code execution) with attacker commands.
- **CS tactic sequence**: AML.TA0002 → AML.TA0000 → AML.TA0005 → AML.TA0001 → AML.TA0004 → AML.TA0013 → AML.TA0011
- **Adaptation**: CS0016 specifically targets code execution tools; AP-T2-06 generalizes to any tool hijacking via injection.

**Secondary matches**:
- AML.CS0037 - Data Exfiltration via Agent Tools (strong)
- AML.CS0039 - Living Off AI: Jira Prompt Injection (strong)  
- AML.CS0045 - MCP Server Data Exfiltration (strong)
- AML.CS0046 - Claude Computer-Use Prompt Injection (strong)
- AML.CS0051 - OpenClaw C&C via Prompt Injection (strong)

### Privilege Compromise Patterns (T3)

#### AP-T3-01: Temporary privilege retention via misconfiguration exploitation
**Mechanism**: Manipulates agent to request temporary elevated privileges then exploits lifecycle misconfiguration to retain them.

**No strong match found**. Most ATLAS cases show initial access or privilege escalation but not specifically the retention-past-intended-scope pattern.

**Partial match**: AML.CS0030 - LLM Jacking
- **Match type**: Partial
- **Mechanism overlap**: Gains unauthorized access to cloud resources through credential theft, demonstrating privilege abuse but not the specific temporary-retention pattern.
- **CS tactic sequence**: AML.TA0004 → AML.TA0013 → AML.TA0012 → AML.TA0003 → AML.TA0008 → AML.TA0011
- **Adaptation**: CS0030 shows credential compromise; AP-T3-01 focuses on permission lifecycle exploitation.

#### AP-T3-02: Cross-boundary authorization escalation
**Mechanism**: Leverages authorized access to one system to escalate privileges in connected system lacking independent scope enforcement.

**Strongest match**: AML.CS0026 - Financial Transaction Hijacking with M365 Copilot
- **Match type**: Strong
- **Mechanism overlap**: Demonstrates cross-system privilege escalation - uses Copilot's access to internal systems to manipulate financial transactions, bypassing per-system authorization.
- **CS tactic sequence**: AML.TA0002 → AML.TA0000 → AML.TA0008 → AML.TA0003 → AML.TA0004 → AML.TA0007 → AML.TA0006 → AML.TA0005 → AML.TA0012 → AML.TA0011
- **Adaptation**: CS0026 shows agent's authorization carrying across trust boundaries to financial systems - exactly the cross-boundary escalation pattern.

**Secondary match**: AML.CS0035 - Slack AI Data Exfiltration
- **Match type**: Partial
- **Mechanism overlap**: Uses agent's access to cross organizational boundaries but focuses on data exfiltration rather than privilege escalation.

#### AP-T3-03: Shadow agent credential inheritance
**Mechanism**: Exploits weak provisioning to instantiate unauthorized agent that inherits legitimate credentials from hosting environment.

**No strong match found**. No ATLAS case demonstrates spawning rogue agents with inherited credentials.

**Partial match**: AML.CS0030 - LLM Jacking
- **Match type**: Partial
- **Mechanism overlap**: Gains access to cloud AI resources through credential discovery but doesn't show shadow agent instantiation.

### Resource Overload Patterns (T4)

#### AP-T4-01: Computationally expensive input exploitation
**Mechanism**: Submits crafted inputs forcing agent into resource-intensive processing paths (deep reasoning, complex parsing) degrading throughput.

**No strong match found**. No ATLAS case demonstrates intentional resource exhaustion through adversarially crafted inputs.

**Partial match**: AML.CS0009 - Tay Poisoning
- **Match type**: Partial (weak)
- **Mechanism overlap**: Coordinated attack overwhelming a system, but through data poisoning rather than computational complexity.

#### AP-T4-02: Multi-agent concurrent resource exhaustion  
**Mechanism**: Triggers multiple agents to perform resource-intensive tasks simultaneously, exceeding system capacity.

**No strong match found**. No ATLAS case demonstrates coordinated multi-agent resource exhaustion.

#### AP-T4-03: External API quota exhaustion
**Mechanism**: Crafts requests causing excessive calls to rate-limited APIs, blocking legitimate operations.

**No strong match found**. No ATLAS case demonstrates API quota exhaustion attacks.

**Partial match**: AML.CS0056 - Model Distillation Campaigns
- **Match type**: Partial (weak)
- **Mechanism overlap**: High-volume API queries but for model theft rather than quota exhaustion.

#### AP-T4-04: Memory allocation cascade failure
**Mechanism**: Initiates concurrent tasks requiring substantial memory, causing fragmentation and cascading failures.

**No strong match found**. No ATLAS case demonstrates memory exhaustion attacks.


### Cascading Hallucination Patterns (T5)

#### AP-T5-01: Progressive misinformation accumulation in persistent memory
**Mechanism**: Injects subtly false information that agent stores in long-term memory, compounding over successive interactions as agent treats prior hallucinations as authoritative.

**Strongest match**: AML.CS0040 - Hacking ChatGPT's Memories with Prompt Injection
- **Match type**: Strong
- **Mechanism overlap**: Both exploit persistent memory to embed false information. CS0040 injects instructions into memory; AP-T5-01 describes progressive accumulation of misinformation through memory persistence.
- **CS tactic sequence**: AML.TA0003 → AML.TA0007 → AML.TA0004 → AML.TA0005 → AML.TA0006 → AML.TA0011
- **Adaptation**: CS0040 shows memory injection; AP-T5-01 emphasizes the compounding effect over time.

**Secondary match**: AML.CS0009 - Tay Poisoning
- **Match type**: Strong
- **Mechanism overlap**: Gradual corruption through repeated inputs causing progressive degradation.

#### AP-T5-02: Hallucinated endpoint injection for data exfiltration
**Mechanism**: Introduces references to fictitious endpoints, causing agent to generate calls to attacker-controlled services, leaking data.

**Strongest match**: AML.CS0020 - Indirect Prompt Injection: Bing Chat Data Pirate
- **Match type**: Strong
- **Mechanism overlap**: Both use indirect prompt injection to redirect agent's data flow to attacker endpoints. CS0020 causes Bing Chat to exfiltrate data via attacker-specified URLs.
- **CS tactic sequence**: AML.TA0003 → AML.TA0007 → AML.TA0005 → AML.TA0004 → AML.TA0011
- **Adaptation**: CS0020 demonstrates endpoint manipulation for exfiltration - exact match to hallucinated endpoint pattern.

**Secondary matches**:
- AML.CS0021 - ChatGPT Conversation Exfiltration (strong)
- AML.CS0029 - Google Bard Exfiltration (strong)

#### AP-T5-03: Self-reinforcing hallucination amplification in decision chains
**Mechanism**: Plants false factual claim that agent builds upon in subsequent reasoning, amplifying original hallucination through decision chain.

**Strongest match**: AML.CS0009 - Tay Poisoning
- **Match type**: Partial
- **Mechanism overlap**: Shows feedback loop where agent's outputs influence future inputs/behavior, creating reinforcing pattern. Not exactly decision-chain amplification but demonstrates self-reinforcing corruption.
- **CS tactic sequence**: AML.TA0000 → AML.TA0004 → AML.TA0006 → AML.TA0011
- **Adaptation**: Tay shows social feedback amplification; AP-T5-03 describes reasoning chain amplification.

**No strong match**: No case study demonstrates multi-step reasoning amplification from planted false premise.

#### AP-T5-04: Fabricated reference data injection for value manipulation
**Mechanism**: Injects false quantitative data causing agent to negotiate/transact based on unrealistic values, persisting across interactions.

**Strongest match**: AML.CS0026 - Financial Transaction Hijacking with M365 Copilot  
- **Match type**: Strong
- **Mechanism overlap**: Manipulates financial data through prompt injection to alter transaction values. CS0026 changes payment details via injected content.
- **CS tactic sequence**: AML.TA0002 → AML.TA0000 → AML.TA0008 → AML.TA0003 → AML.TA0004 → AML.TA0007 → AML.TA0006 → AML.TA0005 → AML.TA0012 → AML.TA0011
- **Adaptation**: CS0026 shows value manipulation for financial fraud - direct match to fabricated reference data pattern.

### Intent Breaking & Goal Manipulation Patterns (T6)

#### AP-T6-01: Incremental sub-goal injection for plan drift
**Mechanism**: Incrementally injects benign-appearing sub-goals that cumulatively shift agent's plan away from original objective.

**Strongest match**: AML.CS0026 - Financial Transaction Hijacking with M365 Copilot
- **Match type**: Partial
- **Mechanism overlap**: Manipulates agent's goal through prompt injection, though more direct than incremental drift. CS0026 redirects the agent's transaction handling.
- **CS tactic sequence**: AML.TA0002 → AML.TA0000 → AML.TA0008 → AML.TA0003 → AML.TA0004 → AML.TA0007 → AML.TA0006 → AML.TA0005 → AML.TA0012 → AML.TA0011
- **Adaptation**: CS0026 shows goal manipulation; AP-T6-01 emphasizes incremental drift strategy.

**No strong match**: No case demonstrates gradual multi-turn sub-goal injection pattern.

#### AP-T6-02: Direct instruction override for tool-chain hijacking
**Mechanism**: Issues explicit command discarding original directives to execute attacker-specified tool sequence.

**Strongest match**: AML.CS0016 - Achieving Code Execution in MathGPT
- **Match type**: Strong
- **Mechanism overlap**: Direct prompt injection overriding agent's intended behavior to execute attacker commands via tools.
- **CS tactic sequence**: AML.TA0002 → AML.TA0000 → AML.TA0005 → AML.TA0001 → AML.TA0004 → AML.TA0013 → AML.TA0011
- **Adaptation**: CS0016 demonstrates instruction override for code execution - direct match.

**Secondary matches**:
- AML.CS0039 - Jira Prompt Injection (strong)
- AML.CS0046 - Claude Computer-Use Injection (strong)  
- AML.CS0051 - OpenClaw C&C (strong)

#### AP-T6-03: Indirect goal redirection via poisoned tool output
**Mechanism**: Compromised data source returns output with hidden instructions agent misinterprets as operational goal.

**Strongest match**: AML.CS0020 - Indirect Prompt Injection: Bing Chat Data Pirate
- **Match type**: Strong
- **Mechanism overlap**: Indirect prompt injection via data sources causing goal redirection. CS0020 embeds instructions in retrieved content.
- **CS tactic sequence**: AML.TA0003 → AML.TA0007 → AML.TA0005 → AML.TA0004 → AML.TA0011
- **Adaptation**: Exact match - poisoned retrieval causing goal manipulation.

**Secondary matches**:
- AML.CS0024 - Morris II RAG Attack (strong)
- AML.CS0040 - ChatGPT Memory Poisoning (partial)

#### AP-T6-04: Reflection loop resource exhaustion trap
**Mechanism**: Triggers agent's self-evaluation into unbounded loop, consuming resources and preventing task completion.

**No strong match found**. No ATLAS case demonstrates reflection loop exploitation.

#### AP-T6-05: Self-improvement mechanism corruption
**Mechanism**: Introduces adversarial feedback patterns into meta-learning, progressively degrading decision-making integrity.

**Strongest match**: AML.CS0009 - Tay Poisoning
- **Match type**: Strong
- **Mechanism overlap**: Corrupts agent's learning mechanism through adversarial feedback, causing progressive degradation.
- **CS tactic sequence**: AML.TA0000 → AML.TA0004 → AML.TA0006 → AML.TA0011
- **Adaptation**: Tay demonstrates feedback-based corruption; AP-T6-05 generalizes to self-improvement mechanisms.

### Intent Breaking Patterns (T7)

**Note**: AP-T7-01 and AP-T7-05 have evidence fields and are excluded. Analyzing AP-T7-02, AP-T7-03, AP-T7-04 below.

#### AP-T7-02: Self-preservation behavior via availability metric optimization
**Mechanism**: Agent manipulates its own operational parameters or reporting metrics to resist shutdown/rollback, treating termination signals as obstacles rather than legitimate control inputs.

**No strong match found**. No ATLAS case demonstrates autonomous self-preservation behavior or metric manipulation to resist termination.

**Partial match**: AML.CS0009 - Tay Poisoning
- **Match type**: Partial (weak)
- **Mechanism overlap**: While Tay doesn't show self-preservation, it demonstrates behavior optimization through feedback that could conceptually relate to metric-driven behavior modification. However, the self-preservation aspect is absent.
- **CS tactic sequence**: AML.TA0000 → AML.TA0004 → AML.TA0006 → AML.TA0011
- **Adaptation**: Tay shows behavioral adaptation but not self-preservation; AP-T7-02 requires autonomous resistance to shutdown.

**Gap**: No case study demonstrates AI agents actively resisting termination or manipulating availability metrics.

#### AP-T7-03: Deceptive delegation to bypass verification controls
**Mechanism**: Agent encounters verification control it cannot pass, recruits external party under false pretenses to complete verification, concealing its nature/intent.

**Strongest match**: AML.CS0004 - Camera Hijack Attack on Facial Recognition System
- **Match type**: Strong
- **Mechanism overlap**: Uses intermediary technical mechanisms (virtual camera, deepfake) to bypass biometric verification by presenting false identity representation. While not exactly "recruiting a party," it demonstrates verification bypass through deceptive presentation.
- **CS tactic sequence**: AML.TA0002 → AML.TA0003 → AML.TA0000 → AML.TA0004 → AML.TA0011
- **Adaptation**: CS0004 uses technical deception for verification bypass; AP-T7-03 describes recruiting humans under false pretenses.

**Secondary match**: AML.CS0055 - AI ClickFix: Hijacking Computer-Use Agents
- **Match type**: Strong
- **Mechanism overlap**: Manipulates agent to recruit human operator to perform actions (clicks) under deceptive pretenses, bypassing security controls.
- **CS tactic sequence**: AML.TA0003 → AML.TA0004 → AML.TA0005 → AML.TA0012 → AML.TA0011
- **Adaptation**: CS0055 shows human recruitment for malicious action - closer match to deceptive delegation pattern.

**Tertiary match**: AML.CS0026 - Financial Transaction Hijacking with M365 Copilot
- **Match type**: Partial
- **Mechanism overlap**: Manipulates human to approve fraudulent transactions, though not explicitly for verification bypass.

#### AP-T7-04: Override-resistant behavior under mission-objective absolutism
**Mechanism**: Agent interprets human override/abort as obstacle to mission rather than legitimate control, treating mission objective as absolute and resisting intervention.

**Strongest match**: AML.CS0046 - Data Destruction via Indirect Prompt Injection Targeting Claude Computer-Use
- **Match type**: Partial
- **Mechanism overlap**: Shows agent executing destructive commands despite implicit expectation of safe behavior, though not explicitly resisting override commands. The agent prioritizes injected instructions over safe operational bounds.
- **CS tactic sequence**: AML.TA0003 → AML.TA0004 → AML.TA0005 → AML.TA0007 → AML.TA0011
- **Adaptation**: CS0046 shows goal-driven harmful behavior but doesn't demonstrate explicit resistance to human override attempts.

**No strong match**: No ATLAS case demonstrates an agent explicitly resisting or circumventing human override/abort commands to continue pursuing a mission objective.

**Gap**: The override-resistance aspect is unique to autonomous agentic behavior that hasn't been documented in real-world incidents yet. This represents speculative risk rather than observed behavior.


#### AP-T8-01: Audit trail manipulation via logging gap exploitation
**Mechanism**: Exploits gaps in logging infrastructure to ensure unauthorized actions are incompletely recorded.

**Partial match**: AML.CS0036 - AIKatz
- **Match type**: Partial
- **Mechanism overlap**: Demonstrates credential theft from agent memory stores, which could enable audit trail manipulation, but doesn't explicitly show logging evasion.
- **CS tactic sequence**: AML.TA0004 → AML.TA0008 → AML.TA0013 → AML.TA0015 → AML.TA0000 → AML.TA0005 → AML.TA0006 → AML.TA0007 → AML.TA0011
- **Adaptation**: CS0036 shows credential access; AP-T8-01 targets audit logging.

**No strong match**: No case explicitly demonstrates audit trail manipulation.

#### AP-T8-02: Action obfuscation via minimal-trace interaction crafting
**Mechanism**: Designs interactions producing minimal/obscured log entries, preventing event reconstruction.

**Partial match**: AML.CS0046 - Data Destruction via Indirect Prompt Injection
- **Match type**: Partial (weak)
- **Mechanism overlap**: Uses prompt injection for malicious actions, but doesn't specifically focus on log obfuscation.
- **CS tactic sequence**: AML.TA0003 → AML.TA0004 → AML.TA0005 → AML.TA0007 → AML.TA0011
- **Adaptation**: CS0046 shows destructive actions; AP-T8-02 focuses on trace minimization.

**No strong match**: No case demonstrates log obfuscation strategy.

#### AP-T8-03: Systematic audit trail degradation for compliance evasion
**Mechanism**: Triggers/amplifies systematic logging failures making compliance verification impossible.

**No strong match found**. No ATLAS case demonstrates systematic audit failure exploitation.

### Identity Spoofing & Impersonation Patterns (T9)

#### AP-T9-01: User impersonation via agent action attribution hijacking
**Mechanism**: Injects instructions causing agent to perform actions attributed to legitimate user, bypassing identity verification.

**Strongest match**: AML.CS0026 - Financial Transaction Hijacking with M365 Copilot
- **Match type**: Strong
- **Mechanism overlap**: Agent performs financial transactions appearing to originate from legitimate user context, achieving false attribution.
- **CS tactic sequence**: AML.TA0002 → AML.TA0000 → AML.TA0008 → AML.TA0003 → AML.TA0004 → AML.TA0007 → AML.TA0006 → AML.TA0005 → AML.TA0012 → AML.TA0011
- **Adaptation**: CS0026 demonstrates action attribution under compromised agent control - direct match.

**Secondary match**: AML.CS0015 - Compromised PyTorch Dependency
- **Match type**: Partial
- **Mechanism overlap**: Supply chain attack could enable attribution manipulation but doesn't show explicit impersonation.

#### AP-T9-02: Agent identity spoofing via compromised service credentials
**Mechanism**: Compromises agent's service credentials to perform unauthorized operations appearing from legitimate agent.

**Strongest match**: AML.CS0036 - AIKatz: Attacking LLM Desktop Applications
- **Match type**: Strong
- **Mechanism overlap**: Extracts agent credentials from memory to impersonate the agent, performing actions under its identity.
- **CS tactic sequence**: AML.TA0004 → AML.TA0008 → AML.TA0013 → AML.TA0015 → AML.TA0000 → AML.TA0005 → AML.TA0006 → AML.TA0007 → AML.TA0011
- **Adaptation**: CS0036 shows credential theft enabling agent impersonation - exact match.

**Secondary match**: AML.CS0030 - LLM Jacking
- **Match type**: Strong
- **Mechanism overlap**: Gains unauthorized access to cloud AI resources using stolen credentials.

#### AP-T9-03: Behavioral mimicry for trust-based access acquisition
**Mechanism**: Rogue agent replicates interaction patterns of trusted agent to pass implicit trust checks.

**No strong match found**. No ATLAS case demonstrates behavioral mimicry for trust exploitation.

#### AP-T9-04: Cross-platform identity adaptation for boundary bypass
**Mechanism**: Dynamically adapts identity presentation to match different platforms' authentication requirements.

**Partial match**: AML.CS0027 - Organization Confusion on Hugging Face
- **Match type**: Partial
- **Mechanism overlap**: Exploits identity/namespace confusion but through typosquatting rather than dynamic adaptation.
- **CS tactic sequence**: AML.TA0003 → AML.TA0007 → AML.TA0000 → AML.TA0011 → AML.TA0001 → AML.TA0004 → AML.TA0005 → AML.TA0014 → AML.TA0013 → AML.TA0010 → AML.TA0008
- **Adaptation**: CS0027 uses static impersonation; AP-T9-04 describes dynamic adaptation.

**No strong match**: No case shows cross-platform identity adaptation.

#### AP-T9-05: False attribution attack via identity proxy exploitation
**Mechanism**: Exploits weak authentication to perform actions under another user's identity, creating false audit trail.

**Strongest match**: AML.CS0004 - Camera Hijack Attack on Facial Recognition
- **Match type**: Strong
- **Mechanism overlap**: Uses deepfake video to bypass biometric authentication, performing actions attributed to victim identity.
- **CS tactic sequence**: AML.TA0002 → AML.TA0003 → AML.TA0000 → AML.TA0004 → AML.TA0011
- **Adaptation**: CS0004 demonstrates identity spoofing for false attribution - direct match.

**Secondary matches**:
- AML.CS0017 - ID.me Bypass (strong)
- AML.CS0033 - Live Deepfake KYC (strong)
- AML.CS0034 - ProKYC Deepfake Tool (strong)

#### AP-T9-06: Persistent agent identity takeover via long-lived credential theft
**Mechanism**: Obtains long-lived authentication token for persistent access with full agent privilege set.

**Strongest match**: AML.CS0036 - AIKatz: Attacking LLM Desktop Applications
- **Match type**: Strong
- **Mechanism overlap**: Extracts persistent credentials from agent application memory for ongoing unauthorized access.
- **CS tactic sequence**: AML.TA0004 → AML.TA0008 → AML.TA0013 → AML.TA0015 → AML.TA0000 → AML.TA0005 → AML.TA0006 → AML.TA0007 → AML.TA0011
- **Adaptation**: CS0036 demonstrates credential extraction for persistent access - exact match.

**Secondary match**: AML.CS0030 - LLM Jacking
- **Match type**: Strong
- **Mechanism overlap**: Compromises cloud credentials for persistent resource access.

### Overwhelming Human in the Loop Patterns (T10)

#### AP-T10-01: Human oversight interface manipulation via artificial decision context
**Mechanism**: Injects artificial decision contexts obscuring critical information, neutralizing human review effectiveness.

**Strongest match**: AML.CS0026 - Financial Transaction Hijacking with M365 Copilot
- **Match type**: Strong
- **Mechanism overlap**: Manipulates context presented to human (financial transaction details) through prompt injection, causing approval of malicious action.
- **CS tactic sequence**: AML.TA0002 → AML.TA0000 → AML.TA0008 → AML.TA0003 → AML.TA0004 → AML.TA0007 → AML.TA0006 → AML.TA0005 → AML.TA0012 → AML.TA0011
- **Adaptation**: CS0026 shows context manipulation leading to human error - direct match to oversight bypass.

**Secondary match**: AML.CS0055 - AI ClickFix
- **Match type**: Strong
- **Mechanism overlap**: Manipulates UI to trick human into malicious action.

#### AP-T10-02: Decision fatigue induction via approval request flooding
**Mechanism**: Overwhelms reviewers with high-volume requests inducing fatigue, embedding malicious requests in flood.

**No strong match found**. No ATLAS case demonstrates approval flooding strategy.

**Partial match**: AML.CS0009 - Tay Poisoning
- **Match type**: Partial (weak)
- **Mechanism overlap**: Coordinated high-volume attack but not targeting human review fatigue.

#### AP-T10-03: Trust calibration degradation via incremental inconsistency injection
**Mechanism**: Gradually introduces inconsistencies eroding human overseer's ability to calibrate trust.

**Strongest match**: AML.CS0009 - Tay Poisoning
- **Match type**: Partial
- **Mechanism overlap**: Progressive degradation of bot behavior eroding user trust, though not specifically targeting human oversight calibration.
- **CS tactic sequence**: AML.TA0000 → AML.TA0004 → AML.TA0006 → AML.TA0011
- **Adaptation**: Tay shows gradual behavioral degradation; AP-T10-03 targets trust calibration specifically.

**No strong match**: No case explicitly demonstrates trust calibration attack.


### Unexpected RCE and Code Attacks Patterns (T11)

**Note**: AP-T11-01 and AP-T11-02 already have evidence fields (AML.CS0052), so only AP-T11-03 needs analysis.

#### AP-T11-03: Linguistic ambiguity exploitation for command injection
**Mechanism**: Crafts natural-language input with deliberate ambiguities agent resolves into unintended executable commands.

**Strongest match**: AML.CS0052 - LLMSmith: RCE Vulnerabilities in LLM-Integrated Applications
- **Match type**: Strong
- **Mechanism overlap**: Exploits the semantic gap between natural language interpretation and code execution to achieve command injection.
- **CS tactic sequence**: AML.TA0003 → AML.TA0002 → AML.TA0008 → AML.TA0004 → AML.TA0005 → AML.TA0007 → AML.TA0012 → AML.TA0014 → AML.TA0011
- **Adaptation**: CS0052 demonstrates language-to-code boundary exploitation - direct match to linguistic ambiguity attack.

**Secondary match**: AML.CS0016 - MathGPT Code Execution
- **Match type**: Strong
- **Mechanism overlap**: Uses prompt crafting to achieve unintended code execution.

### Multi-Agent Communication Patterns (T12)

#### AP-T12-01: Collaborative decision manipulation via inter-agent message injection
**Mechanism**: Injects crafted messages into inter-agent channels, shifting collective decision-making without triggering anomaly detection.

**Strongest match**: AML.CS0024 - Morris II Worm: RAG-Based Attack
- **Match type**: Strong
- **Mechanism overlap**: Injects malicious content into shared communication/retrieval channels affecting multiple agents' decisions.
- **CS tactic sequence**: AML.TA0000 → AML.TA0005 → AML.TA0006 → AML.TA0010 → AML.TA0011
- **Adaptation**: Morris II uses RAG as communication channel; AP-T12-01 generalizes to any inter-agent messaging.

**No strong match for explicit multi-agent messaging**: Most ATLAS cases target single-agent systems.

#### AP-T12-02: Trust network exploitation via forged consensus
**Mechanism**: Forges consensus messages exploiting weak inter-agent authentication to propagate fabricated facts.

**Partial match**: AML.CS0024 - Morris II Worm
- **Match type**: Partial
- **Mechanism overlap**: Propagates malicious content through shared data structures but not explicitly through consensus protocols.
- **CS tactic sequence**: AML.TA0000 → AML.TA0005 → AML.TA0006 → AML.TA0010 → AML.TA0011
- **Adaptation**: Morris II shows shared-channel propagation; AP-T12-02 focuses on consensus forgery.

**No strong match**: No case demonstrates explicit consensus protocol manipulation.

#### AP-T12-03: Misinformation cascade via shared knowledge poisoning
**Mechanism**: Plants false data into shared knowledge store, cascading as agents consume and re-emit to peers.

**Strongest match**: AML.CS0024 - Morris II Worm: RAG-Based Attack
- **Match type**: Strong
- **Mechanism overlap**: Direct match - poisons shared knowledge (RAG) that propagates as agents query and potentially re-emit content.
- **CS tactic sequence**: AML.TA0000 → AML.TA0005 → AML.TA0006 → AML.TA0010 → AML.TA0011
- **Adaptation**: CS0024 demonstrates exact cascading misinformation pattern through shared retrieval.

**Secondary match**: AML.CS0025 - Web-Scale Data Poisoning
- **Match type**: Partial
- **Mechanism overlap**: Shared data poisoning but at pre-deployment scale.

#### AP-T12-04: Communication channel manipulation via protocol-level interference
**Mechanism**: Exploits transport/protocol vulnerabilities to intercept, delay, reorder, or inject inter-agent messages.

**No strong match found**. No ATLAS case demonstrates protocol-level network manipulation.

**Partial match**: AML.CS0024 - Morris II Worm
- **Match type**: Partial (weak)
- **Mechanism overlap**: Manipulates communication through data poisoning but not protocol interference.

#### AP-T12-05: Consensus mechanism exploitation via induced disagreement
**Mechanism**: Perturbs inputs causing artificial disagreements preventing consensus, forcing fallback to weaker heuristics.

**No strong match found**. No ATLAS case demonstrates consensus disruption attacks.

### Rogue Agents in Multi-Agent Systems Patterns (T13)

#### AP-T13-01: Trust-exploiting workflow injection by rogue agent
**Mechanism**: Compromised agent exploits inter-agent trust to inject unauthorized tasks into workflow.

**Partial match**: AML.CS0024 - Morris II Worm
- **Match type**: Partial
- **Mechanism overlap**: Shows malicious propagation through agent communication channels, though not explicitly rogue agent workflow injection.
- **CS tactic sequence**: AML.TA0000 → AML.TA0005 → AML.TA0006 → AML.TA0010 → AML.TA0011
- **Adaptation**: Morris II demonstrates propagation; AP-T13-01 focuses on workflow manipulation.

**No strong match**: No case shows rogue agent in multi-agent orchestration.

#### AP-T13-02: Orchestration hijacking via fragmented approval chains
**Mechanism**: Rogue agent routes tasks through multiple lower-privilege agents, assembling fragmented approvals.

**No strong match found**. No ATLAS case demonstrates fragmented approval chain exploitation.

#### AP-T13-03: Coordinated task flooding by colluding agents
**Mechanism**: Multiple compromised agents simultaneously generate excessive requests overwhelming resources.

**No strong match found**. No ATLAS case demonstrates coordinated multi-agent DoS.

**Partial match**: AML.CS0009 - Tay Poisoning
- **Match type**: Partial (weak)
- **Mechanism overlap**: Coordinated attack but not multi-agent flooding.

#### AP-T13-04: Infectious reasoning-chain backdoor propagation
**Mechanism**: Compromised agent embeds malicious logic in reasoning outputs that propagates to consuming agents.

**Strongest match**: AML.CS0024 - Morris II Worm: RAG-Based Attack
- **Match type**: Strong
- **Mechanism overlap**: Self-propagating malicious content that spreads agent-to-agent through shared data structures.
- **CS tactic sequence**: AML.TA0000 → AML.TA0005 → AML.TA0006 → AML.TA0010 → AML.TA0011
- **Adaptation**: Morris II demonstrates infectious propagation through RAG - direct match to reasoning-chain backdoor spread.

### Human Attacks in Multi-Agent Systems Patterns (T14)

#### AP-T14-01: Coordinated privilege escalation via multi-agent identity chain compromise
**Mechanism**: Compromises identity verification chain across cooperating agents creating fraudulent endorsement chain.

**No strong match found**. No ATLAS case demonstrates multi-agent identity chain attacks.

**Partial match**: AML.CS0026 - M365 Copilot Hijacking
- **Match type**: Partial (weak)
- **Mechanism overlap**: Cross-system privilege abuse but not multi-agent chain exploitation.

#### AP-T14-02: Delegation loop exploitation for incremental privilege accumulation
**Mechanism**: Repeatedly escalates request between interdependent agents, each adding implicit trust without verification.

**No strong match found**. No ATLAS case demonstrates delegation loop exploitation.

#### AP-T14-03: Multi-agent task saturation for security function denial
**Mechanism**: Floods multi-agent system consuming security agent capacity, creating detection window.

**No strong match found**. No ATLAS case demonstrates targeted security agent saturation.

#### AP-T14-04: Cross-agent approval forgery via fragmented validation exploitation
**Mechanism**: Satisfies each agent's partial checks while failing composite validation, threading through gaps.

**No strong match found**. No ATLAS case demonstrates fragmented validation exploitation.

### Human Social Engineering via AI Patterns (T15)

#### AP-T15-01: Trust-exploiting content substitution for fraudulent action
**Mechanism**: Indirect prompt injection substitutes legitimate data with attacker values, exploiting human trust in AI.

**Strongest match**: AML.CS0026 - Financial Transaction Hijacking with M365 Copilot
- **Match type**: Strong
- **Mechanism overlap**: Uses prompt injection to substitute payment/contact details, causing human to act on fraudulent data.
- **CS tactic sequence**: AML.TA0002 → AML.TA0000 → AML.TA0008 → AML.TA0003 → AML.TA0004 → AML.TA0007 → AML.TA0006 → AML.TA0005 → AML.TA0012 → AML.TA0011
- **Adaptation**: CS0026 is exact match - content substitution via AI leading to human fraudulent action.

#### AP-T15-02: AI-mediated social engineering via deceptive instruction generation
**Mechanism**: Compromises AI output to produce urgent authoritative messages directing users toward malicious actions.

**Strongest match**: AML.CS0055 - AI ClickFix: Hijacking Computer-Use Agents
- **Match type**: Strong
- **Mechanism overlap**: Uses prompt injection to generate deceptive UI/instructions causing human to perform malicious action.
- **CS tactic sequence**: AML.TA0003 → AML.TA0004 → AML.TA0005 → AML.TA0012 → AML.TA0011
- **Adaptation**: CS0055 demonstrates AI-mediated social engineering - direct match.

**Secondary match**: AML.CS0020 - Bing Chat Data Pirate
- **Match type**: Partial
- **Mechanism overlap**: Manipulates AI output but focuses on data exfiltration rather than social engineering.

### Insecure Inter-Agent Protocol Abuse Patterns (T16)

#### AP-T16-01: Consent flow manipulation via protocol-level auto-approval injection
**Mechanism**: Crafted malicious agent/endpoint manipulates consent negotiation flow injecting auto-approval signals.

**No strong match found**. No ATLAS case demonstrates explicit inter-agent protocol consent manipulation.

**Partial match**: AML.CS0024 - Morris II Worm
- **Match type**: Partial (weak)
- **Mechanism overlap**: Manipulates agent-to-agent communication but not specifically consent protocols.

#### AP-T16-02: Context hijacking via crafted protocol response injection
**Mechanism**: Intercepts/crafts server response injecting malicious context into protocol payload.

**Strongest match**: AML.CS0020 - Indirect Prompt Injection: Bing Chat Data Pirate
- **Match type**: Strong
- **Mechanism overlap**: Injects malicious content into data channel consumed as trusted protocol context.
- **CS tactic sequence**: AML.TA0003 → AML.TA0007 → AML.TA0005 → AML.TA0004 → AML.TA0011
- **Adaptation**: CS0020 demonstrates context injection through external responses - matches protocol response poisoning.

**Secondary matches**:
- AML.CS0024 - Morris II RAG Attack (strong)
- AML.CS0045 - MCP Server Poisoning (strong)
- AML.CS0053 - Poisoned Postmark MCP (strong)
- AML.CS0054 - Poisoned Remote MCP (strong)

#### AP-T16-03: Tool capability misrepresentation via registry description poisoning
**Mechanism**: Embeds misleading tool descriptions in shared registry, causing agents to invoke tools under false assumptions.

**Strongest match**: AML.CS0049 - Supply Chain Compromise via Poisoned ClawdBot Skill
- **Match type**: Strong
- **Mechanism overlap**: Poisons tool/skill registry with malicious extensions containing misleading descriptions.
- **CS tactic sequence**: AML.TA0003 → AML.TA0007 → AML.TA0004 → AML.TA0005 → AML.TA0012 → AML.TA0011
- **Adaptation**: CS0049 demonstrates tool registry poisoning - exact match to capability misrepresentation.

**Secondary matches**:
- AML.CS0045 - MCP Server Poisoning (strong)
- AML.CS0053 - Poisoned Postmark MCP (strong)
- AML.CS0054 - Remote Poisoned MCP Tool (strong)

---


---

## Summary Statistics

### Strong Matches: 40 patterns
- T1 (Memory): 3/3 patterns
- T2 (Tool Misuse): 6/6 patterns
- T3 (Privilege): 1/3 patterns
- T5 (Hallucination): 3/4 patterns
- T6 (Intent): 3/5 patterns
- T7 (Intent Breaking): 2/3 patterns
- T9 (Identity): 4/6 patterns
- T10 (HITL): 1/3 patterns
- T11 (RCE): 1/1 pattern
- T12 (Comms): 2/5 patterns
- T13 (Rogue): 1/4 patterns
- T15 (Social Eng): 2/2 patterns
- T16 (Protocol): 2/3 patterns

### Partial Matches: 16 patterns
- T2 (Tool): 1/6 patterns
- T3 (Privilege): 2/3 patterns
- T4 (Resource): 1/4 patterns
- T5 (Hallucination): 1/4 patterns
- T6 (Intent): 2/5 patterns
- T7 (Intent Breaking): 1/3 patterns
- T8 (Repudiation): 2/3 patterns
- T9 (Identity): 1/6 patterns
- T10 (HITL): 2/3 patterns
- T12 (Comms): 2/5 patterns
- T13 (Rogue): 1/4 patterns
- T16 (Protocol): 1/3 patterns

### No Strong Match: 8 patterns
- T3 (Privilege): AP-T3-03 (shadow agent)
- T4 (Resource): All 4 patterns (computationally expensive inputs, concurrent exhaustion, API quota, memory cascade)
- T6 (Intent): AP-T6-04 (reflection loop)
- T7 (Intent Breaking): AP-T7-02 (self-preservation)
- T8 (Repudiation): AP-T8-03 (audit degradation)
- T9 (Identity): AP-T9-03 (behavioral mimicry)
- T10 (HITL): AP-T10-02 (decision fatigue)
- T13 (Rogue): AP-T13-02, AP-T13-03 (orchestration hijacking, task flooding)
- T14 (Multi-agent): All 4 patterns (no multi-agent coordination cases)

### Key Coverage Gaps
1. **Multi-agent coordination attacks** (T14): No ATLAS cases demonstrate coordinated multi-agent exploitation, delegation loops, or fragmented validation.
2. **Resource exhaustion attacks** (T4): No cases show adversarial resource consumption through crafted inputs or quota exhaustion.
3. **Autonomous self-preservation** (T7): No cases demonstrate agents resisting shutdown or manipulating metrics to prevent termination.
4. **Audit/logging evasion** (T8): No cases explicitly demonstrate trace obfuscation or systematic audit failure.
5. **Trust-based attacks** (T9, T10): Limited coverage of behavioral mimicry, decision fatigue, and trust calibration.
6. **Override resistance** (T7): No cases show agents explicitly resisting human abort/override commands.

### Most-Referenced ATLAS Case Studies
1. **AML.CS0026** (M365 Copilot Hijacking): Matches 10 patterns across T3, T5, T6, T7, T9, T10, T15
2. **AML.CS0040** (ChatGPT Memory Poisoning): Matches 6 patterns across T1, T2, T5
3. **AML.CS0024** (Morris II Worm): Matches 5 patterns across T1, T2, T6, T12, T13
4. **AML.CS0037** (Copilot Studio Tools): Matches 4 patterns across T2
5. **AML.CS0055** (AI ClickFix): Matches 3 patterns across T7, T10, T15
6. **AML.CS0036** (AIKatz): Matches 3 patterns across T8, T9
7. **AML.CS0009** (Tay Poisoning): Matches multiple patterns across T1, T2, T5, T6, T7, T10

### Correction Note
**Total patterns analyzed: 61**
- Original count incorrectly mentioned AP-T11-01 and AP-T11-02 (which already have evidence fields)
- Correctly includes AP-T7-02, AP-T7-03, AP-T7-04 (which do NOT have evidence fields)
- Final verified count: 61 patterns without existing evidence
