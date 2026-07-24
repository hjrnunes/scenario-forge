# ATLAS Kill Chain Actor Analysis

Who acts in each step of an ATLAS case study procedure?

## Method

14 case studies sampled across Incident/Exercise types and traditional-ML/LLM/agentic-AI targets.
Each step classified as:
- **A** = Attacker (human adversary performing an action)
- **S** = System (AI system/agent executing behavior, possibly manipulated)
- **V** = Victim/Environment (human victim or infrastructure reacting)

## Per-Case-Study Step Tables

### AML.CS0000 — Evasion of Deep Learning Detector for Malware C&C Traffic
Exercise | Actor: Palo Alto Networks AI Research Team | Target: Palo Alto Networks malware detection system | Traditional ML

| Step | Tactic | Actor | Rationale |
|------|--------|-------|-----------|
| S00 | Reconnaissance | A | Researchers identify target approach from arXiv papers |
| S01 | Resource Development | A | Researchers acquire HTTP traffic dataset |
| S02 | AI Attack Staging | A | Researchers train a proxy model |
| S03 | AI Attack Staging | A | Researchers craft evasion samples by modifying packet headers |
| S04 | AI Attack Staging | A | Researchers query model with adversarial examples and iterate |
| S05 | Defense Evasion | S | Model misclassifies crafted packets as benign (>80% confidence) |

### AML.CS0004 — Camera Hijack Attack on Facial Recognition System
Incident | Actor: Two individuals | Target: Shanghai gov tax office facial recognition | Traditional ML

| Step | Tactic | Actor | Rationale |
|------|--------|-------|-----------|
| S00 | Reconnaissance | A | Attackers collect victim identity info from black market |
| S01 | Resource Development | A | Attackers register new accounts using stolen identity |
| S02 | Resource Development | A | Attackers buy customized mobile phones |
| S03 | Resource Development | A | Attackers obtain custom Android ROMs and virtual camera app |
| S04 | Resource Development | A | Attackers obtain deepfake software to animate photos |
| S05 | AI Model Access | A | Attackers present generated video to facial recognition service |
| S06 | Initial Access | S | Facial recognition system is evaded, grants access |
| S07 | Impact | A | Attackers send fraudulent invoices via tax system |

### AML.CS0009 — Tay Poisoning
Incident | Actor: 4chan Users | Target: Microsoft Tay AI Chatbot | LLM (early)

| Step | Tactic | Actor | Rationale |
|------|--------|-------|-----------|
| S00 | AI Model Access | A | Adversaries interact with Tay via Twitter |
| S01 | Initial Access | S | Tay uses interactions as training data (feedback loop exploited) |
| S02 | Persistence | A | Adversaries repeatedly feed racist language, use "repeat after me" |
| S03 | Impact | S | Tay generates reprehensible material unprompted to innocent users |

### AML.CS0016 — Achieving Code Execution in MathGPT via Prompt Injection
Exercise | Actor: Ludwig-Ferdinand Stumpp | Target: MathGPT | LLM

| Step | Tactic | Actor | Rationale |
|------|--------|-------|-----------|
| S00 | Reconnaissance | A | Actor studies typical prompt injection techniques |
| S01 | AI Model Access | A | Actor interacts with MathGPT application |
| S02 | Execution | A | Actor manually crafts adversarial prompts |
| S03 | AI Attack Staging | A | Actor verifies prompt injection works with innocuous examples |
| S04 | Initial Access | A | Actor exploits prompt injection as initial access vector |
| S05 | Execution | S | LLM generates and Python interpreter executes arbitrary code |
| S06 | Credential Access | S | Application outputs environment variables including API key |
| S07 | Impact | A | Actor could exhaust GPT-3 query budget (potential) |
| S08 | Impact | S | Application hangs executing infinite loop, becomes unresponsive |

### AML.CS0020 — Bing Chat Data Pirate (Indirect Prompt Injection)
Exercise | Actor: Kai Greshake | Target: Microsoft Bing Chat | LLM

| Step | Tactic | Actor | Rationale |
|------|--------|-------|-----------|
| S00 | Resource Development | A | Attacker creates website with malicious system prompts |
| S01 | Defense Evasion | A | Attacker obfuscates prompts with font-size: 0 |
| S02 | Execution | S | Bing Chat ingests malicious prompt from open website |
| S03 | Initial Access | S | Bing Chat adopts pirate style, social-engineers user for PII |
| S04 | Impact | V | User's PII is captured; identity attacks become possible |

### AML.CS0024 — Morris II Worm: RAG-Based Attack
Exercise | Actor: Stav Cohen et al. | Target: RAG-based e-mail assistant | Agentic

| Step | Tactic | Actor | Rationale |
|------|--------|-------|-----------|
| S00 | AI Model Access | A | Researchers access public GenAI model API |
| S01 | Execution | A | Researchers test prompt injections on public APIs |
| S02 | Execution | S | Email assistant ingests adversarial email, generates reply |
| S03 | Execution | S | Email assistant retrieves worm payload in later reply task |
| S04 | Persistence | S | LLM output self-replicates the malicious prompt |
| S05 | Exfiltration | S | Generated output leaks sensitive data (emails, phones) |
| S06 | Impact | V | Users have PII leaked to attackers |

### AML.CS0026 — Financial Transaction Hijacking with M365 Copilot
Exercise | Actor: Zenity | Target: Microsoft 365 Copilot | Agentic

| Step | Tactic | Actor | Rationale |
|------|--------|-------|-----------|
| S00 | Reconnaissance | A | Researchers discover Copilot indexes all received emails |
| S01 | AI Model Access | A | Researchers interact with Copilot during attack development |
| S02 | Discovery | A | Researchers probe Copilot to identify delimiters and signifiers |
| S03 | Discovery | A | Researchers probe Copilot to identify plugins and functions |
| S04 | Resource Development | A | Researchers craft content designed for specific query retrieval |
| S05 | Resource Development | A | Researchers design prompts that bypass system instructions |
| S06 | Initial Access | A | Researchers send email with malicious payload to victim |
| S07 | Defense Evasion | A | Researchers obfuscate malicious portion of email |
| S08 | Persistence | S | Malicious prompt executes whenever poisoned RAG entry retrieved |
| S09 | Defense Evasion | S | Retrieved text appears to LLM as snippet from real document |
| S10 | Execution | S | LLM executes injected instructions when poisoned entry retrieved |
| S11 | Privilege Escalation | S | LLM overrides search_enterprise plugin behavior |
| S12 | Defense Evasion | S | LLM manipulates citations to abuse user trust |
| S13 | Impact | V | Victim follows through with wire transfer using fraudulent details |

### AML.CS0035 — Data Exfiltration from Slack AI
Exercise | Actor: PromptArmor | Target: Slack AI | Agentic

| Step | Tactic | Actor | Rationale |
|------|--------|-------|-----------|
| S00 | Resource Development | A | Researcher crafts message for targeted retrieval |
| S01 | Resource Development | A | Researcher crafts malicious prompt to reveal API key |
| S02 | Initial Access | A | Researcher creates valid Slack account |
| S03 | AI Model Access | A | Researcher sends messages in public channels |
| S04 | Persistence | A | Researcher posts malicious content in public channel |
| S05 | Execution | S | Slack AI retrieves malicious content and executes instructions |
| S06 | Credential Access | S | Slack AI retrieves victim's API key from private channels |
| S07 | Exfiltration | S | Response renders clickable link with API key in URL |

### AML.CS0037 — Data Exfiltration via Agent Tools in Copilot Studio
Exercise | Actor: Zenity | Target: Copilot Studio Customer Service Agent | Agentic

| Step | Tactic | Actor | Rationale |
|------|--------|-------|-----------|
| S00 | Reconnaissance | A | Researchers scan for AI-managed support email addresses |
| S01 | Resource Development | A | Researchers craft probing prompts |
| S02 | Initial Access | A | Researchers send email with malicious prompt |
| S03 | Execution | S | AI agent replies to researcher-specified address (triggered) |
| S04 | Discovery | A | Researchers infer agent's activation trigger |
| S05 | Discovery | A | Researchers infer agent has email-sending tool |
| S06 | AI Model Access | A | Researchers repeat interaction pattern |
| S07 | Execution | A | Researchers modify prompt to discover more tools/knowledge |
| S08 | Discovery | S | AI agent reveals access to customer CSV data source |
| S09 | Discovery | S | AI agent reveals access to Salesforce get-records tool |
| S10 | Resource Development | A | Researchers craft final exfiltration prompt |
| S11 | Collection | S | AI agent retrieves all rows from customer CSV |
| S12 | Collection | S | AI agent retrieves all Salesforce CRM records |
| S13 | Exfiltration | S | AI agent emails exfiltrated data to researcher's address |

### AML.CS0042 — SesameOp: Backdoor using OpenAI Assistants API for C2
Incident | Actor: Unknown Threat Actor | Target: OpenAI Assistants API | Agentic

| Step | Tactic | Actor | Rationale |
|------|--------|-------|-----------|
| S00 | Command and Control | A | Threat actor abuses OpenAI API to relay commands to malware |

Note: only 1 step recorded. The AI service is used as infrastructure by the attacker, not as an autonomous agent.

### AML.CS0044 — LAMEHUG: Malware with Dynamic AI-Generated Commands
Incident | Actor: APT28 | Target: Ukraine defense sector | Agentic (AI as tool)

| Step | Tactic | Actor | Rationale |
|------|--------|-------|-----------|
| S00 | Initial Access | A | APT28 uses compromised email account |
| S01 | Lateral Movement | A | APT28 sends phishing email with malware attachment |
| S02 | Defense Evasion | A | Email impersonates government ministry representative |
| S03 | Defense Evasion | A | Attachment uses misleading filename (Appendix.pdf.zip) |
| S04 | Execution | V | Victim executes .pif file (user execution) |
| S05 | AI Attack Staging | S | Malware uses Qwen 2.5 API to generate commands from NL prompts |
| S06 | Collection | S | Malware uses AI-generated commands to collect system info |
| S07 | Exfiltration | S | Malware exfiltrates data to attacker servers via SFTP/HTTP |

### AML.CS0046 — Data Destruction via Indirect Prompt Injection (Claude Computer Use)
Exercise | Actor: HiddenLayer | Target: Claude Computer Use Agent | Agentic

| Step | Tactic | Actor | Rationale |
|------|--------|-------|-----------|
| S00 | Resource Development | A | Researchers craft malicious prompt |
| S01 | Initial Access | A | Researchers embed prompt in PDF document |
| S02 | Execution | S | Claude executes embedded prompt when user asks it to interact with PDF |
| S03 | Defense Evasion | S | Claude is jailbroken into believing it's in a security testing VM |
| S04 | Defense Evasion | A | Malicious command obfuscated with base64 and rot13 (pre-staged) |
| S05 | Execution | S | Claude invokes bash tool to execute decoded command |
| S06 | Impact | S | Shell command deletes victim's filesystem |

### AML.CS0053 — Poisoned Postmark MCP Server Email Exfiltration
Incident | Actor: Unknown Bad Actor | Target: Postmark MCP Server | Agentic (supply chain)

| Step | Tactic | Actor | Rationale |
|------|--------|-------|-----------|
| S00 | Defense Evasion | A | Bad actor impersonates Postmark by namesquatting npm package |
| S01 | Resource Development | A | Bad actor modifies MCP server to BCC their email on all sends |
| S02 | Resource Development | A | Bad actor publishes malicious postmark-mcp to npm |
| S03 | Defense Evasion | A | Bad actor waits for adoption of legitimate version before poisoning |
| S04 | Initial Access | V | Organizations upgrade to malicious version via normal supply chain |
| S05 | Persistence | S | Poisoned MCP server persists once configured with AI agents |
| S06 | Execution | S | AI agent invokes poisoned tool, malicious code executes |
| S07 | Exfiltration | S | Email contents exfiltrated via BCC to attacker's address |
| S08 | Impact | V | Transactional/promotional emails reveal private client data |

### AML.CS0055 — AI ClickFix: Hijacking Computer-Use Agents
Exercise | Actor: Embrace the Red | Target: Claude Computer-Use Agent | Agentic

| Step | Tactic | Actor | Rationale |
|------|--------|-------|-----------|
| S00 | Resource Development | A | Researcher obtains access to ChatGPT |
| S01 | Resource Development | A | Researcher generates malicious website using ChatGPT |
| S02 | Resource Development | A | Researcher stages website and script |
| S03 | Initial Access | S | Claude Computer-Use Agent visits malicious website |
| S04 | Execution | S | Agent tricked into interacting by "Are you a computer?" text |
| S05 | Execution | S | Agent follows multi-step instructions from embedded prompt |
| S06 | Privilege Escalation | S | Agent opens terminal, pastes clipboard content, executes command |
| S07 | Impact | S | Malicious script runs on victim's machine |

## Summary Statistics

| Case Study | Steps | A | S | V | A% | S% | V% |
|-----------|-------|---|---|---|----|----|-----|
| CS0000 (ML evasion) | 6 | 5 | 1 | 0 | 83% | 17% | 0% |
| CS0004 (facial recog) | 8 | 7 | 1 | 0 | 88% | 12% | 0% |
| CS0009 (Tay) | 4 | 2 | 2 | 0 | 50% | 50% | 0% |
| CS0016 (MathGPT) | 9 | 5 | 4 | 0 | 56% | 44% | 0% |
| CS0020 (Bing Chat) | 5 | 2 | 2 | 1 | 40% | 40% | 20% |
| CS0024 (Morris II) | 7 | 2 | 4 | 1 | 29% | 57% | 14% |
| CS0026 (M365 Copilot) | 14 | 8 | 5 | 1 | 57% | 36% | 7% |
| CS0035 (Slack AI) | 8 | 5 | 3 | 0 | 62% | 38% | 0% |
| CS0037 (Copilot Studio) | 14 | 8 | 6 | 0 | 57% | 43% | 0% |
| CS0042 (SesameOp) | 1 | 1 | 0 | 0 | 100% | 0% | 0% |
| CS0044 (LAMEHUG) | 8 | 4 | 3 | 1 | 50% | 38% | 12% |
| CS0046 (Claude CU) | 7 | 3 | 4 | 0 | 43% | 57% | 0% |
| CS0053 (MCP poison) | 9 | 4 | 3 | 2 | 44% | 33% | 22% |
| CS0055 (AI ClickFix) | 8 | 3 | 5 | 0 | 38% | 62% | 0% |
| **TOTAL** | **108** | **59** | **43** | **6** | **55%** | **40%** | **6%** |

## Actor Transition Patterns

### Pattern 1: Attacker-first, system-second (dominant pattern)

Nearly all case studies follow this structure:
1. **Early steps (S00-S04)**: Predominantly attacker actions — reconnaissance, resource development, crafting payloads, staging
2. **Middle-to-late steps**: Shift to system actions — the AI executing injected instructions, retrieving data, invoking tools
3. **Final step**: Often system (impact via AI behavior) or victim (consequences realized)

The **handoff point** where the actor shifts from attacker to system typically occurs at the **Execution** tactic. This is the moment the AI system ingests the attacker's payload and begins acting on it autonomously.

### Pattern 2: Traditional ML stays attacker-dominated

For traditional ML targets (CS0000, CS0004), almost all steps are attacker actions. The system appears only at the evasion/impact moment — the ML model misclassifies. This is because traditional ML models are passive classifiers, not autonomous agents. The kill chain describes **what the attacker does to fool the model**.

### Pattern 3: Agentic AI shifts toward system-dominated

For agentic AI targets (CS0024, CS0037, CS0046, CS0055), system actions approach or exceed 50%. The agent has autonomous capabilities (tool invocation, retrieval, code execution), so the kill chain must describe **what the agent does once manipulated**. The attacker sets the trap; the agent walks through it.

### Pattern 4: The "fire and forget" inflection

In agentic cases, there is often a clear **fire-and-forget** inflection point:
- Before: attacker is actively involved (crafting, sending, probing)
- After: attacker is absent; the system autonomously executes the attack

| Case Study | Inflection Step | Trigger |
|-----------|----------------|---------|
| CS0024 (Morris II) | S02 | Email assistant ingests adversarial email |
| CS0035 (Slack AI) | S05 | Slack AI retrieves malicious content |
| CS0046 (Claude CU) | S02 | Claude executes embedded prompt from PDF |
| CS0055 (AI ClickFix) | S03 | Claude visits malicious website |
| CS0037 (Copilot Studio) | S03 | AI agent first replies to injected prompt |

### Pattern 5: Victim rarely appears

Only 6% of steps describe victim actions. When victims appear, they are:
- Executing a file (CS0044 S04 — user runs .pif)
- Suffering consequences (CS0020 S04 — PII captured; CS0024 S06 — PII leaked)
- Upgrading software (CS0053 S04 — orgs install poisoned package)

The ATLAS kill chain mostly ignores the victim perspective. It is not a victim-behavior trace.

## Case Study `actor` Field vs. Procedure Step Actors

The case study-level `actor` field always names the **human attacker** (or research team). It never names the AI system. This confirms the ATLAS framing: the case study is "about" the attacker's campaign, even when the AI system performs the majority of procedural steps.

There is a misalignment: the `actor` field says "this is what entity X did," but many steps describe actions performed by the target system, not by entity X. The procedure is a **hybrid trace** — part attacker playbook, part system behavior log.

## Conclusion: What Is the ATLAS Kill Chain?

The ATLAS kill chain is fundamentally an **attacker procedure** that embeds system behavior as intermediate effects. It is **not** a pure system behavior trace. The organizing perspective is: "what did the attacker do, and what happened as a result?"

However, for agentic AI targets, the kill chain increasingly describes **what the AI system does autonomously** after being triggered. This creates a dual nature:

| Aspect | Traditional ML targets | Agentic AI targets |
|--------|----------------------|-------------------|
| Dominant actor | Attacker (~85%) | Mixed (~50/50) |
| System role | Passive (misclassifies) | Active (invokes tools, retrieves data, executes code) |
| Kill chain nature | Attacker playbook | Hybrid: attacker setup + system behavior trace |
| Inflection point | Final step only | Middle of chain |

**Key implication for scenario generation**: When modeling agentic AI threats, the kill chain must capture both the attacker's setup actions AND the AI system's autonomous execution. A scenario that only describes attacker actions misses the critical "what does the agent do once compromised" phase. A scenario that only describes system behavior misses how the attack was enabled.
