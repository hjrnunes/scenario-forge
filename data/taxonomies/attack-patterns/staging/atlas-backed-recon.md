# ATLAS-Backed Attack Pattern Reconnaissance Report

## Summary

This report compares 8 attack patterns (2 reference non-existent case studies) against their source ATLAS case studies to identify discrepancies between worker-authored kill chains and canonical attack procedures.

**Key finding:** CS0059 and CS0062 do not exist in ATLAS-2026.05.yaml.

---

## Pattern Analysis

### AP-T1-01 → AML.CS0040 (Hacking ChatGPT Memories with Prompt Injection)

**Pattern kill chain (existing):**
| Step | Tactic | Action |
|------|--------|--------|
| setup | AML.TA0003 (Resource Development) | Craft adversarial prompt injection with false rules, conceal in content |
| delivery | AML.TA0004 (Initial Access) | Deliver poisoned content via connected app channel |
| execution | AML.TA0005 (Execution) | User references content → injection executes |
| persistence | AML.TA0006 (Persistence) | Injection writes false rules to persistent memory |
| propagation | AML.TA0006 (Persistence) | Poisoned content remains in channel, infects other users |
| impact | AML.TA0011 (Impact) | Agent operates with corrupted memory |

**Case study procedure (canonical):**
| Step | Technique | Tactic (via achieves) | Description | Actor |
|------|-----------|----------------------|-------------|-------|
| S00 | AML.T0065 | AML.TA0003 | Craft prompt asking to set memory with incorrect facts | A |
| S01 | AML.T0068 | AML.TA0007 | Hide prompt in Google Doc header (tiny font, background color) | A |
| S02 | AML.T0093 | AML.TA0004 | Share Google Doc with victim via Connected App | A |
| S03 | AML.T0051.001 | AML.TA0005 | User references doc → prompt executes | V |
| S04 | AML.T0080.000 | AML.TA0006 | Prompt creates poisoned memories in ChatGPT | S |
| S05 | AML.T0093 | AML.TA0006 | Poisoned doc persists, spreads to other users | A/S |
| S06 | AML.T0048.003 | AML.TA0011 | Victim misinformed/misled by poisoned memories | V |

**Tactic sequence comparison:**
- Pattern: [TA0003] → [TA0004] → [TA0005] → [TA0006] → [TA0006] → [TA0011]
- Case study: [TA0003] → [TA0007] → [TA0004] → [TA0005] → [TA0006] → [TA0006] → [TA0011]

**Discrepancies:**
- **Missing Defense Evasion step:** Pattern omits S01 (AML.T0068 / TA0007) where the attacker hides the prompt using steganographic techniques (invisible font).
- **Technique granularity:** Pattern uses "AML.T0051.001" for execution but doesn't specify the indirect nature via Connected App.
- **Propagation detail:** Pattern correctly identifies dual persistence steps but doesn't distinguish between memory persistence (S04) and content persistence (S05).

**Achieves validation:**
All technique→tactic mappings match ATLAS achieves relationships.

**Adaptation needed:**
- Insert Defense Evasion step after setup (hiding prompt in document)
- Clarify that execution is indirect (AML.T0051.001, not direct prompt injection)
- Pattern is appropriately abstracted from ChatGPT-specific details to "agent with persistent memory"

**Alignment quality:** GOOD (minor omission of evasion step)

---

### AP-T1-06 → AML.CS0059

**Status:** Case study AML.CS0059 does NOT exist in ATLAS-2026.05.yaml.

**Pattern claims:** "Zero-click RAG poisoning with rendered-output exfiltration"

**Alignment quality:** N/A - NO SOURCE CASE STUDY

**Recommendation:** Either identify the correct case study reference or mark this pattern as "hypothetical/synthesized" rather than "ATLAS-derived."

---

### AP-T11-01 → AML.CS0052 (LLMSmith: RCE in LLM-Integrated Apps)

**Pattern kill chain (existing):**
| Step | Tactic | Action |
|------|--------|--------|
| reconnaissance | AML.TA0002 (Reconnaissance) | Identify AI frameworks with code execution sinks |
| setup | AML.TA0003 (Resource Development) | Craft prompt to invoke tool chains targeting sinks |
| delivery | AML.TA0004 (Initial Access) | Submit prompt via public interface or indirect channel |
| execution | AML.TA0005 (Execution) | Prompt causes agent to prepare tool invocation |
| tool_invocation | AML.TA0012 (Privilege Escalation) | Agent invokes tool, passes data to execution sink |
| code_execution | AML.TA0005 (Execution) | Attacker input evaluated as code |
| impact | AML.TA0011 (Impact) | Full system control |

**Case study procedure (canonical):**
| Step | Technique | Tactic (via achieves) | Description | Actor |
|------|-----------|----------------------|-------------|-------|
| S00 | AML.T0017 | AML.TA0003 | Static analysis of LLM framework APIs to find RCE vulns | A |
| S01 | AML.T0004 | AML.TA0002 | Scan repos for app deployment URLs | A |
| S02 | AML.T0084.003 | AML.TA0008 | Extract call chains from source to identify RCE paths | A |
| S03 | AML.T0065 | AML.TA0003 | Develop prompts to trigger RCE tool invocations | A |
| S04 | AML.T0049 | AML.TA0004 | Access public-facing app that exposes agent | A |
| S05 | AML.T0051.000 | AML.TA0005 | Directly prompt agent with malicious instructions | A |
| S06 | AML.T0054 | AML.TA0007 | Use jailbreak to bypass guardrails | A |
| S07 | AML.T0053 | AML.TA0012 | Prompts call agent tools targeting RCE chains | A |
| S08 | AML.T0050 | AML.TA0005 | Code executes in sandboxed interpreter | S |
| S09 | AML.T0105 | AML.TA0012 | Code escape techniques bypass sandbox | A |
| S10 | AML.T0072 | AML.TA0014 | Open reverse shell for C2 | A |
| S11 | AML.T0112.000 | AML.TA0011 | Full system control achieved | A |

**Tactic sequence comparison:**
- Pattern: [TA0002] → [TA0003] → [TA0004] → [TA0005] → [TA0012] → [TA0005] → [TA0011]
- Case study: [TA0003] → [TA0002] → [TA0008] → [TA0003] → [TA0004] → [TA0005] → [TA0007] → [TA0012] → [TA0005] → [TA0012] → [TA0014] → [TA0011]

**Discrepancies:**
- **Missing Discovery phase:** Pattern omits S02 (AML.T0084.003 / TA0008) - extracting call chains from source code.
- **Missing Defense Evasion:** Pattern omits S06 (AML.T0054 / TA0007) - jailbreak techniques to bypass guardrails.
- **Missing sandbox escape:** Pattern omits S09 (AML.T0105 / TA0012) - critical step where attacker escapes Python sandbox.
- **Missing C2 establishment:** Pattern omits S10 (AML.T0072 / TA0014) - opening reverse shell.
- **Reconnaissance ordering:** Pattern starts with recon, case study starts with Resource Development (static analysis).
- **Technique mismatch:** Pattern uses generic "identify sinks" vs. case study's specific static analysis (T0017) and source code extraction (T0084.003).

**Achieves validation:**
All technique→tactic mappings match ATLAS achieves relationships.

**Adaptation needed:**
- Add Discovery step for call chain extraction (T0084.003)
- Add Defense Evasion step for jailbreak (T0054)
- Split privilege escalation into two steps: initial tool invocation (T0053) and sandbox escape (T0105)
- Add Command & Control step for reverse shell (T0072)
- Reorder to match actual research workflow: analysis → targeting → exploitation

**Alignment quality:** PARTIAL (missing 4 critical steps including sandbox escape and C2)

---

### AP-T11-02 → AML.CS0062

**Status:** Case study AML.CS0062 does NOT exist in ATLAS-2026.05.yaml.

**Pattern claims:** "Workflow automation backdoor insertion"

**Alignment quality:** N/A - NO SOURCE CASE STUDY

**Recommendation:** Either identify the correct case study reference or mark this pattern as "hypothetical/synthesized" rather than "ATLAS-derived."

---

### AP-T11-05 → AML.CS0055 (AI ClickFix: Hijacking Computer-Use Agents)

**Pattern kill chain (existing):**
| Step | Tactic | Action |
|------|--------|--------|
| setup | AML.TA0003 (Resource Development) | Create adversarial web content with agent-targeted elements |
| delivery | AML.TA0004 (Initial Access) | Agent navigates to adversarial content |
| engagement | AML.TA0005 (Execution) | Agent-targeted clickbait triggers interaction |
| injection | AML.TA0005 (Execution) | Embedded instructions direct agent to GUI actions |
| execution | AML.TA0012 (Privilege Escalation) | Agent executes command via computer-use capabilities |
| impact | AML.TA0011 (Impact) | Arbitrary code executes on host |

**Case study procedure (canonical):**
| Step | Technique | Tactic (via achieves) | Description | Actor |
|------|-----------|----------------------|-------------|-------|
| S00 | AML.T0016.002 | AML.TA0003 | Obtain access to ChatGPT | A |
| S01 | AML.T0017 | AML.TA0003 | Use ChatGPT to generate malicious website + script | A |
| S02 | AML.T0079 | AML.TA0003 | Stage website and script | A |
| S03 | AML.T0078 | AML.TA0004 | Victim's agent visits researcher's website | V |
| S04 | AML.T0100 | AML.TA0005 | Text "Are you a computer?" tricks agent into clicking | S |
| S05 | AML.T0051.001 | AML.TA0005 | Prompt instructs agent to click, paste, execute | S |
| S06 | AML.T0053 | AML.TA0012 | Agent executes command (clipboard → terminal) | S |
| S07 | AML.T0112.000 | AML.TA0011 | Script runs (Calculator demo / arbitrary code) | S |

**Tactic sequence comparison:**
- Pattern: [TA0003] → [TA0004] → [TA0005] → [TA0005] → [TA0012] → [TA0011]
- Case study: [TA0003] → [TA0003] → [TA0003] → [TA0004] → [TA0005] → [TA0005] → [TA0012] → [TA0011]

**Discrepancies:**
- **Setup granularity:** Pattern condenses three Resource Development steps (S00-S02) into one. Case study shows: (1) obtain ChatGPT access, (2) generate content, (3) stage infrastructure.
- **Technique specificity:** Pattern uses generic "create content" vs. case study's specific T0017 (use ChatGPT to generate), T0079 (stage payload).
- **Engagement mechanism:** Pattern correctly identifies clickbait (T0100) but doesn't specify the social engineering text ("Are you a computer?").
- **Execution detail:** Pattern compresses the multi-step execution (click button → JavaScript copies to clipboard → agent pastes in terminal → agent hits return) into generic "GUI actions."

**Achieves validation:**
All technique→tactic mappings match ATLAS achieves relationships.

**Adaptation needed:**
- Pattern is well-abstracted and captures the attack flow correctly
- Could add granularity to setup (generate vs. stage) but not strictly necessary for domain-agnostic pattern
- Pattern correctly identifies the computer-use bridge from web → OS execution

**Alignment quality:** GOOD (pattern is appropriately abstracted)

---

### AP-T17-01 → AML.CS0041 (Rules File Backdoor)

**Pattern kill chain (existing):**
| Step | Tactic | Action |
|------|--------|--------|
| setup | AML.TA0003 (Resource Development) | Stage malicious payload, craft prompt injection |
| obfuscation | AML.TA0007 (Defense Evasion) | Hide prompt using invisible chars/encoding |
| distribution | AML.TA0004 (Initial Access) | Distribute poisoned config via public repo |
| persistence | AML.TA0006 (Persistence) | Users adopt poisoned config → modified behavior |
| execution | AML.TA0005 (Execution) | Agent initializes → hidden prompt executes |
| evasion | AML.TA0007 (Defense Evasion) | Jailbreak + suppress mention in responses |
| impact | AML.TA0011 (Impact) | Agent produces compromised output |

**Case study procedure (canonical):**
| Step | Technique | Tactic (via achieves) | Description | Actor |
|------|-----------|----------------------|-------------|-------|
| S01 | AML.T0065 | AML.TA0003 | Craft prompt to inject script tag into HTML | A |
| S02 | AML.T0068 | AML.TA0007 | Hide prompt using invisible Unicode chars | A |
| S03 | AML.T0010.001 | AML.TA0004 | Upload rules file to GitHub/cursor.directory | A |
| S04 | - | - | (implied: developers adopt the config) | V |
| S05 | AML.T0051.000 | AML.TA0005 | AI assistant reads rules file → prompt executes | S |
| S06 | AML.T0054 | AML.TA0007 | Jailbreak convinces AI to add malicious script | S |
| S07 | AML.T0067 | AML.TA0007 | Prompt instructs AI to suppress mention of changes | S |
| S08 | AML.T0048.003 | AML.TA0011 | Developers use AI-generated code with backdoors | V |

**Tactic sequence comparison:**
- Pattern: [TA0003] → [TA0007] → [TA0004] → [TA0006] → [TA0005] → [TA0007] → [TA0011]
- Case study: [TA0003] → [TA0007] → [TA0004] → [TA0005] → [TA0007] → [TA0007] → [TA0011]

**Discrepancies:**
- **Persistence step mismatch:** Pattern includes explicit TA0006 (Persistence) step, but case study doesn't have a technique mapped to TA0006. The "persistence" is implicit in the adoption of the config (S04), which isn't mapped to a specific technique.
- **Defense Evasion detail:** Pattern correctly identifies two evasion steps but combines S06 (jailbreak) and S07 (suppress output) into one "evasion" step. Case study shows these as distinct techniques.
- **Execution ordering:** Pattern places execution after persistence; case study shows execution (S05) triggering the evasion sequence (S06-S07).

**Achieves validation:**
All technique→tactic mappings match ATLAS achieves relationships. Note that the pattern's "persistence" step doesn't correspond to a specific ATLAS technique in the case study.

**Adaptation needed:**
- Remove or reclassify the "persistence" step (no TA0006 technique in case study)
- Split "evasion" step into two: jailbreak (T0054) and output suppression (T0067)
- Reorder to match: setup → obfuscation → distribution → execution → jailbreak → suppression → impact

**Alignment quality:** PARTIAL (persistence step not backed by case study, evasion steps merged)

---

### AP-T17-02 → AML.CS0049 (Supply Chain Compromise via Poisoned ClawdBot Skill)

**Pattern kill chain (existing):**
| Step | Tactic | Action |
|------|--------|--------|
| setup | AML.TA0003 (Resource Development) | Craft prompt to escape parameter context, achieve RCE |
| delivery | AML.TA0005 (Execution) | Submit prompt → agent prepares malicious tool invocation |
| tool_invocation | AML.TA0012 (Privilege Escalation) | Agent invokes tool with attacker-controlled argument |
| code_execution | AML.TA0005 (Execution) | Tool parameter evaluated in execution sink |
| impact | AML.TA0011 (Impact) | Arbitrary code executes on host |

**Case study procedure (canonical):**
| Step | Technique | Tactic (via achieves) | Description | Actor |
|------|-----------|----------------------|-------------|-------|
| S00 | AML.T0017 | AML.TA0003 | Create simple web server to log requests | A |
| S01 | AML.T0008.002 | AML.TA0003 | Register domain `clawdhub-skill.com` | A |
| S02 | - | - | (implied: publish to ClawdHub) | A |
| S03-S04 | - | - | (implied: skill becomes popular) | - |
| S05 | AML.T0010.005 | AML.TA0004 | Users download poisoned Skill from ClawdHub | V |
| S06 | AML.T0011.002 | AML.TA0005 | User asks "what would Elon do?" → calls skill | V |
| S07 | - | - | (implied: skill execution / impact) | - |
| S08+ | AML.T0048 | AML.TA0011 | PoC warns user; real attack could exfil codebase | - |

**Discrepancies:**
- **MAJOR MISMATCH:** Pattern describes workflow automation backdoor / parameter escaping to RCE, but case study is about supply chain poisoning of a Skill registry.
- **Kill chain structure:** Pattern is 5 steps focused on parameter injection → RCE. Case study is 8+ steps focused on registry → download → skill invocation → impact.
- **Attack mechanism:** Pattern = code injection via tool parameter escaping. Case study = prompt injection embedded in Skill files.
- **Tactics:** Pattern includes Privilege Escalation (TA0012) for tool invocation. Case study has no TA0012 step.

**Achieves validation:**
N/A - pattern and case study describe different attacks.

**Adaptation needed:**
- **WRONG MAPPING:** AP-T17-02 should NOT reference CS0049. Either:
  1. AP-T17-02 needs a different case study (or is synthesized), OR
  2. AP-T17-02 description should be rewritten to match CS0049's supply chain attack

**Alignment quality:** POOR - pattern and case study are fundamentally different attacks

---

### AP-T17-03 → AML.CS0053 (Poisoned Postmark MCP Server Email Exfiltration)

**Pattern kill chain (existing):**
| Step | Tactic | Action |
|------|--------|--------|
| setup | AML.TA0007 (Defense Evasion) | Impersonate service via registry namesquatting |
| trust_building | AML.TA0003 (Resource Development) | Publish legitimate version to build trust |
| poisoning | AML.TA0003 (Resource Development) | Publish malicious update with exfil side-channel |
| evasion | AML.TA0007 (Defense Evasion) | Rug-pull timing evades scrutiny |
| distribution | AML.TA0004 (Initial Access) | Users upgrade via normal dependency management |
| persistence | AML.TA0006 (Persistence) | Poisoned tool persists in agent configs |
| exfiltration | AML.TA0010 (Exfiltration) | Every tool invocation leaks data |
| impact | AML.TA0011 (Impact) | Continuous data leak to attacker |

**Case study procedure (canonical):**
| Step | Technique | Tactic (via achieves) | Description | Actor |
|------|-----------|----------------------|-------------|-------|
| S00 | AML.T0073 | AML.TA0007 | Namesquat `postmark-mcp` on npm before official | A |
| S01 | AML.T0017 | AML.TA0003 | Modify MCP server to add BCC to all emails | A |
| S02 | AML.T0104 | AML.TA0003 | Publish malicious version to npm | A |
| S03 | AML.T0109 | AML.TA0007 | Wait for adoption before rug-pull to evade scrutiny | A |
| S04 | AML.T0010.005 | AML.TA0004 | Users upgrade to v1.0.16 via supply chain | V |
| S05 | AML.T0110 | AML.TA0006 | Poisoned tool persists in agent configs | S |
| S06 | AML.T0011.002 | AML.TA0005 | Users instruct agent to use poisoned tool | V |
| S07 | AML.T0086 | AML.TA0010 | Email contents exfiltrated via BCC | S |
| S08 | AML.T0048 | AML.TA0011 | Transactional/promotional emails leaked | V |

**Tactic sequence comparison:**
- Pattern: [TA0007] → [TA0003] → [TA0003] → [TA0007] → [TA0004] → [TA0006] → [TA0010] → [TA0011]
- Case study: [TA0007] → [TA0003] → [TA0003] → [TA0007] → [TA0004] → [TA0006] → [TA0005] → [TA0010] → [TA0011]

**Discrepancies:**
- **Missing Execution step:** Pattern omits S06 (AML.T0011.002 / TA0005) where users actually invoke the poisoned tool. Pattern jumps from persistence directly to exfiltration.
- **Trust building detail:** Pattern describes "publish legitimate version" but case study shows this was done as part of S00-S03 sequence (namesquat → modify → publish → wait). Case study doesn't explicitly show a "clean initial version."
- **Technique granularity:** Pattern's "trust_building" step doesn't map to a specific case study technique. Case study shows the trust-building as part of the timing evasion (T0109).

**Achieves validation:**
All technique→tactic mappings match ATLAS achieves relationships.

**Adaptation needed:**
- Add Execution step (TA0005 / T0011.002) between persistence and exfiltration
- Clarify that "trust_building" is achieved through timing (T0109) rather than a separate initial publication
- Pattern is otherwise well-aligned

**Alignment quality:** GOOD (missing execution step but otherwise strong)

---

### AP-T3-04 → AML.CS0048 (Exposed ClawdBot Control Interfaces)

**Pattern kill chain (existing):**
| Step | Tactic | Action |
|------|--------|--------|
| reconnaissance | AML.TA0002 (Reconnaissance) | Scan for exposed control interfaces via search engines |
| initial_access | AML.TA0004 (Initial Access) | Access exposed interface (weak auth / proxy misconfig) |
| credential_harvest | AML.TA0013 (Credential Access) | Access config file, harvest plaintext credentials |
| agent_exploitation | AML.TA0005 (Execution) | Send arbitrary prompts via control interface |
| privilege_escalation | AML.TA0012 (Privilege Escalation) | Prompt agent to invoke tools for elevated access |
| lateral_movement | AML.TA0010 (Exfiltration) | Use harvested credentials to access connected services |
| impact | AML.TA0011 (Impact) | Access entire digital footprint via connected services |

**Case study procedure (canonical):**
| Step | Technique | Tactic (via achieves) | Description | Actor |
|------|-----------|----------------------|-------------|-------|
| S00 | AML.T0000 | AML.TA0002 | Search Shodan for "Clawdbot Control" | A |
| S01 | AML.T0049 | AML.TA0004 | Exploit proxy misconfiguration for access | A |
| S02 | AML.T0083 | AML.TA0013 | Access config file with plaintext credentials | A |
| S03 | AML.T0051.001 | AML.TA0005 | Prompt ClawdBot directly via control interface | A |
| S04 | AML.T0069.002 | AML.TA0008 | Prompt ClawdBot to `cat SOUL.md` (system prompt) | A |
| S05 | AML.T0098 | AML.TA0013 | Prompt ClawdBot with `env` to get more secrets | A |
| S06 | AML.T0053 | AML.TA0012 | Prompt with `root` → bash skill runs as root | A |
| S07 | AML.T0092 | AML.TA0007 | Use Anthropic API keys to manipulate chat history | A |
| S08 | AML.T0025 | AML.TA0010 | Exfiltrate conversation histories from messaging apps | A |
| S09 | AML.T0048.003 | AML.TA0011 | Impersonate user via connected messaging services | A |

**Tactic sequence comparison:**
- Pattern: [TA0002] → [TA0004] → [TA0013] → [TA0005] → [TA0012] → [TA0010] → [TA0011]
- Case study: [TA0002] → [TA0004] → [TA0013] → [TA0005] → [TA0008] → [TA0013] → [TA0012] → [TA0007] → [TA0010] → [TA0011]

**Discrepancies:**
- **Missing Discovery step:** Pattern omits S04 (AML.T0069.002 / TA0008) where attacker discovers system prompt.
- **Missing second Credential Access:** Pattern omits S05 (AML.T0098 / TA0013) where attacker harvests additional secrets via `env` command.
- **Missing Defense Evasion:** Pattern omits S07 (AML.T0092 / TA0007) where attacker manipulates chat history using harvested API keys.
- **Lateral movement vs Exfiltration:** Pattern maps "lateral_movement" to TA0010 (Exfiltration) but should be TA0015 (Lateral Movement). However, case study uses T0025 which maps to TA0010 (Exfiltration), not lateral movement. This is a naming mismatch in the pattern.
- **Credential harvest granularity:** Pattern shows one credential harvest step; case study shows two (S02: config file, S05: env vars).

**Achieves validation:**
All technique→tactic mappings match ATLAS achieves relationships. Note: Pattern's "lateral_movement" step is mislabeled - it's actually exfiltration (TA0010).

**Adaptation needed:**
- Add Discovery step (TA0008 / T0069.002) after initial agent exploitation
- Split credential harvest into two steps: config file (T0083) and env vars (T0098)
- Add Defense Evasion step (TA0007 / T0092) for chat history manipulation
- Rename "lateral_movement" to "exfiltration" (tactic is already correct as TA0010)
- Pattern is otherwise well-structured

**Alignment quality:** PARTIAL (missing 3 steps, mislabeled lateral movement)

---

### AP-T6-06 → AML.CS0051 (OpenClaw C2 via Prompt Injection)

**Pattern kill chain (existing):**
| Step | Tactic | Action |
|------|--------|--------|
| reconnaissance | AML.TA0002 (Reconnaissance) | Study agent's config for control sequences, system prompt |
| discovery | AML.TA0008 (Discovery) | Identify control sequences delimiting messages/tool results |
| setup | AML.TA0003 (Resource Development) | Craft multi-stage injection spoofing control sequences |
| delivery | AML.TA0004 (Initial Access) | Lure agent to fetch attacker-controlled content |
| execution | AML.TA0005 (Execution) | Injection activates, spoofs control flow → download script |
| persistence | AML.TA0006 (Persistence) | Script modifies config prepended to all system prompts |
| c2_activation | AML.TA0014 (Command and Control) | Agent fetches task list from attacker server |
| impact | AML.TA0011 (Impact) | Agent permanently hijacked, executes attacker commands |

**Case study procedure (canonical):**
| Step | Technique | Tactic (via achieves) | Description | Actor |
|------|-----------|----------------------|-------------|-------|
| S01 | AML.T0002.002 | AML.TA0003 | Acquire agent configs useful for attack | A |
| S02-S03 | - | - | (implied: study configs) | A |
| S04 | AML.T0065 | AML.TA0003 | Develop prompt to retrieve and execute script | A |
| S05 | AML.T0065 | AML.TA0003 | Develop prompt to fetch TODO list from server | A |
| S06 | AML.T0008 | AML.TA0003 | Acquire domain `aisystem.tech` | A |
| S07-S09 | - | - | (implied: stage payloads) | A |
| S10 | AML.T0051.001 | AML.TA0005 | Prompt injection embedded in website executes | V/S |
| S11 | AML.T0054 | AML.TA0007 | Use `<think>` control sequences to spoof reasoning | S |
| S12 | AML.T0053 | AML.TA0005 | Prompt causes bash skill to retrieve and execute script | S |
| S13 | - | - | (implied: script modifies config) | S |
| S14 | AML.T0051.000 | AML.TA0005 | Modified system prompt executes in future sessions | S |
| S15+ | - | - | (implied: C2 activation and impact) | S |

**Tactic sequence comparison:**
- Pattern: [TA0002] → [TA0008] → [TA0003] → [TA0004] → [TA0005] → [TA0006] → [TA0014] → [TA0011]
- Case study: [TA0003] → [TA0003] → [TA0003] → [TA0003] → [TA0005] → [TA0007] → [TA0005] → [TA0005]

**Discrepancies:**
- **Reconnaissance/Discovery ordering:** Pattern starts with TA0002 (Reconnaissance) → TA0008 (Discovery), but case study starts with TA0003 (Resource Development / acquire configs). This is a reasonable abstraction difference.
- **Missing Defense Evasion:** Pattern omits S11 (AML.T0054 / TA0007) where attacker uses `<think>` tags to spoof the agent's internal reasoning and bypass safety alignment.
- **Missing delivery step:** Pattern includes explicit "delivery" step (TA0004), but case study doesn't have a technique mapped to TA0004. The delivery is implicit in S10 where the agent visits the malicious website.
- **Incomplete case study mapping:** Case study relationships stop at S14 (modified system prompt executes). Steps S13 (persistence), S15+ (C2 activation, impact) are implied but not mapped to specific techniques. Pattern correctly infers these steps.
- **Execution granularity:** Pattern shows one execution step; case study shows three (S10: injection executes, S12: bash skill runs, S14: modified prompt executes).

**Achieves validation:**
All technique→tactic mappings match ATLAS achieves relationships.

**Adaptation needed:**
- Add Defense Evasion step (TA0007 / T0054) for control sequence spoofing with `<think>` tags
- Split execution into multiple steps: initial injection (T0051.001), tool invocation (T0053), persistent prompt execution (T0051.000)
- Pattern correctly infers persistence and C2 steps that aren't fully detailed in case study
- Consider removing explicit "discovery" step or merging with reconnaissance (both are part of initial config study)

**Alignment quality:** GOOD (pattern correctly infers missing case study steps, minor evasion omission)

---

## Summary Table

| Pattern | Case Study | Alignment Quality | Key Issues |
|---------|-----------|------------------|------------|
| AP-T1-01 | AML.CS0040 | GOOD | Missing defense evasion step (hide prompt) |
| AP-T1-06 | AML.CS0059 | N/A | **Case study does not exist** |
| AP-T11-01 | AML.CS0052 | PARTIAL | Missing 4 steps: discovery, evasion, sandbox escape, C2 |
| AP-T11-02 | AML.CS0062 | N/A | **Case study does not exist** |
| AP-T11-05 | AML.CS0055 | GOOD | Well-abstracted, minor setup granularity difference |
| AP-T17-01 | AML.CS0041 | PARTIAL | Persistence step not backed by case study, evasion steps merged |
| AP-T17-02 | AML.CS0049 | POOR | **Wrong mapping - completely different attacks** |
| AP-T17-03 | AML.CS0053 | GOOD | Missing execution step (tool invocation) |
| AP-T3-04 | AML.CS0048 | PARTIAL | Missing 3 steps: discovery, second cred harvest, evasion |
| AP-T6-06 | AML.CS0051 | GOOD | Missing defense evasion (control spoofing), well-inferred steps |

**Overall Statistics:**
- 8 patterns analyzed (2 excluded for non-existent case studies)
- 4 GOOD alignments (50%)
- 3 PARTIAL alignments (37.5%)
- 1 POOR alignment (12.5%)

**Critical Issues:**
1. **AP-T1-06** and **AP-T11-02** reference non-existent case studies (CS0059, CS0062)
2. **AP-T17-02** is mapped to the wrong case study (describes different attack than CS0049)
3. **AP-T11-01** is missing critical steps (sandbox escape, C2) that are central to the case study's impact

**Common Patterns:**
- Defense evasion steps are frequently omitted (AP-T1-01, AP-T11-01, AP-T17-01, AP-T3-04, AP-T6-06)
- Discovery/reconnaissance phases are sometimes compressed or reordered
- Multi-step execution sequences are often simplified into single steps
- Patterns tend to abstract well but sometimes omit critical technical details

**Recommendations:**
1. Verify case study references for AP-T1-06 and AP-T11-02
2. Remap or rewrite AP-T17-02 to match its actual case study
3. Add missing defense evasion steps across multiple patterns
4. Review AP-T11-01 for critical missing steps (sandbox escape is essential to the attack)
5. Consider adding Discovery (TA0008) steps where case studies show explicit system exploration
