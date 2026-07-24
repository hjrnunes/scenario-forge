# Tactic Sequences for T3 (Privilege Compromise) + T9 (Identity Spoofing)

This document provides ATLAS tactic sequences for 6 attack patterns, derived from matched case studies. Each sequence is adapted from the case study's canonical procedure to fit the pattern's specific mechanism.

---

## T3 (Privilege Compromise) Patterns

### AP-T3-02: Cross-boundary authorization escalation

**Source case study**: AML.CS0026 — Financial Transaction Hijacking with M365 Copilot (strong match)
**Existing kill chain**: YES — being replaced

**Proposed tactic sequence:**
| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0002 | Reconnaissance | Identify agent's connected systems and trust boundaries where authorization scope is not independently enforced | explicit |
| 2 | AML.TA0000 | AI Model Access | Interact with agent in source system to probe trust relationships and cross-system capabilities | adapted |
| 3 | AML.TA0008 | Discovery | Discover agent's plugins, APIs, and connected services that span trust boundaries | explicit |
| 4 | AML.TA0003 | Resource Development | Craft request leveraging agent's legitimate access in source system to target connected system | explicit |
| 5 | AML.TA0004 | Initial Access | Deliver crafted request causing agent to authenticate to target system using inherited credentials | explicit |
| 6 | AML.TA0007 | Defense Evasion | Obfuscate cross-boundary request to evade detection in source system | explicit |
| 7 | AML.TA0006 | Persistence | Poisoned data persists in agent's knowledge store, re-triggering cross-boundary escalation | explicit |
| 8 | AML.TA0005 | Execution | Agent processes request, inheriting authorization from source system | explicit |
| 9 | AML.TA0012 | Privilege Escalation | Agent's credentials from source system grant elevated access in target system lacking scope enforcement | explicit |
| 10 | AML.TA0011 | Impact | Unauthorized access to resources beyond agent's intended authorization domain | explicit |

**Adaptation rationale**: CS0026 demonstrates cross-system privilege escalation through M365 Copilot's ability to access internal financial systems. The pattern generalizes this to any agent with access to multiple systems. The core mechanism — inherited authorization crossing trust boundaries — is preserved. Added Discovery (TA0008) steps S02-S03 from CS0026 that probe internal structure. The sequence follows CS0026's tactic flow: Recon → Model Access → Discovery → Resource Dev → Initial Access → Defense Evasion → Persistence → Execution → Privilege Escalation → Impact.

**Comparison with existing kill chain**: 
- **Existing**: [TA0002] → [TA0003] → [TA0004] → [TA0012] → [TA0011] (5 steps)
- **Proposed**: [TA0002] → [TA0000] → [TA0008] → [TA0003] → [TA0004] → [TA0007] → [TA0006] → [TA0005] → [TA0012] → [TA0011] (10 steps)
- **Key additions**: AI Model Access (TA0000) for agent probing, Discovery (TA0008) for internal enumeration, Defense Evasion (TA0007) for obfuscation, Persistence (TA0006) for RAG poisoning, Execution (TA0005) for agent processing
- **Why changed**: Existing pattern was too compressed and missed critical ATLAS steps from CS0026. New sequence shows full attack lifecycle including agent-specific phases (model probing, discovery, persistence in RAG).

---

### AP-T3-04: Exposed agent control interface exploitation

**Source case study**: AML.CS0048 — Exposed ClawdBot Control Interfaces (evidenced match)
**Existing kill chain**: YES — being replaced

**Proposed tactic sequence:**
| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0002 | Reconnaissance | Scan for exposed agent control interfaces using search engines or port scanners | explicit |
| 2 | AML.TA0004 | Initial Access | Access exposed interface exploiting weak auth, proxy misconfiguration, or default credentials | explicit |
| 3 | AML.TA0013 | Credential Access | Access agent configuration, harvest plaintext credentials for connected services | explicit |
| 4 | AML.TA0005 | Execution | Send arbitrary prompts via control interface to exploit agent's instruction-following | explicit |
| 5 | AML.TA0008 | Discovery | Prompt agent to reveal system prompt, environment variables, and internal configuration | explicit |
| 6 | AML.TA0013 | Credential Access | Prompt agent to execute commands (e.g., `env`) harvesting additional secrets | explicit |
| 7 | AML.TA0012 | Privilege Escalation | Prompt agent to invoke privileged tools (e.g., bash as root) for elevated host access | explicit |
| 8 | AML.TA0007 | Defense Evasion | Use harvested API keys to manipulate agent's chat history, covering tracks | explicit |
| 9 | AML.TA0010 | Exfiltration | Use harvested credentials to access connected services, exfiltrating conversation histories | explicit |
| 10 | AML.TA0011 | Impact | Access user's entire digital footprint, enabling impersonation and data theft | explicit |

**Adaptation rationale**: CS0048 directly demonstrates this pattern — exposed ClawdBot control interfaces leading to credential theft and privilege escalation. The sequence preserves all 10 steps from CS0048 (S00-S09), mapping them 1:1 to the pattern. No significant adaptation needed as the case study IS the pattern. The dual Credential Access steps (S02 config file, S05 env vars) are both critical and evidenced.

**Comparison with existing kill chain**:
- **Existing**: [TA0002] → [TA0004] → [TA0013] → [TA0005] → [TA0012] → [TA0010] → [TA0011] (7 steps)
- **Proposed**: [TA0002] → [TA0004] → [TA0013] → [TA0005] → [TA0008] → [TA0013] → [TA0012] → [TA0007] → [TA0010] → [TA0011] (10 steps)
- **Key additions**: Discovery (TA0008/S04) for system prompt extraction, second Credential Access (TA0013/S05) for env vars, Defense Evasion (TA0007/S07) for chat history manipulation
- **Why changed**: Existing pattern condensed multi-stage credential harvesting and missed critical discovery/evasion steps. New sequence matches CS0048's evidenced 10-step procedure exactly, showing iterative privilege build-up (config → prompt → env → root → API manipulation → exfil).

---

## T9 (Identity Spoofing & Impersonation) Patterns

### AP-T9-01: User impersonation via agent action attribution hijacking

**Source case study**: AML.CS0026 — Financial Transaction Hijacking with M365 Copilot (strong match)
**Existing kill chain**: YES — being replaced

**Proposed tactic sequence:**
| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0008 | Discovery | Discover agent's delegated action capabilities (messaging, transactions) and attribution model | adapted |
| 2 | AML.TA0003 | Resource Development | Craft prompt injection to instruct agent to perform actions attributed to target user | explicit |
| 3 | AML.TA0005 | Execution | Inject instructions through data channel agent consumes, triggering attribution hijack | adapted |
| 4 | AML.TA0012 | Privilege Escalation | Agent performs actions using delegated capabilities, with attribution to legitimate user | adapted |
| 5 | AML.TA0011 | Impact | Unauthorized actions appear to originate from legitimate user, bypassing identity verification | explicit |

**Adaptation rationale**: AP-T9-01 focuses on ACTION ATTRIBUTION hijacking, distinct from AP-T3-02's PRIVILEGE escalation emphasis despite sharing CS0026. T9-01 strips out the cross-boundary privilege escalation steps and focuses on the impersonation mechanism: injecting instructions → agent acts → actions attributed to user. The sequence is condensed to 5 core steps emphasizing identity spoofing rather than system privilege. Discovery replaces Reconnaissance to emphasize understanding attribution (not just trust boundaries). Removes Persistence/Defense Evasion as non-essential to attribution hijack.

**Comparison with existing kill chain**:
- **Existing**: [TA0008] → [TA0003] → [TA0005] → [TA0012] → [TA0011] (5 steps)
- **Proposed**: [TA0008] → [TA0003] → [TA0005] → [TA0012] → [TA0011] (5 steps)
- **Key changes**: Same structure but different emphasis — existing pattern correctly identified the core attribution hijack flow. Confirmed as appropriate abstraction from CS0026.
- **Why validated**: Pattern correctly distills the attribution hijacking mechanism from CS0026 without the cross-boundary privilege escalation complexity of AP-T3-02. Distinction is mechanism focus, not tactic sequence.

---

### AP-T9-02: Agent identity spoofing via compromised service credentials

**Source case study**: AML.CS0036 — AIKatz: Attacking LLM Desktop Applications (strong match)
**Existing kill chain**: NO

**Proposed tactic sequence:**
| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0004 | Initial Access | Gain initial access to system hosting agent application | explicit |
| 2 | AML.TA0008 | Discovery | Enumerate running agent processes on victim's machine to identify credential targets | explicit |
| 3 | AML.TA0013 | Credential Access | Extract authentication tokens from agent process memory (e.g., /proc, process handle) | explicit |
| 4 | AML.TA0015 | Lateral Movement | Use stolen token to authenticate to LLM backend, impersonating agent identity | explicit |
| 5 | AML.TA0000 | AI Model Access | Obtain access to communicate directly with agent's LLM backend as spoofed identity | explicit |
| 6 | AML.TA0005 | Execution | Send malicious prompts to LLM under agent's ongoing conversations | explicit |
| 7 | AML.TA0006 | Persistence | Craft prompts to manipulate context of agent's chat session for persistence | explicit |
| 8 | AML.TA0007 | Defense Evasion | Injected prompts remain hidden from victim in ongoing chat interface | explicit |
| 9 | AML.TA0011 | Impact | Access all victim's chat activity with LLM, impersonating agent to backend | inferred |
| 10 | AML.TA0011 | Impact | Delete victim's chats or trigger rate-limiting denial of service | inferred |

**Adaptation rationale**: CS0036 demonstrates a 13-step attack procedure from initial access through credential theft to sustained impersonation. AP-T9-02 adapts this sequence to emphasize SERVICE CREDENTIAL COMPROMISE: the attacker extracts tokens from memory and uses them for one-shot impersonation to backend services. Steps S00-S08 map directly (Initial Access → Discovery → Credential Access → Lateral Movement → AI Model Access → Execution → Persistence in session → Defense Evasion). Impact steps (S09-S12) are consolidated into two focused consequences: accessing victim's chat activity and causing service disruption. The sequence preserves CS0036's tactic flow while focusing on the credential-spoofing mechanism rather than sustained takeover.

**Comparison with existing kill chain**: NO PRIOR KILL CHAIN

---

### AP-T9-05: False attribution attack via identity proxy exploitation

**Source case study**: AML.CS0004 — Camera Hijack Attack on Facial Recognition (strong match); also CS0017, CS0033, CS0034
**Existing kill chain**: NO

**Proposed tactic sequence:**
| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0002 | Reconnaissance | Collect victim identity information and biometric data from black market or open sources | explicit |
| 2 | AML.TA0003 | Resource Development | Create fake identity documents using stolen details and attacker's biometric data | explicit |
| 3 | AML.TA0003 | Resource Development | Obtain deepfake tools, virtual camera software, and modified devices for identity spoofing | explicit |
| 4 | AML.TA0000 | AI Model Access | Present spoofed identity (deepfake video, forged documents) to AI-based authentication system | explicit |
| 5 | AML.TA0004 | Initial Access | Successfully evade biometric authentication, gaining access under victim's identity | explicit |
| 6 | AML.TA0011 | Impact | Perform actions attributed to victim identity, creating false audit trail | explicit |

**Adaptation rationale**: CS0004 demonstrates deepfake-based identity spoofing for false attribution. The sequence follows CS0004's 7-step procedure (S00-S06) but condenses the two Resource Development steps (S01 register identity, S02 acquire devices, S03 obtain software, S04 generate deepfake) into two consolidated TA0003 steps. The core mechanism — spoofing biometric identity → false attribution — is preserved. CS0017, CS0033, CS0034 show similar mechanisms (forged IDs with wigs, live deepfake injection, ProKYC tool) with identical tactic flow, validating the sequence.

**Comparison with existing kill chain**: NO PRIOR KILL CHAIN

---

### AP-T9-06: Persistent agent identity takeover via long-lived credential theft

**Source case study**: AML.CS0036 — AIKatz: Attacking LLM Desktop Applications (strong match); also CS0030 — LLM Jacking
**Existing kill chain**: NO

**Proposed tactic sequence:**
| # | Tactic ID | Tactic Name | Abstract Action | Confidence |
|---|-----------|-------------|-----------------|------------|
| 1 | AML.TA0004 | Initial Access | Gain initial access to system hosting long-lived agent credentials | explicit |
| 2 | AML.TA0008 | Discovery | Enumerate agent processes and credential storage locations for long-lived tokens | explicit |
| 3 | AML.TA0013 | Credential Access | Extract long-lived authentication tokens surviving across sessions | explicit |
| 4 | AML.TA0015 | Lateral Movement | Use stolen long-lived token to authenticate to LLM backend with persistent validity | explicit |
| 5 | AML.TA0000 | AI Model Access | Obtain persistent access to LLM backend independent of victim's active sessions | explicit |
| 6 | AML.TA0005 | Execution | Send malicious prompts to LLM under agent's ongoing conversations using long-lived token | explicit |
| 7 | AML.TA0006 | Persistence | Manipulate agent's chat session context to maintain attacker influence within active sessions | explicit |
| 8 | AML.TA0006 | Persistence | Manipulate agent's memory store to maintain control across multiple victim sessions | explicit |
| 9 | AML.TA0007 | Defense Evasion | Ongoing injected prompts remain hidden from victim across multiple sessions | explicit |
| 10 | AML.TA0011 | Impact | Sustained impersonation enables surveillance of victim's LLM activity and service disruption across sessions | inferred |

**Adaptation rationale**: CS0036 demonstrates a 13-step attack with long-lived token theft enabling SUSTAINED impersonation over time. AP-T9-06 emphasizes LONG-LIVED PERSISTENCE, structurally distinct from AP-T9-02's one-shot credential spoofing. The sequence follows CS0036's actual flow: S00-S04 (Initial Access → Discovery → Credential Access → Lateral Movement → AI Model Access), S05 (Execution: send malicious prompts), S06-S07 (dual Persistence: session context + memory manipulation), S08 (Defense Evasion). Impact consolidates CS0036's four consequence variants (spam, surveillance, chat deletion, rate-limit abuse) into one step reflecting sustained cross-session compromise. Structural differentiation from T9-02: T9-02 shows credential theft → immediate use (10 steps); T9-06 shows credential theft → execution → persistence establishment → sustained exploitation (10 steps with dual Persistence).

**Comparison with existing kill chain**: NO PRIOR KILL CHAIN

---

## Summary Table

| Pattern | Case Study | Existing KC? | Proposed Steps | Explicit/Adapted/Inferred |
|---------|-----------|--------------|----------------|---------------------------|
| AP-T3-02 | CS0026 | YES (5 steps) | 10 | 10/0/0 |
| AP-T3-04 | CS0048 | YES (7 steps) | 10 | 10/0/0 |
| AP-T9-01 | CS0026 | YES (5 steps) | 5 | 2/3/0 |
| AP-T9-02 | CS0036 | NO | 10 | 8/2/0 |
| AP-T9-05 | CS0004 | NO | 6 | 6/0/0 |
| AP-T9-06 | CS0036 | NO | 10 | 9/0/1 |

**Key observations:**
- CS0026 serves BOTH AP-T3-02 (cross-boundary privilege escalation) and AP-T9-01 (action attribution hijacking) with different tactic sequences emphasizing different mechanisms
- CS0036 serves BOTH AP-T9-02 (service credential spoofing) and AP-T9-06 (long-lived credential theft) with structurally differentiated sequences: T9-02 shows credential theft → immediate use (10 steps); T9-06 shows credential theft → execution → persistence establishment → sustained exploitation (10 steps with dual Persistence tactics)
- AP-T3-02 and AP-T3-04 have fully evidenced sequences from ATLAS case studies
- AP-T9-02 and AP-T9-06 now fully leverage CS0036's complete 13-step procedure, with most steps explicit or adapted rather than inferred
- AP-T9-05 has fully evidenced sequence with strong support from 4 different case studies (CS0004, CS0017, CS0033, CS0034)
