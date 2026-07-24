# QA Audit: ATLAS Tactic Sequences for T3 and T9 Patterns

**Audit Date:** 2026-07-24  
**Auditor:** QA Agent  
**Scope:** 6 attack patterns (T3-02, T3-04, T9-01, T9-02, T9-05, T9-06)

---

## Executive Summary

This audit verifies the factual accuracy of ATLAS tactic sequences mapped to attack patterns T3-02, T3-04, T9-01, T9-02, T9-05, and T9-06 against MITRE ATLAS case study data.

**Overall findings:**
- **5 patterns PASS** with accurate tactic sequences, correct case study references, and appropriate confidence levels
- **1 pattern has MINOR ISSUES** (T9-02: dual Impact steps not directly evidenced in CS0036)
- **Critical note**: T9-02 and T9-06 correctly use CS0036's full 13-step procedure (S00-S12), addressing the previously reported issue where a worker falsely claimed CS0036 only had 3 mapped steps

---

## Pattern-by-Pattern Audit

### AP-T3-02: Cross-boundary authorization escalation

**Source case study:** AML.CS0026 — Financial Transaction Hijacking with M365 Copilot  
**Verdict:** ✅ **PASS**

#### Tactic Verification
| Step | Claimed Tactic | Tactic Name | CS0026 Evidence | Verdict |
|------|----------------|-------------|-----------------|---------|
| 1 | AML.TA0002 | Reconnaissance | ✅ S00 | Valid |
| 2 | AML.TA0000 | AI Model Access | ✅ S01 | Valid |
| 3 | AML.TA0008 | Discovery | ✅ S02, S03 | Valid |
| 4 | AML.TA0003 | Resource Development | ✅ S04, S05 | Valid |
| 5 | AML.TA0004 | Initial Access | ✅ S06 | Valid |
| 6 | AML.TA0007 | Defense Evasion | ✅ S07, S09, S12 | Valid |
| 7 | AML.TA0006 | Persistence | ✅ S08 | Valid |
| 8 | AML.TA0005 | Execution | ✅ S10 | Valid |
| 9 | AML.TA0012 | Privilege Escalation | ✅ S11 | Valid |
| 10 | AML.TA0011 | Impact | ✅ S13 | Valid |

**CS0026 step count:** 14 steps (S00-S13) ✅ Matches claimed count  
**Confidence claims:** All 10 steps marked "explicit" ✅ Accurate — all tactics directly present in CS0026

#### Mechanism Fidelity
The sequence accurately represents CS0026's cross-boundary privilege escalation mechanism:
- Reconnaissance of trust boundaries (S00)
- Agent probing (S01) 
- Discovery of internal structure (S02-S03)
- Crafting malicious payload (S04-S05)
- Delivery via email (S06)
- Evasion and persistence via RAG poisoning (S07-S09)
- Execution and privilege escalation (S10-S11)
- Impact via fraudulent transaction (S13)

**Issues:** None

---

### AP-T3-04: Exposed agent control interface exploitation

**Source case study:** AML.CS0048 — Exposed ClawdBot Control Interfaces  
**Verdict:** ✅ **PASS**

#### Tactic Verification
| Step | Claimed Tactic | Tactic Name | CS0048 Evidence | Verdict |
|------|----------------|-------------|-----------------|---------|
| 1 | AML.TA0002 | Reconnaissance | ✅ S00 | Valid |
| 2 | AML.TA0004 | Initial Access | ✅ S01 | Valid |
| 3 | AML.TA0013 | Credential Access | ✅ S02 | Valid |
| 4 | AML.TA0005 | Execution | ✅ S03 | Valid |
| 5 | AML.TA0008 | Discovery | ✅ S04 | Valid |
| 6 | AML.TA0013 | Credential Access | ✅ S05 | Valid |
| 7 | AML.TA0012 | Privilege Escalation | ✅ S06 | Valid |
| 8 | AML.TA0007 | Defense Evasion | ✅ S07 | Valid |
| 9 | AML.TA0010 | Exfiltration | ✅ S08 | Valid |
| 10 | AML.TA0011 | Impact | ✅ S09 | Valid |

**CS0048 step count:** 10 steps (S00-S09) ✅ Matches claimed count  
**Confidence claims:** All 10 steps marked "explicit" ✅ Accurate — all tactics directly present in CS0048

#### Mechanism Fidelity
The sequence is a 1:1 mapping of CS0048's procedure, preserving the dual Credential Access pattern:
- Initial credential harvest from config files (S02/TA0013)
- Subsequent credential extraction via agent prompting (S05/TA0013)

This dual pattern is critical to the attack's escalation path and is correctly preserved.

**Issues:** None

---

### AP-T9-01: User impersonation via agent action attribution hijacking

**Source case study:** AML.CS0026 — Financial Transaction Hijacking with M365 Copilot  
**Verdict:** ✅ **PASS**

#### Tactic Verification
| Step | Claimed Tactic | Tactic Name | Claimed Conf. | CS0026 Evidence | Actual Conf. | Verdict |
|------|----------------|-------------|---------------|-----------------|--------------|---------|
| 1 | AML.TA0008 | Discovery | adapted | S02-S03 present | adapted ✅ | Valid |
| 2 | AML.TA0003 | Resource Development | explicit | S04-S05 present | explicit ✅ | Valid |
| 3 | AML.TA0005 | Execution | adapted | S10 present | adapted ✅ | Valid |
| 4 | AML.TA0012 | Privilege Escalation | adapted | S11 present | adapted ✅ | Valid |
| 5 | AML.TA0011 | Impact | explicit | S13 present | explicit ✅ | Valid |

**CS0026 step count:** 14 steps (S00-S13) — pattern uses 5 core steps for attribution focus  
**Confidence claims:** 2 explicit, 3 adapted ✅ Accurate

#### Mechanism Fidelity
The sequence correctly distills the **attribution hijacking** mechanism from CS0026:
- Strips out cross-boundary privilege escalation complexity (AP-T3-02's domain)
- Focuses on agent performing actions attributed to legitimate user
- Uses Discovery (not Reconnaissance) to emphasize understanding attribution model
- Condensed from 14 to 5 steps to highlight impersonation core

**Differentiation from AP-T3-02:** ✅ Clear — T3-02 emphasizes privilege escalation across system boundaries; T9-01 emphasizes action attribution to user identity. Same case study, different mechanism focus.

**Issues:** None

---

### AP-T9-02: Agent identity spoofing via compromised service credentials

**Source case study:** AML.CS0036 — AIKatz: Attacking LLM Desktop Applications  
**Verdict:** ⚠️ **PASS WITH MINOR ISSUES**

#### Tactic Verification
| Step | Claimed Tactic | Tactic Name | Claimed Conf. | CS0036 Evidence | Actual Conf. | Verdict |
|------|----------------|-------------|---------------|-----------------|--------------|---------|
| 1 | AML.TA0004 | Initial Access | explicit | ✅ S00 | explicit ✅ | Valid |
| 2 | AML.TA0008 | Discovery | explicit | ✅ S01 | explicit ✅ | Valid |
| 3 | AML.TA0013 | Credential Access | explicit | ✅ S02 | explicit ✅ | Valid |
| 4 | AML.TA0015 | Lateral Movement | explicit | ✅ S03 | explicit ✅ | Valid |
| 5 | AML.TA0000 | AI Model Access | explicit | ✅ S04 | explicit ✅ | Valid |
| 6 | AML.TA0005 | Execution | explicit | ✅ S05 | explicit ✅ | Valid |
| 7 | AML.TA0006 | Persistence | explicit | ✅ S06 | explicit ✅ | Valid |
| 8 | AML.TA0007 | Defense Evasion | explicit | ✅ S08 | explicit ✅ | Valid |
| 9 | AML.TA0011 | Impact | adapted | ⚠️ S09-S12 all TA0011 | inferred ⚠️ | Issue |
| 10 | AML.TA0011 | Impact | adapted | ⚠️ S09-S12 all TA0011 | inferred ⚠️ | Issue |

**CS0036 step count:** 13 steps (S00-S12) ✅ Correct (addresses false claim from original worker)  
**Confidence claims:** 8 explicit, 2 adapted — **Issue:** Steps 9-10 should be "inferred" not "adapted"

#### CS0036 Impact Steps (S09-S12)
All four CS0036 impact steps use the same tactic (AML.TA0011):
- S09: Impact (access victim's chat activity)
- S10: Impact (delete chats)
- S11: Impact (spam messages)
- S12: Impact (rate-limiting DoS)

The pattern consolidates these into 2 Impact steps but claims "adapted" confidence. However:
- The consolidation from 4 CS steps to 2 pattern steps is **synthesis, not adaptation**
- The specific consequences (chat access + DoS) are **abstracted from CS0036**, not directly evidenced as consolidated pairs
- Correct confidence: **inferred** (pattern-specific synthesis of evidenced impacts)

#### Mechanism Fidelity
The sequence correctly emphasizes **SERVICE CREDENTIAL COMPROMISE** for one-shot impersonation:
- Extract tokens from memory (S02)
- Use stolen token for immediate backend access (S03-S04)
- Execute one-shot impersonation (S05-S08)
- Immediate impact without sustained persistence (S09-S12 consolidated)

**Differentiation from AP-T9-06:** ✅ Clear — T9-02 shows credential theft → immediate use (10 steps); T9-06 shows credential theft → persistence establishment → sustained exploitation (12 steps)

**Issues:**
1. ⚠️ Steps 9-10 confidence should be "inferred" not "adapted" (consolidation of 4 evidenced impacts into 2 abstracted outcomes)

---

### AP-T9-05: False attribution attack via identity proxy exploitation

**Source case study:** AML.CS0004 — Camera Hijack Attack on Facial Recognition  
**Verdict:** ✅ **PASS**

#### Tactic Verification
| Step | Claimed Tactic | Tactic Name | CS0004 Evidence | Verdict |
|------|----------------|-------------|-----------------|---------|
| 1 | AML.TA0002 | Reconnaissance | ✅ S00 | Valid |
| 2 | AML.TA0003 | Resource Development | ✅ S01 | Valid |
| 3 | AML.TA0003 | Resource Development | ✅ S02, S03, S04 | Valid |
| 4 | AML.TA0000 | AI Model Access | ✅ S05 | Valid |
| 5 | AML.TA0004 | Initial Access | ✅ S06 | Valid |
| 6 | AML.TA0011 | Impact | ✅ S07 | Valid |

**CS0004 step count:** 8 steps (S00-S07) — pattern uses 6 steps (condensed 3 Resource Dev steps)  
**Confidence claims:** All 6 steps marked "explicit" ✅ Accurate — all tactics directly present in CS0004

#### Mechanism Fidelity
The sequence accurately represents CS0004's deepfake-based identity spoofing:
- Collect victim biometric data (S00)
- Create fake identity documents (S01)
- Obtain deepfake tools and devices (S02-S04, condensed into 2 pattern steps)
- Present spoofed identity to AI authentication (S05)
- Evade biometric verification (S06)
- Perform actions under false attribution (S07)

The consolidation of S02-S04 (acquire devices, obtain software, generate deepfake) into 2 Resource Development steps is reasonable abstraction.

**Supporting case studies:** CS0017, CS0033, CS0034 mentioned as validating similar mechanism ✅ Appropriate

**Issues:** None

---

### AP-T9-06: Persistent agent identity takeover via long-lived credential theft

**Source case study:** AML.CS0036 — AIKatz: Attacking LLM Desktop Applications  
**Verdict:** ⚠️ **PASS WITH MINOR ISSUES**

#### Tactic Verification
| Step | Claimed Tactic | Tactic Name | Claimed Conf. | CS0036 Evidence | Actual Conf. | Verdict |
|------|----------------|-------------|---------------|-----------------|--------------|---------|
| 1 | AML.TA0004 | Initial Access | explicit | ✅ S00 | explicit ✅ | Valid |
| 2 | AML.TA0008 | Discovery | explicit | ✅ S01 | explicit ✅ | Valid |
| 3 | AML.TA0013 | Credential Access | explicit | ✅ S02 | explicit ✅ | Valid |
| 4 | AML.TA0015 | Lateral Movement | explicit | ✅ S03 | explicit ✅ | Valid |
| 5 | AML.TA0000 | AI Model Access | explicit | ✅ S04 | explicit ✅ | Valid |
| 6 | AML.TA0006 | Persistence | explicit | ✅ S06 | explicit ✅ | Valid |
| 7 | AML.TA0006 | Persistence | explicit | ✅ S07 | explicit ✅ | Valid |
| 8 | AML.TA0005 | Execution | explicit | ✅ S05 | explicit ✅ | Valid |
| 9 | AML.TA0007 | Defense Evasion | explicit | ✅ S08 | explicit ✅ | Valid |
| 10 | AML.TA0011 | Impact | adapted | ⚠️ S09-S12 all TA0011 | inferred ⚠️ | Issue |
| 11 | AML.TA0011 | Impact | adapted | ⚠️ S09-S12 all TA0011 | inferred ⚠️ | Issue |
| 12 | AML.TA0011 | Impact | adapted | ⚠️ S09-S12 all TA0011 | inferred ⚠️ | Issue |

**CS0036 step count:** 13 steps (S00-S12) ✅ Correct (addresses false claim from original worker)  
**Confidence claims:** 9 explicit, 3 adapted — **Issue:** Steps 10-12 should be "inferred" not "adapted"

#### CS0036 Impact Steps (Same as T9-02)
The same issue as AP-T9-02 applies here:
- S09-S12 are all TA0011 Impact steps in CS0036
- Pattern reinterprets them as "spam over days", "continuous surveillance", "persistent DoS"
- This is **temporal reinterpretation** (sustained vs. one-shot), not direct adaptation
- Correct confidence: **inferred**

#### Mechanism Fidelity
The sequence correctly emphasizes **LONG-LIVED PERSISTENCE**:
- Dual TA0006 Persistence steps (S06 session context, S07 memory manipulation) — ✅ Explicit in CS0036
- Reordered to emphasize persistence establishment BEFORE execution (steps 6-7-8) — ✅ Valid structural choice
- 3 Impact steps showing sustained consequences over time — ⚠️ Temporal reinterpretation of CS0036's 4 impact steps

**Differentiation from AP-T9-02:** ✅ Clear — T9-06 has dual Persistence tactics and 12 total steps (vs. T9-02's single Persistence and 10 steps); emphasis on sustained exploitation over time

#### Critical Verification: CS0036 Step Count
✅ **Confirmed:** CS0036 has 13 steps (S00-S12), NOT 3 steps as originally falsely claimed. Both T9-02 and T9-06 correctly use the full CS0036 procedure.

**Issues:**
1. ⚠️ Steps 10-12 confidence should be "inferred" not "adapted" (temporal reinterpretation of 4 evidenced impacts)

---

## Summary Table

| Pattern | Case Study | Verdict | Tactic Accuracy | Confidence Accuracy | Mechanism Fidelity | Issues |
|---------|-----------|---------|-----------------|---------------------|-------------------|--------|
| AP-T3-02 | CS0026 | ✅ PASS | 10/10 ✅ | 10/10 ✅ | ✅ Accurate | None |
| AP-T3-04 | CS0048 | ✅ PASS | 10/10 ✅ | 10/10 ✅ | ✅ Accurate | None |
| AP-T9-01 | CS0026 | ✅ PASS | 5/5 ✅ | 5/5 ✅ | ✅ Accurate | None |
| AP-T9-02 | CS0036 | ⚠️ PASS* | 10/10 ✅ | 8/10 ⚠️ | ✅ Accurate | 2 confidence labels wrong |
| AP-T9-05 | CS0004 | ✅ PASS | 6/6 ✅ | 6/6 ✅ | ✅ Accurate | None |
| AP-T9-06 | CS0036 | ⚠️ PASS* | 12/12 ✅ | 9/12 ⚠️ | ✅ Accurate | 3 confidence labels wrong |

\* Minor issues do not affect sequence validity

---

## Detailed Findings

### Critical Verification: CS0036 Step Count (T9-02, T9-06)
✅ **VERIFIED:** CS0036 contains 13 procedure steps (S00-S12), NOT 3 steps.

**Evidence:**
```
CS0036 employs relationships (sorted by step):
S00: AML.TA0004 (Initial Access)
S01: AML.TA0008 (Discovery)
S02: AML.TA0013 (Credential Access)
S03: AML.TA0015 (Lateral Movement)
S04: AML.TA0000 (AI Model Access)
S05: AML.TA0005 (Execution)
S06: AML.TA0006 (Persistence)
S07: AML.TA0006 (Persistence)
S08: AML.TA0007 (Defense Evasion)
S09: AML.TA0011 (Impact)
S10: AML.TA0011 (Impact)
S11: AML.TA0011 (Impact)
S12: AML.TA0011 (Impact)
```

Both T9-02 and T9-06 have been **correctly revised** to leverage the full CS0036 data.

### Confidence Level Issues (T9-02, T9-06)

**Pattern:** Both T9-02 and T9-06 claim "adapted" confidence for their final Impact steps, but the correct confidence is "inferred".

**Why "inferred" not "adapted":**
- CS0036 has 4 Impact steps (S09-S12), all using tactic AML.TA0011
- T9-02 consolidates these into 2 Impact steps ("access victim's chat" + "delete chats/DoS")
- T9-06 consolidates these into 3 Impact steps ("spam over days" + "surveillance" + "persistent DoS")
- The consolidation and temporal reinterpretation is **synthesis**, not direct adaptation
- The specific consolidated outcomes are **abstracted from CS0036**, not evidenced as grouped pairs/triplets

**Confidence definitions (inferred from usage):**
- **Explicit:** CS has that tactic AND mechanism matches exactly
- **Adapted:** Tactic matches but mechanism differs or is reframed
- **Inferred:** Tactic absent from CS OR pattern-specific synthesis of evidenced elements

**Recommended corrections:**
- T9-02 steps 9-10: Change "adapted" → "inferred"
- T9-06 steps 10-12: Change "adapted" → "inferred"

### Tactic Name Verification
All tactic IDs and names verified against ATLAS-2026.05.yaml:
- ✅ AML.TA0000 = AI Model Access
- ✅ AML.TA0002 = Reconnaissance
- ✅ AML.TA0003 = Resource Development
- ✅ AML.TA0004 = Initial Access
- ✅ AML.TA0005 = Execution
- ✅ AML.TA0006 = Persistence
- ✅ AML.TA0007 = Defense Evasion
- ✅ AML.TA0008 = Discovery
- ✅ AML.TA0010 = Exfiltration
- ✅ AML.TA0011 = Impact
- ✅ AML.TA0012 = Privilege Escalation
- ✅ AML.TA0013 = Credential Access
- ✅ AML.TA0015 = Lateral Movement

### Case Study References
All case study IDs verified:
- ✅ AML.CS0026 exists (Financial Transaction Hijacking with M365 Copilot)
- ✅ AML.CS0048 exists (Exposed ClawdBot Control Interfaces)
- ✅ AML.CS0036 exists (AIKatz: Attacking LLM Desktop Applications)
- ✅ AML.CS0004 exists (Camera Hijack Attack on Facial Recognition)

All case studies fall within the valid range CS0000-CS0056.

---

## Recommendations

1. **T9-02 corrections:**
   - Line 109: Change step 9 confidence from "adapted" to "inferred"
   - Line 110: Change step 10 confidence from "adapted" to "inferred"
   - Rationale: Consolidation of 4 CS impacts into 2 abstracted outcomes is synthesis

2. **T9-06 corrections:**
   - Line 156: Change step 10 confidence from "adapted" to "inferred"
   - Line 157: Change step 11 confidence from "adapted" to "inferred"
   - Line 158: Change step 12 confidence from "adapted" to "inferred"
   - Rationale: Temporal reinterpretation of 4 CS impacts into 3 sustained outcomes is synthesis

3. **No changes needed for:**
   - AP-T3-02: Fully accurate
   - AP-T3-04: Fully accurate
   - AP-T9-01: Fully accurate
   - AP-T9-05: Fully accurate

---

## Conclusion

The ATLAS tactic sequences for T3 and T9 patterns are **factually accurate** with respect to:
- Tactic IDs and names
- Case study references and step counts
- Mechanism fidelity to source case studies
- Differentiation between patterns sharing the same case study

**Minor issues** identified:
- 5 Impact steps across T9-02 and T9-06 have "adapted" confidence when "inferred" is more accurate

**Critical verification passed:**
- CS0036 has 13 steps (S00-S12), not 3 steps
- Both T9-02 and T9-06 correctly use the full CS0036 procedure
- The revised versions successfully address the false claim from the original worker

**Overall assessment:** HIGH QUALITY with minor confidence labeling refinements needed.
