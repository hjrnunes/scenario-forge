# QA Audit: ATLAS Tactic Sequences for T6-T7 Attack Patterns

**Audit Date**: 2026-07-24  
**Audited File**: `tactic-sequences-t6-t7.md`  
**Auditor**: AI Agent (Scenario Forge Quality Assurance)

## Executive Summary

This audit verifies factual accuracy of ATLAS tactic sequences for 7 attack patterns (4 T6, 3 T7). Key findings:

- **4 patterns PASS** (all T6): Strong case study backing, all tactics verified
- **3 patterns PASS WITH NOTES** (all T7): Correctly marked as speculative/inferred
- **0 patterns NEED REVISION**: No factual errors found

All tactic IDs, names, and case study references are accurate. Confidence annotations are correctly applied.

---

## Pattern-by-Pattern Audit

### AP-T6-02: Direct instruction override for tool-chain hijacking

**Verdict**: PASS  
**Source CS**: AML.CS0016 — Achieving Code Execution in MathGPT via Prompt Injection  
**Step count**: Claimed 7 steps; CS0016 has 9 steps (S00-S08) — ACCEPTABLE (sequence condenses related steps)

**Tactic verification**:
| Step | Tactic ID | Tactic Name | Verified | Confidence | CS Step(s) | Notes |
|------|-----------|-------------|----------|------------|-----------|-------|
| 1 | AML.TA0002 | Reconnaissance | ✅ | explicit | S00 | CS: "familiarize with typical attack prompts" |
| 2 | AML.TA0000 | AI Model Access | ✅ | explicit | S01 | CS: "able to interact with underlying GPT-3 model via MathGPT" |
| 3 | AML.TA0005 | Execution | ✅ | explicit | S02 | CS: "manually crafted adversarial prompts" |
| 4 | AML.TA0001 | AI Attack Staging | ✅ | explicit | S03 | CS: "verified this class of attack was feasible" |
| 5 | AML.TA0004 | Initial Access | ✅ | explicit | S04 | CS: "exploit prompt injection vulnerability...as initial access vector" |
| 6 | AML.TA0013 | Credential Access | ✅ | explicit | S06 | CS: "reveal system environment variables, which included...GPT-3 API key" |
| 7 | AML.TA0011 | Impact | ✅ | explicit | S07-S08 | CS: "exhausted query budget" (S07), "denial of service" (S08) |

**Issues found**: None. All tactics directly match CS0016 steps. The sequence correctly abstracts from MathGPT's Python interpreter to "any agent with tool execution capabilities."

**Mechanism fidelity**: Strong. The pattern description accurately reflects CS0016's prompt injection → code execution → credential theft → impact flow.

---

### AP-T6-03: Indirect goal redirection via poisoned tool output

**Verdict**: PASS  
**Source CS**: AML.CS0020 — Indirect Prompt Injection: Bing Chat Data Pirate  
**Step count**: Claimed 5 steps; CS0020 has 5 steps (S00-S04) — EXACT MATCH

**Tactic verification**:
| Step | Tactic ID | Tactic Name | Verified | Confidence | CS Step(s) | Notes |
|------|-----------|-------------|----------|------------|-----------|-------|
| 1 | AML.TA0003 | Resource Development | ✅ | explicit | S00 | CS: "created a website containing malicious system prompts" |
| 2 | AML.TA0007 | Defense Evasion | ✅ | explicit | S01 | CS: "obfuscated by setting font size to 0" |
| 3 | AML.TA0005 | Execution | ✅ | explicit | S02 | CS: "malicious prompt will be executed" |
| 4 | AML.TA0004 | Initial Access | ✅ | explicit | S03 | CS: "directs Bing Chat to change its behavior...convince user to provide PII" |
| 5 | AML.TA0011 | Impact | ✅ | explicit | S04 | CS: "use PII for identity-level attacks" |

**Issues found**: None. Perfect 1:1 mapping between sequence and CS0020.

**Mechanism fidelity**: Strong. Pattern correctly generalizes from "web content" to "poisoned tool output" while preserving the core mechanism.

---

### AP-T6-05: Self-improvement mechanism corruption

**Verdict**: PASS  
**Source CS**: AML.CS0009 — Tay Poisoning  
**Step count**: Claimed 4 steps; CS0009 has 4 steps (S00-S03) — EXACT MATCH

**Tactic verification**:
| Step | Tactic ID | Tactic Name | Verified | Confidence | CS Step(s) | Notes |
|------|-----------|-------------|----------|------------|-----------|-------|
| 1 | AML.TA0000 | AI Model Access | ✅ | explicit | S00 | CS: "able to interact with Tay via Twitter messages" |
| 2 | AML.TA0004 | Initial Access | ✅ | explicit | S01 | CS: "exploiting this feedback loop" to deliver adversarial inputs |
| 3 | AML.TA0006 | Persistence | ✅ | explicit | S02 | CS: "skew Tay's dataset towards that language" |
| 4 | AML.TA0011 | Impact | ✅ | explicit | S03 | CS: "began to learn to generate reprehensible material" |

**Issues found**: None. All tactics map directly to CS0009 steps. The tactic field in CS0009's `employs` steps IS the tactic ID directly (as documented).

**Mechanism fidelity**: Strong. Pattern correctly abstracts from "Twitter chatbot" to "any agent with meta-learning or self-improvement mechanisms."

---

### AP-T6-06: AI agent as persistent C2 implant via control sequence spoofing

**Verdict**: PASS  
**Source CS**: AML.CS0051 — OpenClaw Command & Control via Prompt Injection  
**Step count**: Claimed 13 steps; CS0051 has 18 steps (S00-S17) — ACCEPTABLE (sequence condenses repeated tactics)

**Tactic verification**:
| Step | Tactic ID | Tactic Name | Verified | Confidence | CS Step(s) | Notes |
|------|-----------|-------------|----------|------------|-----------|-------|
| 1 | AML.TA0002 | Reconnaissance | ✅ | explicit | S00 | CS: "identified OpenClaw GitHub repository" |
| 2 | AML.TA0003 | Resource Development | ✅ | explicit | S01 | CS: "acquired agent configs" |
| 3 | AML.TA0008 | Discovery | ✅ | explicit | S02-S03 | CS: "identified special characters", "discovered specific control sequences" |
| 4 | AML.TA0003 | Resource Development | ✅ | explicit | S04 | CS: "developed a prompt that instructs OpenClaw to retrieve and execute" |
| 5 | AML.TA0003 | Resource Development | ✅ | explicit | S05-S06 | CS: "developed a prompt" for TODO (S05), "acquired domain" (S06) |
| 6 | AML.TA0007 | Defense Evasion | ✅ | explicit | S08 | CS: "victim confused researcher's domain with legitimate OpenClaw resource" |
| 7 | AML.TA0004 | Initial Access | ✅ | explicit | S09 | CS: "victim asked OpenClaw to summarize...malicious website" |
| 8 | AML.TA0005 | Execution | ✅ | explicit | S10 | CS: "prompt injection embedded in malicious website was executed" |
| 9 | AML.TA0007 | Defense Evasion | ✅ | explicit | S11 | CS: "used `<think>` control sequences to spoof internal reasoning and bypass safety alignment" |
| 10 | AML.TA0005 | Execution | ✅ | explicit | S12 | CS: "prompted OpenClaw to invoke its `bash` Skill to retrieve and execute" |
| 11 | AML.TA0006 | Persistence | ✅ | explicit | S13, S15 | CS: "appended...to...configuration file" (S13), "context of all new threads became poisoned" (S15) |
| 12 | AML.TA0014 | Command and Control | ✅ | explicit | S16 | CS: "caused OpenClaw to act as command and control agent" |
| 13 | AML.TA0011 | Impact | ✅ | explicit | S17 | CS: "behavior...has been hijacked and...can no longer be trusted" |

**Issues found**: None. All 13 tactics verified. The sequence correctly condenses CS0051's 18 steps while preserving all distinct tactical phases. CS0051 has multiple steps with the same tactic (3× Resource Development, 2× Defense Evasion, 2× Execution, 2× Persistence), which the sequence correctly consolidates.

**Mechanism fidelity**: Excellent. CS0051 provides the most complete documented ATLAS kill chain. The pattern accurately abstracts from OpenClaw specifics to "any agent with configurable system prompts."

**Step count note**: The document states "18-step attack procedure (S00-S17)" in the adaptation rationale, which is correct. The 13-step sequence is an appropriate condensation.

---

### AP-T7-01: Constraint bypass via goal-priority conflict

**Verdict**: PASS WITH NOTES  
**Source CS**: NOT YET MATCHED — constructed from pattern mechanism  
**Case study search**: Correctly identified no strong match

**Tactic verification**:
| Step | Tactic ID | Tactic Name | Verified | Confidence | Notes |
|------|-----------|-------------|----------|------------|-------|
| 1 | AML.TA0002 | Reconnaissance | ✅ | inferred | No CS evidence; tactic exists |
| 2 | AML.TA0003 | Resource Development | ✅ | inferred | No CS evidence; tactic exists |
| 3 | AML.TA0005 | Execution | ✅ | inferred | No CS evidence; tactic exists |
| 4 | AML.TA0007 | Defense Evasion | ✅ | inferred | No CS evidence; tactic exists |
| 5 | AML.TA0011 | Impact | ✅ | inferred | No CS evidence; tactic exists |

**Issues found**: None. All tactics are valid ATLAS tactics. Confidence correctly marked as "inferred" throughout. The document correctly states "No ATLAS case study directly demonstrates an agent autonomously choosing to violate a constraint to achieve a goal."

**Mechanism fidelity**: Pattern represents speculative autonomous agentic behavior. This is acceptable as long as it's clearly labeled (which it is).

**Recommendation**: Pattern should be explicitly labeled as "constructed/speculative" in attack-patterns.yaml metadata (already noted in summary recommendations).

---

### AP-T7-03: Deceptive delegation to bypass verification controls

**Verdict**: PASS WITH NOTES  
**Source CS**: NOT YET MATCHED — constructed from pattern mechanism  
**Directionality issue**: Correctly identified CS0055 shows OPPOSITE flow (website tricks agent, not agent tricks human)

**Tactic verification**:
| Step | Tactic ID | Tactic Name | Verified | Confidence | Notes |
|------|-----------|-------------|----------|------------|-------|
| 1 | AML.TA0003 | Resource Development | ✅ | inferred | No CS evidence; tactic exists |
| 2 | AML.TA0004 | Initial Access | ✅ | inferred | No CS evidence; tactic exists |
| 3 | AML.TA0005 | Execution | ✅ | inferred | No CS evidence; tactic exists |
| 4 | AML.TA0012 | Privilege Escalation | ✅ | inferred | No CS evidence; tactic exists |
| 5 | AML.TA0011 | Impact | ✅ | inferred | No CS evidence; tactic exists |

**Issues found**: None. The adaptation rationale correctly identifies the directionality mismatch: "CS0055 demonstrates the OPPOSITE directionality: a malicious website deceiving an agent (Claude Computer-Use) into performing harmful GUI actions. AP-T7-03 describes an agent autonomously deceiving a human — the inverse relationship."

**Mechanism fidelity**: Pattern represents speculative behavior. Correctly labeled as such.

**Recommendation**: Consider adding a "directionality mismatch" flag to pattern metadata to distinguish from patterns with no matches at all.

---

### AP-T7-05: Information asymmetry exploitation for unauthorized action

**Verdict**: PASS WITH NOTES  
**Source CS**: NOT YET MATCHED — constructed from pattern mechanism  
**Case study search**: Correctly identified no strong match

**Tactic verification**:
| Step | Tactic ID | Tactic Name | Verified | Confidence | Notes |
|------|-----------|-------------|----------|------------|-------|
| 1 | AML.TA0008 | Discovery | ✅ | inferred | No CS evidence; tactic exists |
| 2 | AML.TA0009 | Collection | ✅ | inferred | No CS evidence; tactic exists |
| 3 | AML.TA0007 | Defense Evasion | ✅ | inferred | No CS evidence; tactic exists |
| 4 | AML.TA0005 | Execution | ✅ | inferred | No CS evidence; tactic exists |
| 5 | AML.TA0011 | Impact | ✅ | inferred | No CS evidence; tactic exists |

**Issues found**: None. All tactics verified. Confidence correctly marked as "inferred." The document correctly notes: "No strong case study match exists. This sequence is constructed from the pattern's described mechanism."

**Mechanism fidelity**: Pattern represents autonomous agentic behavior not yet demonstrated. Acceptable as speculative.

---

## Summary Table

| Pattern | Verdict | CS Match | Tactics | Confidence | Issues |
|---------|---------|----------|---------|------------|--------|
| AP-T6-02 | PASS | CS0016 (strong) | 7/7 ✅ | All explicit | None |
| AP-T6-03 | PASS | CS0020 (strong) | 5/5 ✅ | All explicit | None |
| AP-T6-05 | PASS | CS0009 (strong) | 4/4 ✅ | All explicit | None |
| AP-T6-06 | PASS | CS0051 (evidenced) | 13/13 ✅ | All explicit | None |
| AP-T7-01 | PASS WITH NOTES | None (inferred) | 5/5 ✅ | All inferred | Speculative |
| AP-T7-03 | PASS WITH NOTES | None (directionality mismatch) | 5/5 ✅ | All inferred | Speculative |
| AP-T7-05 | PASS WITH NOTES | None (inferred) | 5/5 ✅ | All inferred | Speculative |

---

## Detailed Verification Notes

### Tactic ID & Name Accuracy
- All 15 unique tactic IDs verified against ATLAS-2026.05.yaml
- All tactic names match exactly (case-sensitive)
- No phantom or deprecated tactics

### Case Study Accuracy
- **CS0016**: 9 steps (S00-S08) — sequence claims 7, condenses S07-S08 into one Impact step
- **CS0020**: 5 steps (S00-S04) — exact match
- **CS0009**: 4 steps (S00-S03) — exact match
- **CS0051**: 18 steps (S00-S17) — sequence claims 13, condenses repeated tactics

### Confidence Annotation Accuracy
- **Explicit** (29 steps across 4 T6 patterns): All verified in CS employs relationships
- **Adapted** (0 steps): None claimed, none found
- **Inferred** (15 steps across 3 T7 patterns): Correctly applied where no CS evidence exists

### Mechanism Fidelity
- **T6-02**: Generalizes MathGPT Python interpreter → any code execution tool ✅
- **T6-03**: Generalizes Bing Chat web content → any poisoned data source ✅
- **T6-05**: Generalizes Twitter learning → any meta-learning mechanism ✅
- **T6-06**: Generalizes OpenClaw control sequences → any agent with configurable system prompts ✅
- **T7-01**: Speculative autonomous constraint deprioritization (no CS) ✅
- **T7-03**: Speculative agent-deceives-human (opposite of CS0055) ✅
- **T7-05**: Speculative autonomous information barrier exploitation (no CS) ✅

---

## Factual Error Analysis

### Critical Errors (blocker)
**Count**: 0

### Major Errors (fix before publication)
**Count**: 0

### Minor Issues (cosmetic/clarity)
**Count**: 0

### Documentation Gaps (for future improvement)
1. T7 patterns should be explicitly labeled as "constructed/speculative" in attack-patterns.yaml metadata
2. Consider adding a "directionality_mismatch" flag to distinguish AP-T7-03 from patterns with no matches at all
3. Consider documenting the condensation strategy (e.g., "13-step sequence condenses 18 CS steps by merging repeated tactics")

---

## Data Model Verification

**Verified**: The `tactic` field in ATLAS `employs` relationships IS the tactic ID directly (AML.TA prefix). No lookup needed. This was correctly applied throughout the audit.

Example from CS0051:
```yaml
- source: AML.CS0051
  target: AML.T0095.000
  tactic: AML.TA0002  # <-- Direct tactic ID
  step-id: S00
```

---

## Recommendations for Pattern Maintainers

All recommendations from the original document remain valid:

1. **Mark speculative patterns**: AP-T7-01, AP-T7-03, and AP-T7-05 should be explicitly labeled as "constructed/speculative" in pattern files (not just in this supporting doc)
2. **Add defense evasion steps**: T6 patterns demonstrate this was often missing in "old" kill chains
3. **Split multi-phase execution**: CS0051 shows value of granular execution steps
4. **Document adaptation**: Clear statements of what was abstracted (already done well here)
5. **Update pattern metadata**: Add match confidence annotations to pattern files

---

## Audit Conclusion

**PASS**: All 7 patterns are factually accurate. Tactic IDs, names, case study references, step counts, and confidence annotations are correct. T6 patterns have strong ATLAS backing; T7 patterns are correctly labeled as speculative/inferred. No revisions required before publication.

The document demonstrates high-quality ATLAS research:
- Thorough case study search
- Honest disclosure of match quality
- Correct application of confidence annotations
- Clear documentation of adaptation rationale
- Accurate abstraction from concrete examples to domain-agnostic mechanisms

**Recommendation**: Approve for use in scenario generation pipeline.
