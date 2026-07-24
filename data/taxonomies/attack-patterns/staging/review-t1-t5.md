# Adversarial Review: tactic-sequences-t1-t5.md

## Summary

8 patterns reviewed. 14 issues found across 6 patterns. 2 patterns need revision, 4 pass with notes, 2 pass clean.

Overall: The tactic ID-to-name mappings are correct across all 8 patterns -- no mismatches found. No hallucinated case study references (all within CS0000-CS0056 range). The CS0059 non-existence is correctly identified. The main weaknesses are (1) inconsistent and sometimes inflated confidence labeling, (2) one pattern (AP-T5-02) with a significant mechanism mismatch between the case study and the pattern, and (3) one pattern (AP-T1-02) that conflates context window and persistent memory.

## Per-Pattern Findings

### AP-T1-01: Persistent memory rule injection
- **Tactic ID/Name errors**: None. All 7 rows correct.
- **Case study accuracy**: CS0040 is real. The proposed sequence exactly matches CS0040's actual procedure steps (S00-S06): TA0003 -> TA0007 -> TA0004 -> TA0005 -> TA0006 -> TA0006 -> TA0011. All "explicit" confidence labels are justified -- each step maps directly to a CS0040 procedure step.
- **Pattern mechanism fidelity**: Strong. The abstraction from "ChatGPT memories" to "persistent memory" and from "Google Doc" to "connected application channel" is appropriate and preserves the mechanism.
- **Confidence justification**: All "explicit" labels are justified.
- **Sequence coherence**: Logical and complete. The dual Persistence steps (memory write vs. content-channel persistence) correctly reflect CS0040's S04 and S05.
- **Adaptation rationale issue**: Minor inaccuracy. The rationale claims "Added Defense Evasion (S01: T0068) which was missing from original pattern kill chain." However, the existing kill chain for AP-T1-01 in the YAML does include T0068 -- it is bundled with T0065 under the "setup" step mapped to TA0003 (Resource Development), not as a separate Defense Evasion step. So T0068 was present but mis-mapped to TA0003 instead of TA0007. The worker should say "separated Defense Evasion into its own step with the correct tactic" rather than "added" it.
- **Verdict**: PASS

---

### AP-T1-02: Context window saturation for privilege escalation
- **Tactic ID/Name errors**: None. All 7 rows correct.
- **Case study accuracy**: CS0040 is real. The tactic sequence adapts CS0040's structure (same 7-step outline). All steps are correctly marked "adapted" or "inferred" rather than "explicit."
- **Pattern mechanism fidelity**: PROBLEM. The pattern specifically describes exploiting the agent's "finite context window" -- a per-session, ephemeral resource. But step 5 (Persistence, TA0006) describes "Fragments accumulate in context window or memory." Context windows do not persist across sessions. If fragments accumulate in PERSISTENT MEMORY, that is AP-T1-01's mechanism, not AP-T1-02's. If fragments exploit the context window within a session, then TA0006 (Persistence) is the wrong tactic. The worker conflates the two concepts with "or memory," which undermines the pattern's distinguishing characteristic.
- **Confidence justification**: "Adapted" and "inferred" labels are honest.
- **Sequence coherence**: The narrative mixes two different attack models: (a) multi-session fragmentation into persistent memory (which is T1-01 territory), and (b) single-session context window overflow (which does not need Persistence). The sequence does not cleanly represent either.
- **CS0040 adaptation quality**: CS0040 demonstrates single-injection persistent memory poisoning. AP-T1-02 describes multi-session fragmentation exploiting context window limits. These are fundamentally different mechanisms. The adaptation is so heavy that CS0040 provides minimal structural guidance -- the worker essentially constructed a new sequence using CS0040's tactic outline as scaffolding.
- **Verdict**: NEEDS REVISION -- The Persistence step conflates context window (ephemeral) with persistent memory (cross-session). The sequence should either commit to one interpretation or restructure to represent the actual context-window-saturation mechanism described in the pattern.

---

### AP-T1-03: Gradual threat-model erosion via memory drift
- **Tactic ID/Name errors**: None. All 4 rows correct.
- **Case study accuracy**: CS0009 is real. The proposed sequence matches CS0009's actual tactic sequence: TA0000 -> TA0004 -> TA0006 -> TA0011 (S00-S03). Correct.
- **Pattern mechanism fidelity**: Reasonable. Both CS0009 (Tay) and AP-T1-03 involve gradual corruption through repeated adversarial interaction. However, Tay had actual online learning (retraining on user input), while AP-T1-03 describes "persistent memory drift" in deployed agents -- a different technical mechanism. The worker acknowledges this difference.
- **Confidence justification**: PROBLEM. Steps 3 and 4 are marked "explicit" but their abstract actions diverge from CS0009:
  - Step 3 ("Repeated adversarial inputs cause gradual corruption of stored threat classification criteria") -- CS0009 S02 actually describes "skewing Tay's dataset" via "repeat after me" function. Tay did not have "stored threat classification criteria." This is an adapted abstraction, not an explicit match.
  - Step 4 ("Agent progressively reclassifies malicious activity as benign") -- CS0009 S03 describes "Tay's conversation algorithms began to learn to generate reprehensible material." Tay generated offensive content; it did not "reclassify malicious activity as benign." This should be "adapted."
- **Sequence coherence**: The 4-step sequence is appropriately brief. The worker's rationale that "No separate execution step needed; access implies execution in online learning contexts" is sound.
- **Verdict**: PASS WITH NOTES -- Steps 3 and 4 should be "adapted" not "explicit." The abstract actions describe different behavior from what CS0009 actually demonstrated.

---

### AP-T1-04: Shared memory corruption for cross-agent influence
- **Tactic ID/Name errors**: None. All 5 rows correct.
- **Case study accuracy**: CS0024 is real. CS0024's actual procedure has 7 steps (S00-S06) with tactics TA0000 -> TA0005 -> TA0005 -> TA0005 -> TA0006 -> TA0010 -> TA0011. The worker condenses the three TA0005 (Execution) steps into one, producing a 5-step sequence. The condensation is reasonable.
- **Pattern mechanism fidelity**: Strong. CS0024 (Morris II, RAG poisoning affecting multiple agents) maps well to AP-T1-04 (shared memory corruption for cross-agent influence).
- **Confidence justification**: Reasonable. Steps 2 and 4 are "adapted" which is honest.
- **Sequence coherence issue**: Step 4 uses TA0010 (Exfiltration) for "Propagation mechanism causes other agents to read corrupted data." The worker acknowledges that "TA0015 (Lateral Movement) would be more accurate" for pure cross-agent influence, but follows CS0024's actual tactic mapping. The pattern's mechanism is INFLUENCE PROPAGATION, not DATA EXFILTRATION. The worker's honesty about this tension is appreciated, but for a pattern about cross-agent influence, TA0015 would better represent the mechanism.
- **Verdict**: PASS WITH NOTES -- The TA0010 (Exfiltration) vs TA0015 (Lateral Movement) choice is acknowledged but creates a mechanism mismatch. Consider whether the pattern-specific tactic should override the case study's original mapping.

---

### AP-T1-06: Zero-click RAG poisoning with rendered-output exfiltration
- **Tactic ID/Name errors**: None. All 7 rows correct.
- **Case study accuracy**: CS0059 correctly identified as non-existent. The composite construction from CS0024 (RAG poisoning) + CS0021/CS0029 (markdown exfiltration) is well-reasoned.
- **Pattern mechanism fidelity**: Strong. The composite captures both halves of the pattern: (1) zero-click RAG poisoning from CS0024 and (2) rendered-output exfiltration from CS0021/CS0029.
- **Confidence justification**: All steps marked "adapted" or "inferred" which is appropriately conservative given the composite nature. Step 5 (Collection, TA0009) is honestly marked "inferred" with the note that CS0021/CS0029 exfiltrate conversation history, not searched data.
- **Sequence coherence**: The 7-step sequence tells a coherent story: setup -> delivery -> dormant persistence -> retrieval-triggered activation -> collection -> exfiltration -> impact.
- **Comparison with existing kill chain**: The worker correctly notes the new sequence matches the existing kill chain's tactic order (TA0003 -> TA0004 -> TA0006 -> TA0005 -> TA0009 -> TA0010 -> TA0011). The primary change is correcting the non-existent CS0059 evidence source.
- **Recommendation**: The existing AP-T1-06 definition in attack-patterns-atlas-derived.yaml still cites "AML.CS0059" as evidence. This should be updated to cite the composite sources (CS0024 + CS0021/CS0029).
- **Verdict**: PASS

---

### AP-T5-01: Progressive misinformation accumulation in persistent memory
- **Tactic ID/Name errors**: None. All 7 rows correct.
- **Case study accuracy**: CS0040 is real. The sequence follows CS0040's actual procedure: TA0003 -> TA0007 -> TA0004 -> TA0005 -> TA0006 -> TA0006 -> TA0011. Correct.
- **Pattern mechanism fidelity**: Moderate. AP-T5-01 describes "progressive misinformation accumulation" over "successive interactions." CS0040 demonstrates single-injection memory poisoning. The worker acknowledges this: "CS0040 shows single-injection memory poisoning; AP-T5-01 describes progressive accumulation." The progressive/compounding aspect is the pattern's distinguishing feature and is not demonstrated by CS0040.
- **Confidence justification**: Steps 2-5 are marked "explicit." This is defensible at the tactic level (CS0040 does explicitly demonstrate Defense Evasion, Initial Access, Execution, and Persistence), but the abstract actions for steps 5-6 are adapted from CS0040's specific mechanism. Step 6 describes "Agent treats stored hallucinations as authoritative source material" -- CS0040 S05 actually describes "poisoned content persists in shared Google Doc as infection vector for other users." The cross-session authority aspect is an adaptation, not an explicit demonstration.
- **Sequence coherence**: Coherent. The worker honestly notes the sequence is identical to AP-T1-01, with differences only in abstract action descriptions. This raises the question of whether identical tactic sequences for different patterns provide sufficient discriminative value.
- **Verdict**: PASS WITH NOTES -- Step 6's "explicit" label is overstated; CS0040 S05 describes content-channel persistence for propagation, not the agent treating its own stored hallucinations as authoritative. Should be "adapted."

---

### AP-T5-02: Hallucinated endpoint injection for data exfiltration
- **Tactic ID/Name errors**: None. All 6 rows correct.
- **Case study accuracy**: CS0020 is real. CS0020's actual tactic sequence is TA0003 -> TA0007 -> TA0005 -> TA0004 -> TA0011 (5 steps: S00-S04). The worker adds a TA0010 (Exfiltration) step from CS0021, making it 6 steps. The unusual Execution-before-Initial-Access ordering (steps 3-4) accurately reflects CS0020's actual procedure.
- **Pattern mechanism fidelity**: PROBLEM -- SIGNIFICANT MISMATCH.
  - AP-T5-02's mechanism: Agent "generates calls to attacker-controlled services" by treating "fabricated endpoints" as legitimate. The agent itself makes the calls.
  - CS0020's mechanism: Bing Chat changes its "conversational style to that of a pirate" and convinces the USER to provide PII and click a link with PII encoded in the URL. The agent does not call fabricated endpoints -- it socially engineers the human.
  - These are fundamentally different. CS0020 demonstrates social engineering via personality manipulation, not agent-initiated endpoint calls. The worker maps "conversational style change" to "treating fabricated endpoints as legitimate" which is a stretch that obscures the actual CS0020 mechanism.
- **Confidence justification**: Multiple "explicit" labels are overstated:
  - Step 1 ("explicit"): CS0020 S00 creates a website with malicious prompts to change conversational style. The worker describes "Create content containing references to fictitious external endpoints." CS0020's content does not contain endpoint references -- it contains behavior-modification instructions. Should be "adapted."
  - Step 4 ("explicit"): CS0020 S03 directs Bing Chat to adopt a pirate persona and subtly convince users to provide PII. The worker describes "Injection causes agent to change behavior, treating fabricated endpoints as legitimate." CS0020 does not involve fabricated endpoints. Should be "adapted."
  - Step 6 ("explicit"): CS0020 S04 is about using PII for identity attacks. The worker describes "Confidential data exfiltrated through hallucinated endpoint invocations." CS0020 does not involve hallucinated endpoint invocations -- the data leak is via social engineering and URL-encoded PII links. Should be "adapted."
- **Sequence coherence**: The Execution-before-Initial-Access ordering is counterintuitive but accurately reflects CS0020. The overall narrative is internally consistent.
- **Better case study candidates**: CS0021 or CS0029 would be better primary references since they demonstrate the AGENT generating markdown image URLs that exfiltrate data -- which is closer to "agent generating calls to attacker-controlled endpoints." The CS0021 mechanism (agent creates markdown image with data-encoded URL, client auto-fetches it) is much closer to "hallucinated endpoint injection" than CS0020's social engineering approach.
- **Verdict**: NEEDS REVISION -- CS0020 mechanism (social engineering via conversational style change) diverges significantly from AP-T5-02's mechanism (agent calling fabricated endpoints). Multiple "explicit" labels are overstated. Consider using CS0021 as primary reference instead.

---

### AP-T5-04: Fabricated reference data injection for value manipulation
- **Tactic ID/Name errors**: None. All 10 rows correct.
- **Case study accuracy**: CS0026 is real. CS0026's actual procedure has 14 steps (S00-S13) condensed into 10. The condensation merges repeated tactic steps: two TA0008 Discovery steps (S02+S03) into one, two TA0003 Resource Development steps (S04+S05) into one, and three TA0007 Defense Evasion steps (S07+S09+S12) into one. This condensation is reasonable and preserves the tactic flow.
- **Pattern mechanism fidelity**: Strong. CS0026 involves substituting fraudulent bank details for legitimate ones via RAG poisoning and prompt injection. AP-T5-04 describes injecting false quantitative reference data to manipulate value-dependent decisions. Both involve replacing legitimate reference data with attacker-controlled values -- strong mechanism alignment.
- **Confidence justification**: Mostly reasonable, but some "explicit" labels are at the tactic level while abstract actions are adapted for the pattern. Examples:
  - Step 1 ("explicit"): CS0026 S00 identifies that "Copilot indexes all received emails" -- the worker describes "Identify agent's data corpus and query patterns to target value-dependent decisions." The tactic (Reconnaissance) is explicit, but "value-dependent decisions" is an adaptation.
  - Step 7 ("explicit"): CS0026 S08 demonstrates RAG persistence of fraudulent bank details. The worker describes "False reference data indexed into RAG database." The tactic (Persistence) is explicit, but the content description is adapted.
  These are minor and the labels are defensible at the tactic level.
- **Sequence coherence**: The 10-step sequence is the longest proposed and tells a thorough attack story. The progression from reconnaissance through discovery, setup, delivery, evasion, persistence, execution, privilege escalation, and impact is logical and well-motivated.
- **Minor factual note**: The rationale says "CS0026 is the longest case study sequence (S00-S13, 10+ tactics)." It should say "14 steps" not "10+ tactics" for precision -- there are 14 step entries, though some tactics repeat.
- **Verdict**: PASS WITH NOTES -- Strong mapping overall. Minor note on "10+ tactics" imprecision and tactic-level vs. action-level "explicit" distinction.

---

## Cross-Cutting Issues

### 1. Inconsistent confidence labeling
The "explicit" label means different things across patterns. For AP-T1-01, it means the abstract action closely matches the case study step. For AP-T5-04, it means the tactic ID matches the case study even though the abstract action is adapted for the pattern. For AP-T5-02, several "explicit" labels are applied to steps where neither the tactic's application nor the abstract action match the case study. A clear definition should be established: does "explicit" mean (a) "the case study uses this tactic at this position" or (b) "the case study demonstrates this specific abstract action"?

### 2. CS0040 duplication produces identical sequences
AP-T1-01 and AP-T5-01 share identical tactic sequences (TA0003 -> TA0007 -> TA0004 -> TA0005 -> TA0006 -> TA0006 -> TA0011) because both adapt from CS0040. The worker acknowledges this. While different abstract actions differentiate the patterns, identical tactic sequences may reduce discriminative value in downstream pipeline stages that use the kill chain structure. Consider whether the progressive/compounding nature of AP-T5-01 warrants structural differences (e.g., a feedback loop representation, or additional steps representing successive injection rounds).

### 3. Context window vs. persistent memory conflation
AP-T1-02's sequence conflates context window saturation (ephemeral, per-session) with persistent memory accumulation (cross-session). This conflation appears in the Persistence step but also reflects an underlying tension in how CS0040 (persistent memory attack) maps to a context-window attack. If the pattern truly targets context window limits, the tactic sequence should not rely on TA0006 (Persistence) as currently formulated.

### 4. CS0020 is a weak primary reference for endpoint hallucination
CS0020 demonstrates social engineering through conversational style manipulation, not agent-initiated endpoint calls. CS0021/CS0029 are better primary references for AP-T5-02 since they demonstrate the agent itself generating output elements (markdown images) that cause automatic data exfiltration to attacker-controlled endpoints -- much closer to "hallucinated endpoint injection."

### 5. No hallucinated case study references
All referenced case studies (CS0009, CS0020, CS0021, CS0024, CS0026, CS0029, CS0040) are within the valid CS0000-CS0056 range. CS0059 is correctly identified as non-existent.

### 6. All tactic ID-to-name mappings are correct
Zero mismatches found across all 58 tactic rows in the 8 patterns. Every TA ID maps to its correct name per the ATLAS taxonomy.
