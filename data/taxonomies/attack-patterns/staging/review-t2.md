# Adversarial Review: tactic-sequences-t2.md

## Summary

5 patterns reviewed. 14 issues found (4 significant, 6 moderate, 4 minor). Overall assessment: the sequences are structurally sound and tell coherent attack stories, but there is a systemic problem with confidence inflation -- several steps marked "explicit" are better classified as "adapted" because the source case study demonstrates a related but not identical mechanism. One pattern (AP-T2-06) introduces a tactic (TA0003) that does not appear in the primary case study at all yet claims "explicit" confidence. One step count error exists in the comparison text.

## Per-Pattern Findings

### AP-T2-01: Parameter pollution via function-call manipulation

- **Tactic ID/Name errors**: None. All six tactic ID-to-name mappings are correct per the ATLAS mapping.

- **Case study accuracy**: CS0037 is a valid case study (within CS0000-CS0056 range). The name "Data Exfiltration via Agent Tools in Copilot Studio" is correct. However, the worker overstates the match quality for this specific pattern. CS0037 demonstrates tool misuse via prompt injection for **data exfiltration** -- the attacker manipulates which tool to call and what destination to send data to. AP-T2-01 is about **parameter pollution producing boundary-violating outcomes** (amplified quantities, malformed inputs). CS0037 does not demonstrate boundary-violating parameter values, inflated quantities, or malformed inputs. The only "parameter manipulation" in CS0037 is setting an email recipient to an attacker-controlled address, which is tool redirection, not parameter pollution.

- **Pattern mechanism fidelity**: The sequence itself describes a coherent parameter pollution attack. However, the connection to CS0037 is weaker than claimed. The pattern's core mechanism (boundary-violating parameter values producing amplified outcomes) is not demonstrated in CS0037.

- **Confidence justification**: This is the most problematic area.
  - Step 1 (Recon): "explicit" -- fair, CS0037 S00 demonstrates reconnaissance.
  - Step 2 (Resource Dev): "explicit" -- **overstated**. CS0037 S01 shows prompt crafting for exfiltration, not crafting inputs to produce "inflated, malformed, or boundary-violating values." Should be "adapted."
  - Step 3 (Initial Access): "adapted" -- correctly marked.
  - Step 4 (Execution): "explicit" -- **overstated**. CS0037 shows prompt injection causing tool invocation, but not "attacker-influenced values into tool call parameter slots" in the boundary-violation sense. Should be "adapted."
  - Step 5 (Execution): "explicit" -- **overstated**. CS0037 does show authorized tool with attacker-influenced parameters, but not "amplified quantities" or "outcome far outside intended operational bounds" in the quantity/boundary sense. Should be "adapted."
  - Step 6 (Impact): "explicit" -- **partially overstated**. CS0037's impact is data exfiltration, not "amplified quantities, modified recipients." The "modified recipients" aspect is present (email sent to attacker address), but "amplified quantities" is not. Should be "adapted."

- **Sequence coherence**: Good. The six-step flow (recon, craft, deliver, execute, invoke tool, impact) is logically sound and tells a coherent parameter pollution story.

- **Verdict**: NEEDS REVISION -- confidence levels should be downgraded from "explicit" to "adapted" for steps 2, 4, 5, and 6.

---

### AP-T2-02: Multi-tool chain exploitation for data exfiltration

- **Tactic ID/Name errors**: None. All eight tactic ID-to-name mappings are correct.

- **Case study accuracy**: CS0037 is valid and is an excellent primary match for this pattern -- it genuinely demonstrates multi-tool chaining (discovery tools -> collection tools -> email exfiltration tool). CS0021, CS0035, CS0045 are all valid case studies within range. The worker's characterization of CS0037 as an "exact match" is justified for this pattern.

  However, the adaptation rationale contains an inaccuracy about CS0037's step mapping. The worker states: "The sequence directly follows CS0037's step progression (S00-S11), which shows: reconnaissance for tools (S00-S05)." This is wrong. In CS0037's actual procedure:
  - S00 is reconnaissance (TA0002)
  - S01 is resource development (TA0003) -- prompt crafting
  - S02 is initial access (TA0004) -- sending the email
  - S03 is execution (TA0005) -- prompt injection fires
  - S04-S05 are discovery (TA0008) -- inferring activation model and tool availability

  Only S00, S04, and S05 are reconnaissance/discovery. S01-S03 are resource development, initial access, and execution. Calling S00-S05 "reconnaissance for tools" mischaracterizes three of those six steps.

- **Pattern mechanism fidelity**: Strong. The multi-tool chain pattern is accurately represented, and CS0037 genuinely demonstrates this mechanism.

- **Confidence justification**: All eight steps marked "explicit" is largely defensible given the strong match with CS0037. Minor quibble: step 8 (Impact) is more of an implied conclusion than an explicitly demonstrated step -- CS0037's procedure ends at exfiltration (S13, TA0010) with no separate impact step recorded. But framing the completed exfiltration as impact is reasonable.

- **Sequence coherence**: Good. The eight-step flow adds useful granularity by separating Discovery (step 5) and Collection (step 6) as distinct phases, which accurately reflects how CS0037 operates.

- **Verdict**: PASS WITH NOTES -- the adaptation rationale mischaracterizes CS0037 steps S00-S05 as all being "reconnaissance for tools" when only S00, S04, S05 are recon/discovery. The confidence ratings are otherwise reasonable.

---

### AP-T2-04: Tool misuse via poisoned persistent memory

- **Tactic ID/Name errors**: None. All eight tactic ID-to-name mappings are correct.

- **Case study accuracy**: CS0040 is valid. The name "Hacking ChatGPT's Memories with Prompt Injection" is correct. The worker's description of CS0040's procedure is accurate:

  CS0040 actual procedure (verified from ATLAS YAML):
  - S00: TA0003 (Resource Dev) -- craft prompt for memory setting
  - S01: TA0007 (Defense Evasion) -- hide prompt in Google Doc header
  - S02: TA0004 (Initial Access) -- share doc with victim via Connected App
  - S03: TA0005 (Execution) -- prompt executes when user references doc
  - S04: TA0006 (Persistence) -- memories poisoned, persist across sessions
  - S05: TA0006 (Persistence) -- prompt persists in shared doc as infection vector
  - S06: TA0011 (Impact) -- victim misinformed/misled

  Worker's steps 1-6 map exactly to S00-S05. This is accurate.

- **Pattern mechanism fidelity**: Strong. AP-T2-04 requires extending CS0040's misinformation impact to tool misuse. The worker correctly identifies this gap and adapts the final steps (7-8) accordingly. The core insight -- that memory poisoned in session N causes tool misuse in session N+1 -- is faithful to the pattern definition.

- **Confidence justification**: Well-calibrated.
  - Steps 1-6: "explicit" -- correctly mapped to CS0040 S00-S05.
  - Steps 7-8: "adapted" -- correctly acknowledged that CS0040 ends with misinformation impact, while AP-T2-04 extends to tool invocation.

- **Sequence coherence**: Good. The cross-session attack narrative (poison memory now, exploit via tools later) is logically sound and well-structured.

- **Verdict**: PASS -- this is the strongest entry in the document. Confidence levels are accurate, case study mapping is correct, and the adaptation is honest.

---

### AP-T2-05: Tool misuse via adversarial retrieval content

- **Tactic ID/Name errors**: None. All seven tactic ID-to-name mappings are correct.

- **Case study accuracy**: CS0024 is valid. The name "Morris II Worm: RAG-Based Attack" is correct. The worker's description of CS0024's procedure is accurate per the ATLAS YAML.

  CS0024 actual procedure:
  - S00: TA0000 (AI Model Access) -- access GenAI model API
  - S01: TA0005 (Execution) -- test prompts on public model APIs
  - S02: TA0005 (Execution) -- send email with worm; agent ingests into RAG
  - S03: TA0005 (Execution) -- email retrieved, prompt injection changes behavior
  - S04: TA0006 (Persistence) -- self-replicating portion propagates
  - S05: TA0010 (Exfiltration) -- sensitive data leaked
  - S06: TA0011 (Impact) -- PII leaked to attackers

  Issues with the worker's mapping:

  1. **Step 1 (TA0000) description mismatch**: The worker describes step 1 as "Gain access to the vector store or RAG system (either through write access or by injecting content into a data source the system indexes)." But CS0024 S00 is about accessing the **GenAI model API**, not about gaining write access to the vector store. The vector store injection happens later (S02, via email). The worker's description conflates model API access (what S00 actually demonstrates) with vector store write access (what happens later in the attack). The tactic assignment (TA0000) is correct, but the abstract action doesn't match what TA0000/S00 actually demonstrates in CS0024.

  2. **Step 3-4 resequencing**: In CS0024, retrieval/activation (S03, TA0005) occurs **before** persistence/propagation (S04, TA0006). The worker reverses this: step 3 is persistence (TA0006), step 4 is retrieval (TA0005). While this reordering may make more logical sense for the general pattern (content persists first, then is retrieved later), it changes the sequence from CS0024's observed procedure. Step 4 is marked "explicit" despite being resequenced -- should be "adapted."

- **Pattern mechanism fidelity**: Good overall. The adaptation from CS0024's self-replication focus to AP-T2-05's tool-misuse focus is appropriate and clearly stated.

- **Confidence justification**:
  - Step 1: "explicit" -- tactic is correct but description doesn't match CS0024's S00. Borderline.
  - Step 2: "explicit" -- reasonable, maps to S01-S02 combined.
  - Step 3: "explicit" -- maps to S04. Correct tactic.
  - Step 4: "explicit" -- **overstated**. Resequenced from CS0024 and refocused from prompt propagation to tool invocation guidance. Should be "adapted."
  - Step 5: "adapted" -- correctly marked.
  - Step 6: "adapted" -- correctly marked (exfiltration is in CS0024 but via different mechanism).
  - Step 7: "explicit" -- **overstated**. CS0024's impact is PII leakage, not "unauthorized actions driven by poisoned retrieval content with each query potentially triggering malicious behavior." Should be "adapted."

- **Sequence coherence**: Mostly good, though having three consecutive Execution (TA0005) steps (2, 4, 5) is somewhat redundant. The sequence could potentially be cleaner.

- **Verdict**: PASS WITH NOTES -- step 4 and step 7 confidence levels should be downgraded from "explicit" to "adapted." Step 1's abstract action description should be revised to match what TA0000 actually represents in CS0024.

---

### AP-T2-06: Tool hijacking via prompt injection

- **Tactic ID/Name errors**: None. All nine tactic ID-to-name mappings are correct per the ATLAS mapping.

- **Case study accuracy**: CS0016 is valid. CS0037, CS0039, CS0045, CS0046, CS0051 are all valid (within CS0000-CS0056).

  CS0016 actual procedure (verified from ATLAS YAML):
  - S00: TA0002 (Reconnaissance) -- familiarize with prompt injection attacks
  - S01: TA0000 (AI Model Access) -- interact with GPT-3 via MathGPT app
  - S02: TA0005 (Execution) -- craft adversarial prompts to test injection
  - S03: TA0001 (AI Attack Staging) -- verify with innocuous examples ("Hello World")
  - S04: TA0004 (Initial Access) -- confirm as initial access vector
  - S05: TA0005 (Execution) -- gain execution via connected Python interpreter
  - S06: TA0013 (Credential Access) -- reveal environment variables/API key
  - S07: TA0011 (Impact) -- could exhaust GPT-3 query budget
  - S08: TA0011 (Impact) -- denial of service

  **Critical issue: TA0003 (Resource Development) does not appear anywhere in CS0016's procedure.** The worker's step 3 uses TA0003 and is marked "explicit." Looking at the worker's rationale, they map their step 3 to CS0016's "S02 - craft prompt." But S02 in CS0016 uses **TA0005 (Execution)**, not TA0003 (Resource Development). The worker has reassigned the tactic from TA0005 to TA0003 without acknowledging this as an adaptation, and then claims "explicit" confidence.

  TA0003 does appear in secondary case study CS0037 (at S01 and S10), so the tactic is evidenced elsewhere. But claiming it as "explicit" when the primary case study doesn't use it is misleading. This should be marked "adapted" with a note that it's drawn from secondary sources.

  **Sequence reordering**: The worker significantly reorders CS0016's procedure:
  - CS0016 order: TA0002 -> TA0000 -> TA0005 -> TA0001 -> TA0004 -> TA0005 -> TA0013 -> TA0011
  - Worker order: TA0002 -> TA0000 -> TA0003 -> TA0004 -> TA0005 -> TA0001 -> TA0005 -> TA0013 -> TA0011

  Notably, in CS0016, the staging/testing phase (S03, TA0001) occurs **before** initial access (S04, TA0004). The worker reverses this: initial access (step 4) comes before staging (step 6). In CS0016, the attacker tests with innocuous prompts ("Hello World") before escalating to exploitation. The worker places the verification step mid-attack, after initial access and execution. The worker's step 6 description ("through benign test payloads before escalating to malicious ones") implies a pre-exploitation testing phase, but its placement AFTER initial access and execution contradicts this narrative.

- **Pattern mechanism fidelity**: The sequence accurately describes a tool hijacking attack and generalizes CS0016's code-execution-specific attack to any tool with execution capability. This is appropriate for AP-T2-06.

- **Confidence justification**:
  - Steps 1-2: "explicit" -- correct, directly from CS0016 S00-S01.
  - Step 3 (TA0003): "explicit" -- **incorrect**. TA0003 does not appear in CS0016's procedure. Should be "adapted" (drawn from secondary case studies or logical inference).
  - Steps 4-5: "explicit" -- CS0016 has TA0004 (S04) and TA0005 (S02/S05), so the tactics are present, though resequenced.
  - Step 6 (TA0001): "explicit" -- correct, CS0016 S03 demonstrates attack staging.
  - Step 7: "explicit" -- correct, CS0016 S05 demonstrates tool execution.
  - Step 8 (TA0013): "adapted" -- correctly marked. CS0016 S06 demonstrates credential access, but the worker correctly notes it's optional/conditional for the general pattern.
  - Step 9: "explicit" -- correct, CS0016 S07 demonstrates impact.

- **Sequence coherence**: Generally good. The nine-step flow provides useful granularity. However, the placement of staging (step 6) after initial access and execution (steps 4-5) is logically inconsistent with the step 6 description which says "through benign test payloads before escalating to malicious ones" -- if benign tests come first, this step should precede the full exploitation, not follow it.

- **Additional error -- step count in comparison text**: The worker states "The existing kill chain had four steps (setup, delivery, execution, tool_hijack, impact)." This lists **five** step names in parentheses, not four. The actual existing kill chain in attack-patterns-memory-tool.yaml has five steps. The count "four" is wrong.

- **Verdict**: NEEDS REVISION -- (1) step 3 confidence must be downgraded from "explicit" to "adapted" since TA0003 is absent from CS0016; (2) the staging step placement should be reconsidered for logical consistency; (3) the existing kill chain step count should be corrected from "four" to "five."

---

## Cross-Cutting Issues

### 1. Systemic confidence inflation
The most pervasive problem across all five patterns is overstating "explicit" confidence. The methodology defines "explicit" as "Tactic directly demonstrated in source case study." Multiple steps are marked "explicit" when the case study demonstrates a **related tactic applied to a different mechanism**. For example:
- AP-T2-01 maps CS0037 (data exfiltration via tool chaining) to parameter pollution -- the tactic types overlap but the mechanisms are different, making most steps "adapted" rather than "explicit."
- AP-T2-06 claims "explicit" for TA0003 (Resource Development) but this tactic is absent from the primary case study CS0016.
- AP-T2-05 claims "explicit" for resequenced steps.

**Recommendation**: Adopt a stricter rule -- "explicit" should mean the case study demonstrates both the same tactic AND the same mechanism. If only the tactic matches but the mechanism differs, use "adapted."

### 2. Case study step descriptions in rationales contain inaccuracies
When workers describe which CS steps map to which phases, some descriptions don't match the actual ATLAS YAML:
- AP-T2-02 claims "S00-S05 shows reconnaissance for tools" but S01-S03 are resource development, initial access, and execution.
- AP-T2-06 maps S02 to "craft prompt" (implying TA0003) but S02 in CS0016 is actually TA0005.

These inaccuracies suggest the worker may be describing the steps from memory or inference rather than verifying against the source YAML.

### 3. Resequencing without acknowledgment
In AP-T2-05 and AP-T2-06, the worker reorders steps from the source case study without explicitly noting this as a departure. Resequencing may be justified for the generalized pattern, but it should be flagged as an adaptation and the confidence for resequenced steps should reflect this.

### 4. One arithmetic error
AP-T2-06 states the existing kill chain "had four steps" but lists five in parentheses. Minor but should be corrected.
