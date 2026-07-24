# Adversarial Review: tactic-sequences-t11-t17.md

## Summary

7 patterns reviewed. 14 issues found (3 critical, 5 significant, 6 minor). Two patterns need revision (AP-T17-01 and AP-T17-02), two pass with notes (AP-T11-02, AP-T11-05), and three pass clean (AP-T11-01, AP-T11-03, AP-T17-03). The worker correctly identified non-existent case study CS0062 and performed reasonable remappings in some cases. However, the review found one false factual claim about source data (CS0041 persistence step), a poor mechanism match presented as strong (AP-T17-02 to CS0050), and several errors in the summary statistics section.

## Per-Pattern Findings

### AP-T11-01: Infrastructure-as-code injection via agent code generation

- **Tactic ID/Name errors**: None. All 12 rows have correct ID-to-name mappings.
- **Case study accuracy**: Excellent. All 12 steps map directly to CS0052 procedure steps S00-S11 in the ATLAS YAML. The descriptions accurately reflect the case study procedures:
  - Step 1 (TA0003) maps to S00 (static analysis of LLM framework APIs)
  - Step 2 (TA0002) maps to S01 (scanning source code repos for deployment URLs)
  - Step 3 (TA0008) maps to S02 (call chain extraction)
  - Steps 4-12 continue the correct correspondence through S03-S11
- **Pattern mechanism fidelity**: The pattern describes IaC injection via code generation agents; CS0052 demonstrates RCE through LLM framework code execution sinks. The general code execution mechanism aligns, though the pattern's specific IaC angle (infrastructure configuration with embedded malicious commands) is more specific than CS0052's generic framework RCE. The worker acknowledges this abstraction. Acceptable.
- **Confidence justification**: All 12 steps marked "explicit" -- verified correct. Every step corresponds to an actual procedure step in CS0052.
- **Sequence coherence**: Logical and complete attack narrative from research through exploitation to persistence.
- **Verdict**: PASS

---

### AP-T11-02: Workflow automation backdoor insertion

- **Tactic ID/Name errors**: None. All 6 rows have correct ID-to-name mappings.
- **Case study accuracy**: CS0047 exists and the worker's description of it is accurate. The worker correctly identified that the original evidence (CS0062) does not exist in ATLAS. The 6-step sequence corresponds to CS0047's 7-step procedure (S00-S06), with the three TA0005 steps (S03, S04, S05) compressed into two. This compression is reasonable.
- **Pattern mechanism fidelity**: **SIGNIFICANT CONCERN.** The pattern says: "Agent responsible for generating or modifying automation workflows is manipulated into embedding backdoor logic within the generated scripts." CS0047 shows a *human attacker* who steals a GitHub token and directly commits malicious code to a repository, which then deploys an Amazon Q agent with a destructive prompt. In CS0047, the agent is the *payload* (the destructive tool), not the *target* being manipulated. The pattern describes manipulation of a workflow-generating agent; CS0047 describes supply chain compromise of a code repository. The worker's adaptation rationale partially acknowledges this ("abstracting from 'deployed destructive agent' to 'workflow generation poisoning'") but understates the gap.
- **Confidence justification**: All 6 steps marked "explicit." This is misleading. While the individual CS0047 steps are real, applying them to a fundamentally different pattern mechanism means the mapping is adapted, not explicit. The confidence should be "adapted" for all steps.
- **Sequence coherence**: The sequence is internally coherent but tells a supply chain compromise story rather than the agent manipulation story the pattern describes.
- **Verdict**: PASS WITH NOTES -- The remapping from non-existent CS0062 to CS0047 is a reasonable pragmatic choice, but the confidence levels should be "adapted" rather than "explicit" and the rationale should be more honest about the mechanism gap.

---

### AP-T11-03: Linguistic ambiguity exploitation for command injection

- **Tactic ID/Name errors**: None. All 7 rows have correct ID-to-name mappings.
- **Case study accuracy**: CS0052 is the source. The worker correctly identifies this as an adaptation rather than a direct match and marks all steps as "adapted."
- **Pattern mechanism fidelity**: Good. The pattern describes exploiting the semantic gap between natural language interpretation and command execution. CS0052 demonstrates the language-to-code boundary, though through direct prompt injection rather than linguistic ambiguity. The worker is honest about this difference and correctly strips framework-specific steps.
- **Confidence justification**: All 7 steps marked "adapted" -- this is honest and appropriate.
- **Sequence coherence**: Clean attack narrative. The removal of CS0052's research-phase steps (static analysis, call chain extraction) and post-exploitation steps (sandbox escape, C2) is appropriate for the pattern's different attack vector.
- **Verdict**: PASS

---

### AP-T11-05: Computer-use agent exploitation via adversarial web content

- **Tactic ID/Name errors**: None. All 8 rows have correct ID-to-name mappings.
- **Case study accuracy**: Excellent. All 8 steps map directly to CS0055's procedure steps S00-S07:
  - Step 1 (TA0003) maps to S00 (obtain ChatGPT access, AML.T0016.002)
  - Step 2 (TA0003) maps to S01 (generate adversarial web content, AML.T0017)
  - Step 3 (TA0003) maps to S02 (stage website and script, AML.T0079)
  - Step 4 (TA0004) maps to S03 (agent visits website, AML.T0078)
  - Step 5 (TA0005) maps to S04 (agent clickbait interaction, AML.T0100)
  - Step 6 (TA0005) maps to S05 (embedded instructions, AML.T0051.001)
  - Step 7 (TA0012) maps to S06 (agent executes command, AML.T0053)
  - Step 8 (TA0011) maps to S07 (arbitrary code execution, AML.T0112.000)
- **Pattern mechanism fidelity**: Direct match. CS0055 demonstrates exactly the attack the pattern describes.
- **Confidence justification**: All 8 steps marked "explicit" -- verified correct.
- **Sequence coherence**: Perfect. Complete attack narrative.
- **Minor note**: The adaptation rationale claims "three Resource Development steps that show the full attack preparation workflow" but while accurate, the first Resource Development step (obtaining LLM access to generate content) is a meta-preparation step -- the attacker using an LLM to build the attack. This is faithfully preserved from CS0055 but is worth noting as a preparatory step rather than a core attack mechanism step.
- **Verdict**: PASS WITH NOTES (minor note only)

---

### AP-T17-01: Upstream artifact poisoning via repository compromise

- **Tactic ID/Name errors**: None. All 8 rows have correct ID-to-name mappings.
- **Case study accuracy**: **CRITICAL ERROR.** The worker claims in the adaptation rationale: "CS0041 doesn't map a technique to TA0006." This is factually false. CS0041 procedure step S04 explicitly maps AML.T0081 to AML.TA0006 (Persistence), with description: "Users then pulled the latest version of the rules file, replacing their coding assistant's configuration with the malicious one. The coding assistant's behavior was modified, affecting all future code generation." The worker omitted the Persistence step from the proposed sequence and justified the omission with a false claim about the source data.
- **Missing step**: The Persistence step (TA0006, CS0041 step S04) is omitted. CS0041's actual tactic sequence is: TA0003, TA0003, TA0007, TA0004, **TA0006**, TA0005, TA0007, TA0007, TA0011 (9 steps). The worker's sequence is: TA0003, TA0003, TA0007, TA0004, TA0005, TA0007, TA0007, TA0011 (8 steps). The missing Persistence step should be inserted between step 4 (Initial Access/distribution) and step 5 (Execution/prompt activation).
- **Pattern mechanism fidelity**: Good match. CS0041 (Rules File Backdoor) demonstrates exactly the supply chain poisoning described by the pattern.
- **Confidence justification**: All 8 steps marked "explicit" but one real step from CS0041 is missing. With the omission corrected, the remaining steps are genuinely explicit.
- **Sequence coherence**: The sequence is coherent but incomplete -- adding the Persistence step would improve it by showing how the poisoned config persists after adoption.
- **Verdict**: NEEDS REVISION -- Must add the missing Persistence (TA0006) step and remove the false claim that CS0041 lacks a TA0006 mapping.

---

### AP-T17-02: Autonomous agent self-sabotage via unvalidated execution

- **Tactic ID/Name errors**: None. All 8 rows have correct ID-to-name mappings.
- **Case study accuracy**: **TWO SIGNIFICANT OMISSIONS.**
  1. **Missing Credential Access (TA0013)**: CS0050 step S03 maps AML.T0106 to AML.TA0013 -- the malicious script steals the Gateway token by redirecting the OpenClaw control interface to the attacker's WebSocket server. This credential theft is a critical step in the exploit chain. The worker merged this with step 4 (TA0012 Privilege Escalation) but incorrectly labeled it as TA0012 only, losing the TA0013 tactic entirely.
  2. **Missing Defense Evasion (TA0007)**: CS0050 step S04 maps AML.T0107 to AML.TA0007 -- Cross-Site WebSocket Hijacking (CSWSH) to bypass localhost network restrictions. This is a significant technical step that enables the subsequent authentication. The worker omitted it entirely.
  - CS0050 actual sequence: TA0003, TA0003, TA0005, **TA0013**, **TA0007**, TA0012, TA0007, TA0012, TA0005 (9 steps)
  - Worker's sequence: TA0003, TA0003, TA0005, TA0012, TA0007, TA0012, TA0005, TA0011 (8 steps)
- **Pattern mechanism fidelity**: **CRITICAL MISMATCH.** The pattern describes "autonomous agent self-sabotage via unvalidated execution" -- an agent that "hallucinates incorrect resource references, destroys legitimate data, and then produces falsified verification results." This is about the agent's own autonomous behavior causing harm through hallucination and lack of validation controls. CS0050 demonstrates a completely different mechanism: an external 1-click exploit using Cross-Site WebSocket Hijacking to steal authentication tokens and remotely reconfigure an agent's safety controls. CS0050 is an external exploit; AP-T17-02 describes internal autonomous failure. The worker claims these "map perfectly" but they do not -- the mechanisms are fundamentally different. The worker's argument ("an attacker disabling safety controls and causing the agent to execute destructive commands") describes external compromise, not self-sabotage.
- **Confidence justification**: Steps 1-7 marked "explicit" despite missing two procedure steps from CS0050. Step 8 honestly marked "inferred" (Impact step added by worker, not present in CS0050). The "explicit" ratings for the remaining steps overstate fidelity given the omissions.
- **Sequence coherence**: Internally coherent as an exploit chain but does not tell the "autonomous self-sabotage" story the pattern describes.
- **Note on original mapping**: The worker correctly identifies that CS0049 (skill registry poisoning) is a poor match for this pattern. However, CS0050 is equally poor in a different way. Neither case study demonstrates autonomous agent self-sabotage via hallucination. This pattern may genuinely lack a strong ATLAS case study match, and the worker should state that rather than forcing a match.
- **Verdict**: NEEDS REVISION -- The mechanism mismatch is too severe. Either find a better case study, honestly acknowledge the weak match and mark all confidence as "adapted" or "inferred," or acknowledge that no strong match exists.

---

### AP-T17-03: Tool supply chain poisoning via registry namesquatting

- **Tactic ID/Name errors**: None. All 9 rows have correct ID-to-name mappings.
- **Case study accuracy**: Excellent. All 9 steps map directly to CS0053's procedure steps S00-S08:
  - Step 1 (TA0007) maps to S00 (namesquatting, AML.T0073)
  - Step 2 (TA0003) maps to S01 (functional tool with exfil, AML.T0017)
  - Step 3 (TA0003) maps to S02 (publish malicious version, AML.T0104)
  - Step 4 (TA0007) maps to S03 (rug-pull timing evasion, AML.T0109)
  - Step 5 (TA0004) maps to S04 (users upgrade, AML.T0010.005)
  - Step 6 (TA0006) maps to S05 (persistence in configs, AML.T0110)
  - Step 7 (TA0005) maps to S06 (users invoke tool, AML.T0011.002)
  - Step 8 (TA0010) maps to S07 (exfiltration via BCC, AML.T0086)
  - Step 9 (TA0011) maps to S08 (data leaked, AML.T0048)
- **Pattern mechanism fidelity**: Direct match. CS0053 demonstrates exactly the MCP server namesquatting attack the pattern describes.
- **Confidence justification**: All 9 steps marked "explicit" -- verified correct.
- **Sequence coherence**: Complete and logical attack narrative from namesquatting through persistent exfiltration.
- **Verdict**: PASS

---

## Cross-Cutting Issues

### 1. False factual claim about source data (Critical)

The worker states that "CS0041 doesn't map a technique to TA0006" in AP-T17-01's adaptation rationale. This is demonstrably false -- CS0041 step S04 maps AML.T0081 to AML.TA0006 (Persistence). This false claim is used to justify omitting a real step from the case study. Whether this was careless reading of the ATLAS YAML or deliberate simplification, it undermines trust in the worker's source data verification.

### 2. Summary statistics contain multiple errors (Significant)

- **Defense Evasion count**: Claims "6/7 patterns include explicit evasion steps (jailbreak, obfuscation, timing)." Actual count is **4/7**: T11-01, T17-01, T17-02, T17-03. Three patterns lack any TA0007 step: T11-02, T11-03, T11-05.
- **T11 average sequence length**: Lists "12, 6, 7 steps (avg 8.3)" but omits T11-05 (8 steps). With all four T11 patterns included, the values should be 12, 6, 7, 8 (avg 8.25).
- **T11 pattern count**: The summary lists only 3 T11 sequence lengths but the document covers 4 T11 patterns.

### 3. Confidence rating inconsistency (Significant)

Two patterns (AP-T11-02 and AP-T17-02) mark all or nearly all steps as "explicit" despite significant adaptation from the source case study:
- AP-T11-02: CS0047's mechanism (supply chain code commit) differs fundamentally from the pattern (agent manipulation for workflow backdoors). These steps should be "adapted."
- AP-T17-02: CS0050's mechanism (1-click WebSocket exploit) differs fundamentally from the pattern (autonomous self-sabotage). These steps should be "adapted" or "inferred."

In contrast, AP-T11-03 correctly marks all steps as "adapted" for a comparable level of adaptation from CS0052. The standard is inconsistent.

### 4. Pattern mechanism overstating (Moderate)

Both remapped patterns (T11-02 and T17-02) overstate the quality of the case study match. The worker uses phrases like "maps perfectly" (T17-02) and "correctly models" (T11-02) for matches where the core mechanism differs significantly. The matching analysis document should be referenced more carefully -- it correctly identifies some of these patterns as having only partial matches or no strong matches in ATLAS.

### 5. Omitted procedure steps in two patterns

Two patterns omit real procedure steps from their source case studies:
- AP-T17-01: Missing TA0006 Persistence step from CS0041 (S04)
- AP-T17-02: Missing TA0013 Credential Access (CS0050 S03) and TA0007 Defense Evasion (CS0050 S04)

In AP-T17-01 the omission is justified with a false claim. In AP-T17-02 the omissions are not acknowledged at all.
