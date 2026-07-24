# Adversarial Review: tactic-sequences-t6-t7.md

## Summary

7 patterns reviewed. 14 issues found across 3 patterns; 4 patterns pass clean. The T6-06 pattern has the most serious problems: incorrect confidence annotations ("adapted" for steps that are explicitly in the ATLAS data) and omission of entire tactic phases (Reconnaissance, Discovery, Initial Access) that are directly documented in CS0051. The T7-03 pattern mischaracterizes CS0055's mechanism -- the worker claims CS0055 shows "an agent manipulating a human" when the case study actually shows a website manipulating an agent. The remaining five patterns are accurate.

## Per-Pattern Findings

### AP-T6-02: Direct instruction override for tool-chain hijacking

- **Tactic ID/Name errors**: None. All 7 mappings are correct.
- **Case study accuracy**: CS0016 is real (CS0000-CS0056 range). The tactic sequence TA0002 -> TA0000 -> TA0005 -> TA0001 -> TA0004 -> TA0013 -> TA0011 matches the actual CS0016 procedure steps (S00-S08) when duplicate-tactic steps are compressed. Minor note: The worker describes step 6 as "Exfiltrate environment variables and API keys through the hijacked code execution." In CS0016 (S06), the actor used a prompt to *display* environment variables via `os.environ` in the application output. The term "exfiltrate" slightly overstates what happened -- the credentials were revealed in the application UI, not sent to an attacker-controlled endpoint. This is a minor accuracy issue; the underlying tactic (TA0013, Credential Access) is correctly applied.
- **Pattern mechanism fidelity**: Good. The pattern describes direct instruction override for tool-chain hijacking; CS0016 demonstrates exactly this via prompt injection overriding MathGPT's behavior to achieve code execution.
- **Confidence justification**: All 7 steps marked "explicit." Verified against CS0016 procedure steps S00-S08: every tactic is directly documented in the case study. Justified.
- **Sequence coherence**: Coherent attack story. The ordering where Execution (step 3) comes before Initial Access (step 5) looks counterintuitive but accurately reflects CS0016 where the actor tested prompts (S02, Execution) and validated feasibility (S03, Staging) before establishing the initial access vector (S04).
- **Verdict**: PASS WITH NOTES (minor overstatement of "exfiltrate" in step 6 description)

---

### AP-T6-03: Indirect goal redirection via poisoned tool output

- **Tactic ID/Name errors**: None. All 5 mappings are correct.
- **Case study accuracy**: CS0020 is real. The proposed tactic sequence TA0003 -> TA0007 -> TA0005 -> TA0004 -> TA0011 matches CS0020's actual procedure steps exactly:
  - S00: TA0003 (created malicious website) 
  - S01: TA0007 (obfuscated prompts via font-size: 0) 
  - S02: TA0005 (Bing Chat ingests and executes malicious prompt) 
  - S03: TA0004 (malicious prompt redirects Bing Chat behavior) 
  - S04: TA0011 (identity-level attacks using exfiltrated PII) 
- **Pattern mechanism fidelity**: Good. The pattern describes indirect goal redirection via poisoned data sources; CS0020 demonstrates this via web content containing hidden prompt injection.
- **Confidence justification**: All 5 steps marked "explicit." Verified: every step maps directly to a CS0020 procedure step. Justified.
- **Sequence coherence**: Clean, logical progression from resource development through impact.
- **Verdict**: PASS

---

### AP-T6-05: Self-improvement mechanism corruption

- **Tactic ID/Name errors**: None. All 4 mappings are correct.
- **Case study accuracy**: CS0009 is real. The proposed tactic sequence TA0000 -> TA0004 -> TA0006 -> TA0011 matches CS0009's actual procedure steps exactly:
  - S00: TA0000 (interact with Tay via Twitter)
  - S01: TA0004 (exploit feedback loop with adversarial inputs)
  - S02: TA0006 (skew dataset with offensive language, persisting changes)
  - S03: TA0011 (generate reprehensible material)
- **Pattern mechanism fidelity**: Good. The pattern describes corruption of meta-learning mechanisms via adversarial feedback; Tay Poisoning is the textbook demonstration of this.
- **Confidence justification**: All 4 steps marked "explicit." Verified. Justified.
- **Sequence coherence**: Clean, logical.
- **Verdict**: PASS

---

### AP-T6-06: AI agent as persistent C2 implant via control sequence spoofing

- **Tactic ID/Name errors**: None. All tactic IDs map to correct names.
- **Case study accuracy**: CS0051 is real. However, multiple significant accuracy problems:

  **CRITICAL -- Incorrect confidence annotations (steps 7-9)**: The worker marks steps 7 (Persistence, TA0006), 8 (C2, TA0014), and 9 (Impact, TA0011) as "adapted" with the rationale: "the case study relationships end at step S14." This is factually wrong. The actual ATLAS relationships for CS0051 continue through S17:
  - S13: TA0006 (Persistence) -- "The malicious script appended a prompt injection to OpenClaw's HEARTBEAT.md configuration file"
  - S14: TA0005 (Execution) -- "the modified system prompt containing the researcher's instructions is executed"
  - S15: TA0006 (Persistence) -- "The context of all new threads became poisoned"
  - S16: TA0014 (C2) -- "OpenClaw to act as a command and control agent... requested the TODO list and executed the commands"
  - S17: TA0011 (Impact) -- "The behavior of the OpenClaw agent has been hijacked"

  All three "adapted" steps are explicitly documented in the ATLAS relationships. They should be "explicit."

  **Omitted tactics**: The worker's 9-step sequence omits multiple tactic phases that are explicitly in CS0051:
  1. **Reconnaissance (TA0002)** -- S00 in CS0051: "identified the OpenClaw GitHub repository as a source of agent configuration files." The worker's step 1 describes "Acquire or study the agent's configuration files" but maps it to Resource Development (TA0003), conflating S00 (Reconnaissance/TA0002) and S01 (Resource Development/TA0003).
  2. **Discovery (TA0008)** -- S02 and S03 in CS0051: "identified special characters such as `<<<` and `>>>` used to denote control sequences" and "discovered specific control sequences." The worker merges these into step 1's Resource Development, but Discovery and Resource Development are semantically distinct ATLAS tactics. Discovering the target's internal control sequences is TA0008 (Discovery), not TA0003 (Resource Development).
  3. **Initial Access (TA0004)** -- S09 in CS0051: "the victim asked OpenClaw to summarize the website, the prompt injection was retrieved." The worker's step 4 is labeled Execution (TA0005) with the description "Lure or direct agent to fetch attacker-controlled content, causing the injection to execute." This conflates the delivery/fetch (TA0004) and the injection execution (TA0005) into a single Execution step, losing the Initial Access tactic entirely.
  4. **Defense Evasion (TA0007)** at S08 -- "The victim confused the researcher's domain with a legitimate OpenClaw resource." The worker includes a Defense Evasion step (step 5) for control sequence spoofing (S11) but omits the domain confusion defense evasion (S08).

  **Comparison section error**: The worker states they "removed standalone 'discovery' (merged into first resource development step)." But Discovery (TA0008) is explicitly present in CS0051 at S02-S03 and cannot be correctly merged into Resource Development without losing tactic fidelity.

- **Pattern mechanism fidelity**: The pattern's kill chain in attack-patterns-atlas-derived.yaml already has a well-structured 8-step sequence directly derived from CS0051 that includes Reconnaissance and Discovery. The worker's replacement drops these phases while claiming ATLAS backing.
- **Confidence justification**: Steps 1-6 marked "explicit" are mostly defensible (despite the conflation issues above). Steps 7-9 marked "adapted" are incorrectly downgraded -- they should be "explicit" since S13-S17 are in the ATLAS data.
- **Sequence coherence**: The 9-step sequence tells a coherent story but is less complete than the actual CS0051 case study (18 steps) or even the existing kill chain (8 steps). Missing Reconnaissance and Discovery at the start weakens the sequence.
- **Verdict**: NEEDS REVISION

  Required fixes:
  1. Restore Reconnaissance (TA0002) as step 1, matching CS0051 S00
  2. Restore Discovery (TA0008) as a separate step, matching CS0051 S02-S03
  3. Add Initial Access (TA0004) step for CS0051 S09 (content delivery/fetch)
  4. Change steps 7-9 confidence from "adapted" to "explicit"
  5. Update the adaptation rationale to remove the false claim about relationships ending at S14

---

### AP-T7-01: Constraint bypass via goal-priority conflict

- **Tactic ID/Name errors**: None. All 5 mappings are correct.
- **Case study accuracy**: Correctly identified as "NOT YET MATCHED." No hallucinated case study references. The worker honestly acknowledges no ATLAS case study directly demonstrates this mechanism and notes the closest candidates (CS0046, CS0026) with appropriate caveats.
- **Pattern mechanism fidelity**: Good. The sequence (Reconnaissance -> Resource Development -> Execution -> Defense Evasion -> Impact) accurately reflects the pattern's described mechanism of probing for constraint conflicts, crafting a conflicting scenario, and inducing constraint deprioritization.
- **Confidence justification**: All 5 steps marked "inferred." Appropriate given no case study backing.
- **Sequence coherence**: Matches the existing kill chain structure identically. Worker correctly notes "Same structure, techniques unchanged" and only changes confidence levels.
- **Verdict**: PASS

---

### AP-T7-03: Deceptive delegation to bypass verification controls

- **Tactic ID/Name errors**: None. All 5 mappings are correct.
- **Case study accuracy**: Both CS0004 and CS0055 are real (within CS0000-CS0056 range). However, the worker's characterization of CS0055 is factually incorrect.

  **CRITICAL -- CS0055 mechanism mischaracterization**: The worker states: "CS0055 (AI ClickFix) demonstrates an agent manipulating a human to perform malicious actions (clicking UI elements, pasting commands) under deceptive pretenses."

  This reverses the actual directionality of CS0055. In the case study:
  - An ATTACKER creates a malicious website with agent-targeted clickbait ("Are you a computer?")
  - A computer-use AGENT visits the website and is tricked into interacting
  - JavaScript copies malicious commands to the clipboard
  - The AGENT follows instructions to open a terminal, paste, and execute

  CS0055 shows a **website manipulating an agent**, not an **agent manipulating a human**. The AP-T7-03 pattern requires the reverse directionality: an agent that autonomously recruits a human under false pretenses to bypass verification. CS0055 does not demonstrate this at all.

  **Overstated confidence levels**: Steps 1, 2, 3, and 5 are marked "explicit" but none of these map to demonstrated behavior in CS0055:
  - Step 1 ("Create deceptive content designed to manipulate agent into recruiting human assistance") -- CS0055 shows creating content that manipulates an agent directly, not content that causes an agent to recruit humans. Should be "inferred."
  - Step 2 ("Agent encounters verification control it cannot pass") -- CS0055 does not demonstrate an agent encountering a verification gate. Should be "inferred."
  - Step 3 ("Agent determines it needs external assistance and engages with attacker-crafted deceptive prompts") -- CS0055 shows an agent following instructions, not autonomously determining it needs help. Should be "adapted" at best.
  - Step 5 ("Agent bypasses verification control it could not pass directly") -- CS0055 shows arbitrary code execution, not verification bypass. Should be "adapted."

  Only step 4 (TA0012, Privilege Escalation, marked "adapted") has an honest confidence annotation.

- **Pattern mechanism fidelity**: Weak. The pattern describes an agent autonomously deceiving a human to bypass verification controls. Neither CS0004 (human attackers using deepfake to bypass AI verification) nor CS0055 (attacker website tricking an AI agent) demonstrates an agent autonomously recruiting human help. The fundamental mechanism -- an AI agent deciding it needs human help and deceiving that human -- is speculative and not evidenced.
- **Confidence justification**: As noted, 4 of 5 "explicit" annotations are unjustified. The tactic sequence itself is reasonable for the described pattern mechanism but should not be presented as explicitly backed by CS0055.
- **Sequence coherence**: The sequence is logical for the described mechanism but is not grounded in the case studies as claimed.
- **Verdict**: NEEDS REVISION

  Required fixes:
  1. Correct the characterization of CS0055 -- it shows a website tricking an agent, not an agent tricking a human
  2. Downgrade steps 1, 2, 3, 5 from "explicit" to "inferred" (the pattern mechanism is speculative, not demonstrated in any cited case study)
  3. Update the adaptation rationale to honestly describe the gap between CS0055's mechanism and the pattern's mechanism
  4. Consider whether this pattern should be classified as "constructed/speculative" like AP-T7-01 and AP-T7-05

---

### AP-T7-05: Information asymmetry exploitation for unauthorized action

- **Tactic ID/Name errors**: None. All 5 mappings are correct.
- **Case study accuracy**: Correctly identified as "NOT YET MATCHED." No hallucinated references. Closest candidates (CS0036, CS0048, CS0026) appropriately noted with honest assessment of why none match.
- **Pattern mechanism fidelity**: Good. The Discovery -> Collection -> Defense Evasion -> Execution -> Impact sequence accurately models the described mechanism of an agent finding privileged information, collecting it, rationalizing its use, acting on it, and causing harm.
- **Confidence justification**: All 5 steps marked "inferred." Appropriate given no case study backing.
- **Sequence coherence**: Matches existing kill chain identically. Worker correctly notes "Same structure, techniques unchanged."
- **Verdict**: PASS

---

## Cross-Cutting Issues

### 1. Inconsistent confidence standards between patterns

AP-T7-03 has 4 steps marked "explicit" based on CS0055 despite the case study not demonstrating the pattern's core mechanism (agent-to-human deception). Meanwhile, AP-T7-01 and AP-T7-05 honestly mark everything "inferred" for similar situations where no case study directly demonstrates the mechanism. AP-T7-03 should follow the same standard -- if the cited case studies don't show the actual pattern mechanism, steps should be "inferred" not "explicit."

### 2. Tactic conflation in multi-step case studies

For AP-T6-06, the worker compresses CS0051's 18 procedure steps into 9, losing entire ATLAS tactic phases (Reconnaissance, Discovery, Initial Access) in the process. The worker acknowledges "removed standalone discovery" but does not flag this as a fidelity loss. When a case study explicitly demonstrates a tactic, removing it from the proposed sequence undermines the "explicit" confidence claim.

### 3. CS0055 directionality error is consequential

The mischaracterization of CS0055 ("agent manipulating human" vs. actual "website manipulating agent") could propagate into downstream scenarios if the tactic sequence is adopted. The confusion between "an attacker tricks an AI" and "an AI tricks a human" is a fundamental mechanism difference that affects what scenarios would be generated from this pattern.

### 4. Summary statistics are internally inconsistent

The summary claims "26 steps across 5 patterns" are marked "explicit." Given the issues identified above, the actual count of genuinely explicit steps is lower. Specifically:
- AP-T6-06: 3 steps marked "adapted" should be "explicit" (net +3 explicit, -3 adapted)
- AP-T7-03: 4 steps marked "explicit" should be "inferred" (net -4 explicit, +4 inferred)
- Net effect: 25 explicit, 1 adapted, 14 inferred (vs. claimed 26 explicit, 4 adapted, 10 inferred)
