# Adversarial Review: tactic-sequences-t3-t9.md

## Summary

6 patterns reviewed. 11 issues found (2 critical, 4 significant, 5 minor). The T3 patterns (AP-T3-02, AP-T3-04) are solid, with AP-T3-04 being essentially a perfect 1:1 mapping. The T9 patterns have serious problems: AP-T9-02 and AP-T9-06 both contain a factually false claim about CS0036's procedure coverage that cascades into incorrect confidence ratings for 12 steps across the two patterns. AP-T9-05 overstates validation from secondary case studies. AP-T9-01 has a summary table arithmetic error.

---

## Per-Pattern Findings

### AP-T3-02: Cross-boundary authorization escalation

- **Tactic ID/Name errors**: None. All 10 rows have correct ID-to-name mappings.

- **Case study accuracy**: CS0026 exists (valid). The worker correctly identifies all CS0026 procedure steps and maps them coherently. CS0026 has 14 steps (S00-S13); the worker condensed to 10 by merging duplicate Discovery (S02+S03), Resource Development (S04+S05), and Defense Evasion (S07+S09+S12) steps. This condensation is defensible.

- **Pattern mechanism fidelity**: MINOR CONCERN. CS0026's demonstrated mechanism is RAG poisoning via email to inject false bank details, followed by social engineering (user approves fraudulent wire transfer). AP-T3-02 defines "cross-boundary authorization escalation" as credential/trust carryover across system boundaries. The match is reasonable because Copilot's enterprise search privileges span system boundaries, but the abstract actions drift from the case study's actual mechanism. Specifically:
  - Step 8 ("Agent processes request, inheriting authorization from source system") -- CS0026's S10 is about the prompt injection executing when the RAG entry is retrieved, not about authorization inheritance.
  - Step 9 ("Agent's credentials from source system grant elevated access in target system lacking scope enforcement") -- CS0026's S11 shows the search_enterprise plugin being manipulated to override its behavior, not credentials carrying over to a target system.
  
  The abstract actions are written to fit the pattern's framing rather than accurately reflecting what CS0026 demonstrates.

- **Confidence justification**: All 10 steps rated "explicit" -- this is technically defensible since each step does map to a CS0026 procedure step, even if the abstract actions reframe the mechanism.

- **Sequence coherence**: Coherent. The 10-step sequence tells a logical attack story and follows CS0026's actual ordering.

- **Verdict**: PASS WITH NOTES -- abstract actions in steps 8-9 overfit to pattern framing rather than accurately reflecting CS0026's mechanism.

---

### AP-T3-04: Exposed agent control interface exploitation

- **Tactic ID/Name errors**: None. All 10 rows correct.

- **Case study accuracy**: CS0048 exists (valid). The worker's 10-step sequence maps 1:1 to CS0048's actual 10 procedure steps (S00-S09). Every step accurately describes what CS0048 demonstrates. Verified against ATLAS YAML:
  - S00: TA0002 -- Shodan search for "Clawdbot Control" title tag
  - S01: TA0004 -- Proxy misconfiguration exploit
  - S02: TA0013 -- Config file credential harvest (clawdbot.json)
  - S03: TA0005 -- Direct prompting via control interface
  - S04: TA0008 -- System prompt extraction (SOUL.md)
  - S05: TA0013 -- `env` command for additional secrets
  - S06: TA0012 -- Root access via bash skill
  - S07: TA0007 -- Chat history manipulation via API keys
  - S08: TA0010 -- Conversation exfiltration from connected apps
  - S09: TA0011 -- Impersonation and data theft

- **Pattern mechanism fidelity**: Exact match. CS0048 IS the pattern -- the pattern was derived from this case study.

- **Confidence justification**: All 10 steps rated "explicit" -- fully justified; every step has a direct 1:1 CS0048 procedure mapping.

- **Sequence coherence**: Excellent. The iterative privilege build-up (config credentials -> env vars -> root -> API manipulation -> exfiltration) is both logical and evidenced.

- **Verdict**: PASS

---

### AP-T9-01: User impersonation via agent action attribution hijacking

- **Tactic ID/Name errors**: None. All 5 rows correct.

- **Case study accuracy**: CS0026 exists (valid). The adaptation from CS0026 is reasonable -- the worker correctly identifies that the same case study supports both AP-T3-02 (privilege escalation focus) and AP-T9-01 (attribution hijacking focus), and strips the sequence to the attribution-relevant steps.

- **Pattern mechanism fidelity**: Good. The 5-step sequence correctly captures the attribution hijacking mechanism: discover capabilities -> craft injection -> inject -> agent acts under user identity -> false attribution.

- **Confidence justification**: ERROR IN SUMMARY TABLE. The detailed table shows:
  - Step 1 (Discovery): adapted
  - Step 2 (Resource Dev): explicit
  - Step 3 (Execution): adapted
  - Step 4 (Privilege Escalation): adapted
  - Step 5 (Impact): explicit
  
  This is 2 explicit, 3 adapted (2/3/0). The summary table at the bottom claims "3/2/0" (3 explicit, 2 adapted). The summary table count is wrong.

- **Sequence coherence**: Good. The comparison with the existing kill chain confirms the worker validated the existing sequence rather than changing it, which is the correct outcome when the existing sequence is already well-matched.

- **Verdict**: PASS WITH NOTES -- fix the summary table count from "3/2/0" to "2/3/0".

---

### AP-T9-02: Agent identity spoofing via compromised service credentials

- **Tactic ID/Name errors**: None. All 9 rows correct.

- **Case study accuracy**: CRITICAL ERROR. The worker states: "The case study relationships only cover S00 (initial access), S11-S12 (impact/availability). Steps S01-S10 (discovery, credential extraction, lateral movement, execution, persistence, evasion) are IMPLIED by the case study description but not explicitly mapped to techniques."

  This is factually false. CS0036 has EXPLICIT technique mappings for ALL 13 steps (S00-S12) in the ATLAS YAML relationships section. The actual mappings are:
  
  | Step | Tactic | Technique | Description |
  |------|--------|-----------|-------------|
  | S00 | AML.TA0004 | AML.T0012 | Initial access to victim system |
  | S01 | AML.TA0008 | AML.T0089 | Enumerated processes, identified LLM apps |
  | S02 | AML.TA0013 | AML.T0090 | Extracted auth token from process memory |
  | S03 | AML.TA0015 | AML.T0091.000 | Used token to authenticate with LLM backend |
  | S04 | AML.TA0000 | AML.T0047 | Communicated with LLM backend as desktop client |
  | S05 | AML.TA0005 | AML.T0051.000 | Sent malicious prompts |
  | S06 | AML.TA0006 | AML.T0080.001 | Manipulated chat context |
  | S07 | AML.TA0006 | AML.T0080.000 | Manipulated LLM memory |
  | S08 | AML.TA0007 | AML.T0092 | Manipulated conversation history |
  | S09 | AML.TA0011 | AML.T0048.000 | Spam/financial harm |
  | S10 | AML.TA0011 | AML.T0048.003 | Access to victim's activity |
  | S11 | AML.TA0011 | AML.T0029 | Deleted chats |
  | S12 | AML.TA0011 | AML.T0029 | Rate limit abuse |

  The worker's proposed 9-step sequence actually aligns well with CS0036's first 9 distinct tactics (S00-S08). But ALL steps should be rated "explicit" or at least "adapted" (for minor reframing), not "inferred." The current rating of 6 "inferred" steps is unjustified.

  Furthermore, the matching analysis document (owasp-atlas-matching.md) that the worker was working from already lists the full 9-tactic CS0036 sequence: "AML.TA0004 -> AML.TA0008 -> AML.TA0013 -> AML.TA0015 -> AML.TA0000 -> AML.TA0005 -> AML.TA0006 -> AML.TA0007 -> AML.TA0011". The worker had access to this information and still claimed the steps were not mapped.

- **Pattern mechanism fidelity**: Good. The sequence accurately represents the agent identity spoofing mechanism through credential extraction.

- **Confidence justification**: INCORRECT. Should be approximately "9/0/0" or "8/1/0" (with Discovery rated "adapted" for the slight shift from process enumeration to "identify agent process"), not "3/0/6".

- **Sequence coherence**: Good. Logical progression from initial access through credential theft to agent impersonation.

- **Verdict**: NEEDS REVISION -- false claim about CS0036 coverage; all 6 "inferred" ratings must be upgraded to "explicit" (or "adapted" where the abstract action reframes slightly).

---

### AP-T9-05: False attribution attack via identity proxy exploitation

- **Tactic ID/Name errors**: None. All 6 rows correct.

- **Case study accuracy**: CS0004 exists (valid). CS0017, CS0033, CS0034 all exist (valid, within CS0000-CS0056 range).

  MINOR ERROR in adaptation rationale: Worker says "CS0004's 7-step procedure (S00-S06)" but CS0004 actually has 8 steps (S00-S07). S00-S06 is 7 steps, but the full procedure includes S07 (Impact), which the worker includes in their proposed sequence as step 6. The correct statement would be "CS0004's 8-step procedure (S00-S07)."

  SIGNIFICANT ERROR in secondary case study validation: Worker claims CS0017, CS0033, CS0034 show "identical tactic flow, validating the sequence." This is false:
  
  - **CS0017** (ID.me) has only 3 steps: TA0000 -> TA0004 -> TA0011. No Reconnaissance, no Resource Development. Fundamentally different flow.
  - **CS0033** (Live Deepfake KYC) has 10 steps and includes TA0001 (AI Attack Staging) and TA0007 (Defense Evasion) -- both absent from the proposed sequence.
  - **CS0034** (ProKYC) has 9 steps and similarly includes TA0001 and TA0007.

  The secondary case studies share the same general PATTERN (identity spoofing for false attribution) but have meaningfully different tactic flows. Claiming "identical tactic flow" is an overstatement. The proper claim would be "similar core mechanism with varying levels of Resource Development and additional Attack Staging / Defense Evasion steps."

- **Pattern mechanism fidelity**: Good. The 6-step sequence captures the core identity spoofing mechanism.

- **Confidence justification**: All 6 rated "explicit" based on CS0004 -- this is justified since each step maps to CS0004 procedures.

- **Sequence coherence**: Good, but notably omits the Defense Evasion step (TA0007) that CS0033 and CS0034 both include between Initial Access and Impact (impersonation detection evasion). This could be a meaningful gap -- once the attacker evades biometric auth, they may still need to evade ongoing impersonation detection.

- **Verdict**: PASS WITH NOTES -- fix the step count claim, remove "identical tactic flow" claim for secondary case studies, consider adding Defense Evasion step per CS0033/CS0034 evidence.

---

### AP-T9-06: Persistent agent identity takeover via long-lived credential theft

- **Tactic ID/Name errors**: None. All 9 rows correct.

- **Case study accuracy**: CRITICAL ERROR -- same as AP-T9-02. The worker inherits the false claim that CS0036 only maps S00 and S11-S12. As documented above, CS0036 has explicit technique mappings for ALL steps. The confidence ratings of 6 "inferred" are unjustified.

  Additionally, the worker references CS0030 (LLM Jacking) as a secondary source with "TA0012 (Privilege Escalation) instead of TA0015 (Lateral Movement) at step 2." CS0030's actual procedure from ATLAS is:
  - S00: TA0004 (Initial Access) -- Exploited vulnerable Laravel
  - S01: TA0013 (Credential Access) -- Found unsecured credentials
  - S02: TA0012 (Privilege Escalation) -- Used credentials for cloud access
  - S03: TA0003 (Resource Development) -- Obtained keychecker tool
  - S04: TA0008 (Discovery) -- Enumerated LLM services and quotas
  - S05: TA0003 (Resource Development) -- Created reverse proxy
  - S06: TA0011 (Impact) -- Financial harm
  
  The worker's description of CS0030 is approximately correct. However, the worker says CS0030 has "TA0012 instead of TA0015 at step 2" but CS0030's step 2 (S02) is Privilege Escalation (TA0012) while the worker's proposed step 4 is Lateral Movement (TA0015). These are different tactics serving different functions -- TA0012 is about gaining higher privileges, TA0015 is about moving between systems using stolen credentials. The worker conflates these.

- **Pattern mechanism fidelity**: Good differentiation from AP-T9-02 in principle (emphasis on PERSISTENT access via long-lived tokens), but the actual proposed sequences are nearly identical. The only difference is step 4: "adapted" vs "inferred" for Lateral Movement. The "different persistence emphasis" justification is thin given the sequences are functionally the same.

- **Confidence justification**: INCORRECT -- same issue as AP-T9-02. Should be mostly "explicit" based on CS0036's actual procedure mappings.

- **Sequence coherence**: Good as an attack story, but nearly indistinguishable from AP-T9-02's sequence.

- **Verdict**: NEEDS REVISION -- same CS0036 false claim; upgrade "inferred" ratings; strengthen differentiation from AP-T9-02.

---

## Cross-Cutting Issues

### 1. CS0036 procedure data was not read (CRITICAL)

The most significant systemic error: the worker appears to have NOT consulted the CS0036 relationships/procedure section in the ATLAS YAML. This is evidenced by the false claim (repeated in both AP-T9-02 and AP-T9-06) that CS0036 "only maps S00 (initial access), S11-S12 (impact/availability)." The ATLAS YAML contains explicit technique-to-tactic mappings for ALL 13 CS0036 steps. This error cascades into 12 incorrect "inferred" confidence ratings across two patterns.

Compounding the error: the matching analysis document (owasp-atlas-matching.md), which the worker was working from, already lists the FULL 9-tactic CS0036 sequence. The worker had the correct information available but either did not read it or disregarded it.

### 2. Summary table arithmetic error

The summary table for AP-T9-01 claims "3/2/0" (Explicit/Adapted/Inferred) but the detailed table shows 2 explicit and 3 adapted, which should be "2/3/0".

### 3. AP-T9-02 and AP-T9-06 insufficient differentiation

Both patterns use CS0036 as the primary source and produce nearly identical 9-step sequences with identical tactic orderings. The justification for separate sequences ("service credential spoofing" vs. "long-lived credential theft") describes different attacker MOTIVATIONS but not different tactic SEQUENCES. If the sequences are meant to be distinct, the differentiation should be visible in the tactic flow itself (e.g., AP-T9-06 could emphasize the persistence mechanism more strongly, perhaps with additional Persistence steps or different ordering). As proposed, they are functionally duplicates.

### 4. Overstated secondary case study validation (AP-T9-05)

The claim that CS0017, CS0033, and CS0034 show "identical tactic flow" to the proposed sequence is false. CS0017 has a fundamentally different (much shorter) flow. CS0033 and CS0034 include AI Attack Staging (TA0001) and Defense Evasion (TA0007) steps absent from the proposal. Validation claims should be precise about what is shared (attack mechanism) vs. what differs (tactic sequence details).

### 5. Abstract action drift from case study evidence (minor, AP-T3-02)

In AP-T3-02, several abstract actions are written to fit the pattern's "cross-boundary authorization" framing rather than accurately reflecting what CS0026 demonstrates (RAG poisoning for content substitution fraud). While this may be an acceptable abstraction for pattern purposes, it creates a gap between what the confidence label "explicit" promises (directly evidenced) and what the abstract action actually says (reframed interpretation).
