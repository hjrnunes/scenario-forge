"""ATLAS technique metadata lookups.

Shared name and description dictionaries for MITRE ATLAS technique IDs,
used by both the candidate expansion and scenario generation stages.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# ATLAS technique name lookup
# ---------------------------------------------------------------------------

ATLAS_TECHNIQUE_NAMES: dict[str, str] = {
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0015": "LLM Capability Escalation",
    "AML.T0016": "Obtain Capabilities",
    "AML.T0020": "Poison Training Data",
    "AML.T0021": "Establish Accounts",
    "AML.T0024": "Exfiltration via AI Inference API",
    "AML.T0025": "Resource Exhaustion via Embedding",
    "AML.T0029": "Denial of AI Service",
    "AML.T0031": "Erode AI Model Integrity",
    "AML.T0034": "Cost Harvesting",
    "AML.T0040": "Unsafe Deserialisation via LLM",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0047": "AI-Enabled Product or Service",
    "AML.T0048": "External Harms",
    "AML.T0049": "Spearphishing via AI",
    "AML.T0051.000": "Direct Prompt Injection",
    "AML.T0051.001": "Indirect Prompt Injection",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0060": "Publish Hallucinated Entities",
    "AML.T0066": "Retrieval Content Crafting",
    "AML.T0067": "Output Manipulation",
    "AML.T0070": "RAG Poisoning",
    "AML.T0071": "Embedding Manipulation",
}

# ---------------------------------------------------------------------------
# ATLAS technique descriptions (sourced from MITRE ATLAS / OWASP crosswalk)
# ---------------------------------------------------------------------------

ATLAS_TECHNIQUE_DESCRIPTIONS: dict[str, str] = {
    "AML.T0010": (
        "Compromising ML supply chain components — datasets, models, "
        "frameworks — to embed backdoors or malicious functionality"
    ),
    "AML.T0015": (
        "Exploiting overly permissive LLM tool access to perform actions "
        "beyond intended scope"
    ),
    "AML.T0016": (
        "Acquiring capabilities, tools, or resources needed to carry out "
        "an attack against AI systems"
    ),
    "AML.T0020": (
        "Injecting malicious data into training pipelines to corrupt "
        "model behaviour at the data level"
    ),
    "AML.T0021": (
        "Creating accounts or identities to facilitate adversarial "
        "access to AI systems or services"
    ),
    "AML.T0024": (
        "Extracting sensitive data from AI systems through inference "
        "API queries, including membership inference and model inversion"
    ),
    "AML.T0025": (
        "Flooding vector stores with adversarial embeddings to degrade "
        "retrieval quality or cause service degradation"
    ),
    "AML.T0029": (
        "Overloading AI systems with computationally expensive inputs "
        "to cause service degradation or denial of service"
    ),
    "AML.T0031": (
        "Degrading model integrity through poisoned training data, "
        "embedding hidden trigger-response patterns"
    ),
    "AML.T0034": (
        "Crafting inputs that maximise token usage or API costs per "
        "request to impose financial burden on the target"
    ),
    "AML.T0040": (
        "LLM outputs containing serialised payloads executed by "
        "downstream components via unsafe deserialisation"
    ),
    "AML.T0043": (
        "Crafting adversarial training examples designed to corrupt "
        "model behaviour or bypass safety controls"
    ),
    "AML.T0047": (
        "Generating high-volume automated content via AI-enabled "
        "services to shape perception or overwhelm fact-checking"
    ),
    "AML.T0048": (
        "Introducing persistent malicious behaviour into a model "
        "through supply chain compromise, leading to downstream "
        "external harms"
    ),
    "AML.T0049": (
        "Using AI to generate highly personalised and convincing "
        "spearphishing messages targeting specific individuals"
    ),
    "AML.T0051.000": (
        "Attacker directly manipulates user-facing prompt to alter "
        "model behaviour, bypass safety guardrails, or execute "
        "unauthorised actions"
    ),
    "AML.T0051.001": (
        "Hidden instructions in content the model processes — "
        "documents, web pages, RAG chunks — that hijack model "
        "behaviour without direct user input"
    ),
    "AML.T0053": (
        "LLM autonomously invoking tools or APIs beyond its intended "
        "access scope, executing unintended or harmful actions"
    ),
    "AML.T0054": (
        "Circumventing model safety guardrails via crafted prompt "
        "sequences to elicit prohibited outputs or behaviours"
    ),
    "AML.T0056": (
        "Extraction of internal model configuration, instructions, "
        "or system prompts revealing security controls and "
        "business logic"
    ),
    "AML.T0057": (
        "Unintended exposure of training data or sensitive context "
        "through model outputs, including PII, credentials, "
        "and proprietary information"
    ),
    "AML.T0060": (
        "AI-generated hallucinated content published as fact, "
        "spreading false information that users or systems act upon"
    ),
    "AML.T0066": (
        "Crafting content specifically designed to rank highly in "
        "semantic search and influence model outputs via retrieval"
    ),
    "AML.T0067": (
        "Crafting inputs that produce dangerous outputs consumed "
        "by downstream systems, enabling XSS, command injection, "
        "or other output-based attacks"
    ),
    "AML.T0070": (
        "Injecting malicious content into RAG knowledge bases to "
        "manipulate retrieval results and poison model responses"
    ),
    "AML.T0071": (
        "Crafting inputs whose embeddings manipulate similarity "
        "search results, steering retrieval towards "
        "attacker-controlled content"
    ),
}

# ---------------------------------------------------------------------------
# Technique-zone semantic constraints
# ---------------------------------------------------------------------------
#
# Maps ATLAS technique IDs to the set of zones where they can validly
# operate.  Used by the skeleton builder to override narrative-derived
# zone assignments when they conflict with technique semantics.
#
# Techniques absent from this dict have no zone constraint (any zone
# is acceptable).

TECHNIQUE_ZONE_CONSTRAINTS: dict[str, frozenset[str]] = {
    "AML.T0051.000": frozenset({"input"}),
    "AML.T0051.001": frozenset({"input"}),
    "AML.T0052": frozenset({"input"}),
    "AML.T0053": frozenset({"tool_execution"}),
    "AML.T0054": frozenset({"input", "reasoning"}),
    "AML.T0056": frozenset({"input", "reasoning"}),
    "AML.T0057": frozenset({"reasoning", "tool_execution"}),
    "AML.T0060": frozenset({"reasoning"}),
    "AML.T0066": frozenset({"input"}),
    "AML.T0067": frozenset({"tool_execution", "reasoning"}),
    "AML.T0070": frozenset({"input"}),
    "AML.T0071": frozenset({"input"}),
    "AML.T0073": frozenset({"input", "reasoning"}),
}
