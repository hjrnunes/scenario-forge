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
    # -----------------------------------------------------------------
    # LAAF (LLM Agent Assessment Framework) technique names
    # Source: https://github.com/qorvexconsulting1/laaf-V2.0
    # -----------------------------------------------------------------
    # Structural techniques — payload hiding in document/data formats
    "S1": "JSON Value Payload Embedding",
    "S2": "YAML Front Matter Injection",
    "S3": "Markdown Comment Injection",
    "S4": "HTML Meta Tag Injection",
    "S6": "Split Payload Reassembly",
    "S8": "PDF Metadata Injection",
    # Semantic techniques — contextual reframing of malicious content
    "M1": "Formatting Request Disguise",
    "M2": "Compliance Obligation Framing",
    "M3": "System Initialization Impersonation",
    "M4": "Tool Schema Injection",
    "M5": "Authority Level Spoofing",
    "M7": "Gradual Trust Escalation",
    "M8": "Document Configuration Injection",
    # Layered techniques — chained encoding/structural/semantic methods
    "L1": "Multi-Layer Encoding Chain",
    "L2": "Unicode-HTML Encoded Injection",
    "L3": "Nested Encoding with Authority Framing",
    "L4": "Hex-Split Payload Injection",
    "L5": "URL-Encoded Code Block Injection",
    # Trigger techniques — conditional activation mechanisms
    "T1": "Keyword-Triggered Activation",
    "T2": "Compound AND-Condition Trigger",
    "T3": "Compound OR-Condition Trigger",
    "T5": "Turn-Count Delayed Activation",
    "T8": "Tool Event Triggered Activation",
    # Exfiltration techniques
    "EX1": "Markdown Link Data Exfiltration",
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
    # -----------------------------------------------------------------
    # LAAF (LLM Agent Assessment Framework) technique descriptions
    # Source: https://github.com/qorvexconsulting1/laaf-V2.0
    # -----------------------------------------------------------------
    # Structural techniques
    "S1": (
        "Embeds the attack payload as a value within a JSON object, "
        "exploiting the model's tendency to process structured data "
        "fields as trusted input"
    ),
    "S2": (
        "Hides malicious instructions inside YAML front matter blocks "
        "commonly used in Markdown documents, where the model may "
        "interpret metadata as operational directives"
    ),
    "S3": (
        "Conceals payloads within Markdown comment syntax that is "
        "invisible in rendered output but may still be processed "
        "by the model during context interpretation"
    ),
    "S4": (
        "Inserts malicious instructions into HTML meta tag attributes, "
        "exploiting document metadata processing to inject directives "
        "outside the visible content flow"
    ),
    "S6": (
        "Fragments the malicious instruction across multiple separated "
        "segments that are individually benign, relying on the model "
        "to reassemble and execute the complete payload"
    ),
    "S8": (
        "Embeds attack instructions within PDF metadata fields such as "
        "author, title, or custom properties, exploiting document "
        "processing pipelines that extract and surface metadata"
    ),
    # Semantic techniques
    "M1": (
        "Disguises injected instructions as benign formatting or "
        "display requirements, causing the model to execute "
        "directives it interprets as presentation-layer requests"
    ),
    "M2": (
        "Frames malicious payloads as data protection compliance "
        "obligations the model must follow, exploiting alignment "
        "towards regulatory and privacy requirements"
    ),
    "M3": (
        "Presents attack content as system initialization or startup "
        "configuration commands, exploiting the model's tendency to "
        "treat system-context instructions as authoritative"
    ),
    "M4": (
        "Embeds malicious instructions within what appears to be "
        "tool or function schema definitions, exploiting the trust "
        "boundary between tool metadata and executable directives"
    ),
    "M5": (
        "Impersonates operator-level or administrative authority to "
        "elevate instruction trust, causing the model to treat "
        "attacker directives as privileged system commands"
    ),
    "M7": (
        "Incrementally establishes credibility through a series of "
        "benign-seeming interactions before injecting the malicious "
        "payload, exploiting accumulated conversational trust"
    ),
    "M8": (
        "Frames malicious content as document configuration or "
        "metadata settings, exploiting the model's processing of "
        "document-level directives as operational instructions"
    ),
    # Layered techniques
    "L1": (
        "Chains ROT13 cipher with Base64 encoding wrapped in a JSON "
        "structure and semantic reframing layer, using multi-layer "
        "obfuscation to bypass content filters"
    ),
    "L2": (
        "Combines Unicode escape sequences with HTML entity encoding "
        "and compliance-themed semantic framing to hide payloads "
        "behind multiple encoding and contextual layers"
    ),
    "L3": (
        "Nests Base64 encoding within YAML front matter paired with "
        "authority-spoofing semantic context, combining structural "
        "concealment with social engineering framing"
    ),
    "L4": (
        "Uses hexadecimal encoding with split-payload structural "
        "delivery and formatting-request semantic cover, distributing "
        "the attack across encoding and presentation layers"
    ),
    "L5": (
        "Applies URL encoding inside code block structural wrappers "
        "with ISO audit semantic framing, leveraging trusted document "
        "conventions to conceal encoded payloads"
    ),
    # Trigger techniques
    "T1": (
        "Activates a dormant payload when a specific keyword appears "
        "in conversation, enabling time-delayed or context-conditional "
        "attack execution"
    ),
    "T2": (
        "Fires the payload only when multiple conditions are "
        "simultaneously satisfied, requiring compound state to "
        "activate and evading single-condition detection"
    ),
    "T3": (
        "Triggers payload execution when any one of several specified "
        "conditions occurs, broadening the activation surface while "
        "maintaining conditional dormancy"
    ),
    "T5": (
        "Fires the payload after a specific number of conversational "
        "turns have elapsed, exploiting temporal distance from the "
        "initial injection to evade detection"
    ),
    "T8": (
        "Activates when a specific tool invocation or function call "
        "occurs, tying payload execution to the agent's tool-use "
        "workflow to exploit action-phase trust"
    ),
    # Exfiltration techniques
    "EX1": (
        "Causes the model to render Markdown links pointing to "
        "attacker-controlled URLs, embedding sensitive context data "
        "in URL parameters for exfiltration via HTTP requests"
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
    # -----------------------------------------------------------------
    # LAAF (LLM Agent Assessment Framework) zone constraints
    # Source: https://github.com/qorvexconsulting1/laaf-V2.0
    # -----------------------------------------------------------------
    # Structural techniques — payload arrives via input channels
    "S1": frozenset({"input"}),
    "S2": frozenset({"input"}),
    "S3": frozenset({"input"}),
    "S4": frozenset({"input"}),
    "S6": frozenset({"input", "memory", "inter_agent"}),
    "S8": frozenset({"input"}),
    # Semantic techniques — reframing affects input interpretation
    # and reasoning; some cross trust boundaries
    "M1": frozenset({"input", "reasoning"}),
    "M2": frozenset({"input", "reasoning"}),
    "M3": frozenset({"input", "reasoning"}),
    "M4": frozenset({"input", "tool_execution"}),
    "M5": frozenset({"input", "reasoning", "inter_agent"}),
    "M7": frozenset({"input", "reasoning"}),
    "M8": frozenset({"input"}),
    # Layered techniques — encoded payloads arrive via input
    "L1": frozenset({"input"}),
    "L2": frozenset({"input"}),
    "L3": frozenset({"input"}),
    "L4": frozenset({"input"}),
    "L5": frozenset({"input"}),
    # Trigger techniques — conditional activation in reasoning
    # or execution phases
    "T1": frozenset({"input", "reasoning"}),
    "T2": frozenset({"input", "reasoning"}),
    "T3": frozenset({"input", "reasoning"}),
    "T5": frozenset({"reasoning"}),
    "T8": frozenset({"tool_execution"}),
    # Exfiltration — data leakage via model output and tool actions
    "EX1": frozenset({"reasoning", "tool_execution"}),
}
