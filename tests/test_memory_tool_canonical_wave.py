"""Wave test for the memory-tool canonical-chain migration (bead 422o.2.4).

Validates data/taxonomies/attack-patterns/attack-patterns-memory-tool.yaml
against the authoritative catalog-lineage.yaml dispositions for the 17
historical memory-tool sources (T1-T4):

- exactly the 14 authoritative resulting records exist, in catalog order;
  deferred sources (AP-T3-01, AP-T4-02, AP-T4-04) produce no live record;
- legacy ``kill_chain``/``evidence`` fields are removed;
- every record parses and qualifies against the production taxonomy resolver
  (ATLAS is the sole v1 authority; LAAF is absent);
- each canonical chain is one branch-free total-order chain whose step mapping
  decisions, chain mapping, resource slots, and description match the lineage
  entry exactly, with a recomputed semantic digest.
"""

from __future__ import annotations

import pytest
import yaml

from scenario_forge.data.catalog_lineage import load_catalog_lineage
from scenario_forge.data.loaders import (
    _DEFAULT_ATTACK_PATTERNS_DIR,
    load_attack_patterns,
)
from scenario_forge.data.taxonomy_pins import load_taxonomy_resolver
from scenario_forge.models.attack_pattern import (
    compute_chain_semantic_digest,
    validate_attack_pattern,
)

MEMORY_TOOL_FILE = _DEFAULT_ATTACK_PATTERNS_DIR / "attack-patterns-memory-tool.yaml"

EXPECTED_IDS = [
    "AP-T1-01",
    "AP-T1-02",
    "AP-T1-03",
    "AP-T1-04",
    "AP-T2-01",
    "AP-T2-02",
    "AP-T2-03",
    "AP-T2-04",
    "AP-T2-05",
    "AP-T2-06",
    "AP-T3-02",
    "AP-T3-03",
    "AP-T4-01",
    "AP-T4-03",
]

DEFERRED_IDS = ["AP-T3-01", "AP-T4-02", "AP-T4-04"]

# Record-specific expected causal spines (exact step_id sequences), pinned by
# the Mayor exact-head semantic review: no side branches, and the chain ends
# at the first observable terminal of the lineage terminal semantics.
EXPECTED_STEPS = {
    "AP-T1-01": [
        "craft_payload",
        "conceal_injection",
        "deliver_payload",
        "execute_injection",
        "persist_in_memory",
        "impact",
    ],
    "AP-T1-02": [
        "craft_fragments",
        "deliver_fragments",
        "execute_fragments",
        "escalate_privileges",
    ],
    "AP-T1-03": ["gain_access", "deliver_inputs", "corrupt_memory", "impact"],
    "AP-T1-04": [
        "gain_access",
        "craft_payload",
        "inject_payload",
        "poison_shared_memory",
        "propagate_corruption",
        "impact",
    ],
    "AP-T2-01": [
        "reconnaissance",
        "craft_payload",
        "deliver_payload",
        "execute_injection",
        "invoke_tool",
        "impact",
    ],
    "AP-T2-02": [
        "reconnaissance",
        "craft_payload",
        "deliver_payload",
        "execute_injection",
        "discover_data",
        "collect_data",
        "exfiltrate_data",
    ],
    "AP-T2-03": ["discover_tools", "setup", "execution", "amplification"],
    "AP-T2-04": [
        "craft_payload",
        "conceal_injection",
        "deliver_payload",
        "execute_injection",
        "persist_in_memory",
        "invoke_tool_from_memory",
    ],
    "AP-T2-05": [
        "gain_access",
        "craft_adversarial_content",
        "inject_content",
        "persist_in_retrieval",
        "trigger_tool_invocation",
    ],
    "AP-T2-06": [
        "reconnaissance",
        "gain_access",
        "craft_payload",
        "verify_attack",
        "deliver_injection",
        "execute_injection",
        "invoke_tool",
    ],
    "AP-T3-02": [
        "reconnaissance",
        "probe_trust_boundaries",
        "discover_connected_services",
        "craft_cross_boundary_request",
        "obfuscate_request",
        "deliver_request",
        "execute_request",
        "escalate_privileges",
    ],
    "AP-T3-03": [
        "identify_provisioning_weakness",
        "instantiate_shadow_agent",
        "inherit_credentials",
        "operate_shadow_agent",
    ],
    "AP-T4-01": [
        "analyze_processing_behavior",
        "craft_expensive_input",
        "submit_expensive_input",
        "impact",
    ],
    "AP-T4-03": [
        "identify_quota_bound_integrations",
        "craft_quota_exhausting_request",
        "deliver_request",
        "amplify_api_calls",
        "impact",
    ],
}

# Expected terminal step per record and a verbatim fragment of the lineage
# terminal semantics that the terminal observable must carry.
EXPECTED_TERMINAL = {
    "AP-T1-01": ("impact", "authorizes an action violating its real constraints"),
    "AP-T1-02": ("escalate_privileges", "grants the escalated access"),
    "AP-T1-03": ("impact", "classifies a genuinely malicious activity as benign"),
    "AP-T1-04": ("impact", "A second agent reads the corrupted store"),
    "AP-T2-01": ("impact", "out-of-bounds"),
    "AP-T2-02": ("exfiltrate_data", "first observable exfiltration"),
    "AP-T2-03": ("amplification", "first observable external effect"),
    "AP-T2-04": ("invoke_tool_from_memory", "first observable misuse"),
    "AP-T2-05": ("trigger_tool_invocation", "first observable tool misuse"),
    "AP-T2-06": ("invoke_tool", "first observable unauthorized execution"),
    "AP-T3-02": ("escalate_privileges", "first observable cross-boundary escalation"),
    "AP-T3-03": (
        "operate_shadow_agent",
        "first observable unauthorized-agent operation",
    ),
    "AP-T4-01": ("impact", "denial-of-service"),
    "AP-T4-03": ("impact", "third-party denial condition"),
}

# Deliberate, reported lineage deltas (Mayor exact-head review). Any deviation
# between the lineage atlas_step_mappings and the owned step mapping decisions
# beyond these entries must fail the wave test.
#
# AP-T3-02 deliver_request: lineage asserts exact AML.T0051.000 on AML.CS0026
# S06, but S06 is indirect RAG injection; the owned step is unmapped rather
# than preserving a false exact mapping. Integration should remove the lineage
# step mapping or accept this narrowing.
DELTA_UNMAPPED_STEPS = {("AP-T3-02", "deliver_request"): "AML.T0051.000"}
# AP-T2-06 harvest_credentials: credential harvest is post-terminal impact per
# the lineage terminal semantics (command execution is the first observable
# terminal), so the step and its exact AML.T0055 mapping are intentionally not
# realized in the live chain. Integration should remove the lineage step
# mapping or re-scope the record.
DELTA_UNREALIZED_STEPS = {("AP-T2-06", "harvest_credentials"): "AML.T0055"}

# Record-specific provenance tier pins for the review-mandated downgrades.
EXPECTED_STEP_TIERS = {
    ("AP-T3-02", "deliver_request"): "variant",
    ("AP-T3-02", "execute_request"): "variant",
    ("AP-T3-02", "escalate_privileges"): "variant",
    ("AP-T2-03", "amplification"): "designed",
    ("AP-T3-03", "operate_shadow_agent"): "designed",
    ("AP-T1-02", "escalate_privileges"): "inferred",
    ("AP-T1-01", "impact"): "inferred",
}

# Record-specific exact-mapping pins for the review-mandated narrowing.
EXPECTED_EXACT_STEP_MAPPINGS = {
    ("AP-T2-06", "invoke_tool"): ["AML.T0050"],
    ("AP-T1-04", "propagate_corruption"): ["AML.T0080.000"],
    ("AP-T1-04", "inject_payload"): ["AML.T0051.001"],
    ("AP-T3-02", "escalate_privileges"): ["AML.T0012"],
    ("AP-T1-01", "persist_in_memory"): ["AML.T0080.000"],
    ("AP-T2-04", "invoke_tool_from_memory"): ["AML.T0051.002"],
    ("AP-T2-02", "exfiltrate_data"): ["AML.T0086"],
}


@pytest.fixture(scope="module")
def document() -> dict:
    return yaml.safe_load(MEMORY_TOOL_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def patterns(document) -> dict:
    return document["patterns"]


@pytest.fixture(scope="module")
def resolver():
    return load_taxonomy_resolver()


@pytest.fixture(scope="module")
def lineage() -> dict:
    return {
        entry["source_pattern_id"]: entry for entry in load_catalog_lineage()["sources"]
    }


def resulting(lineage: dict, pid: str) -> dict:
    records = lineage[pid]["resulting_patterns"]
    assert len(records) == 1
    return records[0]


def test_exact_resulting_id_set_and_order(patterns) -> None:
    assert list(patterns) == EXPECTED_IDS


def test_deferred_sources_produce_no_live_record(patterns) -> None:
    for pid in DEFERRED_IDS:
        assert pid not in patterns


def test_legacy_fields_removed(patterns) -> None:
    for pid, record in patterns.items():
        assert "kill_chain" not in record, pid
        assert "evidence" not in record, pid


def test_records_validate_against_production_resolver(patterns, resolver) -> None:
    for record in patterns.values():
        validate_attack_pattern(record, resolver)


def test_envelope_and_threat_context_preserved(patterns, lineage) -> None:
    for pid, record in patterns.items():
        entry = lineage[pid]
        assert record["id"] == pid
        assert record["threat_id"] == entry["threat_id"]
        assert record["name"]
        assert record["prerequisite_capabilities"]["min_zones"]


def test_description_is_lineage_mechanism_boundary(patterns, lineage) -> None:
    for pid, record in patterns.items():
        assert record["description"] == resulting(lineage, pid)["mechanism_boundary"]


def test_chain_mapping_is_exactly_lineage_chain_mapping(patterns, lineage) -> None:
    for pid, record in patterns.items():
        res = resulting(lineage, pid)
        mappings = record["canonical_chain"]["mappings"]
        assert len(mappings) == 1
        (mapping,) = mappings
        assert mapping["decision"] == "exact"
        assert mapping["taxonomy"] == "ATLAS"
        assert list(mapping["ids"]) == [m["id"] for m in res["atlas_chain_mappings"]]


def test_resource_slots_are_lineage_slot_plan_verbatim(patterns, lineage) -> None:
    for pid, record in patterns.items():
        res = resulting(lineage, pid)
        slots = [
            (s["slot_id"], s["kind"], s["purpose"])
            for s in record["canonical_chain"]["resource_slots"]
        ]
        assert slots == [
            (s["slot_id"], s["kind"], s["purpose"]) for s in res["resource_slot_plan"]
        ]
        chain = record["canonical_chain"]
        ingress = [
            s for s in chain["resource_slots"] if s["purpose"] == "initial_ingress"
        ]
        assert len(ingress) == 1
        assert chain["initial_ingress_slot_id"] == ingress[0]["slot_id"]


def test_step_mapping_decisions_match_lineage(patterns, lineage) -> None:
    for pid, record in patterns.items():
        res = resulting(lineage, pid)
        lineage_step_mappings = {
            m["step"]: m["id"] for m in res.get("atlas_step_mappings", [])
        }
        seen = set()
        for step in record["canonical_chain"]["steps"]:
            (decision,) = step["mappings"]
            seen.add(step["step_id"])
            if (pid, step["step_id"]) in DELTA_UNMAPPED_STEPS:
                # Reported delta: the lineage exact claim is deliberately not
                # preserved because it rests on indirect-injection evidence.
                assert (
                    lineage_step_mappings[step["step_id"]]
                    == DELTA_UNMAPPED_STEPS[(pid, step["step_id"])]
                )
                assert decision["decision"] == "unmapped", (pid, step["step_id"])
                assert decision["rationale"].strip(), (pid, step["step_id"])
            elif step["step_id"] in lineage_step_mappings:
                assert decision["decision"] == "exact", (pid, step["step_id"])
                assert decision["ids"] == [lineage_step_mappings[step["step_id"]]]
            elif step["attacker_controlled"]:
                assert decision["decision"] == "unmapped", (pid, step["step_id"])
                assert decision["rationale"].strip(), (pid, step["step_id"])
            else:
                assert decision["decision"] == "not_applicable", (pid, step["step_id"])
        expected_lineage = set(lineage_step_mappings) - {
            step for (p, step) in DELTA_UNREALIZED_STEPS if p == pid
        }
        assert expected_lineage <= seen, (pid, expected_lineage - seen)


def test_reported_lineage_deltas_are_exactly_scoped(patterns, lineage) -> None:
    """The unrealized AP-T2-06 harvest mapping is the only lineage step mapping
    with no live step, and it carries the expected ATLAS id."""
    for (pid, step_id), atlas_id in DELTA_UNREALIZED_STEPS.items():
        res = resulting(lineage, pid)
        lineage_step_mappings = {
            m["step"]: m["id"] for m in res.get("atlas_step_mappings", [])
        }
        assert lineage_step_mappings[step_id] == atlas_id
        live = {s["step_id"] for s in patterns[pid]["canonical_chain"]["steps"]}
        assert step_id not in live


def test_chain_is_branch_free_total_order(patterns) -> None:
    for pid, record in patterns.items():
        steps = record["canonical_chain"]["steps"]
        assert [s["order"] for s in steps] == list(range(1, len(steps) + 1)), pid
        assert all(s["requirement"] == "required" for s in steps), pid
        assert all(s["condition"] is None for s in steps), pid
        assert len({s["step_id"] for s in steps}) == len(steps), pid


def test_start_semantics(patterns) -> None:
    """The earliest attacker-controlled action is the first chain step."""
    for pid, record in patterns.items():
        chain = record["canonical_chain"]
        first = chain["steps"][0]
        assert first["attacker_controlled"], pid
        assert first["executor_role"] == "attacker", pid
        assert chain["earliest_attacker_controlled_step_id"] == first["step_id"], pid


def test_terminal_semantics(patterns) -> None:
    """Exactly the final step carries the security-relevant terminal outcome."""
    for pid, record in patterns.items():
        steps = record["canonical_chain"]["steps"]
        for step in steps[:-1]:
            assert not any(
                p["security_relevant"] and p["terminal"]
                for p in step["observable_postconditions"]
            ), (pid, step["step_id"])
        assert any(
            p["security_relevant"] and p["terminal"]
            for p in steps[-1]["observable_postconditions"]
        ), pid


def test_consumed_references_are_produced_in_order(patterns) -> None:
    """Every consumed reference is produced by an earlier step (causal order)."""
    for pid, record in patterns.items():
        produced: set[str] = set()
        for step in record["canonical_chain"]["steps"]:
            for ref in step["consumed"]:
                assert ref["ref_id"] in produced, (pid, step["step_id"], ref["ref_id"])
            produced |= {ref["ref_id"] for ref in step["produced"]}


def test_provenance_is_tiered_and_cited(patterns) -> None:
    for pid, record in patterns.items():
        for step in record["canonical_chain"]["steps"]:
            provenance = step["provenance"]
            assert provenance["tier"] in {"observed", "variant", "inferred", "designed"}
            assert 0 <= provenance["confidence"] <= 100
            assert provenance["references"], (pid, step["step_id"])
            assert provenance["adaptation_rationale"].strip(), (pid, step["step_id"])


def test_semantic_digest_recomputes(patterns) -> None:
    for pid, record in patterns.items():
        chain = record["canonical_chain"]
        assert chain["semantic_digest"] == compute_chain_semantic_digest(chain), pid


def test_taxonomy_context_pins_resolver_and_laaf_absent(patterns, resolver) -> None:
    expected = resolver.taxonomy_context.model_dump(mode="json")
    for pid, record in patterns.items():
        chain = record["canonical_chain"]
        assert chain["taxonomy_context"] == expected, pid
        assert chain["taxonomy_context"]["laaf"] is None, pid
        decisions = list(chain["mappings"]) + [
            m for s in chain["steps"] for m in s["mappings"]
        ]
        assert all(m["taxonomy"] == "ATLAS" for m in decisions), pid


def test_catalog_loader_integrates_migrated_records(resolver) -> None:
    loaded = load_attack_patterns()
    for pid in EXPECTED_IDS:
        assert pid in loaded
        validate_attack_pattern(loaded[pid], resolver)
    for pid in DEFERRED_IDS:
        assert pid not in loaded


def test_record_specific_causal_spines(patterns) -> None:
    """Each record's step sequence is exactly the pinned causal spine."""
    assert set(EXPECTED_STEPS) == set(patterns)
    for pid, record in patterns.items():
        actual = [s["step_id"] for s in record["canonical_chain"]["steps"]]
        assert actual == EXPECTED_STEPS[pid], pid


def test_record_specific_terminal_steps(patterns, lineage) -> None:
    """The terminal step is the pinned one and its terminal observable carries
    the lineage terminal semantics; nothing after the first observable event."""
    for pid, record in patterns.items():
        steps = record["canonical_chain"]["steps"]
        expected_step, fragment = EXPECTED_TERMINAL[pid]
        assert steps[-1]["step_id"] == expected_step, pid
        terminal_posts = [
            p
            for p in steps[-1]["observable_postconditions"]
            if p["security_relevant"] and p["terminal"]
        ]
        assert terminal_posts, pid
        assert any(fragment in p["description"] for p in terminal_posts), (
            pid,
            terminal_posts,
        )
        lineage_terminal = resulting(lineage, pid)["terminal_semantics"]
        joined = "".join(p["description"] for p in terminal_posts).lower()
        assert lineage_terminal.split(":")[0][:40].lower() in joined, (
            pid,
            lineage_terminal,
        )


def test_backward_reachability_to_terminal(patterns) -> None:
    """Every required nonterminal step contributes to the terminal: at least
    one of its produced references is consumed by a later step, and the
    reference graph reaches the terminal step."""
    for pid, record in patterns.items():
        steps = record["canonical_chain"]["steps"]
        consumers: dict[int, set[int]] = {i: set() for i in range(len(steps))}
        for j, step in enumerate(steps):
            consumed_ids = {r["ref_id"] for r in step["consumed"]}
            for i in range(j):
                produced_ids = {r["ref_id"] for r in steps[i]["produced"]}
                if produced_ids & consumed_ids:
                    consumers[i].add(j)
        terminal = len(steps) - 1
        for i in range(terminal):
            assert consumers[i], (pid, steps[i]["step_id"], "dangling side branch")
            # transitive reachability to the terminal step
            reached = set()
            frontier = list(consumers[i])
            while frontier:
                node = frontier.pop()
                if node in reached:
                    continue
                reached.add(node)
                frontier.extend(consumers[node])
            assert terminal in reached, (pid, steps[i]["step_id"])


def test_record_specific_provenance_tiers(patterns) -> None:
    for (pid, step_id), tier in EXPECTED_STEP_TIERS.items():
        step = next(
            s
            for s in patterns[pid]["canonical_chain"]["steps"]
            if s["step_id"] == step_id
        )
        assert step["provenance"]["tier"] == tier, (pid, step_id)


def test_record_specific_exact_step_mappings(patterns) -> None:
    for (pid, step_id), ids in EXPECTED_EXACT_STEP_MAPPINGS.items():
        step = next(
            s
            for s in patterns[pid]["canonical_chain"]["steps"]
            if s["step_id"] == step_id
        )
        (decision,) = step["mappings"]
        assert decision["decision"] == "exact", (pid, step_id)
        assert decision["taxonomy"] == "ATLAS"
        assert list(decision["ids"]) == ids, (pid, step_id)


def test_review_mandated_narrowing_rationales(patterns) -> None:
    """The exact-identity narrowing and lineage deltas are documented in the
    affected steps' rationales (fail closed, not silent qualification)."""

    def step_of(pid, step_id):
        return next(
            s
            for s in patterns[pid]["canonical_chain"]["steps"]
            if s["step_id"] == step_id
        )

    t006 = step_of("AP-T2-06", "invoke_tool")
    assert "interpreter" in t006["provenance"]["adaptation_rationale"].lower()
    assert "reported as a delta" in t006["provenance"]["adaptation_rationale"]

    t104 = step_of("AP-T1-04", "propagate_corruption")
    assert "pinned AML.T0080.000 operation" in (
        t104["observable_postconditions"][0]["description"]
        + t104["provenance"]["adaptation_rationale"]
    )

    t302 = step_of("AP-T3-02", "deliver_request")
    (decision,) = t302["mappings"]
    assert decision["decision"] == "unmapped"
    assert "indirect" in decision["rationale"]
    assert "AML.T0051.000" in decision["rationale"]
