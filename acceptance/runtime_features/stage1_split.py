"""Acceptance step handlers for the stage1_split feature group."""

from __future__ import annotations

from runtime_shared import (
    Path,
    World,
    json,
    re,
)


def _h_stage1_bg_usecase_risk(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a use-case file and a risk-extraction file are available."""
    # No-op background precondition for static scenarios.
    # Pipeline scenarios set up fixtures in the When step.
    return True, ""


def _h_stage1_bg_llm_endpoint(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an LLM endpoint is configured."""
    # Background precondition — we accept this as given. The When step
    # will fail with a clear message if no LLM endpoint is actually available.
    return True, ""


def _h_stage1_prompts_not_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the prompts directory does not contain `X.j2`.

    Also verifies (case-sensitive) that the template name is a recognized
    retired template, so that Gherkin value mutations that change the
    example cell to a nonsense name — which is also absent — are killed
    rather than silently surviving.
    """
    from scenario_forge.stpa.system_model import PROMPTS_DIR

    _KNOWN_RETIRED_TEMPLATES = frozenset(
        {
            "stage1a_system.j2",
            "stage1a_user.j2",
            "stage2_call2_system.j2",
            "stage2_call2_user.j2",
        }
    )
    m = re.search(r"does not contain `([^`]+)`", text)
    if not m:
        return False, f"Could not parse template name from: {text}"
    tmpl = m.group(1)
    path = PROMPTS_DIR / tmpl
    if path.exists():
        return False, f"Template {tmpl} exists in prompts directory (expected absent)"
    if tmpl not in _KNOWN_RETIRED_TEMPLATES:
        return False, f"Template name '{tmpl}' is not a recognized retired template"
    return True, ""


def _h_stage1_prompts_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the prompts directory contains `X.j2`.

    Uses a case-sensitive directory listing to kill Gherkin value
    mutations that change the template name casing. On macOS,
    path.exists() is case-insensitive, so we must explicitly verify
    the filename matches exactly.
    """
    from scenario_forge.stpa.system_model import PROMPTS_DIR

    m = re.search(r"contains `([^`]+)`", text)
    if not m:
        return False, f"Could not parse template name from: {text}"
    tmpl = m.group(1)
    path = PROMPTS_DIR / tmpl
    if not path.exists():
        return False, f"Template {tmpl} not found in prompts directory"
    # Case-sensitive check: verify the actual filename matches exactly.
    # macOS APFS is case-insensitive but case-preserving, so iterdir()
    # returns the real on-disk spelling.
    actual_names = {f.name for f in PROMPTS_DIR.iterdir() if f.is_file()}
    if tmpl not in actual_names:
        return False, f"Template '{tmpl}' not found (case mismatch)"
    return True, ""


def _h_stage1_model_no_declare(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the `Stage1Profile` model does not declare `X`."""
    m = re.search(r"does not declare `([^`]+)`", text)
    if not m:
        return False, f"Could not parse field name from: {text}"
    field_name = m.group(1)
    profile_model_path = (
        next(
            p
            for p in Path(__file__).resolve().parents
            if (p / "pyproject.toml").is_file()
        )
        / "src"
        / "scenario_forge"
        / "models"
        / "capability_profile.py"
    )
    src = profile_model_path.read_text(encoding="utf-8")
    # Extract the Stage1Profile class body
    match = re.search(
        r"class Stage1Profile\(BaseModel\):(.*?)(?=\nclass |\Z)",
        src,
        re.DOTALL,
    )
    if not match:
        return False, "Could not locate Stage1Profile class definition"
    class_body = match.group(1)
    decl_pattern = rf"^\s*{re.escape(field_name)}\s*:\s*bool\s*=\s*Field"
    found = bool(re.search(decl_pattern, class_body, re.MULTILINE))
    if found:
        return False, f"Stage1Profile declares '{field_name}' as a bool Field"
    return True, ""


def _h_stage1_template_contains_text(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the prompt template `X.j2` contains the text `Y`."""
    from scenario_forge.stpa.system_model import PROMPTS_DIR

    m = re.search(r"template `([^`]+\.j2)` contains the text `([^`]+)`", text)
    if not m:
        return False, f"Could not parse from: {text}"
    tmpl_name, expected_text = m.group(1), m.group(2)
    path = PROMPTS_DIR / tmpl_name
    if not path.exists():
        return False, f"Template {tmpl_name} not found"
    content = path.read_text(encoding="utf-8")
    if expected_text not in content:
        return False, f"Template {tmpl_name} does not contain '{expected_text}'"
    return True, ""


def _h_stage1_template_not_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the prompt template `X.j2` does not contain `Y`."""
    from scenario_forge.stpa.system_model import PROMPTS_DIR

    m = re.search(r"template `([^`]+\.j2)` does not contain `([^`]+)`", text)
    if not m:
        return False, f"Could not parse from: {text}"
    tmpl_name, forbidden_text = m.group(1), m.group(2)
    path = PROMPTS_DIR / tmpl_name
    if not path.exists():
        return False, f"Template {tmpl_name} not found"
    content = path.read_text(encoding="utf-8")
    if forbidden_text in content:
        return (
            False,
            f"Template {tmpl_name} contains '{forbidden_text}' (expected absent)",
        )
    return True, ""


def _h_stage1_given_zero_risk_cards(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the risk-extraction file contains zero risk cards."""
    # Setup step for pipeline scenario — no-op without LLM.
    return True, ""


def _h_stage1_given_prebuilt_profile(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a pre-built `capability-profile.yaml` file is available."""
    # Setup step for pipeline scenario — no-op without LLM.
    return True, ""


def _pipeline_input_files() -> tuple[Path, Path, Path]:
    """Create isolated, file-backed inputs for a pipeline scenario."""
    import tempfile

    fixture_dir = Path(tempfile.mkdtemp(prefix="stage1-acc-fixture-"))
    use_case = fixture_dir / "use-case.txt"
    risk_file = fixture_dir / "risk-extraction.json"
    profile = fixture_dir / "capability-profile.yaml"
    use_case.write_text(
        "An AI assistant accepts user prompts and reasons about requests.\n",
        encoding="utf-8",
    )
    risk_file.write_text(json.dumps({"risks": []}) + "\n", encoding="utf-8")
    profile_source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "scenario_forge"
        / "stpa"
        / "fixtures"
        / "capability_profile_klarna.yaml"
    )
    profile.write_text(profile_source.read_text(encoding="utf-8"), encoding="utf-8")
    return use_case, risk_file, profile


def _h_stage1_run_stpa(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: I run `scenario-forge stpa-run ...`."""
    import os
    import subprocess
    import tempfile

    # Check for LLM endpoint
    has_endpoint = bool(
        os.environ.get("SCENARIO_FORGE_MODEL_BASE_URL")
        or os.environ.get("OPENAI_BASE_URL")
        or os.environ.get("OPENAI_API_KEY")
        or os.environ.get("SCENARIO_FORGE_API_KEY")
    )
    if not has_endpoint:
        return (
            False,
            "LLM endpoint not configured (pipeline-mode scenario requires LLM)",
        )

    # Parse the command from backticks
    m = re.search(r"`scenario-forge stpa-run([^`]+)`", text)
    if not m:
        return False, f"Could not parse command from: {text}"
    cmd_args = m.group(1).strip()

    # Resolve placeholders to temp paths
    output_dir = Path(tempfile.mkdtemp(prefix="stage1-acc-")) / "output"
    output_dir.mkdir()
    use_case, risk_file, profile = _pipeline_input_files()
    cmd_args = cmd_args.replace("<use_case>", f"@{use_case}")
    cmd_args = cmd_args.replace("<risk_file>", str(risk_file))
    cmd_args = cmd_args.replace("<dir>", str(output_dir))
    cmd_args = cmd_args.replace("<profile>", str(profile))

    cmd = f"uv run scenario-forge stpa-run {cmd_args}"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
    world.stage1_exit_code = proc.returncode
    world.stage1_output_dir = output_dir
    world.stage1_stderr = proc.stderr
    world.acceptance_status_detail = f"fixture={use_case.parent} output={output_dir}"

    return True, ""


def _h_stage1_exit_code_zero(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the command exits with code 0."""
    exit_code = getattr(world, "stage1_exit_code", None)
    if exit_code is None:
        return False, "No pipeline run was executed"
    if exit_code != 0:
        stderr = getattr(world, "stage1_stderr", "")
        return False, f"Exit code {exit_code}, stderr: {stderr[:300]}"
    return True, ""


def _h_stage1_output_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the output directory contains `X.yaml`."""
    m = re.search(r"contains `([^`]+)`", text)
    if not m:
        return False, f"Could not parse filename from: {text}"
    fname = m.group(1)
    output_dir = getattr(world, "stage1_output_dir", None)
    if output_dir is None:
        return False, "No output directory available"
    path = output_dir / fname
    if not path.exists():
        return False, f"{fname} not found in output directory"
    # Cache loaded YAML for subsequent steps
    if not hasattr(world, "stage1_artifacts"):
        world.stage1_artifacts = {}
    if fname.endswith(".yaml") or fname.endswith(".yml"):
        import yaml

        world.stage1_artifacts[fname] = yaml.safe_load(path.read_text(encoding="utf-8"))
    elif fname.endswith(".jsonl"):
        world.stage1_artifacts[fname] = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    return True, ""


def _h_stage1_loss_has_provenance(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: `loss-analysis.yaml` contains at least one loss with `provenance` set to `X`."""
    m = re.search(r"set to `([^`]+)`", text)
    if not m:
        return False, f"Could not parse provenance from: {text}"
    expected_prov = m.group(1)
    artifacts = getattr(world, "stage1_artifacts", {})
    la = artifacts.get("loss-analysis.yaml")
    if la is None:
        return False, "loss-analysis.yaml not loaded"
    all_losses = la.get("risk_card_losses", []) + la.get("use_case_losses", [])
    found = any(loss.get("provenance") == expected_prov for loss in all_losses)
    if not found:
        return False, f"No loss with provenance '{expected_prov}'"
    return True, ""


def _h_stage1_risk_card_empty_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: every `risk_card`-provenance loss has a non-empty `source_risk_cards` list."""
    artifacts = getattr(world, "stage1_artifacts", {})
    la = artifacts.get("loss-analysis.yaml")
    if la is None:
        return False, "loss-analysis.yaml not loaded"
    risk_losses = la.get("risk_card_losses", [])
    for loss in risk_losses:
        if not loss.get("source_risk_cards"):
            return False, f"Loss {loss.get('loss_id')} has empty source_risk_cards"
    return True, ""


def _h_stage1_use_case_empty_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: every `use_case`-provenance loss has an empty `source_risk_cards` list."""
    artifacts = getattr(world, "stage1_artifacts", {})
    la = artifacts.get("loss-analysis.yaml")
    if la is None:
        return False, "loss-analysis.yaml not loaded"
    uc_losses = la.get("use_case_losses", [])
    for loss in uc_losses:
        if loss.get("source_risk_cards"):
            return False, f"Loss {loss.get('loss_id')} has non-empty source_risk_cards"
    return True, ""


def _h_stage1_loss_empty_risk_card_losses(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: `loss-analysis.yaml` has an empty `risk_card_losses` list."""
    artifacts = getattr(world, "stage1_artifacts", {})
    la = artifacts.get("loss-analysis.yaml")
    if la is None:
        return False, "loss-analysis.yaml not loaded"
    if la.get("risk_card_losses"):
        return (
            False,
            f"risk_card_losses is not empty (count: {len(la['risk_card_losses'])})",
        )
    return True, ""


def _h_stage1_ids_sequential(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: loss/hazard/security constraint IDs in `loss-analysis.yaml` are sequential."""
    artifacts = getattr(world, "stage1_artifacts", {})
    la = artifacts.get("loss-analysis.yaml")
    if la is None:
        return False, "loss-analysis.yaml not loaded"

    if "loss IDs" in text:
        prefix = "L-"
        all_losses = la.get("risk_card_losses", []) + la.get("use_case_losses", [])
        ids = [loss.get("loss_id", "") for loss in all_losses]
    elif "hazard IDs" in text:
        prefix = "H-"
        ids = [h.get("hazard_id", "") for h in la.get("hazards", [])]
    elif "security constraint IDs" in text:
        prefix = "SC-"
        ids = [sc.get("constraint_id", "") for sc in la.get("security_constraints", [])]
    else:
        return False, f"Could not determine ID type from: {text}"

    seen = set()
    expected = 1
    for id_str in ids:
        if id_str in seen:
            return False, f"Duplicate ID: {id_str}"
        seen.add(id_str)
        match = re.match(rf"^{prefix}(\d+)$", id_str)
        if not match:
            return False, f"Invalid ID format: {id_str}"
        num = int(match.group(1))
        if num != expected:
            return False, f"ID {id_str} is not sequential (expected {prefix}{expected})"
        expected += 1
    return True, ""


def _h_stage1_hazard_refs_valid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: every hazard in `loss-analysis.yaml` references at least one valid loss_id."""
    artifacts = getattr(world, "stage1_artifacts", {})
    la = artifacts.get("loss-analysis.yaml")
    if la is None:
        return False, "loss-analysis.yaml not loaded"
    all_losses = la.get("risk_card_losses", []) + la.get("use_case_losses", [])
    loss_ids = {loss.get("loss_id") for loss in all_losses}
    for h in la.get("hazards", []):
        refs = h.get("related_losses", [])
        if not refs:
            return False, f"Hazard {h.get('hazard_id')} has no related_losses"
        for r in refs:
            if r not in loss_ids:
                return (
                    False,
                    f"Hazard {h.get('hazard_id')} references invalid loss_id {r}",
                )
    return True, ""


def _h_stage1_sc_refs_valid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: every security constraint references at least one valid hazard_id."""
    artifacts = getattr(world, "stage1_artifacts", {})
    la = artifacts.get("loss-analysis.yaml")
    if la is None:
        return False, "loss-analysis.yaml not loaded"
    hazard_ids = {h.get("hazard_id") for h in la.get("hazards", [])}
    for sc in la.get("security_constraints", []):
        refs = sc.get("related_hazards", [])
        if not refs:
            return False, f"Constraint {sc.get('constraint_id')} has no related_hazards"
        for r in refs:
            if r not in hazard_ids:
                return (
                    False,
                    f"Constraint {sc.get('constraint_id')} references invalid hazard_id {r}",
                )
    return True, ""


def _h_stage1_calls_has_entry(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: `calls.jsonl` contains a call entry with `stage` `X` and `step` `Y`."""
    m = re.search(r"`stage` `([^`]+)`.*`step` `([^`]+)`", text)
    if not m:
        return False, f"Could not parse stage/step from: {text}"
    stage, step = m.group(1), m.group(2)
    artifacts = getattr(world, "stage1_artifacts", {})
    calls = artifacts.get("calls.jsonl")
    if calls is None:
        # Try loading from output dir
        output_dir = getattr(world, "stage1_output_dir", None)
        if output_dir and (output_dir / "calls.jsonl").exists():
            calls = [
                json.loads(line)
                for line in (output_dir / "calls.jsonl").read_text().splitlines()
                if line.strip()
            ]
            world.stage1_artifacts["calls.jsonl"] = calls
    if calls is None:
        return False, "calls.jsonl not loaded"
    found = any(c.get("stage") == stage and c.get("step") == step for c in calls)
    if not found:
        return False, f"No call entry with stage={stage} step={step}"
    return True, ""


def _h_stage1_calls_not_has_entry(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: `calls.jsonl` does not contain a call entry with `stage` `X`."""
    m = re.search(r"`stage` `([^`]+)`", text)
    if not m:
        return False, f"Could not parse stage from: {text}"
    stage = m.group(1)
    artifacts = getattr(world, "stage1_artifacts", {})
    calls = artifacts.get("calls.jsonl")
    if calls is None:
        output_dir = getattr(world, "stage1_output_dir", None)
        if output_dir and (output_dir / "calls.jsonl").exists():
            calls = [
                json.loads(line)
                for line in (output_dir / "calls.jsonl").read_text().splitlines()
                if line.strip()
            ]
            world.stage1_artifacts["calls.jsonl"] = calls
    if calls is None:
        return False, "calls.jsonl not loaded"
    found = any(c.get("stage") == stage for c in calls)
    if found:
        return False, f"Found call entry with stage={stage} (expected absent)"
    return True, ""


def _h_stage1_manifest_call_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: `run-manifest.yaml` has `stage_summary.stage_1a.call_count` equal to `N`."""
    m = re.search(r"equal to `(\d+)`", text)
    if not m:
        return False, f"Could not parse count from: {text}"
    expected = int(m.group(1))
    artifacts = getattr(world, "stage1_artifacts", {})
    manifest = artifacts.get("run-manifest.yaml")
    if manifest is None:
        return False, "run-manifest.yaml not loaded"
    actual = manifest.get("stage_summary", {}).get("stage_1a", {}).get("call_count", 0)
    if actual != expected:
        return False, f"stage_1a.call_count is {actual} (expected {expected})"
    return True, ""


def _h_stage1_cap_kc_nonempty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: `capability-profile.yaml` has a non-empty `kc_subcodes` list."""
    artifacts = getattr(world, "stage1_artifacts", {})
    cap = artifacts.get("capability-profile.yaml")
    if cap is None:
        return False, "capability-profile.yaml not loaded"
    if not cap.get("kc_subcodes"):
        return False, "kc_subcodes is empty"
    return True, ""


def _h_stage1_cap_kc_valid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: every value in `kc_subcodes` is a valid KC sub-code."""
    from scenario_forge.models.capability_profile import VALID_KC_SUBCODES, KCX_PREFIX

    artifacts = getattr(world, "stage1_artifacts", {})
    cap = artifacts.get("capability-profile.yaml")
    if cap is None:
        return False, "capability-profile.yaml not loaded"
    codes = cap.get("kc_subcodes", [])
    for c in codes:
        if not c.startswith(KCX_PREFIX) and c not in VALID_KC_SUBCODES:
            return False, f"Invalid KC sub-code: {c}"
    return True, ""


def _h_stage1_cap_zones(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: `capability-profile.yaml` has a `zones_active` list containing `input` and `reasoning`."""
    artifacts = getattr(world, "stage1_artifacts", {})
    cap = artifacts.get("capability-profile.yaml")
    if cap is None:
        return False, "capability-profile.yaml not loaded"
    zones = cap.get("zones_active", [])
    if "input" not in zones:
        return False, f"zones_active missing 'input': {zones}"
    if "reasoning" not in zones:
        return False, f"zones_active missing 'reasoning': {zones}"
    return True, ""


def _h_stage1_cap_bool_consistent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: `capability-profile.yaml` has `X` consistent with `kc_subcodes`."""
    from scenario_forge.models.capability_profile import (
        _KC4_PERSISTENT,
        _KC_MULTI_AGENT,
    )

    m = re.search(r"has `([^`]+)` consistent with", text)
    if not m:
        return False, f"Could not parse field name from: {text}"
    field_name = m.group(1)
    artifacts = getattr(world, "stage1_artifacts", {})
    cap = artifacts.get("capability-profile.yaml")
    if cap is None:
        return False, "capability-profile.yaml not loaded"
    kc_set = set(cap.get("kc_subcodes", []))
    if field_name == "has_persistent_memory":
        expected = bool(kc_set & _KC4_PERSISTENT) or "KCX-PMEM" in kc_set
    elif field_name == "multi_agent":
        expected = bool(kc_set & _KC_MULTI_AGENT)
    elif field_name == "hitl":
        expected = "KCX-HITL" in kc_set
    else:
        return False, f"Unknown boolean field: {field_name}"
    actual = cap.get(field_name)
    if actual != expected:
        return False, f"{field_name} is {actual} (expected {expected} from kc_subcodes)"
    return True, ""


def _h_stage1_cap_entry_points(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: `capability-profile.yaml` has a non-empty `entry_points` list."""
    artifacts = getattr(world, "stage1_artifacts", {})
    cap = artifacts.get("capability-profile.yaml")
    if cap is None:
        return False, "capability-profile.yaml not loaded"
    eps = cap.get("entry_points", [])
    if not eps:
        return False, "entry_points is empty"
    return True, ""


def _h_stage1_cap_ep_name_dir(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: every entry point has a `name` and a `direction`."""
    artifacts = getattr(world, "stage1_artifacts", {})
    cap = artifacts.get("capability-profile.yaml")
    if cap is None:
        return False, "capability-profile.yaml not loaded"
    for ep in cap.get("entry_points", []):
        if not ep.get("name"):
            return False, f"Entry point missing name: {ep}"
        if not ep.get("direction"):
            return False, f"Entry point missing direction: {ep}"
    return True, ""


def _h_stage1_cap_tool_inv(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: if `capability-profile.yaml` has `tool_execution` in `zones_active` then `tool_inventory` is non-empty."""
    artifacts = getattr(world, "stage1_artifacts", {})
    cap = artifacts.get("capability-profile.yaml")
    if cap is None:
        return False, "capability-profile.yaml not loaded"
    zones = cap.get("zones_active", [])
    if "tool_execution" in zones:
        if not cap.get("tool_inventory"):
            return False, "tool_execution in zones_active but tool_inventory is empty"
    return True, ""


def _h_stage1_calls_1b_before_1a(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: in `calls.jsonl` the `stage_1b` call appears before the first `stage_1a` call."""
    artifacts = getattr(world, "stage1_artifacts", {})
    calls = artifacts.get("calls.jsonl")
    if calls is None:
        return False, "calls.jsonl not loaded"
    b_calls = [i for i, c in enumerate(calls) if c.get("stage") == "stage_1b"]
    a_calls = [i for i, c in enumerate(calls) if c.get("stage") == "stage_1a"]
    if not b_calls:
        return False, "No stage_1b call found"
    if not a_calls:
        return False, "No stage_1a call found"
    if b_calls[0] >= a_calls[0]:
        return False, f"stage_1b at index {b_calls[0]}, stage_1a at index {a_calls[0]}"
    return True, ""


def _h_stage1_calls_risk_before_gap(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: in `calls.jsonl` the `stage_1a` `risk_derivation` call appears before the `stage_1a` `gap_analysis` call."""
    artifacts = getattr(world, "stage1_artifacts", {})
    calls = artifacts.get("calls.jsonl")
    if calls is None:
        return False, "calls.jsonl not loaded"
    risk_calls = [
        i
        for i, c in enumerate(calls)
        if c.get("stage") == "stage_1a" and c.get("step") == "risk_derivation"
    ]
    gap_calls = [
        i
        for i, c in enumerate(calls)
        if c.get("stage") == "stage_1a" and c.get("step") == "gap_analysis"
    ]
    if not risk_calls:
        return False, "No stage_1a/risk_derivation call found"
    if not gap_calls:
        return False, "No stage_1a/gap_analysis call found"
    if risk_calls[0] >= gap_calls[0]:
        return (
            False,
            f"risk_derivation at index {risk_calls[0]}, gap_analysis at index {gap_calls[0]}",
        )
    return True, ""


def _h_stage1_gap_has_kc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the `stage_1a` `gap_analysis` call entry has a `user_prompt_text` containing `kc_subcodes`."""
    artifacts = getattr(world, "stage1_artifacts", {})
    calls = artifacts.get("calls.jsonl")
    if calls is None:
        return False, "calls.jsonl not loaded"
    gap_calls = [
        c
        for c in calls
        if c.get("stage") == "stage_1a" and c.get("step") == "gap_analysis"
    ]
    if not gap_calls:
        return False, "No stage_1a/gap_analysis call found"
    prompt_text = gap_calls[0].get("user_prompt_text", "")
    if "kc_subcodes" not in prompt_text:
        return False, "gap_analysis user_prompt_text does not contain 'kc_subcodes'"
    return True, ""


def _h_stage1_1b_no_loss_input(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the `stage_1b` call entry has a `user_prompt_text` that does not contain `loss_analysis` / `risk_card_losses`."""
    artifacts = getattr(world, "stage1_artifacts", {})
    calls = artifacts.get("calls.jsonl")
    if calls is None:
        return False, "calls.jsonl not loaded"
    b_calls = [c for c in calls if c.get("stage") == "stage_1b"]
    if not b_calls:
        return False, "No stage_1b call found"
    prompt_text = b_calls[0].get("user_prompt_text", "")
    if "loss_analysis" in text and "loss_analysis" in prompt_text:
        return False, "stage_1b user_prompt_text contains 'loss_analysis'"
    if "risk_card_losses" in text and "risk_card_losses" in prompt_text:
        return False, "stage_1b user_prompt_text contains 'risk_card_losses'"
    return True, ""


def _h_template_contains(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the prompt template `X.j2` contains `Y`."""
    from scenario_forge.stpa.system_model import PROMPTS_DIR

    m = re.search(r"template `([^`]+\.j2)` contains `([^`]+)`", text)
    if not m:
        return False, f"Could not parse from: {text}"
    tmpl_name, expected_text = m.group(1), m.group(2)
    path = PROMPTS_DIR / tmpl_name
    if not path.exists():
        return False, f"Template {tmpl_name} not found"
    content = path.read_text(encoding="utf-8")
    if expected_text not in content:
        return False, f"Template {tmpl_name} does not contain '{expected_text}'"
    return True, ""


FEATURE_ID = "stage1_split"


def register(api: object) -> None:
    """Register this feature group through the supplied facade API."""
    api.set_feature(None)
    api.register(
        "a use-case file and a risk-extraction file are available",
        _h_stage1_bg_usecase_risk,
        source_order=21414,
    )
    api.register(
        "an LLM endpoint is configured", _h_stage1_bg_llm_endpoint, source_order=21415
    )
    api.register(
        "the prompts directory does not contain",
        _h_stage1_prompts_not_contains,
        source_order=21417,
    )
    api.register(
        "the prompts directory contains", _h_stage1_prompts_contains, source_order=21418
    )
    api.register(
        "the `Stage1Profile` model does not declare",
        _h_stage1_model_no_declare,
        source_order=21419,
    )
    api.register(
        "the prompt template .* contains the text",
        _h_stage1_template_contains_text,
        source_order=21420,
    )
    api.register(
        "the prompt template .* does not contain",
        _h_stage1_template_not_contains,
        source_order=21421,
    )
    api.register(
        "the prompt template .* contains `", _h_template_contains, source_order=21440
    )
    api.register(
        "the risk-extraction file contains zero risk cards",
        _h_stage1_given_zero_risk_cards,
        source_order=21442,
    )
    api.register(
        "a pre-built `capability-profile.yaml` file is available",
        _h_stage1_given_prebuilt_profile,
        source_order=21443,
    )
    api.register_first(
        "I run `scenario-forge stpa-run", _h_stage1_run_stpa, source_order=21445
    )
    api.register(
        "the command exits with code 0", _h_stage1_exit_code_zero, source_order=21447
    )
    api.register(
        "the output directory contains", _h_stage1_output_contains, source_order=21448
    )
    api.register(
        "`loss-analysis.yaml` contains at least one loss with `provenance` set to",
        _h_stage1_loss_has_provenance,
        source_order=21449,
    )
    api.register(
        "every `risk_card`-provenance loss has a non-empty `source_risk_cards` list",
        _h_stage1_risk_card_empty_source,
        source_order=21450,
    )
    api.register(
        "every `use_case`-provenance loss has an empty `source_risk_cards` list",
        _h_stage1_use_case_empty_source,
        source_order=21451,
    )
    api.register(
        "`loss-analysis.yaml` has an empty `risk_card_losses` list",
        _h_stage1_loss_empty_risk_card_losses,
        source_order=21452,
    )
    api.register(
        "loss IDs in `loss-analysis.yaml` are sequential",
        _h_stage1_ids_sequential,
        source_order=21453,
    )
    api.register(
        "hazard IDs in `loss-analysis.yaml` are sequential",
        _h_stage1_ids_sequential,
        source_order=21454,
    )
    api.register(
        "security constraint IDs in `loss-analysis.yaml` are sequential",
        _h_stage1_ids_sequential,
        source_order=21455,
    )
    api.register(
        "every hazard in `loss-analysis.yaml` references at least one valid loss_id",
        _h_stage1_hazard_refs_valid,
        source_order=21456,
    )
    api.register(
        "every security constraint in `loss-analysis.yaml` references at least one valid hazard_id",
        _h_stage1_sc_refs_valid,
        source_order=21457,
    )
    api.register(
        "`calls.jsonl` contains a call entry with `stage`",
        _h_stage1_calls_has_entry,
        source_order=21458,
    )
    api.register(
        "`calls.jsonl` does not contain a call entry with `stage`",
        _h_stage1_calls_not_has_entry,
        source_order=21459,
    )
    api.register(
        "`run-manifest.yaml` has `stage_summary.stage_1a.call_count` equal to",
        _h_stage1_manifest_call_count,
        source_order=21460,
    )
    api.register(
        "`capability-profile.yaml` has a non-empty `kc_subcodes` list",
        _h_stage1_cap_kc_nonempty,
        source_order=21461,
    )
    api.register(
        "every value in `kc_subcodes` is a valid KC sub-code",
        _h_stage1_cap_kc_valid,
        source_order=21462,
    )
    api.register(
        "`capability-profile.yaml` has a `zones_active` list containing",
        _h_stage1_cap_zones,
        source_order=21463,
    )
    api.register(
        "`capability-profile.yaml` has `[^`]+` consistent with `kc_subcodes`",
        _h_stage1_cap_bool_consistent,
        source_order=21464,
    )
    api.register(
        "`capability-profile.yaml` has a non-empty `entry_points` list",
        _h_stage1_cap_entry_points,
        source_order=21465,
    )
    api.register(
        "every entry point has a `name` and a `direction`",
        _h_stage1_cap_ep_name_dir,
        source_order=21466,
    )
    api.register(
        "if `capability-profile.yaml` has `tool_execution` in `zones_active` then `tool_inventory` is non-empty",
        _h_stage1_cap_tool_inv,
        source_order=21467,
    )
    api.register(
        "in `calls.jsonl` the `stage_1b` call appears before the first `stage_1a` call",
        _h_stage1_calls_1b_before_1a,
        source_order=21468,
    )
    api.register(
        "in `calls.jsonl` the `stage_1a` `risk_derivation` call appears before the `stage_1a` `gap_analysis` call",
        _h_stage1_calls_risk_before_gap,
        source_order=21469,
    )
    api.register(
        "the `stage_1a` `gap_analysis` call entry in `calls.jsonl` has a `user_prompt_text` containing",
        _h_stage1_gap_has_kc,
        source_order=21470,
    )
    api.register(
        "the `stage_1b` call entry in `calls.jsonl` has a `user_prompt_text` that does not contain",
        _h_stage1_1b_no_loss_input,
        source_order=21471,
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]
