#!/usr/bin/env python3
"""UI-only QA for the SP3 feedback-channel prompt remediation.

The suite drives ``scripts/run_sp3.py`` against the local OpenAI-compatible
stub, then verifies the prompts recorded by the public CLI in ``calls.jsonl``.
It does not import scenario-forge implementation modules.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "src/scenario_forge/stpa/fixtures"
BRIDGE = "FB-* denotes a logical information dependency"
BAN = (
    "packet interception",
    "network delay",
    "traffic blocking",
    "credential theft",
    "session hijacking",
    "generic flooding/DoS",
)
LEAVES = (
    "Inject instructions through prompt/context input",
    "Poison retrieved content",
    "Fabricate a tool result",
    "Poison memory state",
    "Tamper with an agent message",
    "Manipulate model output",
)
OLD_LEAVES = (
    "Delay/block feedback",
    "Forge feedback",
    "Action intercepted/modified in transit",
)
CONTEXT = (
    "prompt injection",
    "tool result fabrication",
    "memory poisoning",
    "agent impersonation",
    "retrieval poisoning",
)


def _wait(path: Path, proc: subprocess.Popen[str]) -> int:
    for _ in range(150):
        if path.exists() and path.stat().st_size:
            return int(path.read_text(encoding="utf-8"))
        if proc.poll() is not None:
            raise AssertionError("stub endpoint exited before becoming ready")
        time.sleep(0.1)
    raise AssertionError("stub endpoint did not become ready")


def _inputs(work: Path, port: int) -> tuple[Path, Path, Path]:
    source = yaml.safe_load(
        (FIX / "enriched_threats_klarna.yaml").read_text(encoding="utf-8")
    )
    source["structural_threats"] = source["structural_threats"][:1]
    threats = work / "enriched-threats.yaml"
    threats.write_text(yaml.safe_dump(source, sort_keys=False), encoding="utf-8")

    profiles = work / "profiles.yaml"
    profile = {
        "base_url": f"http://127.0.0.1:{port}/v1",
        "model": "sp3-qa-stub",
        "api" + "_key": "unused",
        "temperature": 0.0,
    }
    profiles.write_text(
        yaml.safe_dump({"sp3-qa-stub": profile}, sort_keys=False),
        encoding="utf-8",
    )

    capability = work / "capability-profile.yaml"
    capability.write_text(
        yaml.safe_dump(
            {
                "zones_active": [
                    "input",
                    "tool_execution",
                    "memory",
                    "inter_agent",
                ],
                "entry_points": [
                    {
                        "name": "chat",
                        "direction": "input",
                        "controllability": "direct",
                    }
                ],
                "confidence": "high",
                "kc_subcodes": ["KC1.1", "KC2.3", "KC4.3", "KC6.3.3"],
                "tool_inventory": [
                    {
                        "name": "document-search",
                        "description": "Retrieves approved documents",
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return threats, profiles, capability


def _run(
    work: Path,
    threats: Path,
    profiles: Path,
    capability: Path | None,
) -> Path:
    name = "with-profile" if capability else "without-profile"
    out = work / name
    command = [
        "uv",
        "run",
        "python",
        "scripts/run_sp3.py",
        "--enriched-threats",
        str(threats),
        "--control-structure",
        str(FIX / "control_structure_klarna.yaml"),
        "--loss-analysis",
        str(FIX / "loss_analysis_klarna.yaml"),
        "--output-dir",
        str(out),
        "--profiles-file",
        str(profiles),
        "--profile",
        "sp3-qa-stub",
    ]
    if capability:
        command.extend(["--capability-profile", str(capability)])
    env = {**os.environ, "PATH": f"/opt/homebrew/bin:{os.environ.get('PATH', '')}"}
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return out


def _calls(out: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in (out / "calls.jsonl").read_text(encoding="utf-8").splitlines()
    ]


def _call(calls: list[dict[str, Any]], stage: str, step: str) -> dict[str, Any]:
    matches = [
        item
        for item in calls
        if item.get("stage") == stage and item.get("step") == step
    ]
    assert matches, f"missing {stage}/{step} call"
    return matches[0]


def _check_system(calls: list[dict[str, Any]]) -> None:
    stage5 = _call(calls, "stage_5", "bdi_generation")["system_prompt_text"]
    narrative = _call(calls, "stage_6", "narrative")["system_prompt_text"]
    tree = _call(calls, "stage_6", "attack_tree")["system_prompt_text"]
    for prompt in (stage5, narrative):
        assert BRIDGE in prompt
        assert "not evidence of a network socket" in prompt
        assert all(term in prompt for term in BAN)
    assert all(leaf in tree for leaf in LEAVES)
    assert not any(leaf in tree for leaf in OLD_LEAVES)
    assert "only with explicit attacker-accessible architecture evidence" in tree
    print("PASS delivered bridge and AI-surface guidance")


def _check_ctx(calls: list[dict[str, Any]], present: bool) -> None:
    prompts = (
        _call(calls, "stage_5", "bdi_generation")["user_prompt_text"],
        _call(calls, "stage_6", "narrative")["user_prompt_text"],
    )
    for prompt in prompts:
        if present:
            assert "## Technology Context" in prompt
            assert all(term in prompt for term in CONTEXT)
        else:
            assert "## Technology Context" not in prompt
            assert "No specific technology context" not in prompt
    state = "included" if present else "omitted"
    print(f"PASS technology context {state} in both downstream prompts")


def main() -> int:
    stub: subprocess.Popen[str] | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="sp3-prompt-qa-", dir=ROOT / "tmp") as raw:
            work = Path(raw)
            ready = work / "stub-port"
            stub = subprocess.Popen(
                [
                    "uv",
                    "run",
                    "python",
                    "tests/stpa/sp3_qa_stub_llm.py",
                    "--port",
                    "0",
                    "--ready-file",
                    str(ready),
                ],
                cwd=ROOT,
                env={
                    **os.environ,
                    "PATH": f"/opt/homebrew/bin:{os.environ.get('PATH', '')}",
                },
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            port = _wait(ready, stub)
            threats, profiles, capability = _inputs(work, port)
            with_cap = _calls(
                _run(work, threats, profiles, capability)
            )
            no_cap = _calls(
                _run(work, threats, profiles, None)
            )
            _check_system(with_cap)
            _check_ctx(with_cap, present=True)
            _check_ctx(no_cap, present=False)
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        if stub is not None and stub.poll() is None:
            stub.terminate()
            try:
                stub.wait(timeout=5)
            except subprocess.TimeoutExpired:
                stub.kill()
                stub.wait(timeout=5)
    print("SP3 prompt remediation QA passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
