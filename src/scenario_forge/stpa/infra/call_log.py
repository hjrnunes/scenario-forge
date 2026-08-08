"""JSONL call logging for the STPA pipeline — clean copy.

Simplified from ``scenario_forge.pipeline.io.write_pipeline_call_log``.
Appends JSONL entries with stage/step/slot_id/scenario_id metadata.
No manifest coupling.

Call log entry format (Section 6 of the STPA-Sec foundation spec):

    {
      "stage": "stage_2",
      "step": "call_2_responsibilities",
      "slot_id": null,
      "scenario_id": null,
      "system_prompt_hash": "sha256...",
      "user_prompt_hash": "sha256...",
      "model": "claude-sonnet-4-...",
      "prompt_tokens": 4500,
      "completion_tokens": 1200,
      "duration_ms": 8500,
      "timestamp": "2026-08-08T12:34:56Z",
      "success": true
    }
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _sha256(text: str) -> str:
    """Return SHA-256 hex digest of *text*."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_call_log_entry(
    *,
    stage: str,
    step: str,
    model: str,
    system_prompt: str = "",
    user_prompt: str = "",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    duration_ms: int = 0,
    success: bool = True,
    slot_id: str | None = None,
    scenario_id: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Build a call-log entry dict following the STPA format (Section 6).

    Args:
        stage: Pipeline stage (e.g. ``stage_2``, ``stage_6_narrative``).
        step: Sub-step within the stage (e.g. ``call_1_requirements``).
        model: LLM model name.
        system_prompt: System prompt text (hashed in the entry).
        user_prompt: User prompt text (hashed in the entry).
        prompt_tokens: Prompt tokens consumed.
        completion_tokens: Completion tokens generated.
        duration_ms: Wall-clock duration in milliseconds.
        success: Whether the call succeeded.
        slot_id: Stage 3 slot ID (e.g. ``RESP-1:CA-1-1:TYPE-1``), or None.
        scenario_id: Stage 5/6 scenario ID (e.g. ``SCN-001``), or None.
        timestamp: ISO 8601 timestamp; defaults to current UTC time.

    Returns:
        A dict suitable for JSONL serialization.
    """
    return {
        "stage": stage,
        "step": step,
        "slot_id": slot_id,
        "scenario_id": scenario_id,
        "system_prompt_hash": _sha256(system_prompt) if system_prompt else "",
        "user_prompt_hash": _sha256(user_prompt) if user_prompt else "",
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "duration_ms": duration_ms,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "success": success,
    }


def append_call_log(entries: list[dict], run_dir: Path) -> None:
    """Append call-log entries to ``calls.jsonl`` in *run_dir*.

    If *entries* is empty, no file is created. The directory is created
    if it does not exist.
    """
    if not entries:
        return
    run_dir.mkdir(parents=True, exist_ok=True)
    calls_path = run_dir / "calls.jsonl"
    with calls_path.open("a", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
