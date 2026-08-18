#!/usr/bin/env -S uv run python
"""UI-only executable QA for SP2 ICA identifier repair.

The suite serves deterministic OpenAI-compatible responses, invokes
``scripts/run_sp2.py` in five fresh output directories, and inspects only the
published YAML artifacts and command output. It does not import project code.

Usage:
    uv run python acceptance/qa/sp2_ica_ids.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
AIRBNB = ROOT / "output" / "runs" / "20260811-full3-airbnb"
SLOT_RE = re.compile(r"slot_id:\s*(\S+)")
TARGET = "RESP-3:CA-3-1"


def identity(slot_id: str) -> dict[str, object]:
    """Build the identity fields required by the SP2 slot contract."""
    owner, action, uca_type = slot_id.split(":")
    return {
        "slot_id": slot_id,
        "responsibility": owner,
        "coordination_link": None,
        "control_action": action,
        "uca_type": uca_type,
    }


def ica(slot_id: str, pos: int, value: str) -> dict[str, object]:
    """Build one deterministic ICA fixture."""
    return {
        "ica_id": value,
        "ica_text": f"{slot_id} ICA text {pos}",
        "hazardous_context": f"{slot_id} hazardous context {pos}",
        "loss_scenario": f"{slot_id} loss scenario {pos}",
        "related_hazards": [],
        "related_constraints": [],
    }


def fixture_id(case: str, slot_id: str, pos: int) -> str:
    """Return the deliberately supplied identifier for a fixture case."""
    expected = f"{slot_id}:{pos}"
    missing = {
        "RESP-3:CA-3-1:NOT_PROVIDED",
        "RESP-4:CA-4-1:NOT_PROVIDED",
        "RESP-7:CA-7-1:NOT_PROVIDED",
    }
    if case in {"01", "05"}:
        if slot_id in missing:
            return f"{':'.join(slot_id.split(':')[:2])}:{pos}"
        if slot_id == "RESP-2:CA-2-1:INCORRECT":
            return f"RESP-1:CA-1-1:INCORRECT:{pos}"
        if slot_id == "RESP-2:CA-2-1:WRONG_TIMING":
            return f"{slot_id}:9"
    if case == "02" and slot_id.startswith(f"{TARGET}:"):
        return f"{TARGET}:1"
    return expected


def fill(case: str, prompt: str) -> dict[str, object]:
    """Build a slot-fill response from the placeholders in a user prompt."""
    slot_ids = list(dict.fromkeys(SLOT_RE.findall(prompt)))
    filled: list[dict[str, object]] = []
    for slot_id in slot_ids:
        item = identity(slot_id)
        count = 3 if case == "03" and slot_id == f"{TARGET}:WRONG_TIMING" else 1
        values = [fixture_id(case, slot_id, pos) for pos in range(1, count + 1)]
        if count == 3:
            values = [f"{TARGET}:1", f"{TARGET}:1", f"{slot_id}:9"]
        item.update(
            {
                "is_na": False,
                "icas": [
                    ica(slot_id, pos, value)
                    for pos, value in enumerate(values, start=1)
                ],
                "na_justification": None,
            }
        )
        filled.append(item)
    return {"filled_slots": filled}


class Handler(BaseHTTPRequestHandler):
    """Serve deterministic chat-completion responses."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: object) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        if not self.path.endswith("/chat/completions"):
            self.send_error(404)
            return
        size = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(size) or b"{}")
        prompt = "".join(
            str(message.get("content", ""))
            for message in request.get("messages", [])
            if message.get("role") == "user"
        )
        model = str(request.get("model", "qa-01"))
        case = model.removeprefix("qa-")
        content = json.dumps(fill(case, prompt))
        body = json.dumps(
            {
                "id": "sp2-ica-repair-qa",
                "object": "chat.completion",
                "created": 0,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": content,
                            "refusal": None,
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2,
                },
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def load(path: Path) -> dict[str, Any]:
    """Load one published YAML artifact."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def run(
    case: str, work: Path, port: int
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run the public SP2 command for one fixture case."""
    output = work / f"case-{case}"
    profiles = work / f"profiles-{case}.yaml"
    profiles.write_text(
        yaml.safe_dump(
            {
                f"qa-{case}": {
                    "base_url": f"http://127.0.0.1:{port}/v1",
                    "model": f"qa-{case}",
                    "api_key": "unused",
                    "temperature": 0.0,
                }
            }
        ),
        encoding="utf-8",
    )
    command = [
        "uv",
        "run",
        "python",
        "scripts/run_sp2.py",
        "--control-structure",
        str(AIRBNB / "control-structure.yaml"),
        "--capability-profile",
        str(AIRBNB / "capability-profile.yaml"),
        "--loss-analysis",
        str(AIRBNB / "loss-analysis.yaml"),
        "--output-dir",
        str(output),
        "--profiles-file",
        str(profiles),
        "--profile",
        f"qa-{case}",
        "--max-workers",
        "4",
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    return result, output


def slots(output: Path) -> list[dict[str, Any]]:
    """Load slots from the published enumeration."""
    return load(output / "ica-enumeration.yaml")["slots"]


def assert_aligned(items: list[dict[str, Any]]) -> None:
    """Assert the slot-relative identifier invariant and uniqueness."""
    values: list[str] = []
    for slot in items:
        for pos, item in enumerate(slot.get("icas", []), start=1):
            expected = f"{slot['slot_id']}:{pos}"
            assert item["ica_id"] == expected, (item["ica_id"], expected)
            values.append(item["ica_id"])
    assert len(values) == len(set(values)), "duplicate ICA IDs remain"


def assert_payload(items: list[dict[str, Any]]) -> None:
    """Assert every non-identifier field retains its fixture value."""
    for slot in items:
        for pos, item in enumerate(slot.get("icas", []), start=1):
            expected = ica(slot["slot_id"], pos, item["ica_id"])
            assert item == expected, (item, expected)


def check(case: str, result: subprocess.CompletedProcess[str], output: Path) -> None:
    """Check one procedure from the QA specification."""
    assert result.returncode == 0, result.stdout + result.stderr
    items = slots(output)
    assert_aligned(items)
    assert_payload(items)

    if case == "02":
        wanted = {
            f"{TARGET}:NOT_PROVIDED": f"{TARGET}:NOT_PROVIDED:1",
            f"{TARGET}:INCORRECT": f"{TARGET}:INCORRECT:1",
            f"{TARGET}:WRONG_TIMING": f"{TARGET}:WRONG_TIMING:1",
        }
        actual = {
            slot["slot_id"]: slot["icas"][0]["ica_id"]
            for slot in items
            if slot["slot_id"] in wanted
        }
        assert actual == wanted, actual
    if case == "03":
        selected = next(
            slot for slot in items if slot["slot_id"] == f"{TARGET}:WRONG_TIMING"
        )
        assert [item["ica_id"] for item in selected["icas"]] == [
            f"{TARGET}:WRONG_TIMING:1",
            f"{TARGET}:WRONG_TIMING:2",
            f"{TARGET}:WRONG_TIMING:3",
        ]
    if case == "05":
        assert (output / "enriched-threats.yaml").is_file()
        manifest = load(output / "run-manifest.yaml")
        assert manifest["stage_summary"]["stage_3"]["call_count"] == 7
        assert manifest.get("stage_errors") == []
        diagnostics = (result.stdout + result.stderr).lower()
        assert "duplicate ica" not in diagnostics
        assert "ica-id-format" not in diagnostics


def main() -> int:
    """Run all five end-to-end QA procedures."""
    needed = (
        AIRBNB / "control-structure.yaml",
        AIRBNB / "capability-profile.yaml",
        AIRBNB / "loss-analysis.yaml",
    )
    missing = [str(path) for path in needed if not path.is_file()]
    if missing:
        print(f"FAIL: missing production inputs: {missing}", file=sys.stderr)
        return 1

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    passed = 0
    try:
        with tempfile.TemporaryDirectory(prefix="sp2-ica-qa-", dir=ROOT / "tmp") as raw:
            work = Path(raw)
            for case in ("01", "02", "03", "04", "05"):
                result, output = run(case, work, server.server_address[1])
                check(case, result, output)
                print(f"PASS QA-SP2-ICA-ID-{case}")
                passed += 1
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    print(f"SP2 ICA ID repair QA: {passed}/5 procedures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
