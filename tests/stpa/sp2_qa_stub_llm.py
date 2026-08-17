#!/usr/bin/env python3
"""Stub OpenAI-compatible LLM endpoint for the SP2 end-to-end QA suite.

The SP2 QA suite drives ``scripts/run_sp2.py`` through its real command
line. Stage 3 makes one LLM call per responsibility, so a real endpoint
would make the suite non-deterministic, slow, and billable. This server
speaks just enough of the OpenAI chat-completions protocol for the
``openai`` SDK's structured-output ``parse`` path.

The stub echoes the slot identity of every slot it is asked about, which
is what ``slot_filling._is_expected_slot`` requires. Slots alternate
between a filled ICA and a structurally justified N/A so a QA run
exercises both branches of the merge and both N/A quality gates.

Usage::

    python tests/stpa/sp2_qa_stub_llm.py --port 8123 [--ready-file PATH]

Writes the bound port to ``--ready-file`` (if given) once listening, so
callers can wait for readiness instead of sleeping.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Hazard and constraint IDs present in every SP1 loss-analysis fixture.
# ICAEnumeration.validate_against rejects references outside these sets.
_HAZARD_ID = "H-1"
_CONSTRAINT_ID = "SC-1"

_SLOT_ID_RE = re.compile(r"slot_id:\s*(\S+)")

# na_quality's structural keyword gate looks for wording that describes a
# structural property rather than a technology guess.
_NA_JUSTIFICATION = (
    "The control action is atomic and stateless, so this UCA type has no "
    "structural realization in the control structure."
)


def _slot_identity(slot_id: str) -> dict[str, object] | None:
    """Derive a slot's identity fields from its ID.

    Slot IDs are ``RESP-X:CA-Y:UCA_TYPE`` or ``CL-X:CM-Y:UCA_TYPE``.
    """
    parts = slot_id.split(":")
    if len(parts) != 3:
        return None
    owner, control_action, uca_type = parts
    return {
        "slot_id": slot_id,
        "responsibility": owner if owner.startswith("RESP-") else None,
        "coordination_link": owner if owner.startswith("CL-") else None,
        "control_action": control_action,
        "uca_type": uca_type,
    }


def _fill_slot(identity: dict[str, object], index: int) -> dict[str, object]:
    """Produce a filled slot payload for one placeholder."""
    slot: dict[str, object] = dict(identity)
    if index % 2 == 0:
        slot["is_na"] = False
        slot["icas"] = [
            {
                "ica_id": f"{identity['slot_id']}:1",
                "ica_text": (
                    f"The controller does not correctly provide "
                    f"{identity['control_action']} when required."
                ),
                "hazardous_context": (
                    "An attacker supplies crafted input during a privileged "
                    "request, so the control action is skipped."
                ),
                "loss_scenario": (
                    "The unchecked request completes and the resulting "
                    "unauthorized action is not detected."
                ),
                "related_hazards": [_HAZARD_ID],
                "related_constraints": [_CONSTRAINT_ID],
            }
        ]
        slot["na_justification"] = None
    else:
        slot["is_na"] = True
        slot["icas"] = []
        slot["na_justification"] = _NA_JUSTIFICATION
    return slot


def _build_fill_response(user_prompt: str) -> dict[str, object]:
    """Build an ``ICASlotFillResult`` payload for the slots in a prompt."""
    seen: list[str] = []
    for slot_id in _SLOT_ID_RE.findall(user_prompt):
        if slot_id not in seen:
            seen.append(slot_id)

    filled = []
    for index, slot_id in enumerate(seen):
        identity = _slot_identity(slot_id)
        if identity is not None:
            filled.append(_fill_slot(identity, index))
    return {"filled_slots": filled}


class _StubHandler(BaseHTTPRequestHandler):
    """Serves ``POST /v1/chat/completions`` (and the un-prefixed path)."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: object) -> None:  # noqa: D102 - silence access log
        pass

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if not self.path.endswith("/chat/completions"):
            self.send_error(404, "Not Found")
            return

        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length) or b"{}")
        user_prompt = "".join(
            str(message.get("content", ""))
            for message in request.get("messages", [])
            if message.get("role") == "user"
        )

        content = json.dumps(_build_fill_response(user_prompt))
        body = json.dumps(
            {
                "id": "chatcmpl-sp2-qa-stub",
                "object": "chat.completion",
                "created": 0,
                "model": request.get("model", "sp2-qa-stub"),
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
        ).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    """Start the stub server and serve until killed."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--ready-file", default=None)
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), _StubHandler)
    port = server.server_address[1]
    if args.ready_file:
        with open(args.ready_file, "w", encoding="utf-8") as handle:
            handle.write(str(port))
    print(f"sp2-qa-stub listening on {port}", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
