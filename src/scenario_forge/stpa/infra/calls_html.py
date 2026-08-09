"""HTML rendering of calls.jsonl for the STPA pipeline.

Converts a JSONL file of LLM call entries into a self-contained HTML
file with inline CSS — no external dependencies. Includes a summary
table (totals, success/failure counts) and a detail table with all
call entries. Failed calls are highlighted in red.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

_INLINE_CSS = """\
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2em; color: #222; }
h1 { font-size: 1.4em; }
h2 { font-size: 1.1em; margin-top: 1.5em; }
table { border-collapse: collapse; width: 100%; margin-bottom: 1.5em; }
th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; }
th { background: #f5f5f5; }
.summary td { font-weight: bold; }
tr.failed { background: #fdd; }
tr.failed td { color: #900; }
.error-msg { color: #c00; font-style: italic; }
"""


def _read_calls(path: Path) -> list[dict[str, Any]]:
    """Read a JSONL file and return a list of entry dicts."""
    if not path.exists() or path.stat().st_size == 0:
        return []
    entries: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            entries.append(json.loads(line))
    return entries


def _compute_summary(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute summary statistics from a list of call entries."""
    total = len(entries)
    success = sum(1 for e in entries if e.get("success", True))
    failure = total - success
    prompt_tokens = sum(e.get("prompt_tokens", 0) for e in entries)
    completion_tokens = sum(e.get("completion_tokens", 0) for e in entries)
    total_duration = sum(e.get("duration_ms", 0) for e in entries)
    return {
        "total_calls": total,
        "success_count": success,
        "failure_count": failure,
        "total_prompt_tokens": prompt_tokens,
        "total_completion_tokens": completion_tokens,
        "total_duration_ms": total_duration,
    }


def _html_escape(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _build_summary_html(summary: dict[str, Any]) -> str:
    """Build the summary table HTML."""
    rows = [
        ("Total calls", summary["total_calls"]),
        ("Successful", summary["success_count"]),
        ("Failed", summary["failure_count"]),
        ("Total prompt tokens", summary["total_prompt_tokens"]),
        ("Total completion tokens", summary["total_completion_tokens"]),
        ("Total duration (ms)", summary["total_duration_ms"]),
    ]
    body = "\n".join(
        f"      <tr><td>{label}</td><td>{value}</td></tr>"
        for label, value in rows
    )
    return (
        '  <table class="summary">\n'
        "    <tbody>\n"
        f"{body}\n"
        "    </tbody>\n"
        "  </table>"
    )


_DETAIL_HEADERS = (
    "stage", "step", "model", "prompt_tokens",
    "completion_tokens", "duration_ms", "timestamp", "status",
)


def _build_status_cell(success: bool, entry: dict[str, Any]) -> str:
    """Build the HTML for the status column of a detail row."""
    if success:
        return "<td>OK</td>"
    error = entry.get("error", "")
    return f'<td>FAILED<br><span class="error-msg">{_html_escape(error)}</span></td>'


def _build_entry_cells(entry: dict[str, Any]) -> list[str]:
    """Build all table cells for a single detail-row entry."""
    success = entry.get("success", True)
    cells: list[str] = []
    for h in _DETAIL_HEADERS:
        if h == "status":
            cells.append(_build_status_cell(success, entry))
        else:
            val = entry.get(h, "")
            cells.append(f"<td>{_html_escape(str(val))}</td>")
    return cells


def _build_detail_html(entries: list[dict[str, Any]]) -> str:
    """Build the detail table HTML."""
    header_row = "    <tr>" + "".join(
        f"<th>{h}</th>" for h in _DETAIL_HEADERS
    ) + "</tr>\n"

    body_rows: list[str] = []
    for entry in entries:
        success = entry.get("success", True)
        css_class = "" if success else ' class="failed"'
        cells = _build_entry_cells(entry)
        body_rows.append(f"    <tr{css_class}>" + "".join(cells) + "</tr>")

    body = "\n".join(body_rows)
    return (
        '  <table class="detail">\n'
        '    <thead>\n'
        f"{header_row}"
        "    </thead>\n"
        "    <tbody>\n"
        f"{body}\n"
        "    </tbody>\n"
        "  </table>"
    )


def render_calls_html(calls_jsonl_path: Path, output_path: Path) -> Path:
    """Render a calls.jsonl file into a self-contained HTML file.

    Args:
        calls_jsonl_path: Path to the JSONL file with call entries.
        output_path: Destination HTML file path.

    Returns:
        The output path (same as *output_path*).
    """
    entries = _read_calls(Path(calls_jsonl_path))
    summary = _compute_summary(entries)

    summary_html = _build_summary_html(summary)
    if entries:
        detail_html = _build_detail_html(entries)
    else:
        detail_html = '  <table class="detail">\n  </table>'

    html = (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        "<title>Calls Report</title>\n"
        f"<style>\n{_INLINE_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        "<h1>LLM Calls Report</h1>\n"
        "<h2>Summary</h2>\n"
        f"{summary_html}\n"
        "<h2>Call Details</h2>\n"
        f"{detail_html}\n"
        "</body>\n"
        "</html>\n"
    )

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out


def _main() -> int:
    """CLI entry point: python -m scenario_forge.stpa.infra.calls_html <calls.jsonl> <output.html>."""
    parser = argparse.ArgumentParser(
        description="Render calls.jsonl to a self-contained HTML report."
    )
    parser.add_argument("calls_jsonl", help="Path to calls.jsonl file")
    parser.add_argument("output_html", help="Path for output HTML file")
    args = parser.parse_args()
    result = render_calls_html(Path(args.calls_jsonl), Path(args.output_html))
    print(f"HTML report written to {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
