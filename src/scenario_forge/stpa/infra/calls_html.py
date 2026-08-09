"""HTML rendering of calls.jsonl for the STPA pipeline.

Converts a JSONL file of LLM call entries into a self-contained HTML
file with inline CSS and JavaScript — no external dependencies. Includes
a summary table (totals, success/failure counts), a detail table with all
call entries, collapsible sections for full prompt text and response
content, and a search/filter box. Failed calls are highlighted in red.
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
.search-box { margin-bottom: 1em; padding: 6px 10px; width: 100%; max-width: 400px; font-size: 1em; }
.call-entry { border: 1px solid #ddd; margin-bottom: 1em; padding: 0.5em 1em; }
.call-entry.failed { background: #fdd; }
.call-entry summary { cursor: pointer; font-weight: bold; padding: 4px 0; }
details { margin: 4px 0; }
details summary { cursor: pointer; color: #006; font-size: 0.9em; }
pre { background: #f8f8f8; border: 1px solid #eee; padding: 8px; overflow-x: auto; font-size: 0.85em; white-space: pre-wrap; word-wrap: break-word; }
.collapsible-label { font-size: 0.85em; color: #006; }
"""

_INLINE_JS = """\
function filterCalls() {
  var query = document.getElementById('call-search').value.toLowerCase();
  var entries = document.getElementsByClassName('call-entry');
  for (var i = 0; i < entries.length; i++) {
    var text = entries[i].textContent.toLowerCase();
    entries[i].style.display = text.indexOf(query) !== -1 ? '' : 'none';
  }
}
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


def _format_response_content(content: str) -> str:
    """Format response content for display.

    Pretty-prints JSON content; wraps non-JSON content in a pre block.
    """
    if not content:
        return ""
    try:
        parsed = json.loads(content)
        pretty = json.dumps(parsed, indent=2)
        return f"<pre>{_html_escape(pretty)}</pre>"
    except (json.JSONDecodeError, TypeError):
        return f"<pre>{_html_escape(content)}</pre>"


def _build_collapsible_section(
    label: str,
    content_html: str,
) -> str:
    """Build a collapsible <details> section for prompt or response content."""
    if not content_html:
        return ""
    return (
        f'<details><summary class="collapsible-label">{_html_escape(label)}</summary>\n'
        f"{content_html}\n"
        "</details>\n"
    )


def _build_prompt_section(label: str, content: str) -> str:
    """Build a collapsible section for a raw text prompt.

    Returns an empty string when *content* is empty.
    """
    if not content:
        return ""
    return _build_collapsible_section(
        label,
        f"<pre>{_html_escape(content)}</pre>",
    )


def _build_response_section(label: str, content: str) -> str:
    """Build a collapsible section for response content (pretty-printed JSON).

    Returns an empty string when *content* is empty.
    """
    if not content:
        return ""
    return _build_collapsible_section(label, _format_response_content(content))


# (label, entry_key, section_builder) for each collapsible content section.
_CONTENT_SECTIONS: tuple[tuple[str, str, Any], ...] = (
    ("system_prompt", "system_prompt_text", _build_prompt_section),
    ("user_prompt", "user_prompt_text", _build_prompt_section),
    ("response_content", "response_content", _build_response_section),
)


def _build_call_entry_html(entry: dict[str, Any]) -> str:
    """Build a per-call collapsible entry with metadata, prompts, and response."""
    success = entry.get("success", True)
    stage = entry.get("stage", "")
    step = entry.get("step", "")

    # Build the summary line
    summary_parts = [f"{stage}/{step}"]
    model = entry.get("model", "")
    if model:
        summary_parts.append(f"model={model}")
    prompt_tokens = entry.get("prompt_tokens", 0)
    completion_tokens = entry.get("completion_tokens", 0)
    summary_parts.append(f"tokens={prompt_tokens}+{completion_tokens}")
    css_class = ""
    if not success:
        css_class = " failed"
        error = entry.get("error", "")
        summary_parts.append(f"FAILED: {error}")
    summary_line = " ".join(summary_parts)

    # Build collapsible sections for full content
    sections: list[str] = []
    for label, entry_key, builder in _CONTENT_SECTIONS:
        section = builder(label, entry.get(entry_key, ""))
        if section:
            sections.append(section)

    sections_html = "\n".join(sections)
    return (
        f'<div class="call-entry{css_class}">\n'
        f'<details open><summary>{_html_escape(summary_line)}</summary>\n'
        f"{sections_html}\n"
        "</details>\n"
        "</div>\n"
    )


def _build_call_entries_html(entries: list[dict[str, Any]]) -> str:
    """Build per-call collapsible entries with full content sections."""
    if not entries:
        return ""
    return "\n".join(_build_call_entry_html(entry) for entry in entries)


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
        call_entries_html = _build_call_entries_html(entries)
    else:
        detail_html = '  <table class="detail">\n  </table>'
        call_entries_html = ""

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
        '<h2>Call Details</h2>\n'
        f'<input type="text" id="call-search" class="search-box" '
        'placeholder="Filter calls by text..." onkeyup="filterCalls()">\n'
        f"{detail_html}\n"
        '<h2>Full Call Content</h2>\n'
        f"{call_entries_html}\n"
        f"<script>\n{_INLINE_JS}</script>\n"
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-09T17:41:29Z","module_hash":"f65b010eea31ac98c764604032e452d10684cdb26a97ab6d9c43939d386a48b8","functions":[{"id":"func/_read_calls","name":"_read_calls","line":50,"end_line":59,"hash":"97b7cc0d899bae210d8a4e486a9984fe9b45f48322b07e2edd897e8d46f93527"},{"id":"func/_compute_summary","name":"_compute_summary","line":62,"end_line":77,"hash":"9c8251543992b54eeea58e1d5099c97839b087be963d898d8a77dd83b8d534d3"},{"id":"func/_html_escape","name":"_html_escape","line":80,"end_line":87,"hash":"7fec88fe405896f9ac61ebb977248558c0765cfb5e4811110b6735f09093b891"},{"id":"func/_build_summary_html","name":"_build_summary_html","line":90,"end_line":110,"hash":"f3eb70d2d0aa71b548d2b1963417452f6990cd7102227b5623f98ed2f223b385"},{"id":"func/_build_status_cell","name":"_build_status_cell","line":119,"end_line":124,"hash":"ed7d954efce1f8daa2610a230e1b5080eee12896d4dc00e056f1578218341f89"},{"id":"func/_build_entry_cells","name":"_build_entry_cells","line":127,"end_line":137,"hash":"094f316f76ab144ec22a1f5134117276dca359fec969133740ad092e1f42e633"},{"id":"func/_build_detail_html","name":"_build_detail_html","line":140,"end_line":163,"hash":"335e88a0e2f2ad1708c24f6e5d94504cec9a488436f90d17a084bf4011244d12"},{"id":"func/_format_response_content","name":"_format_response_content","line":166,"end_line":178,"hash":"d1cacc9983448b54d3a9d903977144d3bce608b2027d42515a757614ea3dde3f"},{"id":"func/_build_collapsible_section","name":"_build_collapsible_section","line":181,"end_line":192,"hash":"307ebf8ae0423b22bceb6418cb4f03dda661ee751fc58e451d6c408f8084944d"},{"id":"func/_build_prompt_section","name":"_build_prompt_section","line":195,"end_line":205,"hash":"869fc18211ca8ec48ba40d717ccaf9aee6ea6f42e28555fa6fcc9d3f3ae3cbbe"},{"id":"func/_build_response_section","name":"_build_response_section","line":208,"end_line":215,"hash":"5af7e3353c2b06c721588517fb0ae6fb68d247e25e4a6fef955401dc4ff5bb0e"},{"id":"func/_build_call_entry_html","name":"_build_call_entry_html","line":226,"end_line":261,"hash":"d3ba8e989f69e6cbda3c5db76e11bd8c01cc3cf53bbb30c287de174889d15e04"},{"id":"func/_build_call_entries_html","name":"_build_call_entries_html","line":264,"end_line":268,"hash":"4772579c722b517aaa930065441d27d03bcecbdb0f66f8fc50981d2a361bad76"},{"id":"func/render_calls_html","name":"render_calls_html","line":271,"end_line":318,"hash":"f283c5943bb077ae4572b887a9b8fcab43b062d5818ef72a81eb7f3caf70fe5a"},{"id":"func/_main","name":"_main","line":321,"end_line":331,"hash":"e1e7953f9dde4f1cf8c798bdd46750515d2bd8b16e6c47f070149aa616884d50"}]}
# mutate4py-manifest-end
