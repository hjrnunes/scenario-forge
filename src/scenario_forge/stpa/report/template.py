"""HTML template components for the STPA report.

Self-contained HTML with inline CSS/JS — no external dependencies.
Section builders return HTML strings.  ``build_html`` assembles the
final document.
"""

from __future__ import annotations

import html
import re
from typing import Any


# ---------------------------------------------------------------------------
# Escaping and syntax highlighting
# ---------------------------------------------------------------------------


def _esc(text: str | None) -> str:
    """HTML-escape text safely."""
    if text is None:
        return ""
    return html.escape(str(text))


def _highlight_yaml(text: str) -> str:
    """Simple regex-based YAML syntax highlighting."""
    lines = text.split("\n")
    result: list[str] = []
    for line in lines:
        escaped = _esc(line)
        if escaped.strip().startswith("#"):
            result.append(f'<span class="yaml-comment">{escaped}</span>')
            continue
        m = re.match(r"^(\s*)([\w.-]+)(\s*:\s*)(.*)", escaped)
        if m:
            indent, key, colon, value = m.groups()
            result.append(
                f'{indent}<span class="yaml-key">{key}</span>{colon}'
                f'{_highlight_yaml_value(value)}'
            )
            continue
        m = re.match(r"^(\s*-\s+)(.*)", escaped)
        if m:
            prefix, value = m.groups()
            result.append(f"{prefix}{_highlight_yaml_value(value)}")
            continue
        result.append(escaped)
    return "\n".join(result)


def _is_quoted_string(v: str) -> bool:
    """Check if *v* is a single- or double-quoted YAML string."""
    return (v.startswith("'") and v.endswith("'")) or (
        v.startswith('"') and v.endswith('"')
    )


def _yaml_value_class(v: str) -> str | None:
    """Return the CSS class for a YAML scalar value, or None."""
    if v in ("null", "~"):
        return "yaml-null"
    if v in ("true", "false"):
        return "yaml-bool"
    if re.match(r"^-?\d+(\.\d+)?$", v):
        return "yaml-number"
    if _is_quoted_string(v):
        return "yaml-string"
    return None


def _highlight_yaml_value(value: str) -> str:
    v = value.strip()
    if not v:
        return value
    css = _yaml_value_class(v)
    if css:
        return f'<span class="{css}">{value}</span>'
    return value


_GHERKIN_KEYWORDS = [
    "Feature:",
    "Background:",
    "Scenario:",
    "Scenario Outline:",
    "Given ",
    "When ",
    "Then ",
    "And ",
    "But ",
    "* ",
]


def _apply_gherkin_keyword_highlight(escaped: str) -> str:
    """Apply keyword highlighting to a single escaped Gherkin line."""
    for kw in _GHERKIN_KEYWORDS:
        ekw = _esc(kw)
        if escaped.strip().startswith(ekw):
            idx = escaped.index(ekw)
            css = _gherkin_keyword_class(kw.strip())
            return (
                escaped[:idx]
                + f'<span class="{css}">{ekw}</span>'
                + escaped[idx + len(ekw):]
            )
    return escaped


def _highlight_gherkin(text: str) -> str:
    """Syntax-highlight Gherkin text.

    Given=blue, When=purple, Then=green, But=red, And=indigo.
    Comments (#) are muted; tags (@) are amber.
    """
    lines = text.split("\n")
    result: list[str] = []
    for line in lines:
        escaped = _esc(line)
        if escaped.strip().startswith("#"):
            result.append(f'<span class="gherkin-comment">{escaped}</span>')
            continue
        if escaped.strip().startswith("@"):
            result.append(f'<span class="gherkin-tag">{escaped}</span>')
            continue
        escaped = _apply_gherkin_keyword_highlight(escaped)
        if "&quot;&quot;&quot;" in escaped:
            escaped = escaped.replace(
                "&quot;&quot;&quot;",
                '<span class="gherkin-string">&quot;&quot;&quot;</span>',
            )
        result.append(escaped)
    return "\n".join(result)


def _gherkin_keyword_class(keyword: str) -> str:
    """Return the CSS class for a Gherkin keyword."""
    mapping = {
        "Given:": "step-given",
        "When:": "step-when",
        "Then:": "step-then",
        "But:": "step-but",
        "And:": "step-and",
        "Feature:": "step-given",
        "Background:": "step-given",
        "Scenario:": "step-when",
        "Scenario": "step-when",
        "Outline:": "step-when",
        "*": "step-star",
    }
    return mapping.get(keyword, "gherkin-keyword")


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------


def _build_css() -> str:
    return """<style>
:root {
  --bg-primary: #0f1117;
  --bg-secondary: #1a1d2e;
  --bg-card: #1e2235;
  --bg-card-hover: #252a40;
  --text-primary: #e8eaed;
  --text-secondary: #9ca3af;
  --text-muted: #6b7280;
  --border: #2d3348;
  --accent: #6366f1;
  --accent-glow: rgba(99, 102, 241, 0.15);
  --green: #22c55e;
  --yellow: #f59e0b;
  --red: #ef4444;
  --blue: #3b82f6;
  --purple: #8b5cf6;
  --indigo: #6366f1;
  --orange: #f97316;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  line-height: 1.6;
}
.container { max-width: 1100px; margin: 0 auto; padding: 40px 24px 80px; }

/* Hero */
.hero {
  background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card));
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 32px;
  margin-bottom: 32px;
}
.hero h1 { font-size: 24px; font-weight: 700; margin-bottom: 8px; }
.hero-meta { display: flex; gap: 24px; flex-wrap: wrap; margin-top: 12px; }
.hero-stat { display: flex; flex-direction: column; gap: 2px; }
.hero-stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); }
.hero-stat-value { font-size: 18px; font-weight: 700; color: var(--text-primary); }
.hero-metrics { display: flex; gap: 16px; flex-wrap: wrap; margin-top: 16px; }
.hero-metric { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 10px 16px; }
.hero-metric-name { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); }
.hero-metric-value { font-size: 16px; font-weight: 700; }

/* Flow cards */
.flow-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  margin-bottom: 0;
  overflow: hidden;
}
.flow-card > summary {
  cursor: pointer;
  padding: 18px 24px;
  font-size: 18px;
  font-weight: 700;
  list-style: none;
  display: flex;
  align-items: center;
  gap: 10px;
  background: var(--bg-secondary);
}
.flow-card > summary::-webkit-details-marker { display: none; }
.flow-card > summary::before {
  content: '\\25B6'; font-size: 10px; color: var(--text-muted); transition: transform 0.2s;
}
.flow-card[open] > summary::before { transform: rotate(90deg); }
.flow-card-body { padding: 24px; }

/* Produces arrow */
.produces-arrow {
  text-align: center;
  font-size: 24px;
  color: var(--text-muted);
  padding: 8px 0;
  user-select: none;
}

/* Subsection */
.subsection { margin-bottom: 20px; }
.subsection-title {
  font-size: 13px; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 10px;
  padding-bottom: 6px; border-bottom: 1px solid var(--border);
}

/* Tables */
.data-table { width: 100%; border-collapse: collapse; margin-bottom: 12px; }
.data-table th {
  text-align: left; padding: 8px 12px; background: var(--bg-secondary);
  color: var(--text-secondary); font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border);
}
.data-table td { padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 13px; }
.data-table tr:hover td { background: var(--bg-card-hover); }

/* Zone chips */
.zone-chip {
  display: inline-flex; align-items: center; height: 24px; padding: 0 10px;
  border-radius: 4px; font-size: 11px; font-weight: 600; margin: 2px;
  background: var(--accent-glow); color: var(--accent); border: 1px solid var(--border);
}

/* Scenario cards */
.scenario-card {
  background: var(--bg-secondary); border: 1px solid var(--border);
  border-radius: 8px; margin-bottom: 12px; overflow: hidden;
}
.scenario-card > summary {
  cursor: pointer; padding: 12px 18px; font-size: 14px; font-weight: 600;
  list-style: none; display: flex; align-items: center; gap: 8px;
}
.scenario-card > summary::-webkit-details-marker { display: none; }
.scenario-card > summary::before {
  content: '\\25B6'; font-size: 8px; color: var(--text-muted); transition: transform 0.2s;
}
.scenario-card[open] > summary::before { transform: rotate(90deg); }
.scenario-card-body { padding: 16px 18px; }
.scenario-section { margin-bottom: 16px; }
.scenario-section:last-child { margin-bottom: 0; }
.scenario-section-title {
  font-size: 11px; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 8px;
}

/* BDI */
.bdi-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.bdi-block { background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px; padding: 12px; }
.bdi-block h4 { font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 8px; }
.bdi-item { font-size: 12px; color: var(--text-primary); margin-bottom: 4px; line-height: 1.5; }
.bdi-item-vuln { font-size: 11px; color: var(--text-muted); font-style: italic; }

/* Narrative */
.narrative-text { font-size: 13px; line-height: 1.7; color: var(--text-secondary); white-space: pre-wrap; }

/* Attack tree */
.attack-tree { font-size: 13px; }
.attack-tree-node {
  margin-left: 20px; border-left: 2px solid var(--border); padding-left: 14px;
  margin-bottom: 4px;
}
.attack-tree-node.connector::before {
  content: ''; display: inline-block; width: 10px; height: 2px;
  background: var(--border); margin-left: -14px; margin-right: 4px; vertical-align: middle;
}
.tree-node-label { color: var(--text-primary); }
.tree-node-details { font-size: 11px; color: var(--text-muted); margin-top: 2px; }
.gate-badge {
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 28px; height: 20px; padding: 0 6px; border-radius: 4px;
  font-size: 10px; font-weight: 700; font-family: monospace; margin-right: 6px;
}
.gate-or { background: rgba(59,130,246,0.2); color: #60a5fa; }
.gate-and { background: rgba(139,92,246,0.2); color: #a78bfa; }
.gate-leaf { background: rgba(107,114,128,0.2); color: #9ca3af; }
.cat-controller_side { border-left-color: var(--blue); }
.cat-path_side { border-left-color: var(--green); }
.cat-coordination_gap { border-left-color: var(--orange); }
.tree-empty { font-size: 13px; color: var(--text-muted); font-style: italic; padding: 12px; }

/* Gherkin highlighting */
.step-given { color: #3b82f6; font-weight: 700; }
.step-when { color: #8b5cf6; font-weight: 700; }
.step-then { color: #22c55e; font-weight: 700; }
.step-but { color: #ef4444; font-weight: 700; }
.step-and { color: #6366f1; font-weight: 700; }
.step-star { color: #f59e0b; font-weight: 700; }
.gherkin-keyword { color: #60a5fa; font-weight: 700; }
.gherkin-tag { color: #f59e0b; }
.gherkin-string { color: #a78bfa; }
.gherkin-comment { color: #4b5563; font-style: italic; }
.gherkin-block {
  background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px;
  padding: 14px; font-family: monospace; font-size: 12px; line-height: 1.6;
  white-space: pre-wrap; word-break: break-word; overflow-x: auto;
}

/* YAML highlighting */
.yaml-key { color: #60a5fa; }
.yaml-string { color: #a78bfa; }
.yaml-number { color: #f59e0b; }
.yaml-bool { color: #22c55e; }
.yaml-null { color: #6b7280; font-style: italic; }
.yaml-comment { color: #4b5563; font-style: italic; }
.code-block {
  background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px;
  padding: 14px; font-family: monospace; font-size: 12px; line-height: 1.6;
  white-space: pre-wrap; word-break: break-word; max-height: 400px; overflow-y: auto;
}

/* Collapsible raw YAML */
details.raw-yaml > summary {
  cursor: pointer; font-size: 12px; font-weight: 600; color: var(--text-muted);
  padding: 6px 0; list-style: none;
}
details.raw-yaml > summary::-webkit-details-marker { display: none; }
details.raw-yaml > summary::before { content: '\\25B6 '; font-size: 8px; }
details.raw-yaml[open] > summary::before { content: '\\25BC '; }

/* Eval gauges */
.eval-gauge-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.eval-gauge-name { min-width: 180px; font-size: 12px; font-weight: 600; color: var(--text-secondary); }
.eval-gauge-track {
  flex: 1; height: 20px; background: var(--bg-primary); border-radius: 4px;
  overflow: hidden; max-width: 300px;
}
.eval-gauge-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
.eval-gauge-fill.green { background: var(--green); }
.eval-gauge-fill.yellow { background: var(--yellow); }
.eval-gauge-fill.red { background: var(--red); }
.eval-gauge-pct { font-size: 12px; font-weight: 700; font-family: monospace; min-width: 40px; }
.scorecard-badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; }
.scorecard-badge-green { background: rgba(34,197,94,0.12); color: #22c55e; border: 1px solid rgba(34,197,94,0.25); }
.scorecard-badge-yellow { background: rgba(245,158,11,0.12); color: #f59e0b; border: 1px solid rgba(245,158,11,0.25); }
.scorecard-badge-red { background: rgba(239,68,68,0.12); color: #ef4444; border: 1px solid rgba(239,68,68,0.25); }

/* LLM Call Inspector */
.call-entry {
  background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px;
  margin-bottom: 8px; overflow: hidden;
}
.call-entry.failed { border-left: 3px solid var(--red); }
.call-entry > summary {
  cursor: pointer; padding: 10px 14px; font-size: 13px; list-style: none;
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
}
.call-entry > summary::-webkit-details-marker { display: none; }
.call-entry > summary::before { content: '\\25B6'; font-size: 8px; color: var(--text-muted); transition: transform 0.2s; }
.call-entry[open] > summary::before { transform: rotate(90deg); }
.call-meta { font-size: 12px; color: var(--text-secondary); }
.call-meta-stage { font-family: monospace; font-weight: 600; color: var(--accent); }
.call-fail-indicator { color: var(--red); font-weight: 700; font-size: 11px; }
.call-success-indicator { color: var(--green); font-weight: 700; font-size: 11px; }
.call-entry-body { padding: 12px 14px; }
.call-summary-bar {
  display: flex; gap: 20px; flex-wrap: wrap; padding: 12px 16px;
  background: var(--bg-secondary); border-radius: 6px; margin-bottom: 12px;
}
.call-summary-stat { font-size: 13px; }
.call-summary-stat strong { font-size: 18px; font-weight: 800; color: var(--accent); }

/* Run manifest */
.manifest-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
.manifest-item { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; }
.manifest-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); }
.manifest-value { font-size: 14px; font-weight: 600; word-break: break-all; }

/* Sticky nav */
#sticky-nav {
  position: fixed; top: 20px; right: 20px; width: 140px;
  background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px;
  padding: 12px; z-index: 100; opacity: 0; transition: opacity 0.3s;
}
#sticky-nav.visible { opacity: 1; }
#sticky-nav a {
  display: block; padding: 6px 10px; color: var(--text-secondary);
  text-decoration: none; font-size: 12px; font-weight: 500; border-radius: 4px;
}
#sticky-nav a:hover { background: var(--accent-glow); color: var(--text-primary); }

/* Coverage */
.coverage-rate { font-size: 20px; font-weight: 700; color: var(--accent); }

/* Copy button */
.copy-btn {
  padding: 4px 10px; background: var(--bg-card-hover); border: 1px solid var(--border);
  border-radius: 4px; color: var(--text-secondary); cursor: pointer; font-size: 11px;
}
.copy-btn:hover { background: var(--accent); color: white; }
</style>"""


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------


def _build_js() -> str:
    return """<script>
// Sticky nav visibility on scroll
window.addEventListener('scroll', function() {
  var nav = document.getElementById('sticky-nav');
  if (window.scrollY > 200) {
    nav.classList.add('visible');
  } else {
    nav.classList.remove('visible');
  }
});
// Copy to clipboard
document.querySelectorAll('.copy-btn').forEach(function(btn) {
  btn.addEventListener('click', function() {
    var target = document.getElementById(btn.getAttribute('data-target'));
    if (target) {
      navigator.clipboard.writeText(target.textContent).then(function() {
        btn.textContent = 'Copied!';
        setTimeout(function() { btn.textContent = 'Copy'; }, 1500);
      });
    }
  });
});
</script>"""


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _build_sticky_nav() -> str:
    """Build the sticky mini-navigation with links to major sections."""
    links = [
        ("SP1", "#sp1"),
        ("SP2", "#sp2"),
        ("SP3", "#sp3"),
        ("Calls", "#calls"),
        ("Manifest", "#manifest"),
    ]
    items = "\n".join(
        f'    <a href="{href}">{label}</a>' for label, href in links
    )
    return f'<nav id="sticky-nav" class="sticky-nav">\n{items}\n  </nav>'


def _build_hero_summary(
    run_id: str | None,
    created_at: str | None,
    scenario_count: int | None,
    eval_metrics: dict[str, float] | None,
) -> str:
    """Build the hero summary section."""
    run_id_html = _esc(run_id) if run_id else "N/A"
    ts_html = _esc(created_at) if created_at else "N/A"
    count_html = str(scenario_count) if scenario_count is not None else "N/A"

    metrics_html = ""
    if eval_metrics:
        metric_items = []
        for name, rate in eval_metrics.items():
            pct = f"{rate * 100:.0f}%"
            metric_items.append(
                f'    <div class="hero-metric">'
                f'<div class="hero-metric-name">{_esc(name)}</div>'
                f'<div class="hero-metric-value">{_esc(pct)}</div>'
                f'</div>'
            )
        metrics_html = f'  <div class="hero-metrics">\n{chr(10).join(metric_items)}\n  </div>'
    else:
        metrics_html = '  <div class="hero-metrics"><div class="hero-metric"><div class="hero-metric-name">Eval</div><div class="hero-metric-value">N/A</div></div></div>'

    return (
        f'<section id="hero" class="hero">\n'
        f'  <h1>STPA-Sec Report</h1>\n'
        f'  <div class="hero-meta">\n'
        f'    <div class="hero-stat"><div class="hero-stat-label">Run ID</div><div class="hero-stat-value">{run_id_html}</div></div>\n'
        f'    <div class="hero-stat"><div class="hero-stat-label">Timestamp</div><div class="hero-stat-value">{ts_html}</div></div>\n'
        f'    <div class="hero-stat"><div class="hero-stat-label">Scenarios</div><div class="hero-stat-value">{count_html}</div></div>\n'
        f'  </div>\n'
        f'{metrics_html}\n'
        f'</section>'
    )


def _build_raw_yaml_section(filename: str, raw_text: str) -> str:
    """Build a collapsible raw YAML section."""
    highlighted = _highlight_yaml(raw_text)
    safe_id = re.sub(r"[^a-zA-Z0-9_-]", "-", filename)
    return (
        f'<details class="raw-yaml" data-filename="{_esc(filename)}">\n'
        f'  <summary>Raw YAML: {_esc(filename)}</summary>\n'
        f'  <div class="code-block" id="raw-{safe_id}">{highlighted}</div>\n'
        f'</details>'
    )


def _build_raw_yaml_sections(
    raw_texts: dict[str, str] | None, filenames: tuple[str, ...],
) -> list[str]:
    """Build raw YAML sections for the given filenames if present."""
    if not raw_texts:
        return []
    return [
        _build_raw_yaml_section(fname, raw_texts[fname])
        for fname in filenames
        if fname in raw_texts
    ]


def _build_table_rows(rows_data: list[tuple], cell_count: int) -> str:
    """Build ``<tr>`` elements from a list of tuples."""
    return "\n".join(
        "      " + "".join(f"<td>{_esc(cell)}</td>" for cell in row)
        for row in rows_data
    )


def _build_data_table(
    headers: list[str], rows: str, table_id: str = "",
) -> str:
    """Build a complete ``<table class="data-table">`` element."""
    th = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    return (
        f'    <table class="data-table"><thead><tr>{th}</tr></thead>\n'
        f'    <tbody>\n{rows}\n    </tbody></table>'
    )


def _build_losses_table(losses: list[dict]) -> str:
    """Build the losses data table, or empty string if no losses."""
    if not losses:
        return ""
    rows = _build_table_rows(
        [(loss["id"], loss["description"], loss.get("provenance", "")) for loss in losses], 3,
    )
    return _build_data_table(["ID", "Description", "Provenance"], rows)


def _build_hazards_table(hazards: list) -> str:
    """Build the hazards data table, or empty string if no hazards."""
    if not hazards:
        return ""
    rows = _build_table_rows(
        [(h.hazard_id, h.description) for h in hazards], 2,
    )
    return _build_data_table(["Hazard ID", "Description"], rows)


def _build_constraints_table(constraints: list) -> str:
    """Build the constraints data table, or empty string if no constraints."""
    if not constraints:
        return ""
    rows = _build_table_rows(
        [(sc.constraint_id, sc.description) for sc in constraints], 2,
    )
    return _build_data_table(["Constraint ID", "Description"], rows)


def _build_sp1_losses_section(loss_analysis: Any) -> str:
    """Build the losses, hazards, and constraints subsection of SP1."""
    parts: list[str] = ['<div class="subsection">']
    parts.append('  <div class="subsection-title">Losses, Hazards & Constraints</div>')

    for table in (
        _build_losses_table(list(_loss_analysis_losses(loss_analysis))),
        _build_hazards_table(loss_analysis.hazards),
        _build_constraints_table(loss_analysis.security_constraints),
    ):
        if table:
            parts.append(table)

    parts.append('</div>')
    return "\n".join(parts)


def _build_sp1_capability_section(capability_profile: Any) -> str:
    """Build the capability profile subsection of SP1."""
    parts: list[str] = ['<div class="subsection">']
    parts.append('  <div class="subsection-title">Capability Profile</div>')
    zones = getattr(capability_profile, "zones_active", [])
    if zones:
        chips = " ".join(f'<span class="zone-chip">{_esc(z)}</span>' for z in zones)
        parts.append(f'    <div>{chips}</div>')
    kcs = getattr(capability_profile, "kc_subcodes", [])
    if kcs:
        parts.append(
            f'    <p style="font-size:12px;color:var(--text-secondary);margin-top:8px;">'
            f'KC: {_esc(", ".join(kcs))}</p>'
        )
    parts.append('</div>')
    return "\n".join(parts)


def _build_sp1_control_section(control_structure: Any) -> str:
    """Build the control structure subsection of SP1."""
    parts: list[str] = ['<div class="subsection">']
    parts.append('  <div class="subsection-title">Control Structure</div>')
    if control_structure.responsibilities:
        rows = _build_table_rows(
            [(r.resp_id, r.description) for r in control_structure.responsibilities],
            2,
        )
        parts.append(_build_data_table(["Responsibility", "Description"], rows))
    parts.append('</div>')
    return "\n".join(parts)


def _build_sp1_card(
    loss_analysis: Any | None,
    capability_profile: Any | None,
    control_structure: Any | None,
    raw_texts: dict[str, str] | None,
) -> str:
    """Build the SP1 flow card."""
    body_parts: list[str] = []

    if loss_analysis is not None:
        body_parts.append(_build_sp1_losses_section(loss_analysis))

    if capability_profile is not None:
        body_parts.append(_build_sp1_capability_section(capability_profile))

    if control_structure is not None:
        body_parts.append(_build_sp1_control_section(control_structure))

    body_parts.extend(_build_raw_yaml_sections(
        raw_texts,
        ("loss-analysis.yaml", "capability-profile.yaml", "control-structure.yaml"),
    ))

    body = "\n".join(body_parts)
    return (
        f'<details id="sp1" class="flow-card">\n'
        f'  <summary>SP1 — Loss Analysis & Control Structure</summary>\n'
        f'  <div class="flow-card-body">\n{body}\n  </div>\n'
        f'</details>'
    )


def _loss_to_dict(loss: Any) -> dict[str, str]:
    """Convert a loss model to a flat dict for rendering."""
    provenance = (
        loss.provenance.value if hasattr(loss.provenance, "value") else str(loss.provenance)
    )
    return {
        "id": loss.loss_id,
        "description": loss.description,
        "provenance": provenance,
    }


def _loss_analysis_losses(loss_analysis: Any) -> list[dict[str, str]]:
    """Extract all losses from a LossAnalysis as flat dicts."""
    result: list[dict[str, str]] = []
    for loss in getattr(loss_analysis, "risk_card_losses", []) or []:
        result.append(_loss_to_dict(loss))
    for loss in getattr(loss_analysis, "use_case_losses", []) or []:
        result.append(_loss_to_dict(loss))
    return result


def _build_sp2_ica_section(ica_enumeration: Any) -> str:
    """Build the ICA enumeration subsection of SP2."""
    parts: list[str] = ['<div class="subsection">']
    parts.append('  <div class="subsection-title">ICA Enumeration</div>')
    if ica_enumeration.slots:
        rows = "\n".join(
            f'      <tr><td>{_esc(s.slot_id)}</td><td>{_esc(s.uca_type.value if hasattr(s.uca_type, "value") else s.uca_type)}</td>'
            f'<td>{"N/A" if s.is_na else str(len(s.ics))}</td></tr>'
            for s in ica_enumeration.slots
        )
        parts.append(
            f'    <table class="data-table"><thead><tr><th>Slot ID</th><th>UCA Type</th><th>ICAs</th></tr></thead>\n'
            f'    <tbody>\n{rows}\n    </tbody></table>'
        )
    parts.append('</div>')
    return "\n".join(parts)


def _build_sp2_enrichment_section(enriched_threats: Any) -> str:
    """Build the catalog enrichment subsection of SP2."""
    parts: list[str] = ['<div class="subsection">']
    parts.append('  <div class="subsection-title">Catalog Enrichment</div>')
    if enriched_threats.structural_threats:
        rows: list[str] = []
        for t in enriched_threats.structural_threats:
            mappings = ", ".join(m.id for m in (t.catalog_mappings or []))
            rows.append(f'      <tr><td>{_esc(t.ica_slot_id)}</td><td>{_esc(mappings)}</td></tr>')
        parts.append(
            f'    <table class="data-table"><thead><tr><th>ICA Slot</th><th>Catalog Mappings</th></tr></thead>\n'
            f'    <tbody>\n{chr(10).join(rows)}\n    </tbody></table>'
        )
    parts.append('</div>')
    return "\n".join(parts)


def _build_sp2_coverage_section(enriched_threats: Any) -> str:
    """Build the coverage analysis subsection of SP2."""
    parts: list[str] = ['<div class="subsection">']
    parts.append('  <div class="subsection-title">Coverage Analysis</div>')
    cov = enriched_threats.coverage_analysis
    sc = getattr(cov, "structural_coverage", {}) or {}
    if isinstance(sc, dict):
        rate = sc.get("coverage_rate")
        if rate is not None:
            pct = f"{float(rate) * 100:.1f}%"
            parts.append(f'    <p class="coverage-rate">{_esc(pct)}</p>')
    parts.append('</div>')
    return "\n".join(parts)


def _build_sp2_card(
    ica_enumeration: Any | None,
    enriched_threats: Any | None,
    raw_texts: dict[str, str] | None,
) -> str:
    """Build the SP2 flow card."""
    body_parts: list[str] = []

    if ica_enumeration is not None:
        body_parts.append(_build_sp2_ica_section(ica_enumeration))

    if enriched_threats is not None:
        body_parts.append(_build_sp2_enrichment_section(enriched_threats))
        body_parts.append(_build_sp2_coverage_section(enriched_threats))

    body_parts.extend(_build_raw_yaml_sections(
        raw_texts,
        ("ica-enumeration.yaml", "enriched-threats.yaml"),
    ))

    body = "\n".join(body_parts)
    return (
        f'<details id="sp2" class="flow-card">\n'
        f'  <summary>SP2 — ICA Enumeration & Threat Enrichment</summary>\n'
        f'  <div class="flow-card-body">\n{body}\n  </div>\n'
        f'</details>'
    )


def _parse_tree_dict(tree_dict: dict) -> tuple[str, list, list]:
    """Extract root, branches, and leaves from a tree dict."""
    root = tree_dict.get("root", "")
    branches = tree_dict.get("branches") or []
    leaves = tree_dict.get("leaves") or []
    return root, branches, leaves


def _has_tree_content(root: str, branches: list, leaves: list) -> bool:
    """Check if a parsed tree has any non-empty content."""
    return bool(root or branches or leaves)


def _build_attack_tree_visual(tree_dict: dict | None) -> str:
    """Build a visual attack tree from nested dict structure.

    The tree dict has:
      - root: str (the root goal)
      - branches: list of {category, label, children: [...]}
      - leaves: list of str
    """
    if not tree_dict:
        return '<div class="tree-empty">No attack tree data available.</div>'

    root, branches, leaves = _parse_tree_dict(tree_dict)

    if not _has_tree_content(root, branches, leaves):
        return '<div class="tree-empty">No attack tree data available.</div>'

    parts: list[str] = ['<div class="attack-tree">']

    if root:
        parts.append(
            f'  <div class="attack-tree-node connector">'
            f'<span class="gate-badge gate-or">OR</span>'
            f'<span class="tree-node-label">{_esc(root)}</span></div>'
        )

    for branch in branches:
        parts.extend(_build_tree_branch_node(branch))

    for leaf in leaves:
        parts.append(
            f'  <div class="attack-tree-node connector">'
            f'<span class="gate-badge gate-leaf">LEAF</span>'
            f'<span class="tree-node-label">{_esc(leaf)}</span></div>'
        )

    parts.append('</div>')
    return "\n".join(parts)


def _build_tree_branch_node(branch: dict) -> list[str]:
    """Build HTML for a single branch node with its children."""
    category = branch.get("category", "")
    label = branch.get("label", "")
    cat_class = f"cat-{category}" if category else ""
    parts: list[str] = [
        f'  <div class="attack-tree-node connector {cat_class}" '
        f'data-category="{_esc(category)}">'
        f'<span class="gate-badge gate-and">AND</span>'
        f'<span class="tree-node-label">{_esc(label)}</span>'
    ]
    children = branch.get("children", []) or []
    for child in children:
        parts.extend(_render_tree_child(child))
    parts.append('  </div>')
    return parts


def _render_tree_child(child: dict, depth: int = 0) -> list[str]:
    """Recursively render a tree child node."""
    parts: list[str] = []
    label = child.get("label", "")
    details = child.get("details", "")
    children = child.get("children", []) or []

    if children:
        parts.append(
            f'  <div class="attack-tree-node connector">'
            f'<span class="tree-node-label">{_esc(label)}</span></div>'
        )
        for sub in children:
            parts.extend(_render_tree_child(sub, depth + 1))
    else:
        details_html = ""
        if details:
            details_html = f'<div class="tree-node-details">{_esc(details)}</div>'
        parts.append(
            f'  <div class="attack-tree-node connector">'
            f'<span class="gate-badge gate-leaf">LEAF</span>'
            f'<span class="tree-node-label">{_esc(label)}</span>'
            f'{details_html}</div>'
        )
    return parts


def _attr_list(obj: Any, name: str) -> list:
    """Get a list attribute from an object, defaulting to empty list."""
    return getattr(obj, name, []) or []


def _build_defender_bdi_block(defender: Any) -> str:
    """Build the defender BDI block HTML."""
    parts: list[str] = ['          <div class="bdi-block">']
    parts.append('            <h4>Defender BDI</h4>')
    for b in _attr_list(defender, "beliefs"):
        parts.append(f'            <div class="bdi-item"><strong>{_esc(b.pm_id)}</strong>: {_esc(b.content)}</div>')
        if hasattr(b, "vulnerability") and b.vulnerability:
            parts.append(f'            <div class="bdi-item-vuln">Vulnerability: {_esc(b.vulnerability)}</div>')
    for d in _attr_list(defender, "desires"):
        parts.append(f'            <div class="bdi-item"><strong>Desire</strong> ({_esc(d.resp_id)}): {_esc(d.content)}</div>')
    for i in _attr_list(defender, "intentions"):
        parts.append(f'            <div class="bdi-item"><strong>Intention</strong> ({_esc(i.ca_id)}): {_esc(i.content)}</div>')
    parts.append('          </div>')
    return "\n".join(parts)


def _build_attacker_bdi_block(attacker: Any) -> str:
    """Build the attacker BDI block HTML."""
    parts: list[str] = ['          <div class="bdi-block">']
    parts.append('            <h4>Attacker BDI</h4>')
    for b in _attr_list(attacker, "beliefs"):
        parts.append(f'            <div class="bdi-item"><strong>Belief</strong>: {_esc(b)}</div>')
    for d in _attr_list(attacker, "desires"):
        parts.append(f'            <div class="bdi-item"><strong>Desire</strong>: {_esc(d)}</div>')
    for i in _attr_list(attacker, "intentions"):
        parts.append(f'            <div class="bdi-item"><strong>Intention</strong>: {_esc(i)}</div>')
    parts.append('          </div>')
    return "\n".join(parts)


def _build_bdi_section(scenario_spec: Any) -> str:
    """Build the BDI section for a scenario."""
    parts: list[str] = ['      <div class="scenario-section">']
    parts.append('        <div class="scenario-section-title">BDI Models</div>')
    parts.append('        <div class="bdi-grid">')

    defender = getattr(scenario_spec, "defender_bdi", None)
    if defender:
        parts.append(_build_defender_bdi_block(defender))
    else:
        parts.append('          <div class="bdi-block"><h4>Defender BDI</h4><p class="bdi-item">No data</p></div>')

    attacker = getattr(scenario_spec, "attacker_bdi", None)
    if attacker:
        parts.append(_build_attacker_bdi_block(attacker))
    else:
        parts.append('          <div class="bdi-block"><h4>Attacker BDI</h4><p class="bdi-item">No data</p></div>')

    parts.append('        </div>')
    parts.append('      </div>')
    return "\n".join(parts)


def _build_scenario_card(
    scenario_id: str,
    envelope: Any | None,
    feature_text: str | None,
) -> str:
    """Build a collapsible scenario card."""
    body_parts: list[str] = []

    if envelope is not None:
        spec = getattr(envelope, "scenario_spec", None)

        # BDI section
        if spec is not None:
            body_parts.append(_build_bdi_section(spec))

        # Narrative section
        narrative = getattr(envelope, "narrative", "") or ""
        if narrative:
            body_parts.append('      <div class="scenario-section">')
            body_parts.append('        <div class="scenario-section-title">Narrative</div>')
            body_parts.append(f'        <div class="narrative-text">{_esc(narrative)}</div>')
            body_parts.append('      </div>')

        # Attack tree section
        attack_tree = getattr(envelope, "attack_tree", None)
        body_parts.append('      <div class="scenario-section">')
        body_parts.append('        <div class="scenario-section-title">Attack Tree</div>')
        body_parts.append(f'        {_build_attack_tree_visual(attack_tree)}')
        body_parts.append('      </div>')

    # Gherkin section
    if feature_text:
        highlighted = _highlight_gherkin(feature_text)
        body_parts.append('      <div class="scenario-section">')
        body_parts.append('        <div class="scenario-section-title">Gherkin Spec</div>')
        body_parts.append(f'        <div class="gherkin-block">{highlighted}</div>')
        body_parts.append('      </div>')

    body = "\n".join(body_parts)
    return (
        f'    <details class="scenario-card" data-scenario-id="{_esc(scenario_id)}">\n'
        f'      <summary><span>{_esc(scenario_id)}</span></summary>\n'
        f'      <div class="scenario-card-body">\n{body}\n      </div>\n'
        f'    </details>'
    )


def _rate_field_values(metric_data: dict) -> list:
    """Extract all ``*_rate`` field values from a metric dict."""
    return [v for k, v in metric_data.items() if k.endswith("_rate")]


def _safe_floats(values: list) -> list[float]:
    """Convert values to floats, dropping any that fail."""
    return [r for r in (_safe_float(v) for v in values) if r is not None]


def _average_rate_fields(metric_data: dict) -> float | None:
    """Average all ``*_rate`` fields in a metric dict."""
    rate_fields = _rate_field_values(metric_data)
    if not rate_fields:
        return None
    floats = _safe_floats(rate_fields)
    if not floats:
        return None
    return sum(floats) / len(floats)


def _extract_metric_rate(metric_data: dict) -> float | None:
    """Extract a single rate from a metric dict.

    Looks for 'rate' first, then averages all '*_rate' fields.
    """
    if not isinstance(metric_data, dict):
        return None
    if "rate" in metric_data:
        return _safe_float(metric_data["rate"])
    return _average_rate_fields(metric_data)


def _safe_float(val: Any) -> float | None:
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _gauge_color(rate: float) -> str:
    """Return the gauge color class for a rate."""
    if rate >= 0.8:
        return "green"
    if rate >= 0.6:
        return "yellow"
    return "red"


def _build_eval_gauge(metric_name: str, rate: float) -> str:
    """Build a colored gauge/bar for a single metric."""
    color = _gauge_color(rate)
    pct = rate * 100
    pct_str = f"{pct:.0f}%"
    return (
        f'  <div class="eval-gauge-row" data-metric="{_esc(metric_name)}">\n'
        f'    <div class="eval-gauge-name">{_esc(metric_name)}</div>\n'
        f'    <div class="eval-gauge-track"><div class="eval-gauge-fill {color}" style="width:{pct_str}"></div></div>\n'
        f'    <div class="eval-gauge-pct">{pct_str}</div>\n'
        f'    <span class="scorecard-badge scorecard-badge-{color}">{color.upper()}</span>\n'
        f'  </div>'
    )


def _build_eval_scorecard(eval_data: dict | None) -> str:
    """Build the eval scorecard section with gauges."""
    if not eval_data:
        return '<div class="tree-empty">No eval scorecard available.</div>'

    metrics = eval_data.get("metrics", eval_data)
    if not isinstance(metrics, dict):
        return '<div class="tree-empty">No eval scorecard available.</div>'

    parts: list[str] = ['<div class="subsection">']
    parts.append('  <div class="subsection-title">Eval Scorecard</div>')
    for name, data in metrics.items():
        rate = _extract_metric_rate(data)
        if rate is not None:
            parts.append(_build_eval_gauge(name, rate))
    parts.append('</div>')
    return "\n".join(parts)


def _build_sp3_card(
    scenarios: list[tuple[str, Any, str | None]],
    eval_data: dict | None,
    raw_texts: dict[str, str] | None,
) -> str:
    """Build the SP3 flow card with scenario list and eval scorecard.

    Args:
        scenarios: List of (scenario_id, envelope, feature_text) tuples.
        eval_data: Parsed eval-scorecard dict.
        raw_texts: Raw YAML texts for collapsible sections.
    """
    body_parts: list[str] = []

    # Scenario list
    body_parts.append('<div class="subsection">')
    body_parts.append(f'  <div class="subsection-title">Scenarios ({len(scenarios)})</div>')
    for scenario_id, envelope, feature_text in scenarios:
        body_parts.append(_build_scenario_card(scenario_id, envelope, feature_text))
    body_parts.append('</div>')

    # Eval scorecard
    body_parts.append(_build_eval_scorecard(eval_data))

    # Raw YAML for eval scorecard
    if raw_texts and "eval-scorecard.yaml" in raw_texts:
        body_parts.append(_build_raw_yaml_section("eval-scorecard.yaml", raw_texts["eval-scorecard.yaml"]))

    body = "\n".join(body_parts)
    return (
        f'<details id="sp3" class="flow-card">\n'
        f'  <summary>SP3 — Scenario Production & Evaluation</summary>\n'
        f'  <div class="flow-card-body">\n{body}\n  </div>\n'
        f'</details>'
    )


def _build_llm_call_inspector(calls: list[dict]) -> str:
    """Build the LLM call inspector section.

    Collapsible list of calls, no search. Each call expandable to show
    system prompt, user prompt, and response content.
    """
    total = len(calls)
    success = sum(1 for c in calls if c.get("success", True))
    failed = total - success

    parts: list[str] = ['<section id="calls" class="flow-card">']
    parts.append('  <summary>Calls</summary>')
    parts.append('  <div class="flow-card-body">')

    # Summary
    parts.append('    <div class="call-summary-bar">')
    parts.append(f'      <div class="call-summary-stat">Total: <strong>{total}</strong></div>')
    parts.append(f'      <div class="call-summary-stat">Successful: <strong>{success}</strong></div>')
    parts.append(f'      <div class="call-summary-stat">Failed: <strong>{failed}</strong></div>')
    parts.append('    </div>')

    # Call entries
    for i, entry in enumerate(calls):
        parts.append(_build_call_entry_html(entry, i))

    parts.append('  </div>')
    parts.append('</section>')
    return "\n".join(parts)


def _build_call_entry_html(entry: dict, index: int) -> str:
    """Build a single collapsible call entry."""
    success = entry.get("success", True)
    stage = entry.get("stage", "")
    step = entry.get("step", "")
    model = entry.get("model", "")
    prompt_tokens = entry.get("prompt_tokens", 0)
    completion_tokens = entry.get("completion_tokens", 0)
    duration_ms = entry.get("duration_ms", 0)

    css_class = "call-entry failed" if not success else "call-entry"
    indicator = (
        '<span class="call-fail-indicator">FAILED</span>'
        if not success
        else '<span class="call-success-indicator">OK</span>'
    )

    # Collapsible sections for prompts and response
    sections: list[str] = []
    for label, key in (
        ("system_prompt", "system_prompt_text"),
        ("user_prompt", "user_prompt_text"),
        ("response_content", "response_content"),
    ):
        content = entry.get(key, "")
        if content:
            sections.append(
                f'      <details class="raw-yaml"><summary>{_esc(label)}</summary>'
                f'<pre class="code-block">{_esc(content)}</pre></details>'
            )

    sections_html = "\n".join(sections)
    return (
        f'    <details class="{css_class}" data-call-index="{index}">\n'
        f'      <summary>'
        f'<span class="call-meta-stage">{_esc(stage)}/{_esc(step)}</span>'
        f'<span class="call-meta">model={_esc(model)}</span>'
        f'<span class="call-meta">tokens={prompt_tokens}+{completion_tokens}</span>'
        f'<span class="call-meta">duration={duration_ms}ms</span>'
        f'{indicator}'
        f'</summary>\n'
        f'      <div class="call-entry-body">\n{sections_html}\n      </div>\n'
        f'    </details>'
    )


def _build_manifest_grid(run_id: Any, created_at: Any, model_name: Any, max_workers: Any) -> str:
    """Build the manifest metadata grid."""
    return (
        '    <div class="manifest-grid">\n'
        f'      <div class="manifest-item"><div class="manifest-label">Run ID</div><div class="manifest-value">{_esc(str(run_id))}</div></div>\n'
        f'      <div class="manifest-item"><div class="manifest-label">Created At</div><div class="manifest-value">{_esc(str(created_at))}</div></div>\n'
        f'      <div class="manifest-item"><div class="manifest-label">Model</div><div class="manifest-value">{_esc(str(model_name))}</div></div>\n'
        f'      <div class="manifest-item"><div class="manifest-label">Max Workers</div><div class="manifest-value">{_esc(str(max_workers))}</div></div>\n'
        '    </div>'
    )


def _build_manifest_hashes_table(input_hashes: dict) -> str:
    """Build the input hashes table for the manifest section."""
    rows = "\n".join(
        f'        <tr><td>{_esc(str(name))}</td><td>{_esc(str(hash_val))}</td></tr>'
        for name, hash_val in input_hashes.items()
    )
    return (
        '    <div class="subsection">\n'
        '      <div class="subsection-title">Input Hashes</div>\n'
        '      <table class="data-table"><thead><tr><th>Artifact</th><th>Hash</th></tr></thead><tbody>\n'
        f'{rows}\n'
        '      </tbody></table>\n'
        '    </div>'
    )


def _resolve_model_name(manifest: dict) -> str:
    """Extract the model name from manifest model_config."""
    model_config = manifest.get("model_config", {}) or {}
    if isinstance(model_config, dict):
        return model_config.get("model", "N/A")
    return "N/A"


def _is_valid_hashes(input_hashes: Any) -> bool:
    """Check if input_hashes is a non-empty dict."""
    return bool(input_hashes and isinstance(input_hashes, dict))


def _build_run_manifest(
    manifest: dict | None,
    raw_texts: dict[str, str] | None,
) -> str:
    """Build the run manifest section."""
    if not manifest:
        return '<section id="manifest" class="flow-card"><summary>Manifest</summary><div class="flow-card-body"><div class="tree-empty">No run manifest available.</div></div></section>'

    run_id = manifest.get("run_id", "N/A")
    created_at = manifest.get("created_at", "N/A")
    model_name = _resolve_model_name(manifest)
    max_workers = manifest.get("max_workers", "N/A")
    input_hashes = manifest.get("input_hashes", {}) or {}

    parts: list[str] = ['<section id="manifest" class="flow-card">']
    parts.append('  <summary>Manifest</summary>')
    parts.append('  <div class="flow-card-body">')
    parts.append(_build_manifest_grid(run_id, created_at, model_name, max_workers))

    if _is_valid_hashes(input_hashes):
        parts.append(_build_manifest_hashes_table(input_hashes))

    if raw_texts and "run-manifest.yaml" in raw_texts:
        parts.append(_build_raw_yaml_section("run-manifest.yaml", raw_texts["run-manifest.yaml"]))

    parts.append('  </div>')
    parts.append('</section>')
    return "\n".join(parts)


def _build_produces_arrow() -> str:
    """Build a produces arrow between flow cards."""
    return '<div class="produces-arrow" data-arrow="produces">&darr; produces</div>'


# ---------------------------------------------------------------------------
# Top-level assembler
# ---------------------------------------------------------------------------


def build_html(
    *,
    run_id: str | None = None,
    created_at: str | None = None,
    scenario_count: int | None = None,
    eval_metrics: dict[str, float] | None = None,
    sp1_html: str = "",
    sp2_html: str = "",
    sp3_html: str = "",
    calls_html: str = "",
    manifest_html: str = "",
    has_sp2: bool = True,
    has_sp3: bool = True,
) -> str:
    """Assemble all sections into a single self-contained HTML document."""
    hero = _build_hero_summary(run_id, created_at, scenario_count, eval_metrics)
    nav = _build_sticky_nav()

    sections: list[str] = [hero]

    # SP1 card
    sections.append(sp1_html)

    # SP1 → SP2 arrow + SP2 card
    if has_sp2 and sp2_html:
        sections.append(_build_produces_arrow())
        sections.append(sp2_html)

    # SP2 → SP3 arrow + SP3 card
    if has_sp3 and sp3_html:
        sections.append(_build_produces_arrow())
        sections.append(sp3_html)

    # Calls
    if calls_html:
        sections.append(calls_html)

    # Manifest
    sections.append(manifest_html)

    body = "\n".join(sections)
    css = _build_css()
    js = _build_js()

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>STPA-Sec Report</title>\n"
        f"{css}\n"
        "</head>\n"
        "<body>\n"
        f'{nav}\n'
        f'<div class="container">\n'
        f'{body}\n'
        f'</div>\n'
        f'{js}\n'
        "</body>\n"
        "</html>\n"
    )
