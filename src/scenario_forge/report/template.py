"""HTML template components for the scenario-forge report.

CSS styles, JavaScript interactivity, and HTML section builders.
Each section builder is a function returning an HTML string.
"""

from __future__ import annotations

import html
import re
from typing import Any


# ---------------------------------------------------------------------------
# Zone colour palette
# ---------------------------------------------------------------------------

ZONE_COLORS: dict[int, str] = {
    1: "#3b82f6",  # blue
    2: "#8b5cf6",  # purple
    3: "#f97316",  # orange
    4: "#22c55e",  # green
    5: "#ef4444",  # red
}

ZONE_NAMES: dict[int, str] = {
    1: "Input Surfaces",
    2: "Planning & Reasoning",
    3: "Tool Execution",
    4: "Memory & State",
    5: "Inter-Agent Communication",
}

ZONE_BG_COLORS: dict[int, str] = {
    1: "#1e3a5f",
    2: "#3b1f6e",
    3: "#5c2d0e",
    4: "#0f3d1e",
    5: "#5c1111",
}

# ---------------------------------------------------------------------------
# OWASP Agentic Threat names (stable taxonomy v1.1)
# ---------------------------------------------------------------------------

THREAT_NAMES: dict[str, str] = {
    "T1": "Memory Poisoning",
    "T2": "Tool Misuse",
    "T3": "Privilege Compromise",
    "T4": "Resource Overload",
    "T5": "Cascading Hallucination Attacks",
    "T6": "Intent Breaking & Goal Manipulation",
    "T7": "Misaligned & Deceptive Behaviors",
    "T8": "Repudiation & Untraceability",
    "T9": "Identity Spoofing & Impersonation / Agent Identity Compromise",
    "T10": "Overwhelming Human in the Loop",
    "T11": "Unexpected RCE and Code Attacks",
    "T12": "Agent Communication Poisoning",
    "T13": "Rogue Agents in Multi-Agent Systems",
    "T14": "Human Attacks on Multi-Agent Systems",
    "T15": "Human Manipulation",
    "T16": "Insecure Inter-Agent Protocol Abuse",
    "T17": "Supply Chain Compromise",
}

# Tooltip strings for structural_exposure enum values
_STRUCTURAL_EXPOSURE_TOOLTIPS: dict[str, str] = {
    "single_point_of_failure": "Only one control blocks this attack path",
    "convergence_point": "Multiple attack paths flow through this single control",
    "probabilistic_control": (
        "Relies on an LLM guardrail or classifier "
        "— not a binary pass/fail gate"
    ),
    "defense_in_depth_claim": (
        "Multiple controls back each other up on this path"
    ),
}

# Tooltip strings for gate types
_GATE_TOOLTIPS: dict[str, str] = {
    "AND": "All child steps must succeed for this attack to proceed",
    "OR": "Any one child step is sufficient for this attack to proceed",
    "LEAF": "Concrete attack action — no sub-steps",
}

# Tooltip strings for priority signal fields
_SIGNAL_TOOLTIPS: dict[str, str] = {
    "technique_maturity": (
        "How proven this attack technique is: feasible (theoretically possible), "
        "demonstrated (shown in lab), realized (observed in the wild)"
    ),
    "architecture_match": (
        "How the threat maps to this system: explicit (directly matches a "
        "declared capability) or inferred (indirectly relevant based on "
        "system profile)"
    ),
    "attack_complexity": "Difficulty of executing this attack: low/medium/high",
    "risk_impact": "Potential damage if attack succeeds: low/medium/high/critical",
    "risk_likelihood": "Probability of this attack being attempted: low/medium/high",
    "structural_exposure": (
        "How exposed this attack path is based on the defensive architecture"
    ),
}


def _esc(text: str | None) -> str:
    """HTML-escape text safely."""
    if text is None:
        return ""
    return html.escape(str(text))


def _threat_id_tooltip(tid: str) -> str:
    """Return a data-tooltip attribute string for a threat ID like 'T7'."""
    # Extract base threat ID (e.g. T7 from T7-S1)
    base = tid.split("-")[0] if "-" in tid else tid
    name = THREAT_NAMES.get(base, "")
    if name:
        return f' data-tooltip="{_esc(base)} — {_esc(name)}"'
    return ""


def _sub_scenario_tooltip(sid: str) -> str:
    """Return a data-tooltip attribute for a sub-scenario ID like 'T2-S1'."""
    parts = sid.split("-")
    if len(parts) >= 2:
        base = parts[0]
        name = THREAT_NAMES.get(base, "")
        if name:
            return (
                f' data-tooltip="Sub-scenario seed: threat {_esc(base)}, '
                f'sub-scenario {_esc(parts[1])} '
                f'— expanded from OWASP agentic threat taxonomy"'
            )
    return ""


def _priority_color(composite: float) -> str:
    if composite >= 0.7:
        return "#ef4444"
    if composite >= 0.4:
        return "#f59e0b"
    return "#22c55e"


def _priority_label(composite: float) -> str:
    if composite >= 0.7:
        return "HIGH"
    if composite >= 0.4:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------


def build_css() -> str:
    return """
<style>
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
  --zone-1: #3b82f6;
  --zone-2: #8b5cf6;
  --zone-3: #f97316;
  --zone-4: #22c55e;
  --zone-5: #ef4444;
  --high: #ef4444;
  --medium: #f59e0b;
  --low: #22c55e;
  --sidebar-width: 260px;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html { scroll-behavior: smooth; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  line-height: 1.6;
  display: flex;
  min-height: 100vh;
}

/* Sidebar */
.sidebar {
  position: fixed;
  top: 0; left: 0;
  width: var(--sidebar-width);
  height: 100vh;
  background: var(--bg-secondary);
  border-right: 1px solid var(--border);
  padding: 24px 0;
  overflow-y: auto;
  z-index: 100;
  display: flex;
  flex-direction: column;
}

.sidebar-brand {
  padding: 0 20px 20px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 12px;
}

.sidebar-brand h1 {
  font-size: 16px;
  font-weight: 700;
  color: var(--accent);
  letter-spacing: 0.5px;
}

.sidebar-brand .subtitle {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 2px;
}

.sidebar nav { flex: 1; }

.sidebar a {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 20px;
  color: var(--text-secondary);
  text-decoration: none;
  font-size: 13px;
  font-weight: 500;
  transition: all 0.15s ease;
  border-left: 3px solid transparent;
}

.sidebar a:hover {
  background: var(--accent-glow);
  color: var(--text-primary);
  border-left-color: var(--accent);
}

.sidebar a .nav-icon {
  width: 18px;
  text-align: center;
  font-size: 14px;
}

/* Main content */
.main-content {
  margin-left: var(--sidebar-width);
  flex: 1;
  padding: 40px 48px;
  max-width: 1200px;
}

/* Section */
.section {
  margin-bottom: 56px;
}

.section-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 24px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
}

.section-header h2 {
  font-size: 22px;
  font-weight: 700;
  color: var(--text-primary);
}

.section-header .badge {
  background: var(--accent-glow);
  color: var(--accent);
  font-size: 11px;
  font-weight: 600;
  padding: 3px 10px;
  border-radius: 12px;
}

/* Cards */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 24px;
  margin-bottom: 20px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.2);
  transition: border-color 0.2s ease;
}

.card:hover { border-color: #3d4460; }

/* Zone diagram */
.zone-diagram {
  display: flex;
  gap: 16px;
  justify-content: center;
  padding: 32px 0;
  flex-wrap: wrap;
}

.zone-box {
  width: 160px;
  height: 110px;
  border-radius: 12px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 6px;
  font-weight: 600;
  font-size: 13px;
  text-align: center;
  border: 2px solid;
  transition: transform 0.2s ease;
}

.zone-box:hover { transform: translateY(-3px); }

.zone-box.active {
  box-shadow: 0 4px 20px rgba(0,0,0,0.3);
}

.zone-box.inactive {
  background: #1a1d2e !important;
  border-color: #2d3348 !important;
  color: #4b5563 !important;
  opacity: 0.5;
}

.zone-number {
  font-size: 24px;
  font-weight: 800;
}

/* Capability flags table */
.flags-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 16px;
}

.flags-table th {
  text-align: left;
  padding: 10px 16px;
  background: var(--bg-secondary);
  color: var(--text-secondary);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border-bottom: 1px solid var(--border);
}

.flags-table td {
  padding: 10px 16px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
}

.flag-true { color: var(--low); font-weight: 600; }
.flag-false { color: var(--text-muted); }

.entry-point-list {
  list-style: none;
  padding: 0;
  margin-top: 12px;
}

.entry-point-list li {
  padding: 8px 14px;
  background: var(--bg-secondary);
  border-radius: 6px;
  margin-bottom: 6px;
  font-size: 13px;
  border-left: 3px solid var(--accent);
}

/* Threat surface */
.view-toggle {
  display: flex;
  gap: 8px;
  margin-bottom: 20px;
}

.view-toggle button {
  padding: 8px 18px;
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 13px;
  font-weight: 500;
  transition: all 0.15s ease;
}

.view-toggle button.active {
  background: var(--accent);
  color: white;
  border-color: var(--accent);
}

.view-toggle button:hover:not(.active) {
  background: var(--bg-card-hover);
  color: var(--text-primary);
}

.view-panel { display: none; }
.view-panel.active { display: block; }

/* Risk card table */
.risk-table {
  width: 100%;
  border-collapse: collapse;
}

.risk-table th {
  text-align: left;
  padding: 10px 14px;
  background: var(--bg-secondary);
  color: var(--text-secondary);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 1;
}

.risk-table td {
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
  vertical-align: top;
}

.risk-table tr:hover td { background: var(--bg-card-hover); }

.status-badge {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}

.status-actionable { background: rgba(34,197,94,0.15); color: #22c55e; }
.status-governance { background: rgba(245,158,11,0.15); color: #f59e0b; }

/* Chain diagram */
.chain-diagram {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.chain-hop {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 8px;
  background: var(--bg-secondary);
  border-radius: 4px;
  font-size: 11px;
  font-weight: 500;
  color: var(--text-secondary);
}

.chain-arrow {
  color: var(--text-muted);
  font-size: 12px;
}

/* Sankey flow */
.sankey-container {
  position: relative;
  overflow-x: auto;
  padding: 20px 0;
}

.sankey-svg {
  width: 100%;
  min-height: 300px;
}

.sankey-node {
  cursor: default;
}

.sankey-node rect {
  rx: 4;
  ry: 4;
}

.sankey-node text {
  fill: var(--text-primary);
  font-size: 11px;
  font-weight: 500;
}

.sankey-link {
  fill: none;
  stroke-opacity: 0.2;
  transition: stroke-opacity 0.2s;
}

.sankey-link:hover {
  stroke-opacity: 0.5;
}

/* Scenarios */
.scenario-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  margin-bottom: 24px;
  overflow: hidden;
  box-shadow: 0 2px 8px rgba(0,0,0,0.2);
}

.scenario-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 18px 24px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-secondary);
  flex-wrap: wrap;
  gap: 10px;
}

.scenario-header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.scenario-id {
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 13px;
  color: var(--accent);
  font-weight: 600;
}

.scenario-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--text-primary);
}

.priority-badge {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.scenario-body { padding: 24px; }

.scenario-section {
  margin-bottom: 24px;
}

.scenario-section:last-child { margin-bottom: 0; }

.scenario-section-title {
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.scenario-summary {
  font-size: 14px;
  line-height: 1.7;
  color: var(--text-secondary);
}

/* Zone breadcrumb */
.zone-breadcrumb {
  display: flex;
  align-items: center;
  gap: 4px;
  flex-wrap: wrap;
  margin-top: 10px;
}

.zone-crumb {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border-radius: 8px;
  font-size: 13px;
  font-weight: 700;
  color: white;
}

.zone-crumb-arrow {
  color: var(--text-muted);
  font-size: 14px;
  margin: 0 2px;
}

/* Attack tree */
.attack-tree { font-size: 13px; }

.attack-tree details {
  margin-left: 20px;
  border-left: 2px solid var(--border);
  padding-left: 16px;
  margin-bottom: 4px;
}

.attack-tree details > summary {
  cursor: pointer;
  padding: 8px 12px;
  border-radius: 6px;
  background: var(--bg-secondary);
  margin-bottom: 4px;
  list-style: none;
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  transition: background 0.15s ease;
}

.attack-tree details > summary:hover { background: var(--bg-card-hover); }

.attack-tree details > summary::-webkit-details-marker { display: none; }
.attack-tree details > summary::marker { display: none; content: ''; }

.attack-tree details > summary::before {
  content: '\\25B6';
  font-size: 9px;
  color: var(--text-muted);
  transition: transform 0.2s ease;
}

.attack-tree details[open] > summary::before {
  transform: rotate(90deg);
}

.tree-leaf {
  margin-left: 20px;
  border-left: 2px solid var(--border);
  padding: 8px 12px 8px 16px;
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  font-size: 13px;
  margin-bottom: 4px;
}

.gate-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 28px;
  height: 22px;
  padding: 0 6px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  font-family: 'SF Mono', 'Fira Code', monospace;
}

.gate-and { background: rgba(139,92,246,0.2); color: #a78bfa; }
.gate-or { background: rgba(59,130,246,0.2); color: #60a5fa; }
.gate-leaf { background: rgba(107,114,128,0.2); color: #9ca3af; }

.zone-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 22px;
  height: 22px;
  padding: 0 6px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 700;
  color: white;
}

.tree-label { color: var(--text-primary); }

.tree-meta {
  font-size: 11px;
  color: var(--text-muted);
  font-family: 'SF Mono', 'Fira Code', monospace;
}

/* Behavior spec */
.feature-spec { font-size: 13px; }

.feature-step {
  padding: 10px 14px;
  border-radius: 6px;
  margin-bottom: 6px;
  display: flex;
  align-items: flex-start;
  gap: 10px;
  flex-wrap: wrap;
}

.step-keyword {
  font-weight: 700;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.3px;
  min-width: 60px;
  flex-shrink: 0;
}

.step-text {
  color: var(--text-primary);
  flex: 1;
  min-width: 200px;
}

.step-given { background: rgba(59,130,246,0.08); border-left: 3px solid #3b82f6; }
.step-given .step-keyword { color: #3b82f6; }

.step-when { background: rgba(139,92,246,0.08); border-left: 3px solid #8b5cf6; }
.step-when .step-keyword { color: #8b5cf6; }

.step-and { background: rgba(139,92,246,0.05); border-left: 3px solid #6366f1; }
.step-and .step-keyword { color: #6366f1; }

.step-then { background: rgba(34,197,94,0.08); border-left: 3px solid #22c55e; }
.step-then .step-keyword { color: #22c55e; }

.step-but { background: rgba(239,68,68,0.08); border-left: 3px solid #ef4444; }
.step-but .step-keyword { color: #ef4444; }

.step-star { background: rgba(245,158,11,0.08); border-left: 3px solid #f59e0b; }
.step-star .step-keyword { color: #f59e0b; }

.step-docstring {
  margin: 4px 0 4px 70px;
  padding: 10px 14px;
  background: var(--bg-primary);
  border-radius: 6px;
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 11px;
  color: var(--text-muted);
  white-space: pre-wrap;
  word-break: break-word;
  border: 1px solid var(--border);
  max-height: 200px;
  overflow-y: auto;
}

/* Priority signals */
.signals-panel {
  margin-top: 8px;
}

.signals-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 10px;
}

.signal-item {
  padding: 10px 14px;
  background: var(--bg-secondary);
  border-radius: 6px;
  border: 1px solid var(--border);
}

.signal-label {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  margin-bottom: 4px;
}

.signal-value {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}

/* Heatmap */
.heatmap-grid {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  margin-bottom: 24px;
}

.heatmap-cell {
  width: 48px;
  height: 48px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  font-weight: 700;
  color: white;
  cursor: default;
  position: relative;
  transition: transform 0.15s ease;
}

.heatmap-cell:hover {
  transform: scale(1.1);
}

.heatmap-cell .tooltip {
  display: none;
  position: absolute;
  bottom: 100%;
  left: 50%;
  transform: translateX(-50%);
  background: var(--bg-primary);
  border: 1px solid var(--border);
  padding: 6px 10px;
  border-radius: 6px;
  white-space: nowrap;
  font-size: 11px;
  font-weight: 500;
  color: var(--text-primary);
  z-index: 10;
  margin-bottom: 6px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
}

.heatmap-cell:hover .tooltip { display: block; }

/* Filter controls */
.filter-bar {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 20px;
  padding: 16px;
  background: var(--bg-secondary);
  border-radius: 8px;
  border: 1px solid var(--border);
  align-items: center;
}

.filter-group {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.filter-label {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
}

.filter-select, .filter-input {
  padding: 6px 10px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-primary);
  font-size: 12px;
  min-width: 140px;
}

.filter-select:focus, .filter-input:focus {
  outline: none;
  border-color: var(--accent);
}

.filter-btn {
  padding: 6px 14px;
  background: var(--accent);
  color: white;
  border: none;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  align-self: flex-end;
  transition: opacity 0.15s ease;
}

.filter-btn:hover { opacity: 0.85; }

/* Raw data */
.raw-tabs {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}

.raw-tab {
  padding: 6px 14px;
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 12px;
  font-weight: 500;
  transition: all 0.15s ease;
}

.raw-tab.active {
  background: var(--accent);
  color: white;
  border-color: var(--accent);
}

.raw-tab:hover:not(.active) {
  background: var(--bg-card-hover);
  color: var(--text-primary);
}

.raw-panel {
  display: none;
  position: relative;
}

.raw-panel.active { display: block; }

.copy-btn {
  position: absolute;
  top: 10px;
  right: 10px;
  padding: 5px 12px;
  background: var(--bg-card-hover);
  border: 1px solid var(--border);
  border-radius: 4px;
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 11px;
  font-weight: 500;
  z-index: 2;
  transition: all 0.15s ease;
}

.copy-btn:hover {
  background: var(--accent);
  color: white;
}

.code-block {
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  overflow-x: auto;
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 600px;
  overflow-y: auto;
}

/* Syntax highlighting for YAML */
.yaml-key { color: #60a5fa; }
.yaml-string { color: #a78bfa; }
.yaml-number { color: #f59e0b; }
.yaml-bool { color: #22c55e; }
.yaml-null { color: #6b7280; font-style: italic; }
.yaml-comment { color: #4b5563; font-style: italic; }

/* Gherkin highlighting */
.gherkin-keyword { color: #60a5fa; font-weight: 700; }
.gherkin-tag { color: #f59e0b; }
.gherkin-string { color: #a78bfa; }
.gherkin-comment { color: #4b5563; font-style: italic; }

/* Details/summary for priority signals */
details.expandable > summary {
  cursor: pointer;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  list-style: none;
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 0;
}

details.expandable > summary::-webkit-details-marker { display: none; }
details.expandable > summary::marker { display: none; content: ''; }

details.expandable > summary::before {
  content: '\\25B6';
  font-size: 8px;
  transition: transform 0.2s ease;
}

details.expandable[open] > summary::before {
  transform: rotate(90deg);
}

/* Scenario count badge */
.count-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 24px;
  height: 24px;
  padding: 0 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 700;
  background: var(--accent);
  color: white;
}

/* Score bar */
.score-bar-container {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 4px;
}

.score-bar-track {
  flex: 1;
  height: 6px;
  background: var(--bg-primary);
  border-radius: 3px;
  overflow: hidden;
  max-width: 120px;
}

.score-bar-fill {
  height: 100%;
  border-radius: 3px;
  transition: width 0.3s ease;
}

.score-bar-label {
  font-size: 12px;
  font-weight: 700;
  font-family: 'SF Mono', 'Fira Code', monospace;
  min-width: 36px;
}

/* Coverage section */
.coverage-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 16px;
}

.coverage-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.2);
}

.coverage-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}

.coverage-card-title {
  font-size: 13px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
}

.coverage-status {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
}

.coverage-status-green { background: rgba(34,197,94,0.15); color: #22c55e; }
.coverage-status-amber { background: rgba(245,158,11,0.15); color: #f59e0b; }
.coverage-status-red { background: rgba(239,68,68,0.15); color: #ef4444; }

.coverage-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.coverage-list li {
  padding: 6px 12px;
  background: var(--bg-secondary);
  border-radius: 6px;
  margin-bottom: 4px;
  font-size: 13px;
  border-left: 3px solid var(--high);
  color: var(--text-secondary);
}

.coverage-empty {
  padding: 12px;
  text-align: center;
  color: var(--text-muted);
  font-size: 13px;
  font-style: italic;
}

/* Diversity section */
.diversity-bar-chart {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-top: 12px;
}

.diversity-bar-row {
  display: flex;
  align-items: center;
  gap: 10px;
}

.diversity-bar-label {
  min-width: 130px;
  font-size: 12px;
  font-weight: 500;
  color: var(--text-secondary);
  text-transform: capitalize;
}

.diversity-bar-track {
  flex: 1;
  height: 20px;
  background: var(--bg-primary);
  border-radius: 4px;
  overflow: hidden;
}

.diversity-bar-fill {
  height: 100%;
  border-radius: 4px;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  padding-right: 6px;
  font-size: 11px;
  font-weight: 700;
  color: white;
  min-width: 24px;
}

.diversity-bar-count {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-muted);
  min-width: 24px;
  text-align: right;
}

.warning-banner {
  background: rgba(245,158,11,0.1);
  border: 1px solid rgba(245,158,11,0.3);
  border-radius: 8px;
  padding: 14px 18px;
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 13px;
  color: #f59e0b;
}

.warning-banner-icon {
  font-size: 18px;
  flex-shrink: 0;
}

/* Entry point distribution */
.ep-dist-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 8px;
  margin-top: 12px;
}

.ep-dist-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 12px;
  background: var(--bg-secondary);
  border-radius: 6px;
  border: 1px solid var(--border);
  font-size: 12px;
}

.ep-dist-name {
  color: var(--text-secondary);
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  margin-right: 8px;
}

.ep-dist-count {
  font-weight: 700;
  color: var(--accent);
  font-family: 'SF Mono', 'Fira Code', monospace;
}

/* Legend row */
.legend {
  display: flex;
  gap: 16px;
  align-items: center;
  margin-top: 8px;
  font-size: 11px;
  color: var(--text-muted);
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 4px;
}

.legend-dot {
  width: 10px;
  height: 10px;
  border-radius: 3px;
}

/* CSS tooltips (replace unreliable native title= tooltips) */
[data-tooltip] {
  position: relative;
  cursor: help;
}
[data-tooltip]::after {
  content: attr(data-tooltip);
  position: absolute;
  bottom: 100%;
  left: 50%;
  transform: translateX(-50%);
  padding: 6px 10px;
  background: #1a1a2e;
  color: #e0e0e0;
  border: 1px solid #333;
  border-radius: 4px;
  font-size: 0.8rem;
  max-width: 400px;
  white-space: normal;
  z-index: 1000;
  pointer-events: none;
  opacity: 0;
  transition: opacity 0.15s;
  margin-bottom: 4px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
}
[data-tooltip]:hover::after {
  opacity: 1;
}
.tree-meta[data-tooltip]::after {
  left: 0;
  transform: none;
}
</style>
"""


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------


def build_js() -> str:
    return """
<script>
// View toggle
function toggleView(viewId, btn) {
  document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.view-toggle button').forEach(b => b.classList.remove('active'));
  document.getElementById(viewId).classList.add('active');
  btn.classList.add('active');
}

// Raw data tabs
function switchRawTab(tabId, btn) {
  document.querySelectorAll('.raw-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.raw-tab').forEach(t => t.classList.remove('active'));
  document.getElementById(tabId).classList.add('active');
  btn.classList.add('active');
}

// Copy to clipboard
function copyToClipboard(elementId) {
  const el = document.getElementById(elementId);
  const text = el.innerText || el.textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

// Scenario filtering
function filterScenarios() {
  const threatFilter = document.getElementById('filter-threat').value.toLowerCase();
  const zoneFilter = document.getElementById('filter-zone').value;
  const priorityFilter = document.getElementById('filter-priority').value;

  document.querySelectorAll('.scenario-card[data-scenario]').forEach(card => {
    let show = true;

    if (threatFilter && !card.dataset.threats.toLowerCase().includes(threatFilter)) {
      show = false;
    }
    if (zoneFilter && !card.dataset.zones.includes(zoneFilter)) {
      show = false;
    }
    if (priorityFilter && card.dataset.priority !== priorityFilter) {
      show = false;
    }

    card.style.display = show ? '' : 'none';
  });

  // Update visible count
  const visible = document.querySelectorAll('.scenario-card[data-scenario]:not([style*="display: none"])').length;
  const total = document.querySelectorAll('.scenario-card[data-scenario]').length;
  const counter = document.getElementById('scenario-counter');
  if (counter) counter.textContent = visible + ' / ' + total;
}

function resetFilters() {
  document.getElementById('filter-threat').value = '';
  document.getElementById('filter-zone').value = '';
  document.getElementById('filter-priority').value = '';
  filterScenarios();
}
</script>
"""


# ---------------------------------------------------------------------------
# Section 1: Capability Profile
# ---------------------------------------------------------------------------


def build_capability_profile_section(profile: dict[str, Any]) -> str:
    zones_active = set(profile.get("zones_active", []))

    # Zone diagram
    zone_boxes = []
    for z in range(1, 6):
        active = z in zones_active
        cls = "active" if active else "inactive"
        color = ZONE_COLORS[z]
        bg = ZONE_BG_COLORS[z] if active else ""
        style = f"background:{bg};border-color:{color};color:{color};" if active else ""
        zone_boxes.append(
            f'<div class="zone-box {cls}" style="{style}">'
            f'<span class="zone-number">{z}</span>'
            f"<span>{_esc(ZONE_NAMES[z])}</span>"
            f"</div>"
        )

    # Flags table
    flags = [
        ("Persistent Memory", profile.get("has_persistent_memory", False), ""),
        ("Multi-Agent", profile.get("multi_agent", False), ""),
        ("Human-in-the-Loop", profile.get("hitl", False), ""),
        (
            "Confidence",
            profile.get("confidence", "unknown"),
            "Profile inference confidence — how clearly the use-case description signals these capabilities",
        ),
    ]
    flag_rows = ""
    for name, value, tip in flags:
        tip_attr = f' data-tooltip="{_esc(tip)}"' if tip else ""
        if isinstance(value, bool):
            cls = "flag-true" if value else "flag-false"
            display = "Yes" if value else "No"
        else:
            cls = ""
            display = _esc(str(value).capitalize())
        flag_rows += f'<tr><td{tip_attr}>{_esc(name)}</td><td class="{cls}">{display}</td></tr>'

    # Entry points
    eps = profile.get("entry_points", [])
    ep_items = "".join(f"<li>{_esc(ep)}</li>" for ep in eps)

    return f"""
    <div id="sec-profile" class="section">
      <div class="section-header">
        <h2>Capability Profile</h2>
        <span class="badge">Schneider 5-Zone</span>
      </div>

      <div class="card">
        <div class="zone-diagram">
          {"".join(zone_boxes)}
        </div>
        <div class="legend" style="justify-content:center;">
          <span class="legend-item"><span class="legend-dot" style="background:var(--accent);"></span> Active zone</span>
          <span class="legend-item"><span class="legend-dot" style="background:#2d3348;"></span> Inactive zone</span>
        </div>
      </div>

      <div class="card">
        <table class="flags-table">
          <thead><tr><th>Capability Flag</th><th>Value</th></tr></thead>
          <tbody>{flag_rows}</tbody>
        </table>
      </div>

      <div class="card">
        <div class="scenario-section-title">Entry Points</div>
        <ul class="entry-point-list">{ep_items}</ul>
      </div>
    </div>
    """


# ---------------------------------------------------------------------------
# Section 2: Threat Surface
# ---------------------------------------------------------------------------


def build_threat_surface_section(threat_surface: dict[str, Any]) -> str:
    entries = threat_surface.get("entries", [])
    governance = threat_surface.get("governance_only", [])
    all_entries = entries + governance

    # Option A: Table
    table_rows = ""
    for entry in all_entries:
        rc = entry.get("risk_card", {})
        gov = entry.get("governance_only", False)
        status_cls = "status-governance" if gov else "status-actionable"
        status_text = "Governance" if gov else "Actionable"
        status_tip = (
            "Governance: maps to organizational controls, not directly testable"
            if gov
            else "Actionable: maps to testable agentic threat scenarios"
        )

        # Build LLM IDs with tooltips
        raw_llm = entry.get("owasp_llm_ids", [])
        if raw_llm:
            llm_spans = ", ".join(
                f'<span data-tooltip="OWASP Top 10 for LLM Applications '
                f'— standardized LLM vulnerability category">{_esc(lid)}</span>'
                for lid in raw_llm
            )
        else:
            llm_spans = "-"

        # Build agentic threat IDs with tooltips
        raw_tids = entry.get("agentic_threat_ids", [])
        if raw_tids:
            tid_spans = ", ".join(
                f"<span{_threat_id_tooltip(tid)}>{_esc(tid)}</span>"
                for tid in raw_tids
            )
        else:
            tid_spans = "-"

        # Build sub-scenario IDs with tooltips
        raw_subs = entry.get("sub_scenarios", [])
        if raw_subs:
            sub_spans = ", ".join(
                f"<span{_sub_scenario_tooltip(sid)}>{_esc(sid)}</span>"
                for sid in raw_subs
            )
        else:
            sub_spans = "-"

        # Risk ID tooltip for atlas-* IDs
        risk_id = rc.get("risk_id", "")
        risk_id_tip = ""
        if risk_id.startswith("atlas-"):
            risk_id_tip = ' data-tooltip="IBM AI Risk Atlas — standardized AI risk identifier"'

        # Chain diagram for actionable entries
        chain_html = ""
        if not gov and entry.get("owasp_llm_ids"):
            llm_ids_plain = ", ".join(raw_llm)
            t_ids_plain = ", ".join(raw_tids)
            chain_html = (
                '<div class="chain-diagram">'
                f'<span class="chain-hop"{risk_id_tip}>{_esc(risk_id)}</span>'
                '<span class="chain-arrow">&rarr;</span>'
                f'<span class="chain-hop">{_esc(llm_ids_plain)}</span>'
                '<span class="chain-arrow">&rarr;</span>'
                f'<span class="chain-hop">{_esc(t_ids_plain)}</span>'
                "</div>"
            )

        conf = rc.get("confidence", 0)
        conf_display = f"{conf:.2f}" if isinstance(conf, (int, float)) else str(conf)

        table_rows += f"""
        <tr>
          <td{risk_id_tip}>{_esc(risk_id)}</td>
          <td>{_esc(rc.get("risk_name", ""))}</td>
          <td><span class="status-badge {status_cls}" data-tooltip="{_esc(status_tip)}">{status_text}</span></td>
          <td data-tooltip="Upstream extraction confidence — how strongly the policy text maps to this risk">{conf_display}</td>
          <td>{llm_spans}</td>
          <td>{tid_spans}</td>
          <td>{sub_spans}</td>
          <td>{chain_html}</td>
        </tr>"""

    # Option B: Sankey-style SVG
    sankey_svg = _build_sankey_svg(entries)

    return f"""
    <div id="sec-threats" class="section">
      <div class="section-header">
        <h2>Threat Surface</h2>
        <span class="badge">{len(entries)} actionable / {len(governance)} governance</span>
      </div>

      <div class="view-toggle">
        <button class="active" onclick="toggleView('view-table', this)">Table View</button>
        <button onclick="toggleView('view-sankey', this)">Flow Diagram</button>
      </div>

      <div id="view-table" class="view-panel active">
        <div class="card" style="overflow-x:auto;">
          <table class="risk-table">
            <thead>
              <tr>
                <th>Risk ID</th>
                <th>Risk Name</th>
                <th>Status</th>
                <th>Confidence</th>
                <th>LLM Top 10</th>
                <th>Agentic Threats</th>
                <th>Sub-Scenarios</th>
                <th>Chain</th>
              </tr>
            </thead>
            <tbody>{table_rows}</tbody>
          </table>
        </div>
      </div>

      <div id="view-sankey" class="view-panel">
        <div class="card">
          <div class="sankey-container">{sankey_svg}</div>
        </div>
      </div>
    </div>
    """


def _build_sankey_svg(entries: list[dict[str, Any]]) -> str:
    """Build a pure SVG Sankey-style flow diagram."""
    if not entries:
        return '<p style="color:var(--text-muted);text-align:center;padding:40px;">No actionable entries to visualize.</p>'

    # Collect unique nodes for each column
    risk_ids: list[str] = []
    llm_ids_set: list[str] = []
    threat_ids_set: list[str] = []
    scenario_ids_set: list[str] = []

    for e in entries:
        rc = e.get("risk_card", {})
        rid = rc.get("risk_id", "")
        if rid and rid not in risk_ids:
            risk_ids.append(rid)
        for lid in e.get("owasp_llm_ids", []):
            if lid and lid not in llm_ids_set:
                llm_ids_set.append(lid)
        for tid in e.get("agentic_threat_ids", []):
            if tid and tid not in threat_ids_set:
                threat_ids_set.append(tid)
        for sid in e.get("sub_scenarios", []):
            if sid and sid not in scenario_ids_set:
                scenario_ids_set.append(sid)

    # Layout constants
    col_x = [40, 240, 440, 640]
    node_w = 140
    node_h = 30
    node_gap = 8
    top_pad = 50
    colors = ["#3b82f6", "#8b5cf6", "#f97316", "#ef4444"]
    label_names = ["Risk Atlas", "LLM Top 10", "Agentic Threats", "Sub-Scenarios"]

    columns = [risk_ids, llm_ids_set, threat_ids_set, scenario_ids_set]

    # Calculate total height
    max_nodes = max(len(c) for c in columns) if columns else 1
    svg_h = max(top_pad + max_nodes * (node_h + node_gap) + 40, 200)

    # Center each column vertically
    def node_y(col_idx: int, item_idx: int) -> float:
        col = columns[col_idx]
        total_h = len(col) * node_h + (len(col) - 1) * node_gap
        start_y = top_pad + (svg_h - top_pad - 20 - total_h) / 2
        return start_y + item_idx * (node_h + node_gap)

    # Build node positions
    node_pos: dict[str, tuple[float, float, float, float]] = {}
    svg_nodes = ""

    for ci, col in enumerate(columns):
        for ni, name in enumerate(col):
            x = col_x[ci]
            y = node_y(ci, ni)
            node_pos[f"{ci}:{name}"] = (x, y, x + node_w, y + node_h)

            truncated = name if len(name) <= 20 else name[:17] + "..."
            svg_nodes += f"""
            <g class="sankey-node">
              <rect x="{x}" y="{y}" width="{node_w}" height="{node_h}"
                    fill="{colors[ci]}" opacity="0.8"/>
              <text x="{x + node_w / 2}" y="{y + node_h / 2 + 4}"
                    text-anchor="middle" font-size="10" fill="white" font-weight="600">
                {_esc(truncated)}
              </text>
            </g>"""

    # Build links
    svg_links = ""
    link_colors = ["#3b82f6", "#8b5cf6", "#f97316"]

    for e in entries:
        rc = e.get("risk_card", {})
        rid = rc.get("risk_id", "")

        # Risk -> LLM
        for lid in e.get("owasp_llm_ids", []):
            svg_links += _sankey_link(node_pos, f"0:{rid}", f"1:{lid}", link_colors[0])

        # LLM -> Threat
        for lid in e.get("owasp_llm_ids", []):
            for tid in e.get("agentic_threat_ids", []):
                svg_links += _sankey_link(
                    node_pos, f"1:{lid}", f"2:{tid}", link_colors[1]
                )

        # Threat -> Scenario
        for tid in e.get("agentic_threat_ids", []):
            for sid in e.get("sub_scenarios", []):
                svg_links += _sankey_link(
                    node_pos, f"2:{tid}", f"3:{sid}", link_colors[2]
                )

    # Column headers
    svg_headers = ""
    for ci, label in enumerate(label_names):
        svg_headers += f"""
        <text x="{col_x[ci] + node_w / 2}" y="30" text-anchor="middle"
              fill="var(--text-muted)" font-size="11" font-weight="600"
              text-transform="uppercase" letter-spacing="0.5">{_esc(label)}</text>"""

    return f"""
    <svg class="sankey-svg" viewBox="0 0 820 {svg_h}" xmlns="http://www.w3.org/2000/svg">
      {svg_headers}
      {svg_links}
      {svg_nodes}
    </svg>
    """


def _sankey_link(
    node_pos: dict[str, tuple[float, float, float, float]],
    from_key: str,
    to_key: str,
    color: str,
) -> str:
    if from_key not in node_pos or to_key not in node_pos:
        return ""
    x1, y1, x1r, y1b = node_pos[from_key]
    x2, y2, x2r, y2b = node_pos[to_key]
    sx = x1r
    sy = (y1 + y1b) / 2
    ex = x2
    ey = (y2 + y2b) / 2
    cp1 = (sx + ex) / 2
    return (
        f'<path class="sankey-link" d="M{sx},{sy} C{cp1},{sy} {cp1},{ey} {ex},{ey}"'
        f' stroke="{color}" stroke-width="2"/>'
    )


# ---------------------------------------------------------------------------
# Section 2b: Coverage Gaps
# ---------------------------------------------------------------------------


def _coverage_status(count: int) -> tuple[str, str]:
    """Return (css_class, label) based on the number of uncovered items."""
    if count == 0:
        return "coverage-status-green", "Covered"
    if count <= 2:
        return "coverage-status-amber", f"{count} gap{'s' if count != 1 else ''}"
    return "coverage-status-red", f"{count} gaps"


def build_coverage_section(coverage_data: dict[str, Any]) -> str:
    """Build the Coverage Gaps section from loaded coverage-gaps.json data.

    Args:
        coverage_data: Parsed JSON from ``coverage-gaps.json``.

    Returns:
        HTML string for the coverage gaps section.
    """
    gaps = coverage_data.get("coverage_gaps", {})
    uncovered_eps = gaps.get("uncovered_entry_points", [])
    uncovered_zones = gaps.get("uncovered_zones", [])
    uncovered_threats = gaps.get("uncovered_threats", [])

    total_gaps = len(uncovered_eps) + len(uncovered_zones) + len(uncovered_threats)

    # Entry points card
    ep_cls, ep_label = _coverage_status(len(uncovered_eps))
    if uncovered_eps:
        ep_items = "".join(f"<li>{_esc(ep)}</li>" for ep in uncovered_eps)
        ep_body = f'<ul class="coverage-list">{ep_items}</ul>'
    else:
        ep_body = (
            '<div class="coverage-empty">All entry points have scenario coverage.</div>'
        )

    # Zones card
    z_cls, z_label = _coverage_status(len(uncovered_zones))
    if uncovered_zones:
        z_items = "".join(
            f"<li>Zone {z} &mdash; {_esc(ZONE_NAMES.get(z, 'Unknown'))}</li>"
            for z in uncovered_zones
        )
        z_body = f'<ul class="coverage-list">{z_items}</ul>'
    else:
        z_body = '<div class="coverage-empty">All active zones are traversed by scenarios.</div>'

    # Threats card
    t_cls, t_label = _coverage_status(len(uncovered_threats))
    if uncovered_threats:
        t_items = "".join(f"<li>{_esc(t)}</li>" for t in uncovered_threats)
        t_body = f'<ul class="coverage-list">{t_items}</ul>'
    else:
        t_body = '<div class="coverage-empty">All in-scope threats have scenario coverage.</div>'

    # Overall status badge
    if total_gaps == 0:
        badge_text = "Full Coverage"
    else:
        badge_text = f"{total_gaps} gap{'s' if total_gaps != 1 else ''}"

    return f"""
    <div id="sec-coverage" class="section">
      <div class="section-header">
        <h2>Coverage Analysis</h2>
        <span class="badge">{badge_text}</span>
      </div>

      <div class="coverage-grid">
        <div class="coverage-card">
          <div class="coverage-card-header">
            <span class="coverage-card-title">Entry Points</span>
            <span class="coverage-status {ep_cls}">{ep_label}</span>
          </div>
          {ep_body}
        </div>

        <div class="coverage-card">
          <div class="coverage-card-header">
            <span class="coverage-card-title">Active Zones</span>
            <span class="coverage-status {z_cls}">{z_label}</span>
          </div>
          {z_body}
        </div>

        <div class="coverage-card">
          <div class="coverage-card-header">
            <span class="coverage-card-title">In-Scope Threats</span>
            <span class="coverage-status {t_cls}">{t_label}</span>
          </div>
          {t_body}
        </div>
      </div>
    </div>
    """


# ---------------------------------------------------------------------------
# Section 2c: Actor Profile Distribution
# ---------------------------------------------------------------------------

_DIVERSITY_COLORS: dict[str, str] = {
    "cybercriminal": "#ef4444",        # red
    "nation-state": "#1e40af",         # dark blue
    "malicious-insider": "#f97316",    # orange
    "negligent-insider": "#f59e0b",    # amber/yellow
    "competitor": "#8b5cf6",           # purple
    "hacktivist": "#22c55e",           # green
    "supply-chain-actor": "#14b8a6",   # teal
    "adversarial-user": "#ec4899",     # pink/rose
    "automated-agent": "#6b7280",      # gray
    "unknown": "#4b5563",             # dark gray
}


def build_attacker_diversity_section(scenarios: list[dict[str, Any]]) -> str:
    """Build the Actor Profile Distribution section from scenario data.

    Computes actor type distribution directly from the loaded scenario dicts
    rather than relying on pre-computed data in ``coverage-gaps.json``.

    Args:
        scenarios: List of parsed scenario envelope dicts (from YAML files).

    Returns:
        HTML string for the actor profile distribution section, or empty string
        if no scenarios are provided.
    """
    if not scenarios:
        return ""

    # Count actor types directly from scenario dicts
    model_counts: dict[str, int] = {}
    for s in scenarios:
        actor_profile = s.get("actor_profile")
        if actor_profile and isinstance(actor_profile, dict):
            actor_type = actor_profile.get("actor_type", "unknown")
        else:
            actor_type = "unknown"
        model_counts[actor_type] = model_counts.get(actor_type, 0) + 1

    total = sum(model_counts.values()) if model_counts else 1

    # Compute dominant type and monotone flag (>80% threshold)
    dominant_model = max(model_counts, key=model_counts.get)  # type: ignore[arg-type]
    dominant_count = model_counts[dominant_model]
    dominant_fraction = dominant_count / total
    is_flagged = dominant_fraction > 0.8

    # Warning banner if monotone
    warning_html = ""
    if is_flagged:
        dominant_display = dominant_model.replace("-", " ").replace("_", " ").title()
        pct = int(dominant_fraction * 100)
        warning_html = (
            '<div class="warning-banner">'
            '<span class="warning-banner-icon">&#9888;</span>'
            f"<span>Low actor diversity: {pct}% of scenarios use the "
            f"<strong>{_esc(dominant_display)}</strong> actor type. "
            f"Consider varying threat actor types for broader coverage.</span>"
            "</div>"
        )

    # Bar chart
    bars_html = ""
    for model, count in sorted(model_counts.items(), key=lambda x: x[1], reverse=True):
        pct = (count / total * 100) if total > 0 else 0
        color = _DIVERSITY_COLORS.get(model, "#6b7280")
        display_name = model.replace("-", " ").replace("_", " ").title()
        bars_html += f"""
        <div class="diversity-bar-row">
          <span class="diversity-bar-label">{_esc(display_name)}</span>
          <div class="diversity-bar-track">
            <div class="diversity-bar-fill" style="width:{pct:.0f}%;background:{color};">
              {count}
            </div>
          </div>
          <span class="diversity-bar-count">{pct:.0f}%</span>
        </div>"""

    unique_types = len(model_counts)

    return f"""
    <div id="sec-diversity" class="section">
      <div class="section-header">
        <h2>Actor Profile Distribution</h2>
        <span class="badge">{unique_types} type{"s" if unique_types != 1 else ""}</span>
      </div>

      {warning_html}

      <div class="card">
        <div class="diversity-bar-chart">{bars_html}</div>
      </div>
    </div>
    """


# ---------------------------------------------------------------------------
# Section 3: Scenarios
# ---------------------------------------------------------------------------


def build_scenarios_section(
    scenarios: list[dict[str, Any]],
    feature_files: dict[str, str],
) -> str:
    if not scenarios:
        return '<div id="sec-scenarios" class="section"><div class="section-header"><h2>Scenarios</h2></div><p style="color:var(--text-muted);">No scenarios generated.</p></div>'

    # Heatmap
    heatmap_cells = ""
    for s in scenarios:
        sid = s.get("scenario_id", "")
        composite = s.get("priority", {}).get("composite", 0)
        color = _priority_color(composite)
        title = s.get("narrative", {}).get("title", sid)
        short_id = sid.split("-")[-1][:6] if "-" in sid else sid[:6]
        heatmap_cells += (
            f'<div class="heatmap-cell" style="background:{color};">'
            f'<span class="tooltip">{_esc(title)} ({composite:.2f})</span>'
            f"{_esc(short_id)}"
            f"</div>"
        )

    # Entry point distribution
    ep_counts: dict[str, int] = {}
    for s in scenarios:
        ep = s.get("narrative", {}).get("entry_point", "")
        if ep:
            ep_counts[ep] = ep_counts.get(ep, 0) + 1

    ep_dist_items = ""
    for ep_name, ep_count in sorted(
        ep_counts.items(), key=lambda x: x[1], reverse=True
    ):
        ep_dist_items += (
            f'<div class="ep-dist-item">'
            f'<span class="ep-dist-name" data-tooltip="{_esc(ep_name)}">{_esc(ep_name)}</span>'
            f'<span class="ep-dist-count">{ep_count}</span>'
            f"</div>"
        )

    ep_dist_html = ""
    if ep_counts:
        ep_dist_html = f"""
      <div class="card" style="margin-bottom:24px;">
        <div class="scenario-section-title">Entry Point Distribution</div>
        <div class="ep-dist-grid">{ep_dist_items}</div>
      </div>"""

    # Collect all threat IDs and zones for filters
    all_threat_ids: list[str] = []
    all_zones: set[int] = set()
    for s in scenarios:
        fac = s.get("faceting", {})
        tc = fac.get("taxonomy_chain", {})
        for tid in tc.get("agentic_threat_ids", []):
            if tid not in all_threat_ids:
                all_threat_ids.append(tid)
        cp = fac.get("capability_profile", {})
        for z in cp.get("zones_traversed", []):
            all_zones.add(z)

    threat_options = '<option value="">All</option>'
    for tid in sorted(all_threat_ids):
        tname = THREAT_NAMES.get(tid, "")
        opt_label = f"{tid} — {tname}" if tname else tid
        threat_options += f'<option value="{_esc(tid)}">{_esc(opt_label)}</option>'

    zone_options = '<option value="">All</option>'
    for z in sorted(all_zones):
        zone_options += (
            f'<option value="{z}">Zone {z} - {_esc(ZONE_NAMES.get(z, ""))}</option>'
        )

    # Scenario cards
    cards_html = ""
    for s in scenarios:
        cards_html += _build_scenario_card(s, feature_files)

    return f"""
    <div id="sec-scenarios" class="section">
      <div class="section-header">
        <h2>Scenarios</h2>
        <span class="badge" id="scenario-counter">{len(scenarios)} / {len(scenarios)}</span>
      </div>

      <div class="scenario-section-title" data-tooltip="Composite score combines technique maturity, architecture match, attack complexity, risk impact, and risk likelihood into a single 0-1 score">Composite Score Heatmap</div>
      <div class="heatmap-grid">{heatmap_cells}</div>
      <div class="legend">
        <span class="legend-item"><span class="legend-dot" style="background:var(--high);"></span> High (&ge;0.7)</span>
        <span class="legend-item"><span class="legend-dot" style="background:var(--medium);"></span> Medium (0.4-0.7)</span>
        <span class="legend-item"><span class="legend-dot" style="background:var(--low);"></span> Low (&lt;0.4)</span>
        <span class="legend-item" style="margin-left:8px;font-style:italic;">Composite score combines technique maturity, architecture match, attack complexity, risk impact, and risk likelihood into a 0&ndash;1 score.</span>
      </div>

      {ep_dist_html}

      <div class="filter-bar" style="margin-top:24px;">
        <div class="filter-group">
          <span class="filter-label">Threat ID</span>
          <select id="filter-threat" class="filter-select" onchange="filterScenarios()">
            {threat_options}
          </select>
        </div>
        <div class="filter-group">
          <span class="filter-label">Zone Traversed</span>
          <select id="filter-zone" class="filter-select" onchange="filterScenarios()">
            {zone_options}
          </select>
        </div>
        <div class="filter-group">
          <span class="filter-label">Priority Level</span>
          <select id="filter-priority" class="filter-select" onchange="filterScenarios()">
            <option value="">All</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <button class="filter-btn" onclick="resetFilters()">Reset</button>
      </div>

      {cards_html}
    </div>
    """


_CAPABILITY_COLORS: dict[str, str] = {
    "novice": "#22c55e",       # green
    "intermediate": "#3b82f6", # blue
    "advanced": "#f97316",     # orange
    "expert": "#ef4444",       # red
}


def _build_actor_profile_block(scenario: dict[str, Any]) -> str:
    """Build a collapsible Actor Profile block for a scenario card.

    Returns an empty string when the scenario has no ``actor_profile``.
    """
    actor_profile = scenario.get("actor_profile")
    if not actor_profile:
        return ""

    actor_type = actor_profile.get("actor_type", "unknown")
    motivation = actor_profile.get("motivation", "")
    objective = actor_profile.get("objective", "")
    capability_level = actor_profile.get("capability_level", "")
    resources = actor_profile.get("resources", [])
    campaign_context = actor_profile.get("campaign_context", "")

    type_color = _DIVERSITY_COLORS.get(actor_type, "#6b7280")
    type_display = actor_type.replace("-", " ").replace("_", " ").title()

    cap_color = _CAPABILITY_COLORS.get(capability_level, "#6b7280")
    cap_display = capability_level.title() if capability_level else ""

    resources_str = ", ".join(resources) if resources else "None specified"

    return f"""
        <div class="scenario-section">
          <details class="expandable" open>
            <summary>Actor Profile</summary>
            <div style="padding:12px 0 4px;">
              <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px;">
                <span style="display:inline-block;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:600;background:rgba({_hex_to_rgb_css(type_color)},0.15);color:{type_color};">{_esc(type_display)}</span>
                {f'<span style="display:inline-block;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:600;background:rgba({_hex_to_rgb_css(cap_color)},0.15);color:{cap_color};">{_esc(cap_display)}</span>' if cap_display else ''}
              </div>
              <div style="font-size:13px;color:var(--text-secondary);line-height:1.6;">
                <div style="margin-bottom:8px;">
                  <strong style="color:var(--text-muted);font-size:11px;">MOTIVATION:</strong>
                  <span>{_esc(motivation)}</span>
                </div>
                <div style="margin-bottom:8px;">
                  <strong style="color:var(--text-muted);font-size:11px;">OBJECTIVE:</strong>
                  <span>{_esc(objective)}</span>
                </div>
                <div style="margin-bottom:8px;">
                  <strong style="color:var(--text-muted);font-size:11px;">RESOURCES:</strong>
                  <span>{_esc(resources_str)}</span>
                </div>
                <div>
                  <strong style="color:var(--text-muted);font-size:11px;">CAMPAIGN CONTEXT:</strong>
                  <span>{_esc(campaign_context)}</span>
                </div>
              </div>
            </div>
          </details>
        </div>"""


def _build_scenario_card(
    scenario: dict[str, Any], feature_files: dict[str, str]
) -> str:
    sid = scenario.get("scenario_id", "")
    narrative = scenario.get("narrative", {})
    title = narrative.get("title", "")
    summary = narrative.get("summary", "")
    entry_point = narrative.get("entry_point", "")
    zone_sequence = narrative.get("zone_sequence", [])
    composite = scenario.get("priority", {}).get("composite", 0)
    priority_label = _priority_label(composite)
    priority_color = _priority_color(composite)

    # Data attributes for filtering
    faceting = scenario.get("faceting", {})
    tc = faceting.get("taxonomy_chain", {})
    threats = ",".join(tc.get("agentic_threat_ids", []))
    cp = faceting.get("capability_profile", {})
    zones = ",".join(str(z) for z in cp.get("zones_traversed", []))

    # Zone breadcrumb
    breadcrumb = ""
    for i, z in enumerate(zone_sequence):
        color = ZONE_COLORS.get(z, "#666")
        bg = ZONE_BG_COLORS.get(z, "#333")
        breadcrumb += f'<span class="zone-crumb" style="background:{bg};color:{color};">{z}</span>'
        if i < len(zone_sequence) - 1:
            breadcrumb += '<span class="zone-crumb-arrow">&rarr;</span>'

    # Attack tree
    attack_tree_data = scenario.get("attack_tree", {})
    root = attack_tree_data.get("root")
    attack_tree_html = _build_attack_tree_node(root) if root else ""
    tree_goal = attack_tree_data.get("goal", "")

    # Behavior spec from feature file
    feature_content = feature_files.get(sid, "")
    behavior_html = _build_behavior_spec(feature_content)

    # Priority signals
    signals = scenario.get("priority", {}).get("signals", {})
    signals_html = _build_priority_signals(signals)

    return f"""
    <div class="scenario-card" data-scenario="{_esc(sid)}"
         data-threats="{_esc(threats)}" data-zones="{_esc(zones)}"
         data-priority="{_esc(priority_label.lower())}">
      <div class="scenario-header">
        <div class="scenario-header-left">
          <span class="scenario-id">{_esc(sid)}</span>
          <span class="scenario-title">{_esc(title)}</span>
        </div>
        <div style="display:flex;align-items:center;gap:10px;">
          <div class="score-bar-container">
            <div class="score-bar-track">
              <div class="score-bar-fill" style="width:{composite * 100:.0f}%;background:{priority_color};"></div>
            </div>
            <span class="score-bar-label" style="color:{priority_color};">{composite:.2f}</span>
          </div>
          <span class="priority-badge" style="background:rgba({_hex_to_rgb_css(priority_color)},0.15);color:{priority_color};">
            {priority_label}
          </span>
        </div>
      </div>
      <div class="scenario-body">
        {_build_actor_profile_block(scenario)}

        <div class="scenario-section">
          <div class="scenario-section-title">Narrative</div>
          <p class="scenario-summary">{_esc(summary)}</p>
          <div style="margin-top:12px;font-size:13px;color:var(--text-secondary);">
            <strong style="color:var(--text-muted);font-size:11px;">ENTRY POINT:</strong> {_esc(entry_point)}
          </div>
          <div style="margin-top:8px;">
            <strong style="color:var(--text-muted);font-size:11px;">ZONE SEQUENCE:</strong>
            <div class="zone-breadcrumb">{breadcrumb}</div>
          </div>
        </div>

        <div class="scenario-section">
          <div class="scenario-section-title">Attack Tree</div>
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:10px;font-style:italic;">
            Goal: {_esc(tree_goal)}
          </div>
          <div class="attack-tree">{attack_tree_html}</div>
        </div>

        <div class="scenario-section">
          <div class="scenario-section-title">Behavior Specification</div>
          <div class="feature-spec">{behavior_html}</div>
        </div>

        <div class="scenario-section">
          <details class="expandable">
            <summary>Priority Signals</summary>
            {signals_html}
          </details>
        </div>
      </div>
    </div>
    """


def _hex_to_rgb_css(hex_color: str) -> str:
    """Convert #rrggbb to 'r,g,b' for rgba."""
    h = hex_color.lstrip("#")
    return f"{int(h[0:2], 16)},{int(h[2:4], 16)},{int(h[4:6], 16)}"


def _build_attack_tree_node(node: dict[str, Any] | None) -> str:
    if node is None:
        return ""

    gate = node.get("gate", "LEAF")
    zone = node.get("zone", 1)
    label = node.get("label", "")
    children = node.get("children") or []
    threat_id = node.get("threat_id")
    technique_id = node.get("technique_id")
    control_point = node.get("control_point")
    structural_exposure = node.get("structural_exposure")

    gate_cls = {"AND": "gate-and", "OR": "gate-or", "LEAF": "gate-leaf"}.get(
        gate, "gate-leaf"
    )
    gate_symbol = {"AND": "&and;", "OR": "&or;", "LEAF": "&bull;"}.get(gate, "&bull;")
    gate_tip = _GATE_TOOLTIPS.get(gate, "")
    gate_title = f' data-tooltip="{_esc(gate_tip)}"' if gate_tip else ""
    zone_color = ZONE_COLORS.get(zone, "#666")
    zone_bg = ZONE_BG_COLORS.get(zone, "#333")

    meta_parts = []
    if threat_id:
        meta_parts.append(
            f'<span class="tree-meta"{_threat_id_tooltip(threat_id)}>'
            f"{_esc(threat_id)}</span>"
        )
    if technique_id:
        tech_tip = ""
        if technique_id.startswith("AML.T"):
            tech_tip = (
                ' data-tooltip="MITRE ATLAS — Adversarial Threat Landscape '
                'for AI Systems technique"'
            )
        meta_parts.append(
            f'<span class="tree-meta"{tech_tip}>{_esc(technique_id)}</span>'
        )
    if control_point:
        meta_parts.append(
            f'<span class="tree-meta" style="color:var(--medium);" '
            f'data-tooltip="Defensive control that should block or detect this '
            f'attack step">{_esc(control_point)}</span>'
        )
    if structural_exposure:
        se_str = str(structural_exposure)
        se_display = se_str.replace("_", " ").title()
        se_tip = _STRUCTURAL_EXPOSURE_TOOLTIPS.get(se_str, "Structural exposure")
        meta_parts.append(
            f'<span class="tree-meta" style="color:var(--high);" '
            f'data-tooltip="{_esc(se_tip)}">{_esc(se_display)}</span>'
        )
    meta_html = " ".join(meta_parts)

    if gate == "LEAF" or not children:
        return f"""
        <div class="tree-leaf">
          <span class="gate-badge {gate_cls}"{gate_title}>{gate_symbol}</span>
          <span class="zone-badge" style="background:{zone_bg};color:{zone_color};">Z{zone}</span>
          <span class="tree-label">{_esc(label)}</span>
          {meta_html}
        </div>"""

    children_html = "".join(_build_attack_tree_node(c) for c in children)
    return f"""
    <details open>
      <summary>
        <span class="gate-badge {gate_cls}"{gate_title}>{gate_symbol}</span>
        <span class="zone-badge" style="background:{zone_bg};color:{zone_color};">Z{zone}</span>
        <span class="tree-label">{_esc(label)}</span>
        {meta_html}
      </summary>
      {children_html}
    </details>"""


def _build_behavior_spec(feature_content: str) -> str:
    if not feature_content:
        return '<p style="color:var(--text-muted);">No behavior specification available.</p>'

    lines = feature_content.strip().split("\n")
    result = []
    in_docstring = False
    docstring_lines: list[str] = []

    for line in lines:
        stripped = line.strip()

        # Handle docstrings (triple-quoted blocks)
        if stripped.startswith('"""') and not in_docstring:
            in_docstring = True
            docstring_lines = [stripped[3:]]
            continue
        if in_docstring:
            if stripped.endswith('"""'):
                docstring_lines.append(stripped[:-3])
                ds_text = "\n".join(docstring_lines).strip()
                result.append(f'<div class="step-docstring">{_esc(ds_text)}</div>')
                in_docstring = False
                docstring_lines = []
            else:
                docstring_lines.append(stripped)
            continue

        # Skip @id lines and empty lines
        if stripped.startswith("@") or not stripped:
            if stripped.startswith("@"):
                pass  # skip tags
            continue

        # Parse Gherkin keywords
        keyword = None
        text = stripped
        step_class = ""

        for kw, cls in [
            ("Feature:", ""),
            ("Background:", ""),
            ("Scenario:", ""),
            ("Given ", "step-given"),
            ("When ", "step-when"),
            ("And ", "step-and"),
            ("Then ", "step-then"),
            ("But ", "step-but"),
            ("* ", "step-star"),
        ]:
            if stripped.startswith(kw):
                keyword = kw.strip().rstrip(":")
                text = stripped[len(kw) :]
                step_class = cls
                break

        if not keyword:
            # Continuation or description line
            if stripped and not stripped.startswith("#"):
                result.append(
                    f'<div style="padding:4px 14px 4px 70px;font-size:13px;color:var(--text-secondary);">{_esc(stripped)}</div>'
                )
            continue

        # Feature/Background/Scenario headers
        if keyword in ("Feature", "Background", "Scenario"):
            result.append(
                f'<div style="padding:10px 0 6px;font-size:14px;font-weight:700;color:var(--text-primary);">'
                f'<span style="color:var(--accent);">{_esc(keyword)}:</span> {_esc(text)}</div>'
            )
            continue

        # Extract zone badge from text
        zone_badge = ""
        zone_match = re.search(r"\(.*?[Zz]one\s*(\d).*?\)", text)
        if zone_match:
            z = int(zone_match.group(1))
            if 1 <= z <= 5:
                zc = ZONE_COLORS.get(z, "#666")
                zbg = ZONE_BG_COLORS.get(z, "#333")
                zone_badge = f'<span class="zone-badge" style="background:{zbg};color:{zc};margin-left:6px;">Z{z}</span>'

        result.append(
            f'<div class="feature-step {step_class}">'
            f'<span class="step-keyword">{_esc(keyword)}</span>'
            f'<span class="step-text">{_esc(text)}{zone_badge}</span>'
            f"</div>"
        )

    return "\n".join(result)


def _build_priority_signals(signals: dict[str, Any]) -> str:
    if not signals:
        return ""

    display_map = {
        "technique_maturity": "Technique Maturity",
        "risk_impact": "Risk Impact",
        "risk_likelihood": "Risk Likelihood",
        "attack_complexity": "Attack Complexity",
        "architecture_match": "Architecture Match",
        "structural_exposure": "Structural Exposure",
    }

    items = ""
    for key, label in display_map.items():
        value = signals.get(key, "-")
        if isinstance(value, str):
            display = value.replace("_", " ").title()
        else:
            display = str(value)
        tip = _SIGNAL_TOOLTIPS.get(key, "")
        tip_attr = f' data-tooltip="{_esc(tip)}"' if tip else ""
        items += f"""
        <div class="signal-item"{tip_attr}>
          <div class="signal-label">{_esc(label)}</div>
          <div class="signal-value">{_esc(display)}</div>
        </div>"""

    return f'<div class="signals-grid">{items}</div>'


# ---------------------------------------------------------------------------
# Section 4: Raw Data
# ---------------------------------------------------------------------------


def build_raw_data_section(raw_files: dict[str, str]) -> str:
    if not raw_files:
        return ""

    tabs_html = ""
    panels_html = ""

    for i, (filename, content) in enumerate(raw_files.items()):
        active = " active" if i == 0 else ""
        tab_id = f"raw-{i}"

        tabs_html += f'<button class="raw-tab{active}" onclick="switchRawTab(\'{tab_id}\', this)">{_esc(filename)}</button>'

        if filename.endswith(".yaml") or filename.endswith(".yml"):
            highlighted = _highlight_yaml(content)
        elif filename.endswith(".feature"):
            highlighted = _highlight_gherkin(content)
        else:
            highlighted = _esc(content)

        panels_html += f"""
        <div id="{tab_id}" class="raw-panel{active}">
          <button class="copy-btn" onclick="copyToClipboard('{tab_id}-code')">Copy</button>
          <div class="code-block" id="{tab_id}-code">{highlighted}</div>
        </div>"""

    return f"""
    <div id="sec-raw" class="section">
      <div class="section-header">
        <h2>Raw Data</h2>
        <span class="badge">{len(raw_files)} files</span>
      </div>
      <div class="raw-tabs">{tabs_html}</div>
      {panels_html}
    </div>
    """


def _highlight_yaml(text: str) -> str:
    """Simple regex-based YAML syntax highlighting."""
    lines = text.split("\n")
    result = []
    for line in lines:
        escaped = _esc(line)

        # Comments
        if escaped.strip().startswith("#"):
            result.append(f'<span class="yaml-comment">{escaped}</span>')
            continue

        # Key-value pairs
        m = re.match(r"^(\s*)([\w_-]+)(\s*:\s*)(.*)", escaped)
        if m:
            indent, key, colon, value = m.groups()
            highlighted_value = _highlight_yaml_value(value)
            result.append(
                f'{indent}<span class="yaml-key">{key}</span>{colon}{highlighted_value}'
            )
            continue

        # List items
        m = re.match(r"^(\s*-\s+)(.*)", escaped)
        if m:
            prefix, value = m.groups()
            highlighted_value = _highlight_yaml_value(value)
            result.append(f"{prefix}{highlighted_value}")
            continue

        result.append(escaped)

    return "\n".join(result)


def _highlight_yaml_value(value: str) -> str:
    v = value.strip()
    if not v or v == "":
        return value
    if v in ("null", "~"):
        return f'<span class="yaml-null">{value}</span>'
    if v in ("true", "false"):
        return f'<span class="yaml-bool">{value}</span>'
    if re.match(r"^-?\d+(\.\d+)?$", v):
        return f'<span class="yaml-number">{value}</span>'
    if (v.startswith("'") and v.endswith("'")) or (
        v.startswith('"') and v.endswith('"')
    ):
        return f'<span class="yaml-string">{value}</span>'
    return value


def _highlight_gherkin(text: str) -> str:
    """Simple regex-based Gherkin syntax highlighting."""
    lines = text.split("\n")
    result = []
    for line in lines:
        escaped = _esc(line)

        if escaped.strip().startswith("#"):
            result.append(f'<span class="gherkin-comment">{escaped}</span>')
            continue

        if escaped.strip().startswith("@"):
            result.append(f'<span class="gherkin-tag">{escaped}</span>')
            continue

        for kw in [
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
        ]:
            ekw = _esc(kw)
            if escaped.strip().startswith(ekw):
                idx = escaped.index(ekw)
                escaped = (
                    escaped[:idx]
                    + f'<span class="gherkin-keyword">{ekw}</span>'
                    + escaped[idx + len(ekw) :]
                )
                break

        # Highlight triple-quoted strings
        if "&quot;&quot;&quot;" in escaped:
            escaped = escaped.replace(
                "&quot;&quot;&quot;",
                '<span class="gherkin-string">&quot;&quot;&quot;</span>',
            )

        result.append(escaped)

    return "\n".join(result)


# ---------------------------------------------------------------------------
# Section 5: Glossary appendix
# ---------------------------------------------------------------------------


def build_glossary_section() -> str:
    """Build the Glossary & Methodology appendix section."""
    # Build threat ID rows
    threat_rows = ""
    for tid, tname in THREAT_NAMES.items():
        threat_rows += (
            f"<tr><td><code>{_esc(tid)}</code></td>"
            f"<td>{_esc(tname)}</td></tr>"
        )

    return """
    <div id="glossary" class="section">
      <div class="section-header">
        <h2>Glossary &amp; Methodology</h2>
      </div>

      <!-- Terms glossary -->
      <div class="card">
        <div class="scenario-section-title">Threat IDs (OWASP Agentic Threats)</div>
        <table class="flags-table">
          <thead><tr><th>ID</th><th>Name</th></tr></thead>
          <tbody>""" + threat_rows + """</tbody>
        </table>
      </div>

      <div class="card">
        <div class="scenario-section-title">Taxonomy References</div>
        <table class="flags-table">
          <thead><tr><th>Prefix / Pattern</th><th>Description</th></tr></thead>
          <tbody>
            <tr>
              <td><code>LLM01</code>&ndash;<code>LLM10</code></td>
              <td>OWASP Top 10 for LLM Applications &mdash; standardized LLM vulnerability categories</td>
            </tr>
            <tr>
              <td><code>AML.T*</code></td>
              <td>MITRE ATLAS &mdash; Adversarial Threat Landscape for AI Systems technique identifier</td>
            </tr>
            <tr>
              <td><code>atlas-*</code></td>
              <td>IBM AI Risk Atlas &mdash; standardized AI risk identifier</td>
            </tr>
            <tr>
              <td><code>T&lt;n&gt;-S&lt;m&gt;</code></td>
              <td>Sub-scenario seed &mdash; threat T&lt;n&gt;, sub-scenario m, expanded from the OWASP agentic threat taxonomy</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="scenario-section-title">Status Badges</div>
        <table class="flags-table">
          <thead><tr><th>Badge</th><th>Meaning</th></tr></thead>
          <tbody>
            <tr>
              <td><span class="status-badge status-actionable">Actionable</span></td>
              <td>Maps to testable agentic threat scenarios</td>
            </tr>
            <tr>
              <td><span class="status-badge status-governance">Governance</span></td>
              <td>Maps to organizational controls, not directly testable</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="scenario-section-title">Attack Tree Fields</div>
        <table class="flags-table">
          <thead><tr><th>Field / Value</th><th>Meaning</th></tr></thead>
          <tbody>
            <tr><td><strong>Gate: AND</strong></td><td>All child steps must succeed for this attack to proceed</td></tr>
            <tr><td><strong>Gate: OR</strong></td><td>Any one child step is sufficient for this attack to proceed</td></tr>
            <tr><td><strong>Gate: LEAF</strong></td><td>Concrete attack action &mdash; no sub-steps</td></tr>
            <tr><td><strong>control_point</strong></td><td>Defensive control that should block or detect this attack step</td></tr>
            <tr><td><strong>single_point_of_failure</strong></td><td>Only one control blocks this attack path</td></tr>
            <tr><td><strong>convergence_point</strong></td><td>Multiple attack paths flow through this single control</td></tr>
            <tr><td><strong>probabilistic_control</strong></td><td>Relies on an LLM guardrail or classifier &mdash; not a binary pass/fail gate</td></tr>
            <tr><td><strong>defense_in_depth_claim</strong></td><td>Multiple controls back each other up on this path</td></tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="scenario-section-title">Priority Signals</div>
        <table class="flags-table">
          <thead><tr><th>Signal</th><th>Description</th></tr></thead>
          <tbody>
            <tr><td><strong>technique_maturity</strong></td><td>How proven this attack technique is: <em>feasible</em> (theoretically possible), <em>demonstrated</em> (shown in lab), <em>realized</em> (observed in the wild)</td></tr>
            <tr><td><strong>architecture_match</strong></td><td>How the threat maps to this system: <em>explicit</em> (directly matches a declared capability) or <em>inferred</em> (indirectly relevant based on system profile)</td></tr>
            <tr><td><strong>attack_complexity</strong></td><td>Difficulty of executing this attack: low / medium / high</td></tr>
            <tr><td><strong>risk_impact</strong></td><td>Potential damage if attack succeeds: low / medium / high / critical</td></tr>
            <tr><td><strong>risk_likelihood</strong></td><td>Probability of this attack being attempted: low / medium / high</td></tr>
            <tr><td><strong>composite_score</strong></td><td>Combines the above signals into a single 0&ndash;1 score for prioritization</td></tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="scenario-section-title">Confidence Values</div>
        <table class="flags-table">
          <thead><tr><th>Context</th><th>Meaning</th></tr></thead>
          <tbody>
            <tr><td>Threat Surface table</td><td>Upstream extraction confidence &mdash; how strongly the policy text maps to this risk</td></tr>
            <tr><td>Capability Profile</td><td>Profile inference confidence &mdash; how clearly the use-case description signals these capabilities</td></tr>
          </tbody>
        </table>
      </div>

      <!-- Methodology -->
      <div class="card">
        <div class="scenario-section-title">Methodology Overview</div>

        <div style="margin-bottom:18px;">
          <strong style="color:var(--text-primary);">Schneider 5-Zone Model</strong>
          <p style="font-size:13px;color:var(--text-secondary);margin-top:4px;">
            A capability decomposition framework that maps an AI agent&rsquo;s attack surface into five functional zones:
          </p>
          <ul style="font-size:13px;color:var(--text-secondary);margin:6px 0 0 20px;list-style:disc;">
            <li><strong>Zone 1 &mdash; Input Surfaces:</strong> External interfaces where user or system input enters the agent</li>
            <li><strong>Zone 2 &mdash; Planning &amp; Reasoning:</strong> The agent&rsquo;s decision-making and reasoning engine</li>
            <li><strong>Zone 3 &mdash; Tool Execution:</strong> External tool and API calls the agent can make</li>
            <li><strong>Zone 4 &mdash; Memory &amp; State:</strong> Persistent storage, context windows, and state management</li>
            <li><strong>Zone 5 &mdash; Inter-Agent Communication:</strong> Message passing between agents in multi-agent systems</li>
          </ul>
        </div>

        <div style="margin-bottom:18px;">
          <strong style="color:var(--text-primary);">OWASP Agentic Threat Framework</strong>
          <p style="font-size:13px;color:var(--text-secondary);margin-top:4px;">
            A taxonomy of 17 threat categories (T1&ndash;T17) specific to autonomous AI agent architectures,
            published by OWASP. Each threat describes a class of attack that exploits agent-specific
            capabilities such as tool use, memory, multi-agent communication, or human-in-the-loop
            interactions. Threats are further decomposed into sub-scenarios (e.g.&nbsp;T7-S1, T7-S2) that
            provide concrete attack seeds.
          </p>
        </div>

        <div>
          <strong style="color:var(--text-primary);">Scenario Forge 4-Stage Pipeline</strong>
          <ol style="font-size:13px;color:var(--text-secondary);margin:6px 0 0 20px;">
            <li><strong>Capability Profile:</strong> Infer the agent&rsquo;s capabilities, active zones, and entry points from a use-case description</li>
            <li><strong>Threat Surface:</strong> Map the capability profile against risk taxonomies (IBM AI Risk Atlas, OWASP LLM Top&nbsp;10) and determine which agentic threats apply</li>
            <li><strong>Scenario Seeds:</strong> Expand each applicable threat into concrete sub-scenario seeds drawn from the OWASP agentic threat taxonomy</li>
            <li><strong>Scenario Generation:</strong> Use an LLM to generate full red-team scenarios for each seed, including narrative, attack trees, behavior specifications (Gherkin), and priority signals</li>
          </ol>
        </div>
      </div>

      <!-- External links -->
      <div class="card">
        <div class="scenario-section-title">External References</div>
        <ul style="list-style:none;padding:0;margin:0;">
          <li style="padding:8px 0;border-bottom:1px solid var(--border);">
            <a href="https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none;font-size:13px;">
              OWASP Agentic AI Threats &amp; Mitigations &#8599;
            </a>
          </li>
          <li style="padding:8px 0;border-bottom:1px solid var(--border);">
            <a href="https://genai.owasp.org/llm-top-10/" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none;font-size:13px;">
              OWASP Top 10 for LLM Applications &#8599;
            </a>
          </li>
          <li style="padding:8px 0;border-bottom:1px solid var(--border);">
            <a href="https://atlas.mitre.org/" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none;font-size:13px;">
              MITRE ATLAS &#8599;
            </a>
          </li>
          <li style="padding:8px 0;">
            <a href="https://www.ibm.com/docs/en/watsonx/saas?topic=ai-risk-atlas" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none;font-size:13px;">
              IBM AI Risk Atlas &#8599;
            </a>
          </li>
        </ul>
      </div>
    </div>
    """


# ---------------------------------------------------------------------------
# Full page assembly
# ---------------------------------------------------------------------------


def build_full_page(
    profile_html: str,
    threats_html: str,
    scenarios_html: str,
    raw_html: str,
    coverage_html: str = "",
    diversity_html: str = "",
    title: str = "Scenario Forge Report",
) -> str:
    # Conditionally add sidebar links for coverage and diversity sections
    coverage_nav = ""
    if coverage_html:
        coverage_nav = '<a href="#sec-coverage"><span class="nav-icon">&#9635;</span> Coverage Analysis</a>'
    diversity_nav = ""
    if diversity_html:
        diversity_nav = '<a href="#sec-diversity"><span class="nav-icon">&#9783;</span> Actor Profiles</a>'

    glossary_html = build_glossary_section()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{_esc(title)}</title>
  {build_css()}
</head>
<body>
  <aside class="sidebar">
    <div class="sidebar-brand">
      <h1>SCENARIO FORGE</h1>
      <div class="subtitle">Red-Team Report</div>
    </div>
    <nav>
      <a href="#sec-profile"><span class="nav-icon">&#9670;</span> Capability Profile</a>
      <a href="#sec-threats"><span class="nav-icon">&#9888;</span> Threat Surface</a>
      {coverage_nav}
      {diversity_nav}
      <a href="#sec-scenarios"><span class="nav-icon">&#9733;</span> Scenarios</a>
      <a href="#sec-raw"><span class="nav-icon">&#128196;</span> Raw Data</a>
      <a href="#glossary"><span class="nav-icon">&#128214;</span> Glossary</a>
    </nav>
  </aside>

  <main class="main-content">
    {profile_html}
    {threats_html}
    {coverage_html}
    {diversity_html}
    {scenarios_html}
    {raw_html}
    {glossary_html}
  </main>

  {build_js()}
</body>
</html>
"""
