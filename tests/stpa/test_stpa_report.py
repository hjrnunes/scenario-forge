"""Tests for the STPA HTML report generator."""

from __future__ import annotations

from pathlib import Path

import pytest

from scenario_forge.stpa.report import generate_report
from scenario_forge.stpa.report.template import (
    _esc,
    _highlight_gherkin,
    _highlight_yaml,
    _build_eval_gauge,
    _build_attack_tree_visual,
    _build_produces_arrow,
    _build_sticky_nav,
)

FIXTURES_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "scenario_forge"
    / "stpa"
    / "fixtures"
)


class TestEscaping:
    def test_esc_none(self):
        assert _esc(None) == ""

    def test_esc_html(self):
        assert _esc("<script>alert('xss')</script>") == "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"

    def test_esc_int(self):
        assert _esc(42) == "42"


class TestHighlighting:
    def test_highlight_yaml_keys(self):
        result = _highlight_yaml("key: value")
        assert 'yaml-key' in result

    def test_highlight_yaml_list(self):
        result = _highlight_yaml("- item")
        assert result

    def test_highlight_yaml_comment(self):
        result = _highlight_yaml("# comment")
        assert 'yaml-comment' in result

    def test_highlight_gherkin_given(self):
        result = _highlight_gherkin("Given the system is running")
        assert 'gherkin-keyword' in result

    def test_highlight_gherkin_then(self):
        result = _highlight_gherkin("Then the response should be valid")
        assert 'gherkin-keyword' in result


class TestEvalGauge:
    def test_green_threshold(self):
        html = _build_eval_gauge("test_metric", 0.85)
        assert "green" in html.lower() or "#22c55e" in html.lower()

    def test_yellow_threshold(self):
        html = _build_eval_gauge("test_metric", 0.65)
        assert "yellow" in html.lower() or "#d29922" in html.lower()

    def test_red_threshold(self):
        html = _build_eval_gauge("test_metric", 0.45)
        assert "red" in html.lower() or "#f85149" in html.lower()


class TestAttackTreeVisual:
    def test_empty_tree(self):
        html = _build_attack_tree_visual({})
        assert isinstance(html, str)

    def test_tree_with_branches(self):
        tree = {
            "root": "Test root",
            "branches": [
                {"category": "controller_side", "label": "Corrupt PM", "children": []},
                {"category": "path_side", "label": "Actuator failure", "children": []},
            ],
        }
        html = _build_attack_tree_visual(tree)
        assert "controller_side" in html or "controller-side" in html.lower()
        assert "path_side" in html or "path-side" in html.lower()


class TestProducesArrow:
    def test_arrow_is_div(self):
        html = _build_produces_arrow()
        assert isinstance(html, str)
        assert len(html) > 0


class TestStickyNav:
    def test_nav_has_links(self):
        html = _build_sticky_nav()
        assert "SP1" in html
        assert "SP2" in html
        assert "SP3" in html


class TestGenerateReport:
    def test_generate_from_minimal_dir(self, tmp_path):
        """Report generation works with a minimal output directory."""
        # Create minimal artifacts
        (tmp_path / "loss-analysis.yaml").write_text(
            "risk_card_losses: []\n"
            "use_case_losses:\n"
            "  - loss_id: L-1\n"
            "    description: Test loss\n"
            "    provenance: use_case\n"
            "hazards:\n"
            "  - hazard_id: H-1\n"
            "    description: Test hazard\n"
            "    related_losses: [L-1]\n"
            "security_constraints:\n"
            "  - constraint_id: SC-1\n"
            "    description: Test constraint\n"
            "    related_hazards: [H-1]\n"
        )
        (tmp_path / "run-manifest.yaml").write_text(
            "run_id: test-run\n"
            "created_at: '2026-08-10T12:00:00Z'\n"
        )

        result = generate_report(tmp_path)
        assert result.exists()
        html = result.read_text(encoding="utf-8")
        assert "<html" in html
        assert "</html>" in html
        assert "test-run" in html

    def test_generate_with_custom_output_path(self, tmp_path):
        """Report generation respects custom output path."""
        (tmp_path / "run-manifest.yaml").write_text("run_id: test\n")
        output_file = tmp_path / "custom-report.html"
        result = generate_report(tmp_path, output_file)
        assert result == output_file
        assert output_file.exists()

    def test_nonexistent_dir_raises(self):
        with pytest.raises(FileNotFoundError):
            generate_report(Path("/nonexistent/path"))

    def test_self_contained_no_external_deps(self, tmp_path):
        """Report HTML has no external dependencies."""
        (tmp_path / "run-manifest.yaml").write_text("run_id: test\n")
        result = generate_report(tmp_path)
        html = result.read_text(encoding="utf-8")
        # No external CSS
        assert '<link rel="stylesheet"' not in html
        assert '<link href=' not in html
        # No external JS
        assert '<script src=' not in html
        # No external images
        assert '<img src="http' not in html

    def test_generate_with_klarna_fixtures(self, tmp_path):
        """Report generation works with real Klarna fixtures."""
        import shutil

        # Copy SP1 fixtures
        for name in ["loss_analysis_klarna.yaml", "capability_profile_klarna.yaml",
                      "control_structure_klarna.yaml"]:
            src = FIXTURES_DIR / name
            if src.exists():
                dest_name = name.replace("_klarna", "")
                shutil.copy(src, tmp_path / dest_name)

        # Copy SP2 fixtures
        for name in ["ica_enumeration_klarna.yaml", "enriched_threats_klarna.yaml"]:
            src = FIXTURES_DIR / name
            if src.exists():
                dest_name = name.replace("_klarna", "")
                shutil.copy(src, tmp_path / dest_name)

        # Create minimal manifest
        (tmp_path / "run-manifest.yaml").write_text(
            "run_id: klarna-test\n"
            "created_at: '2026-08-10T12:00:00Z'\n"
        )

        result = generate_report(tmp_path)
        assert result.exists()
        html = result.read_text(encoding="utf-8")
        assert "klarna" in html.lower() or "Klarna" in html
