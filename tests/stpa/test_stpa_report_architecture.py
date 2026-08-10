"""Architecture guard and property tests for the STPA report module.

Architecture guards enforce structural invariants:

1. **Dependency direction**: ``template.py`` (renderer, IO-far) must not
   import from ``generator.py`` (loader, IO-near).  The dependency must
   point from loader → renderer.
2. **Public API contract**: ``generator.py`` may only import names listed
   in ``template.__all__`` — it must never reach into private
   implementation details.
3. **No import cycles**: The report package imports without circular
   dependency errors.

Property tests validate behavioral invariants:

- HTML output is always a well-formed document.
- HTML escaping is idempotent.
- Syntax highlighting preserves text content.
- ``build_html`` always produces a complete document skeleton.
"""

from __future__ import annotations

import ast
import importlib
import re
from html import unescape as _html_unescape
from pathlib import Path

import pytest

from scenario_forge.stpa.report import generate_report
from scenario_forge.stpa.report.template import (
    _esc,
    _highlight_gherkin,
    _highlight_yaml,
    build_html,
    build_sp1_card,
    build_sp2_card,
    build_sp3_card,
    build_llm_call_inspector,
    build_run_manifest,
    extract_metric_rate,
)

REPORT_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "scenario_forge"
    / "stpa"
    / "report"
)
TEMPLATE_PATH = REPORT_DIR / "template.py"
GENERATOR_PATH = REPORT_DIR / "generator.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_imports(file_path: Path) -> list[str]:
    """Return fully-qualified module names imported in *file_path*."""
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    return imports


def _extract_imported_names(file_path: Path, from_module: str) -> set[str]:
    """Return the set of names imported from *from_module* in *file_path*."""
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == from_module:
            for alias in node.names:
                names.add(alias.name)
    return names


def _strip_html_tags(html_str: str) -> str:
    """Remove all HTML tags and decode entities, returning only text content."""
    return _html_unescape(re.sub(r"<[^>]+>", "", html_str))


# ---------------------------------------------------------------------------
# Architecture guard tests — dependency direction
# ---------------------------------------------------------------------------


class TestDependencyDirection:
    """template.py must not depend on generator.py."""

    def test_template_does_not_import_generator(self):
        """template.py has zero imports from generator.py."""
        imports = _extract_imports(TEMPLATE_PATH)
        violations = [
            imp for imp in imports
            if "scenario_forge.stpa.report.generator" in imp
        ]
        assert not violations, (
            f"template.py must not import from generator.py, found: {violations}"
        )

    def test_generator_imports_from_template(self):
        """generator.py imports from template.py (correct direction)."""
        imports = _extract_imports(GENERATOR_PATH)
        assert any("scenario_forge.stpa.report.template" in imp for imp in imports), (
            "generator.py should import from template.py"
        )

    def test_template_does_not_import_models(self):
        """template.py must not import STPA model modules.

        The renderer should be a pure HTML assembly layer that works
        with any duck-typed object — it must not be coupled to specific
        Pydantic model classes.
        """
        imports = _extract_imports(TEMPLATE_PATH)
        violations = [
            imp for imp in imports
            if imp.startswith("scenario_forge.stpa.models.")
            or imp.startswith("scenario_forge.models.")
        ]
        assert not violations, (
            f"template.py must not import model modules, found: {violations}"
        )

    def test_template_only_uses_stdlib(self):
        """template.py imports only from the Python standard library."""
        imports = _extract_imports(TEMPLATE_PATH)
        stdlib_prefixes = (
            "html", "re", "typing", "__future__", "json",
        )
        violations = [
            imp for imp in imports
            if not imp.startswith(stdlib_prefixes)
        ]
        assert not violations, (
            f"template.py should only import stdlib, found: {violations}"
        )


# ---------------------------------------------------------------------------
# Architecture guard tests — public API contract
# ---------------------------------------------------------------------------


class TestPublicApiContract:
    """generator.py may only import public names from template.py."""

    def test_generator_imports_only_public_names(self):
        """generator.py does not import private (_-prefixed) names from template."""
        names = _extract_imported_names(
            GENERATOR_PATH, "scenario_forge.stpa.report.template",
        )
        private = {n for n in names if n.startswith("_")}
        assert not private, (
            f"generator.py must not import private names from template.py: {private}"
        )

    def test_template_has_all_declaration(self):
        """template.py declares __all__ listing its public API."""
        import scenario_forge.stpa.report.template as template_mod
        assert hasattr(template_mod, "__all__"), (
            "template.py must declare __all__ for its public API"
        )
        assert len(template_mod.__all__) > 0

    def test_all_names_are_public(self):
        """Every name in __all__ is public (no underscore prefix)."""
        import scenario_forge.stpa.report.template as template_mod
        private = [n for n in template_mod.__all__ if n.startswith("_")]
        assert not private, (
            f"__all__ must not contain private names: {private}"
        )

    def test_all_names_exist_as_attributes(self):
        """Every name in __all__ is a real attribute of the module."""
        import scenario_forge.stpa.report.template as template_mod
        missing = [
            n for n in template_mod.__all__
            if not hasattr(template_mod, n)
        ]
        assert not missing, (
            f"__all__ lists names that don't exist: {missing}"
        )

    def test_generator_imports_match_all(self):
        """generator.py imports exactly the names in template.__all__."""
        import scenario_forge.stpa.report.template as template_mod
        names = _extract_imported_names(
            GENERATOR_PATH, "scenario_forge.stpa.report.template",
        )
        all_set = set(template_mod.__all__)
        extra = names - all_set
        assert not extra, (
            f"generator.py imports names not in __all__: {extra}"
        )

    def test_public_functions_are_callable(self):
        """All public API functions are callable."""
        for name in (
            build_html, build_sp1_card, build_sp2_card, build_sp3_card,
            build_llm_call_inspector, build_run_manifest, extract_metric_rate,
        ):
            assert callable(name), f"{name} is not callable"


# ---------------------------------------------------------------------------
# Architecture guard tests — no import cycles
# ---------------------------------------------------------------------------


class TestNoImportCycles:
    """The report package must import without circular dependency errors."""

    def test_import_package(self):
        """Importing the report package succeeds without errors."""
        mod = importlib.import_module("scenario_forge.stpa.report")
        assert hasattr(mod, "generate_report")

    def test_import_generator(self):
        """Importing generator.py succeeds without errors."""
        mod = importlib.import_module("scenario_forge.stpa.report.generator")
        assert hasattr(mod, "generate_report")

    def test_import_template(self):
        """Importing template.py succeeds without errors."""
        mod = importlib.import_module("scenario_forge.stpa.report.template")
        assert hasattr(mod, "build_html")


# ---------------------------------------------------------------------------
# Property tests — HTML well-formedness
# ---------------------------------------------------------------------------


class TestHtmlWellFormedness:
    """Generated HTML must always be a well-formed document."""

    def test_build_html_has_doctype(self):
        html = build_html()
        assert html.strip().startswith("<!DOCTYPE html>")

    def test_build_html_has_html_tags(self):
        html = build_html()
        assert "<html" in html
        assert "</html>" in html

    def test_build_html_has_head_and_body(self):
        html = build_html()
        assert "<head>" in html
        assert "</head>" in html
        assert "<body>" in html
        assert "</body>" in html

    def test_build_html_has_style_and_script(self):
        html = build_html()
        assert "<style>" in html
        assert "</style>" in html
        assert "<script>" in html
        assert "</script>" in html

    def test_build_html_with_all_sections_has_doctype(self):
        html = build_html(
            run_id="test",
            sp1_html="<div>SP1</div>",
            sp2_html="<div>SP2</div>",
            sp3_html="<div>SP3</div>",
            calls_html="<div>Calls</div>",
            manifest_html="<div>Manifest</div>",
        )
        assert html.strip().startswith("<!DOCTYPE html>")

    def test_generate_report_produces_well_formed_html(self, tmp_path):
        """Full report generation always yields a well-formed HTML document."""
        (tmp_path / "run-manifest.yaml").write_text("run_id: test\n")
        result = generate_report(tmp_path)
        html = result.read_text(encoding="utf-8")
        assert html.strip().startswith("<!DOCTYPE html>")
        assert "<html" in html and "</html>" in html
        assert "<head>" in html and "</head>" in html
        assert "<body>" in html and "</body>" in html


# ---------------------------------------------------------------------------
# Property tests — escaping idempotence
# ---------------------------------------------------------------------------


class TestEscapingProperties:
    """HTML escaping must produce safe output."""

    @pytest.mark.parametrize("text", [
        "plain text",
        "<script>alert('xss')</script>",
        "a & b < c > d",
        "",
        "no special chars",
        "nested <b>bold</b> & <i>italic</i>",
        "'quotes' and \"double quotes\"",
        "unicode: café ☕",
    ])
    def test_esc_no_raw_special_chars(self, text):
        """After escaping, no raw <, >, or & remain (only HTML entities)."""
        escaped = _esc(text)
        # Remove valid HTML entities
        without_entities = re.sub(r"&[a-zA-Z]+;|&#\d+;|&#x[0-9a-fA-F]+;", "", escaped)
        assert "<" not in without_entities
        assert ">" not in without_entities
        assert "&" not in without_entities

    def test_esc_plain_text_unchanged(self):
        """Strings without HTML-special characters pass through unchanged."""
        assert _esc("hello world") == "hello world"
        assert _esc("café ☕") == "café ☕"

    def test_esc_none_is_empty(self):
        assert _esc(None) == ""


# ---------------------------------------------------------------------------
# Property tests — highlighting preserves text content
# ---------------------------------------------------------------------------


class TestHighlightingPreservesText:
    """Syntax highlighting must not lose or alter text content.

    After stripping all HTML tags from highlighted output, the remaining
    text must match the stripped original.
    """

    @pytest.mark.parametrize("yaml_text", [
        "key: value",
        "# comment\nkey: value",
        "list:\n  - item1\n  - item2",
        "number: 42\nbool: true\nnull_val: null",
        '"quoted": "string value"',
        "nested:\n  deep:\n    deeper: yes",
        "- item with # not a comment in value",
    ])
    def test_yaml_highlighting_preserves_text(self, yaml_text):
        highlighted = _highlight_yaml(yaml_text)
        stripped_highlighted = _strip_html_tags(highlighted)
        stripped_original = _strip_html_tags(yaml_text)
        assert stripped_highlighted == stripped_original

    @pytest.mark.parametrize("gherkin_text", [
        "Feature: Test",
        "Given a step\nWhen another step\nThen result",
        "# a comment\n@tag\nScenario: Test",
        'Given a step\n"""\ndocstring\n"""',
        "Feature: Test\nBackground:\n  Given setup",
    ])
    def test_gherkin_highlighting_preserves_text(self, gherkin_text):
        highlighted = _highlight_gherkin(gherkin_text)
        stripped_highlighted = _strip_html_tags(highlighted)
        stripped_original = _strip_html_tags(gherkin_text)
        assert stripped_highlighted == stripped_original


# ---------------------------------------------------------------------------
# Property tests — section builders return non-empty strings
# ---------------------------------------------------------------------------


class TestSectionBuildersReturnStrings:
    """All public section builders return string values."""

    def test_build_sp1_card_returns_str(self):
        result = build_sp1_card(None, None, None, None)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_build_sp2_card_returns_str(self):
        result = build_sp2_card(None, None, None)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_build_sp3_card_returns_str(self):
        result = build_sp3_card([], None, None)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_build_llm_call_inspector_returns_str(self):
        result = build_llm_call_inspector([])
        assert isinstance(result, str)
        assert len(result) > 0

    def test_build_run_manifest_returns_str(self):
        result = build_run_manifest(None, None)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_build_run_manifest_with_data_returns_str(self):
        manifest = {"run_id": "r1", "created_at": "2026-01-01"}
        result = build_run_manifest(manifest, None)
        assert isinstance(result, str)
        assert "r1" in result


# ---------------------------------------------------------------------------
# Property tests — extract_metric_rate invariants
# ---------------------------------------------------------------------------


class TestExtractMetricRateInvariants:
    """extract_metric_rate must always return a float in [0, 1] or None."""

    @pytest.mark.parametrize("data,expected", [
        (None, None),
        ("string", None),
        ([1, 2], None),
        ({}, None),
        ({"name": "test"}, None),
    ])
    def test_invalid_inputs_return_none(self, data, expected):
        assert extract_metric_rate(data) is expected

    @pytest.mark.parametrize("rate", [0.0, 0.1, 0.5, 0.9, 1.0])
    def test_valid_rate_returned(self, rate):
        assert extract_metric_rate({"rate": rate}) == rate

    def test_rate_takes_precedence_over_rate_fields(self):
        """When both 'rate' and '*_rate' fields exist, 'rate' wins."""
        data = {"rate": 0.9, "a_rate": 0.1, "b_rate": 0.2}
        assert extract_metric_rate(data) == 0.9

    def test_averaged_rate_fields(self):
        data = {"a_rate": 0.8, "b_rate": 0.6}
        assert extract_metric_rate(data) == 0.7


# ---------------------------------------------------------------------------
# Property tests — self-contained HTML (no external deps)
# ---------------------------------------------------------------------------


class TestSelfContainedHtml:
    """Generated HTML must have no external dependencies."""

    @pytest.mark.parametrize("external_pattern", [
        '<link rel="stylesheet"',
        '<link href=',
        '<script src=',
        '<img src="http',
        '<img src="https',
    ])
    def test_no_external_resources(self, external_pattern):
        html = build_html()
        assert external_pattern not in html

    def test_generate_report_no_external_resources(self, tmp_path):
        (tmp_path / "run-manifest.yaml").write_text("run_id: test\n")
        result = generate_report(tmp_path)
        html = result.read_text(encoding="utf-8")
        assert '<link rel="stylesheet"' not in html
        assert '<script src=' not in html
        assert '<img src="http' not in html
