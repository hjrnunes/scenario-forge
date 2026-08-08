"""Tests for STPA infra run manifest (InfraManifest-01 through InfraManifest-05)."""

from __future__ import annotations

import importlib


from scenario_forge.stpa.infra.manifest import STPARunManifest


class TestInfraManifest:
    """Simplified STPA run manifest."""

    def _base_manifest_data(self) -> dict:
        return {
            "run_id": "RUN-001",
            "run_dir": "output/test",
            "created_at": "2026-08-08T12:00:00Z",
            "model_config": {"model": "test-model", "temperature": 0.4},
            "input_hashes": {"use_case": "abc123"},
            "prompt_hashes": {"call0_system.j2": "def456"},
            "stage_summary": {"stage_1": {"calls": 1, "duration_ms": 5000}},
        }

    def test_manifest_01_valid_manifest_passes(self):
        """InfraManifest-01: valid run manifest passes validation."""
        manifest = STPARunManifest(**self._base_manifest_data())
        assert manifest.run_id == "RUN-001"
        assert manifest.run_dir == "output/test"

    def test_manifest_02_with_fill_rate_and_counts(self):
        """InfraManifest-02: manifest with fill_rate and counts passes."""
        data = self._base_manifest_data()
        data["slot_count"] = 10
        data["na_count"] = 2
        data["fill_rate"] = 0.8
        data["scenario_count"] = 5
        manifest = STPARunManifest(**data)
        assert manifest.slot_count == 10
        assert manifest.na_count == 2
        assert manifest.fill_rate == 0.8
        assert manifest.scenario_count == 5

    def test_manifest_03_with_critic_findings(self):
        """InfraManifest-03: manifest with critic findings passes."""
        data = self._base_manifest_data()
        data["critic_findings"] = [
            "gap in hazard coverage",
            "missing constraint for H-2",
        ]
        manifest = STPARunManifest(**data)
        assert len(manifest.critic_findings) == 2

    def test_manifest_04_with_eval_scorecard_path(self):
        """InfraManifest-04: manifest with eval scorecard path passes."""
        data = self._base_manifest_data()
        data["eval_scorecard_path"] = "output/test/eval-scorecard.yaml"
        manifest = STPARunManifest(**data)
        assert manifest.eval_scorecard_path == "output/test/eval-scorecard.yaml"

    def test_manifest_05_not_coupled_to_existing_manifest(self):
        """InfraManifest-05: module does not import the existing pipeline manifest."""
        # Reload the module and check its loaded modules
        mod = importlib.import_module("scenario_forge.stpa.infra.manifest")
        mod_source = open(mod.__file__).read()
        assert "scenario_forge.manifest" not in mod_source
        assert "from scenario_forge.manifest" not in mod_source
        assert "import scenario_forge.manifest" not in mod_source
